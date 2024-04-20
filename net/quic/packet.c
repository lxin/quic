// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/gro.h>
#include "socket.h"
#include "number.h"
#include "frame.h"
#include <linux/version.h>

static int quic_packet_stateless_reset_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_connection_id_set *id_set = quic_dest(sk);
	struct quic_connection_close close = {};
	u8 *token;

	if (skb->len < 22)
		return -EINVAL;

	token = skb->data + skb->len - 16;
	if (!quic_connection_id_token_exists(id_set, token))
		return -EINVAL; /* not a stateless reset and the caller will free skb */

	close.errcode = QUIC_TRANSPORT_ERROR_CRYPTO;
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close))
		return -ENOMEM;
	quic_set_state(sk, QUIC_SS_CLOSED);
	consume_skb(skb);
	pr_debug("%s: peer reset\n", __func__);
	return 0;
}

static int quic_packet_handshake_retry_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_connection_id_set *id_set = quic_dest(sk);
	struct quic_connection_id dcid, scid = {}, *active;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	u32 len = skb->len, version;
	u8 *p = skb->data, tag[16];
	u64 dlen;

	p++;
	len--;
	p += 4;
	len -= 4;
	/* DCID */
	if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen || dlen > QUIC_CONNECTION_ID_MAX_LEN)
		goto err;
	quic_connection_id_update(&dcid, p, dlen);
	len -= dlen;
	p += dlen;
	/* SCID */
	if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen || dlen > QUIC_CONNECTION_ID_MAX_LEN)
		goto err;
	quic_connection_id_update(&scid, p, dlen);
	len -= dlen;
	p += dlen;
	if (len < 16)
		goto err;
	version = quic_inq_version(inq);
	if (quic_crypto_get_retry_tag(crypto, skb, quic_outq_orig_dcid(outq), version, tag) ||
	    memcmp(tag, p + len - 16, 16))
		goto err;
	if (quic_data_dup(quic_token(sk), p, len - 16))
		goto err;

	quic_crypto_destroy(crypto);
	if (quic_crypto_initial_keys_install(crypto, &scid, version, 0, 0))
		goto err;
	active = quic_connection_id_active(id_set);
	quic_connection_id_update(active, scid.data, scid.len);
	quic_outq_set_retry(outq, 1);
	quic_outq_set_retry_dcid(outq, active);
	quic_outq_retransmit_mark(sk, QUIC_CRYPTO_INITIAL, 1);
	quic_outq_transmit(sk);

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

static int quic_packet_handshake_version_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_connection_id dcid, scid;
	u32 len = skb->len, best = 0;
	u8 *p = skb->data;
	u64 dlen, version;

	p++;
	len--;
	p += 4;
	len -= 4;
	/* DCID */
	if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen || dlen > QUIC_CONNECTION_ID_MAX_LEN)
		goto err;
	quic_connection_id_update(&dcid, p, dlen);
	len -= dlen;
	p += dlen;
	/* SCID */
	if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen || dlen > QUIC_CONNECTION_ID_MAX_LEN)
		goto err;
	quic_connection_id_update(&scid, p, dlen);
	len -= dlen;
	p += dlen;
	if (len < 4)
		goto err;

	while (len >= 4) {
		quic_get_int(&p, &len, &version, 4);
		if (quic_compatible_versions(version) && best < version)
			best = version;
	}
	if (best) {
		quic_inq_set_version(inq, best);
		quic_crypto_destroy(crypto);
		if (quic_crypto_initial_keys_install(crypto, &scid, best, 0, 0))
			goto err;
		quic_outq_retransmit_mark(sk, QUIC_CRYPTO_INITIAL, 1);
		quic_outq_transmit(sk);
	}

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

#if KERNEL_VERSION(6, 2, 0) <= LINUX_VERSION_CODE
static void quic_packet_decrypt_done(void *data, int err)
{
	struct sk_buff *skb = data;
#else
static void quic_packet_decrypt_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;
#endif

	if (err) {
		kfree_skb(skb);
		pr_warn_once("%s: err %d\n", __func__, err);
		return;
	}

	quic_inq_decrypted_tail(skb->sk, skb);
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb, u8 resume)
{
	struct quic_connection_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_connection_id *active;
	struct quic_packet_info pki = {};
	u64 version, dlen, slen, tlen;
	u8 *p, level = 0, *scid, type;
	struct quic_crypto *crypto;
	struct quichshdr *hshdr;
	int len, err = -EINVAL;
	struct sk_buff *fskb;

	while (skb->len > 0) {
		hshdr = quic_hshdr(skb);
		if (!hshdr->form) /* handle it later when setting 1RTT key */
			return quic_packet_process(sk, skb, 0);
		p = (u8 *)hshdr;
		len = skb->len;
		if (len < 5)
			goto err;
		/* VERSION */
		p++;
		len--;
		quic_get_int(&p, &len, &version, 4);
		if (!version)
			return quic_packet_handshake_version_process(sk, skb);
		else if (version != quic_inq_version(inq))
			goto err;
		type = quic_version_get_type(version, hshdr->type);
		switch (type) {
		case QUIC_PACKET_INITIAL:
			level = QUIC_CRYPTO_INITIAL;
			break;
		case QUIC_PACKET_HANDSHAKE:
			level = QUIC_CRYPTO_HANDSHAKE;
			crypto = quic_crypto(sk, level);
			if (!quic_crypto_recv_ready(crypto)) {
				quic_inq_backlog_tail(sk, skb);
				return 0;
			}
			break;
		case QUIC_PACKET_0RTT:
			level = QUIC_CRYPTO_EARLY;
			crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
			if (!quic_crypto_recv_ready(crypto)) {
				quic_inq_backlog_tail(sk, skb);
				return 0;
			}
			break;
		case QUIC_PACKET_RETRY:
			return quic_packet_handshake_retry_process(sk, skb);
		default:
			goto err;
		}
		/* DCID */
		if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen ||
		    dlen > QUIC_CONNECTION_ID_MAX_LEN)
			goto err;
		len -= dlen;
		p += dlen;
		/* SCID */
		if (!quic_get_int(&p, &len, &slen, 1) || len < slen ||
		    slen > QUIC_CONNECTION_ID_MAX_LEN)
			goto err;
		len -= slen;
		scid = p;
		p += slen;
		if (level == QUIC_CRYPTO_INITIAL) {
			/* TOKEN */
			if (!quic_get_var(&p, &len, &tlen) || len < tlen)
				goto err;
			if (!quic_is_serv(sk) && tlen) {
				pki.errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
				goto err;
			}
			p += tlen;
			len -= tlen;
		}
		/* LENGTH */
		if (!quic_get_var(&p, &len, &pki.length) || pki.length > len)
			goto err;
		pki.number_offset = p - (u8 *)hshdr;
		if (resume) {
			p = (u8 *)hshdr + pki.number_offset;
			pki.number_len = hshdr->pnl + 1;
			quic_get_int(&p, &len, &pki.number, pki.number_len);
			pki.number = quic_get_num(pki.number_max, pki.number, pki.number_len);
			goto skip;
		}
		pki.crypto_done = quic_packet_decrypt_done;
		pki.resume = resume;
		err = quic_crypto_decrypt(quic_crypto(sk, level), skb, &pki);
		if (err) {
			if (err == -EINPROGRESS)
				return err;
			goto err;
		}

skip:
		if (hshdr->reserved) {
			pki.errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			goto err;
		}

		pr_debug("[QUIC] %s serv: %d number: %llu level: %d len: %d\n", __func__,
			 quic_is_serv(sk), pki.number, level, skb->len);

		if (level == QUIC_CRYPTO_EARLY)
			level = QUIC_CRYPTO_APP; /* pnmap level */
		err = quic_pnmap_check(quic_pnmap(sk, level), pki.number);
		if (err) {
			err = -EINVAL;
			goto err;
		}

		skb_pull(skb, pki.number_offset + pki.number_len);
		pki.length -= pki.number_len;
		pki.length -= packet->taglen[1];
		QUIC_RCV_CB(skb)->level = level;
		err = quic_frame_process(sk, skb, &pki);
		if (err)
			goto err;
		err = quic_pnmap_mark(quic_pnmap(sk, level), pki.number);
		if (err)
			goto err;
		skb_pull(skb, packet->taglen[1]);
		if (pki.ack_eliciting) {
			if (!quic_is_serv(sk) && level == QUIC_CRYPTO_INITIAL) {
				active = quic_connection_id_active(id_set);
				quic_connection_id_update(active, scid, slen);
			}
			fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
			if (fskb)
				quic_outq_ctrl_tail(sk, fskb, true);
		}
		resume = 0;
		skb_reset_transport_header(skb);
	}
	consume_skb(skb);
	return 0;
err:
	pr_warn("[QUIC] %s serv: %d number: %llu level: %d err: %d\n", __func__,
		quic_is_serv(sk), pki.number, level, err);
	quic_outq_transmit_close(sk, pki.frame, pki.errcode, level);
	kfree_skb(skb);
	return err;
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb, u8 resume)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_pnmap *pnmap = quic_pnmap(sk, QUIC_CRYPTO_APP);
	struct quic_connection_id_set *id_set = quic_source(sk);
	struct quic_rcv_cb *rcv_cb = QUIC_RCV_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quichdr *hdr = quic_hdr(skb);
	struct quic_packet_info pki = {};
	u8 *p, key_phase, level = 0;
	union quic_addr addr;
	struct sk_buff *fskb;
	int err = -EINVAL;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	if (hdr->form)
		return quic_packet_handshake_process(sk, skb, resume);

	if (!hdr->fixed && !quic_inq_grease_quic_bit(inq))
		goto err;

	if (!quic_crypto_recv_ready(crypto)) {
		quic_inq_backlog_tail(sk, skb);
		return 0;
	}

	pki.number_offset = quic_connection_id_active(id_set)->len + sizeof(*hdr);
	if (rcv_cb->number_offset)
		pki.number_offset = rcv_cb->number_offset;

	pki.length = skb->len - pki.number_offset;
	pki.number_max = quic_pnmap_max_pn_seen(pnmap);
	if (resume || !packet->taglen[0]) {
		p = (u8 *)hdr + pki.number_offset;
		pki.number_len = hdr->pnl + 1;
		quic_get_int(&p, NULL, &pki.number, pki.number_len);
		pki.number = quic_get_num(pki.number_max, pki.number, pki.number_len);
		pki.key_phase = hdr->key;
		goto skip;
	}
	pki.crypto_done = quic_packet_decrypt_done;
	pki.resume = resume;
	err = quic_crypto_decrypt(crypto, skb, &pki);
	if (err) {
		if (err == -EINPROGRESS)
			return err;
		if (!quic_packet_stateless_reset_process(sk, skb))
			return 0;
		goto err;
	}

skip:
	if (hdr->reserved) {
		pki.errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		goto err;
	}

	pr_debug("[QUIC] %s serv: %d number: %llu len: %d\n", __func__,
		 quic_is_serv(sk), pki.number, skb->len);

	err = quic_pnmap_check(pnmap, pki.number);
	if (err) {
		pki.errcode = QUIC_TRANSPORT_ERROR_INTERNAL;
		err = -EINVAL;
		goto err;
	}

	/* Set path_alt so that the replies will choose the correct path */
	quic_get_msg_addr(sk, &addr, skb, 0);
	if (!quic_path_cmp(quic_src(sk), 1, &addr))
		rcv_cb->path_alt |= QUIC_PATH_ALT_SRC;

	quic_get_msg_addr(sk, &addr, skb, 1);
	if (quic_path_cmp(quic_dst(sk), 0, &addr)) {
		quic_path_addr_set(quic_dst(sk), &addr, 1);
		rcv_cb->path_alt |= QUIC_PATH_ALT_DST;
	}

	skb_pull(skb, pki.number_offset + pki.number_len);
	pki.length -= pki.number_len;
	pki.length -= packet->taglen[0];
	rcv_cb->level = 0;
	err = quic_frame_process(sk, skb, &pki);
	if (err)
		goto err;
	err = quic_pnmap_mark(pnmap, pki.number);
	if (err)
		goto err;
	skb_pull(skb, packet->taglen[0]);
	quic_pnmap_inc_ecn_count(pnmap, quic_get_msg_ecn(sk, skb));

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	if (pki.non_probing && pki.number == quic_pnmap_max_pn_seen(pnmap)) {
		if (!quic_connection_id_disable_active_migration(quic_dest(sk)) &&
		    (rcv_cb->path_alt & QUIC_PATH_ALT_DST))
			quic_sock_change_daddr(sk, &addr, quic_addr_len(sk));
		if (quic_outq_pref_addr(outq) &&
		    (rcv_cb->path_alt & QUIC_PATH_ALT_SRC))
			quic_sock_change_saddr(sk, NULL, 0);
	}

	if (pki.key_update) {
		key_phase = pki.key_phase;
		if (!quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase)) {
			quic_crypto_set_key_pending(crypto, 0);
			quic_crypto_set_key_update_send_ts(crypto, 0);
		}
	}

	if (!pki.ack_eliciting)
		goto out;

	if (!pki.ack_immediate && !quic_pnmap_has_gap(pnmap)) {
		if (!quic_inq_need_sack(inq)) {
			quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_ack_delay(inq));
			quic_inq_set_need_sack(inq, 1);
		}
		goto out;
	}
	fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
	if (fskb) {
		QUIC_SND_CB(fskb)->path_alt = rcv_cb->path_alt;
		quic_outq_ctrl_tail(sk, fskb, true);
	}

out:
	consume_skb(skb);
	if (!quic_inq_need_sack(inq)) /* delay sack timer is reused as idle timer */
		quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_idle_timeout(inq));
	if (quic_is_established(sk))
		quic_outq_transmit(sk);
	return 0;
err:
	pr_warn("[QUIC] %s serv: %d number: %llu len: %d err: %d\n", __func__,
		quic_is_serv(sk), pki.number, skb->len, err);
	quic_outq_transmit_close(sk, pki.frame, pki.errcode, level);
	kfree_skb(skb);
	return err;
}

#define TLS_MT_CLIENT_HELLO	1
#define TLS_EXT_alpn		16

static int quic_packet_get_alpn(u8 *p, u32 len, struct quic_data *alpn)
{
	int err = -EINVAL, found = 0;
	u64 length, type;

	if (!quic_get_int(&p, &len, &type, 1) || type != TLS_MT_CLIENT_HELLO)
		return err;
	if (!quic_get_int(&p, &len, &length, 3) || length < 35 || length > len)
		return err;
	len = length - 35;
	p += 35; /* legacy_version + random + legacy_session_id. */

	if (!quic_get_int(&p, &len, &length, 2) || length > len) /* cipher_suites */
		return err;
	len -= length;
	p += length;

	if (!quic_get_int(&p, &len, &length, 1) || length > len) /* legacy_compression_methods */
		return err;
	len -= length;
	p += length;

	/* TLS Extensions */
	if (!quic_get_int(&p, &len, &length, 2) || length > len)
		return err;
	len = length;
	while (len > 4) {
		if (!quic_get_int(&p, &len, &type, 2))
			break;
		if (!quic_get_int(&p, &len, &length, 2) || length > len)
			break;
		if (type == TLS_EXT_alpn) {
			len = length;
			found = 1;
			break;
		}
		p += length;
		len -= length;
	}
	if (!found)
		return 0;

	/* ALPNs */
	if (!quic_get_int(&p, &len, &length, 2) || length > len)
		return err;
	alpn->len = length;
	alpn->data = p;
	len = length;
	while (len) {
		if (!quic_get_int(&p, &len, &length, 1) || length > len) {
			alpn->len = 0;
			alpn->data = NULL;
			return err;
		}
		len -= length;
		p += length;
	}
	pr_debug("[QUIC] %s alpn len %d\n", __func__, alpn->len);
	return alpn->len;
}

int quic_packet_parse_alpn(struct sk_buff *skb, struct quic_data *alpn)
{
	u8 *p = skb->data, *data, flag = CRYPTO_ALG_ASYNC, type;
	struct quichshdr *hdr = quic_hshdr(skb);
	struct quic_connection_id dcid = {};
	u64 offset, length, dlen, version;
	int len = skb->len, err = -EINVAL;
	struct quic_packet_info pki = {};
	struct quic_crypto *crypto;

	if (len < 5)
		return err;
	if (!hdr->form) /* send stateless reset later */
		return 0;
	p++;
	len--;
	/* VERSION */
	quic_get_int(&p, &len, &version, 4);
	if (!quic_compatible_versions(version)) /* send version negotication later */
		return 0;
	type = quic_version_get_type(version, hdr->type);
	if (type != QUIC_PACKET_INITIAL) /* send stateless reset later */
		return 0;
	/* DCID */
	if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen || dlen > QUIC_CONNECTION_ID_MAX_LEN)
		return err;
	quic_connection_id_update(&dcid, p, dlen);
	len -= dlen;
	p += dlen;
	/* SCID */
	if (!quic_get_int(&p, &len, &dlen, 1) || len < dlen || dlen > QUIC_CONNECTION_ID_MAX_LEN)
		return err;
	len -= dlen;
	p += dlen;
	/* TOKEN */
	if (!quic_get_var(&p, &len, &dlen) || len < dlen)
		return err;
	p += dlen;
	len -= dlen;
	/* LENGTH */
	if (!quic_get_var(&p, &len, &pki.length) || pki.length > len)
		return err;
	crypto = kzalloc(sizeof(*crypto), GFP_ATOMIC);
	if (!crypto)
		return -ENOMEM;
	data = kmemdup(skb->data, skb->len, GFP_ATOMIC);
	if (!data) {
		kfree(crypto);
		return -ENOMEM;
	}
	err = quic_crypto_initial_keys_install(crypto, &dcid, version, flag, 1);
	if (err)
		goto out;
	pki.number_offset = p - skb->data;
	pki.crypto_done = quic_packet_decrypt_done;
	err = quic_crypto_decrypt(crypto, skb, &pki);
	if (err) {
		memcpy(skb->data, data, skb->len);
		goto out;
	}
	skb->decrypted = 1;

	/* QUIC CRYPTO frame */
	err = -EINVAL;
	p += pki.number_len;
	len = pki.length - pki.number_len - QUIC_TAG_LEN;
	if (!len-- || *p++ != QUIC_FRAME_CRYPTO)
		goto out;
	if (!quic_get_var(&p, &len, &offset) || offset)
		goto out;
	if (!quic_get_var(&p, &len, &length) || length > len)
		goto out;

	/* TLS CLIENT_HELLO message */
	err = quic_packet_get_alpn(p, length, alpn);

out:
	quic_crypto_destroy(crypto);
	kfree(crypto);
	kfree(data);
	return err;
}

/* Initial Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 0,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Token Length (i),
 *   Token (..),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 *
 * Handshake Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 2,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 */

static struct sk_buff *quic_packet_handshake_create(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_connection_id_set *id_set;
	u8 *p, type, level = packet->level;
	struct quic_connection_id *active;
	int len, hlen, plen = 0, tlen = 0;
	u32 number_len, version, now;
	struct quic_snd_cb *snd_cb;
	struct sk_buff *fskb, *skb;
	struct sk_buff_head *head;
	struct quic_pnmap *pnmap;
	struct quichshdr *hdr;
	s64 number;

	type = QUIC_PACKET_INITIAL;
	len = packet->len;
	if (level == QUIC_CRYPTO_INITIAL && !quic_is_serv(sk) &&
	    len - packet->overhead > 128 && len < 1184) {
		len = 1184;
		plen = len - packet->len;
	}
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[1], GFP_ATOMIC);
	if (!skb) {
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, hlen + len);

	if (level == QUIC_CRYPTO_HANDSHAKE) {
		type = QUIC_PACKET_HANDSHAKE;
	} else if (level == QUIC_CRYPTO_EARLY) {
		type = QUIC_PACKET_0RTT;
		level = QUIC_CRYPTO_APP; /* pnmap level */
	}
	pnmap = quic_pnmap(sk, level);
	number = quic_pnmap_inc_next_number(pnmap);
	number_len = 4; /* make it fixed for easy coding */
	version = quic_inq_version(inq);
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq_grease_quic_bit(outq);
	hdr->type = quic_version_put_type(version, type);
	hdr->reserved = 0;
	hdr->pnl = 0x3;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, version, 4);

	id_set = quic_dest(sk);
	active = quic_connection_id_active(id_set);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	id_set = quic_source(sk);
	active = quic_connection_id_active(id_set);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	if (level == QUIC_CRYPTO_INITIAL) {
		if (!quic_is_serv(sk))
			tlen = quic_token(sk)->len;
		p = quic_put_var(p, tlen);
		p = quic_put_data(p, quic_token(sk)->data, tlen);
	}

	snd_cb = QUIC_SND_CB(skb);
	snd_cb->number_offset = p + 4 - skb->data;
	snd_cb->number = number;
	snd_cb->level = packet->level;
	snd_cb->path_alt = packet->path_alt;

	p = quic_put_int(p, (len - snd_cb->number_offset) + 16, 4);
	*(p - 4) |= 0x80;
	p = quic_put_int(p, number, number_len);

	len = 0;
	now = jiffies_to_usecs(jiffies);
	head = &packet->frame_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		snd_cb = QUIC_SND_CB(fskb);
		p = quic_put_data(p, fskb->data, fskb->len);
		pr_debug("[QUIC] %s number: %llu type: %u packet_len: %u frame_len: %u level: %u\n",
			 __func__, number, snd_cb->frame_type, skb->len, fskb->len, packet->level);
		if (!quic_frame_retransmittable(snd_cb->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		len += fskb->len;
		quic_outq_transmitted_tail(sk, fskb);
		if (!snd_cb->transmit_ts)
			snd_cb->first_number = number;
		snd_cb->number = number;
		snd_cb->transmit_ts = now;
		snd_cb->sent_count++;
		fskb =  __skb_dequeue(head);
	}
	if (plen)
		memset(p, 0, plen);

	if (len) {
		quic_outq_inc_inflight(outq, len);
		quic_pnmap_inc_inflight(pnmap, len);
		quic_pnmap_set_last_sent_ts(pnmap, now);
		quic_outq_update_loss_timer(sk, level);
	}

	packet->count++;
	return skb;
}

static int quic_packet_number_check(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnmap *pnmap;

	pnmap = quic_pnmap(sk, packet->level);
	if (quic_pnmap_next_number(pnmap) + 1 <= QUIC_PN_MAP_MAX_PN)
		return 0;

	quic_outq_retransmit_list(sk, &packet->frame_list);

	if (!quic_is_closed(sk)) {
		struct quic_connection_close *close;
		u8 frame[10] = {};

		close = (void *)frame;
		close->errcode = 0;
		if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close))
			return -ENOMEM;
		quic_set_state(sk, QUIC_SS_CLOSED);
	}
	return -EPIPE;
}

/* 0-RTT Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 1,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 */

static struct sk_buff *quic_packet_create(struct sock *sk)
{
	struct quic_connection_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p, ecn = 0, level = packet->level;
	struct quic_connection_id *active;
	struct sk_buff *fskb, *skb;
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	struct quic_pnmap *pnmap;
	struct quichdr *hdr;
	u32 number_len, now;
	int len, hlen;
	s64 number;

	if (level)
		return quic_packet_handshake_create(sk);
	pnmap = quic_pnmap(sk, level);
	number = quic_pnmap_inc_next_number(pnmap);
	number_len = 4; /* make it fixed for easy coding */
	len = packet->len;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[0], GFP_ATOMIC);
	if (!skb) {
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 0;
	hdr->fixed = !quic_outq_grease_quic_bit(outq);
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->pnl = 0x3;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	active = quic_connection_id_active(id_set);
	p = quic_put_data(p, active->data, active->len);

	snd_cb = QUIC_SND_CB(skb);
	snd_cb->number_offset = active->len + sizeof(struct quichdr);
	snd_cb->number = number;
	snd_cb->level = level;
	snd_cb->path_alt = packet->path_alt;

	p = quic_put_int(p, number, number_len);

	len = 0;
	now = jiffies_to_usecs(jiffies);
	head = &packet->frame_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		snd_cb = QUIC_SND_CB(fskb);
		p = quic_put_data(p, fskb->data, fskb->len);
		pr_debug("[QUIC] %s number: %llu type: %u packet_len: %u frame_len: %u\n", __func__,
			 number, snd_cb->frame_type, skb->len, fskb->len);
		if (!quic_frame_retransmittable(snd_cb->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		len += fskb->len;
		if (!ecn && packet->ecn_probes < 3) {
			packet->ecn_probes++;
			ecn = INET_ECN_ECT_0;
		}
		quic_outq_transmitted_tail(sk, fskb);
		if (!snd_cb->transmit_ts)
			snd_cb->first_number = number;
		snd_cb->number = number;
		snd_cb->transmit_ts = now;
		snd_cb->ecn = ecn;
		QUIC_SND_CB(skb)->ecn = ecn;
		fskb =  __skb_dequeue(head);
	}

	if (len) {
		quic_outq_inc_inflight(outq, len);
		quic_pnmap_inc_inflight(pnmap, len);
		quic_pnmap_set_last_sent_ts(pnmap, now);
		quic_outq_update_loss_timer(sk, level);
	}
	packet->count++;
	return skb;
}

void quic_packet_set_filter(struct sock *sk, u8 level, u16 count)
{
	struct quic_packet *packet = quic_packet(sk);

	packet->filter = 1;
	packet->level = level;
	packet->max_count = count;
}

void quic_packet_mss_update(struct sock *sk, int mss)
{
	struct quic_packet *packet = quic_packet(sk);
	int max_udp, mss_dgram;

	max_udp = quic_outq_max_udp(quic_outq(sk));
	if (max_udp && mss > max_udp)
		mss = max_udp;
	packet->mss[0] = mss;
	quic_cong_set_mss(quic_cong(sk), packet->mss[0] - packet->taglen[0]);

	mss_dgram = quic_outq_max_dgram(quic_outq(sk));
	if (!mss_dgram)
		return;
	if (mss_dgram > mss)
		mss_dgram = mss;
	packet->mss[1] = mss_dgram;
}

int quic_packet_route(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_path_addr *s = quic_src(sk);
	struct quic_path_addr *d = quic_dst(sk);
	int err, pmtu;

	packet->sa = quic_path_addr(s, packet->path_alt & QUIC_PATH_ALT_SRC);
	packet->da = quic_path_addr(d, packet->path_alt & QUIC_PATH_ALT_DST);
	err = quic_flow_route(sk, packet->da, packet->sa);
	if (err)
		return err;

	pmtu = min_t(u32, dst_mtu(__sk_dst_get(sk)), QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - quic_encap_len(sk));

	if (!quic_path_sent_cnt(s) && !quic_path_sent_cnt(d)) {
		quic_path_pl_reset(d);
		quic_timer_reset(sk, QUIC_TIMER_PATH, quic_inq_probe_timeout(inq));
	}
	return 0;
}

int quic_packet_config(struct sock *sk, u8 level, u8 path_alt)
{
	struct quic_connection_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	int hlen = sizeof(struct quichdr);

	if (packet->filter) {
		if (packet->count >= packet->max_count)
			return -1;
		if (packet->level > level)
			return -1;
		if (packet->level < level)
			return 1;
	}
	if (!skb_queue_empty(&packet->frame_list))
		return 0;

	packet->ipfragok = 0;
	packet->padding = 0;
	hlen += 4; /* packet number */
	hlen += quic_connection_id_active(id_set)->len;
	if (level) {
		hlen += 1;
		id_set = quic_source(sk);
		hlen += 1 + quic_connection_id_active(id_set)->len;
		if (level == QUIC_CRYPTO_INITIAL)
			hlen += quic_var_len(quic_token(sk)->len) + quic_token(sk)->len;
		hlen += 4; /* version */
		hlen += 4; /* length number */
		packet->ipfragok = !!quic_inq_probe_timeout(inq);
	}
	packet->len = hlen;
	packet->overhead = hlen;
	packet->level = level;
	packet->path_alt = path_alt;

	quic_packet_route(sk);
	return 0;
}

#if KERNEL_VERSION(6, 2, 0) <= LINUX_VERSION_CODE
static void quic_packet_encrypt_done(void *data, int err)
{
	struct sk_buff *skb = data;
#else
static void quic_packet_encrypt_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;
#endif

	if (err) {
		kfree_skb(skb);
		pr_warn_once("%s: err %d\n", __func__, err);
		return;
	}

	quic_outq_encrypted_tail(skb->sk, skb);
}

static int quic_packet_bundle(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *p;

	if (!packet->head) {
		packet->head = skb;
		QUIC_SND_CB(packet->head)->last = skb;
		goto out;
	}

	if (packet->head->len + skb->len >= packet->mss[0]) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = skb;
		QUIC_SND_CB(packet->head)->last = skb;
		goto out;
	}
	p = packet->head;
	if (QUIC_SND_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		QUIC_SND_CB(p)->last->next = skb;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;
	QUIC_SND_CB(p)->last = skb;
	QUIC_SND_CB(p)->ecn |= QUIC_SND_CB(skb)->ecn;

out:
	return !QUIC_SND_CB(skb)->level;
}

int quic_packet_xmit(struct sock *sk, struct sk_buff *skb, u8 resume)
{
	struct quic_snd_cb *snd_cb = QUIC_SND_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_packet_info pki = {};
	int err;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	if (!quic_hdr(skb)->form && !packet->taglen[0])
		goto skip;

	pki.number_len = 4;
	pki.number_offset = snd_cb->number_offset;
	pki.number = snd_cb->number;
	pki.crypto_done = quic_packet_encrypt_done;
	pki.resume = resume;

	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb, &pki);
	if (err) {
		if (err != -EINPROGRESS)
			kfree_skb(skb);
		return err;
	}

skip:
	if (quic_packet_bundle(sk, skb)) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = NULL;
	}
	return 0;
}

void quic_packet_build(struct sock *sk)
{
	struct sk_buff *skb;
	int err;

	err = quic_packet_number_check(sk);
	if (err)
		goto err;

	skb = quic_packet_create(sk);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}

	err = quic_packet_xmit(sk, skb, 0);
	if (err && err != -EINPROGRESS)
		goto err;
	return;
err:
	pr_warn("[QUIC] %s %d\n", __func__, err);
}

int quic_packet_flush(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	u16 count;

	if (!skb_queue_empty(&packet->frame_list))
		quic_packet_build(sk);

	if (packet->head) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = NULL;
	}
	count = packet->count;

	packet->count = 0;
	packet->filter = 0;
	return count;
}

int quic_packet_tail(struct sock *sk, struct sk_buff *skb, struct sk_buff_head *from, u8 dgram)
{
	struct quic_snd_cb *snd_cb = QUIC_SND_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	u8 taglen;

	if (snd_cb->level != (packet->level % QUIC_CRYPTO_EARLY) ||
	    snd_cb->path_alt != packet->path_alt || packet->padding)
		return 0;

	taglen = packet->taglen[!!packet->level];
	if (packet->len + skb->len > packet->mss[dgram] - taglen) {
		if (packet->len != packet->overhead)
			return 0;
		if (snd_cb->frame_type != QUIC_FRAME_PING)
			packet->ipfragok = 1;
	}
	if (snd_cb->padding)
		packet->padding = snd_cb->padding;

	__skb_unlink(skb, from);
	__skb_queue_tail(&packet->frame_list, skb);
	packet->len += skb->len;
	return skb->len;
}

/* Retry Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 3,
 *   Unused (4),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Retry Token (..),
 *   Retry Integrity Tag (128),
 * }
 */

static struct sk_buff *quic_packet_retry_create(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_id dcid;
	u8 *p, token[72], tag[16];
	int len, hlen, tokenlen;
	struct quichshdr *hdr;
	struct sk_buff *skb;

	p = token;
	p = quic_put_int(p, 1, 1); /* retry token */
	if (quic_crypto_generate_token(crypto, &req->da, quic_addr_len(sk),
				       &req->dcid, token, &tokenlen))
		return NULL;

	quic_connection_id_generate(&dcid); /* new dcid for retry */
	len = 1 + 4 + 1 + req->scid.len + 1 + dcid.len + tokenlen + 16;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq_grease_quic_bit(outq);
	hdr->type = quic_version_put_type(req->version, QUIC_PACKET_RETRY);
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, req->version, 4);
	p = quic_put_int(p, req->scid.len, 1);
	p = quic_put_data(p, req->scid.data, req->scid.len);
	p = quic_put_int(p, dcid.len, 1);
	p = quic_put_data(p, dcid.data, dcid.len);
	p = quic_put_data(p, token, tokenlen);
	if (quic_crypto_get_retry_tag(crypto, skb, &req->dcid, req->version, tag)) {
		kfree_skb(skb);
		return NULL;
	}
	p = quic_put_data(p, tag, 16);

	return skb;
}

int quic_packet_retry_transmit(struct sock *sk, struct quic_request_sock *req)
{
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, &req->da, &req->sa))
		return -EINVAL;
	skb = quic_packet_retry_create(sk, req);
	if (!skb)
		return -ENOMEM;
	quic_lower_xmit(sk, skb, &req->da, &req->sa);
	return 0;
}

/* Version Negotiation Packet {
 *   Header Form (1) = 1,
 *   Unused (7),
 *   Version (32) = 0,
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..2040),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..2040),
 *   Supported Version (32) ...,
 * }
 */

static struct sk_buff *quic_packet_version_create(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quichshdr *hdr;
	struct sk_buff *skb;
	int len, hlen;
	u8 *p;

	len = 1 + 4 + 1 + req->scid.len + 1 + req->dcid.len + 4 * 2;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq_grease_quic_bit(outq);
	hdr->type = 0;
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, 0, 4);
	p = quic_put_int(p, req->scid.len, 1);
	p = quic_put_data(p, req->scid.data, req->scid.len);
	p = quic_put_int(p, req->dcid.len, 1);
	p = quic_put_data(p, req->dcid.data, req->dcid.len);
	p = quic_put_int(p, QUIC_VERSION_V1, 4);
	p = quic_put_int(p, QUIC_VERSION_V2, 4);

	return skb;
}

int quic_packet_version_transmit(struct sock *sk, struct quic_request_sock *req)
{
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, &req->da, &req->sa))
		return -EINVAL;
	skb = quic_packet_version_create(sk, req);
	if (!skb)
		return -ENOMEM;
	quic_lower_xmit(sk, skb, &req->da, &req->sa);
	return 0;
}

/* Stateless Reset {
 *   Fixed Bits (2) = 1,
 *   Unpredictable Bits (38..),
 *   Stateless Reset Token (128),
 * }
 */

static struct sk_buff *quic_packet_stateless_reset_create(struct sock *sk,
							  struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct sk_buff *skb;
	u8 *p, token[16];
	int len, hlen;

	if (quic_crypto_generate_stateless_reset_token(crypto, req->dcid.data,
						       req->dcid.len, token, 16))
		return NULL;

	len = 64;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	p = skb_push(skb, len);
	get_random_bytes(p, len);

	skb_reset_transport_header(skb);
	quic_hdr(skb)->form = 0;
	quic_hdr(skb)->fixed = 1;

	p += (len - 16);
	p = quic_put_data(p, token, 16);

	return skb;
}

int quic_packet_stateless_reset_transmit(struct sock *sk, struct quic_request_sock *req)
{
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, &req->da, &req->sa))
		return -EINVAL;
	skb = quic_packet_stateless_reset_create(sk, req);
	if (!skb)
		return -ENOMEM;
	quic_lower_xmit(sk, skb, &req->da, &req->sa);
	return 0;
}

int quic_packet_refuse_close_transmit(struct sock *sk, struct quic_request_sock *req, u32 errcode)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_connection_id_set *source = quic_source(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_id *active;
	u8 flag = CRYPTO_ALG_ASYNC;
	struct sk_buff *skb;
	int err;

	active = quic_connection_id_active(source);
	quic_connection_id_update(active, req->dcid.data, req->dcid.len);
	quic_path_addr_set(quic_src(sk), &req->sa, 1);
	quic_path_addr_set(quic_dst(sk), &req->da, 1);
	quic_inq_set_version(quic_inq(sk), req->version);

	quic_crypto_destroy(crypto);
	err = quic_crypto_initial_keys_install(crypto, active, req->version, flag, 1);
	if (err)
		return err;

	quic_outq_set_close_errcode(outq, errcode);
	skb = quic_frame_create(sk, QUIC_FRAME_CONNECTION_CLOSE, NULL);
	if (skb) {
		QUIC_SND_CB(skb)->level = QUIC_CRYPTO_INITIAL;
		QUIC_SND_CB(skb)->path_alt = (QUIC_PATH_ALT_SRC | QUIC_PATH_ALT_DST);
		quic_outq_ctrl_tail(sk, skb, false);
	}
	return 0;
}

void quic_packet_init(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	skb_queue_head_init(&packet->frame_list);
	packet->taglen[0] = QUIC_TAG_LEN;
	packet->taglen[1] = QUIC_TAG_LEN;
	packet->mss[0] = QUIC_TAG_LEN;
	packet->mss[1] = QUIC_TAG_LEN;
}
