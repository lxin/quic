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
	struct quic_common_connection_id *common;
	struct quic_connection_close close = {};
	struct quic_dest_connection_id *dcid;
	u8 *token;

	if (skb->len < 22)
		return -EINVAL;

	token = skb->data + skb->len - 16;
	dcid = (struct quic_dest_connection_id *)quic_dest(sk)->active;
	if (!memcmp(dcid->token, token, 16)) /* fast path */
		goto reset;

	list_for_each_entry(common, &quic_dest(sk)->head, list) {
		dcid = (struct quic_dest_connection_id *)common;
		if (common == quic_dest(sk)->active)
			continue;
		if (!memcmp(dcid->token, token, 16))
			goto reset;
	}
	return -EINVAL; /* not a stateless reset and the caller will free skb */

reset:
	close.errcode = QUIC_TRANS_ERR_CRYPTO;
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
	struct quic_connection_id dcid, scid = {};
	u32 len = skb->len, dlen, slen, version;
	u8 *p = skb->data, tag[16];

	p++;
	len--;
	p += 4;
	len -= 4;
	/* DCID */
	if (len-- < 1)
		goto err;
	dlen = quic_get_int(&p, 1);
	if (len < dlen || dlen > 20)
		goto err;
	dcid.len = dlen;
	memcpy(dcid.data, p, dlen);
	len -= dlen;
	p += dlen;
	/* SCID */
	if (len-- < 1)
		goto err;
	slen = quic_get_int(&p, 1);
	if (len < slen || slen > 20)
		goto err;
	scid.len = slen;
	memcpy(scid.data, p, slen);
	len -= slen;
	p += slen;
	if (len < 16)
		goto err;
	version = quic_local(sk)->version;
	if (quic_crypto_get_retry_tag(crypto, skb, &scid, version, tag) ||
	    memcmp(tag, p + len - 16, 16))
		goto err;
	if (quic_data_dup(quic_token(sk), p, len - 16))
		goto err;

	quic_crypto_destroy(crypto);
	quic_crypto_initial_keys_install(crypto, &scid, version, 0);
	quic_dest(sk)->active->id = scid;
	quic_outq_retransmit(sk);

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

static int quic_packet_handshake_version_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_connection_id dcid, scid;
	u32 len = skb->len, dlen, slen;
	u32 version, best = 0;
	u8 *p = skb->data;

	p++;
	len--;
	p += 4;
	len -= 4;
	/* DCID */
	if (len-- < 1)
		goto err;
	dlen = quic_get_int(&p, 1);
	if (len < dlen || dlen > 20)
		goto err;
	dcid.len = dlen;
	memcpy(dcid.data, p, dlen);
	len -= dlen;
	p += dlen;
	/* SCID */
	if (len-- < 1)
		goto err;
	slen = quic_get_int(&p, 1);
	if (len < slen || slen > 20)
		goto err;
	scid.len = slen;
	memcpy(scid.data, p, slen);
	len -= slen;
	p += slen;
	if (len < 4)
		goto err;

	while (len >= 4) {
		version = quic_get_int(&p, 4);
		len -= 4;
		if (quic_version_supported(version) && best < version)
			best = version;
	}
	if (best) {
		quic_local(sk)->version = best;
		quic_crypto_destroy(crypto);
		quic_crypto_initial_keys_install(crypto, &scid, best, 0);
		quic_outq_retransmit(sk);
	}

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb, u8 resume)
{
	struct quic_packet_info pki = {};
	u8 *p, level = 0, *scid, type;
	struct quichshdr *hshdr;
	struct sk_buff *fskb;
	u64 dlen, slen, tlen;
	u32 version, len;
	int err = -EINVAL;

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
		version = quic_get_int(&p, 4);
		if (!version)
			return quic_packet_handshake_version_process(sk, skb);
		else if (version != quic_local(sk)->version)
			goto err;
		len -= 4;
		type = quic_version_get_type(version, hshdr->type);
		switch (type) {
		case QUIC_PACKET_INITIAL:
			level = QUIC_CRYPTO_INITIAL;
			break;
		case QUIC_PACKET_HANDSHAKE:
			level = QUIC_CRYPTO_HANDSHAKE;
			if (!quic_crypto(sk, level)->recv_ready) {
				__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
				return 0;
			}
			break;
		case QUIC_PACKET_0RTT:
			level = QUIC_CRYPTO_EARLY;
			if (!quic_crypto(sk, QUIC_CRYPTO_APP)->recv_ready) {
				__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
				return 0;
			}
			break;
		case QUIC_PACKET_RETRY:
			return quic_packet_handshake_retry_process(sk, skb);
		default:
			goto err;
		}
		/* DCID */
		if (len-- < 1)
			goto err;
		dlen = quic_get_int(&p, 1);
		if (len < dlen || dlen > 20)
			goto err;
		len -= dlen;
		p += dlen;
		/* SCID */
		if (len-- < 1)
			goto err;
		slen = quic_get_int(&p, 1);
		if (len < slen || slen > 20)
			goto err;
		len -= slen;
		scid = p;
		p += slen;
		if (level == QUIC_CRYPTO_INITIAL) {
			/* TOKEN */
			if (!quic_get_var(&p, &len, &tlen) || len < tlen)
				goto err;
			p += tlen;
			len -= tlen;
		}
		/* LENGTH */
		if (!quic_get_var(&p, &len, &pki.length) || pki.length > len)
			goto err;
		pki.number_offset = p - (u8 *)hshdr;
		pki.resume = resume;
		err = quic_crypto_decrypt(quic_crypto(sk, level), skb, &pki);
		if (err) {
			if (err == -EINPROGRESS)
				return err;
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
		pki.length -= QUIC_TAG_LEN;
		QUIC_RCV_CB(skb)->level = level;
		err = quic_frame_process(sk, skb, &pki);
		if (err)
			goto err;
		err = quic_pnmap_mark(quic_pnmap(sk, level), pki.number);
		if (err)
			goto err;
		skb_pull(skb, QUIC_TAG_LEN);
		if (pki.ack_eliciting) {
			if (!quic_is_serv(sk) && level == QUIC_CRYPTO_INITIAL) {
				quic_dest(sk)->active->id.len = slen;
				memcpy(quic_dest(sk)->active->id.data, scid, slen);
			}
			fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
			if (fskb) {
				/* flush it out in ack timer in case that no handshake packets
				 * from user space come to bundle it.
				 */
				quic_outq_ctrl_tail(sk, fskb, true);
				quic_timer_start(sk, QUIC_TIMER_ACK);
			}
		}
		resume = 0;
		skb_reset_transport_header(skb);
	}
	consume_skb(skb);
	quic_outq_reset(quic_outq(sk));
	return 0;
err:
	pr_warn("[QUIC] %s serv: %d number: %llu level: %d err: %d\n", __func__,
		quic_is_serv(sk), pki.number, level, err);
	kfree_skb(skb);
	return err;
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
	struct sock *sk = skb->sk;

	lock_sock(sk);
	quic_packet_process(sk, skb, 1);
	release_sock(sk);

	pr_info_once("%s\n", __func__);
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb, u8 resume)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_pnmap *pnmap = quic_pnmap(sk, QUIC_CRYPTO_APP);
	struct quic_rcv_cb *rcv_cb = QUIC_RCV_CB(skb);
	struct quic_packet_info pki = {};
	u8 key_phase, level = 0;
	union quic_addr addr;
	struct sk_buff *fskb;
	int err = -EINVAL;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	if (quic_hdr(skb)->form)
		return quic_packet_handshake_process(sk, skb, resume);

	if (!quic_hdr(skb)->fixed && !quic_inq(sk)->grease_quic_bit)
		goto err;

	if (!crypto->recv_ready) {
		__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
		return 0;
	}

	pki.number_offset = quic_source(sk)->active->id.len + sizeof(struct quichdr);
	if (rcv_cb->number_offset)
		pki.number_offset = rcv_cb->number_offset;

	pki.length = skb->len - pki.number_offset;
	pki.number_max = quic_pnmap_max_pn_seen(pnmap);
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

	pr_debug("[QUIC] %s serv: %d number: %llu len: %d\n", __func__,
		 quic_is_serv(sk), pki.number, skb->len);

	err = quic_pnmap_check(pnmap, pki.number);
	if (err) {
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
	pki.length -= QUIC_TAG_LEN;
	rcv_cb->level = 0;
	err = quic_frame_process(sk, skb, &pki);
	if (err)
		goto err;
	err = quic_pnmap_mark(pnmap, pki.number);
	if (err)
		goto err;
	skb_pull(skb, QUIC_TAG_LEN);

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	if (!quic_dest(sk)->disable_active_migration && pki.non_probing &&
	    pki.number == quic_pnmap_max_pn_seen(pnmap) && (rcv_cb->path_alt & QUIC_PATH_ALT_DST))
		quic_sock_change_daddr(sk, &addr, quic_addr_len(sk));

	if (pki.key_update) {
		key_phase = pki.key_phase;
		if (!quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase)) {
			crypto->key_pending = 0;
			crypto->key_update_send_ts = 0;
		}
	}

	if (!pki.ack_eliciting)
		goto out;

	if (!pki.ack_immediate && !quic_pnmap_has_gap(pnmap)) {
		quic_timer_start(sk, QUIC_TIMER_ACK);
		goto out;
	}
	fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
	if (fskb) {
		QUIC_SND_CB(fskb)->path_alt = rcv_cb->path_alt;
		quic_outq_ctrl_tail(sk, fskb, true);
		quic_timer_stop(sk, QUIC_TIMER_ACK);
	}

out:
	consume_skb(skb);

	/* Since a packet was successfully processed, we can reset the idle
	 * timer.
	 */
	quic_timer_reset(sk, QUIC_TIMER_IDLE);
	quic_outq_reset(quic_outq(sk));
	if (quic_is_established(sk))
		quic_outq_flush(sk);
	return 0;
err:
	pr_warn("[QUIC] %s serv: %d number: %llu len: %d err: %d\n", __func__,
		quic_is_serv(sk), pki.number, skb->len, err);
	kfree_skb(skb);
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
	u8 *p, type, level = packet->level;
	struct quic_snd_cb *snd_cb;
	struct sk_buff *fskb, *skb;
	struct sk_buff_head *head;
	int len, hlen, plen = 0;
	struct quichshdr *hdr;
	u32 number_len;
	s64 number;

	type = QUIC_PACKET_INITIAL;
	len = packet->len;
	if (level == QUIC_CRYPTO_INITIAL && !quic_is_serv(sk) &&
	    len - packet->overhead > 128 && len < 1184) {
		len = 1184;
		plen = len - packet->len;
	}
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + QUIC_TAG_LEN, GFP_ATOMIC);
	if (!skb) {
		__skb_queue_purge(&packet->frame_list);
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
	number = quic_pnmap(sk, level)->next_number++;
	number_len = 4; /* make it fixed for easy coding */
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->type = quic_version_put_type(quic_local(sk)->version, type);
	hdr->reserved = 0;
	hdr->pnl = 0x3;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, quic_local(sk)->version, 4);
	p = quic_put_int(p, quic_dest(sk)->active->id.len, 1);
	p = quic_put_data(p, quic_dest(sk)->active->id.data, quic_dest(sk)->active->id.len);
	p = quic_put_int(p, quic_source(sk)->active->id.len, 1);
	p = quic_put_data(p, quic_source(sk)->active->id.data, quic_source(sk)->active->id.len);
	if (level == QUIC_CRYPTO_INITIAL) {
		p = quic_put_var(p, quic_token(sk)->len);
		p = quic_put_data(p, quic_token(sk)->data, quic_token(sk)->len);
	}

	snd_cb = QUIC_SND_CB(skb);
	snd_cb->number_offset = p + 4 - skb->data;
	snd_cb->packet_number = number;
	snd_cb->level = packet->level;
	snd_cb->path_alt = packet->path_alt;

	p = quic_put_int(p, (len - snd_cb->number_offset) + 16, 4);
	*(p - 4) |= 0x80;
	p = quic_put_int(p, number, number_len);

	head = &packet->frame_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		snd_cb = QUIC_SND_CB(fskb);
		p = quic_put_data(p, fskb->data, fskb->len);
		pr_debug("[QUIC] %s number: %llu type: %u packet_len: %u frame_len: %u level: %u\n",
			 __func__, number, snd_cb->frame_type, skb->len, fskb->len,
			 packet->level);
		if (!quic_frame_retransmittable(snd_cb->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		quic_outq_rtx_tail(sk, fskb);
		snd_cb->packet_number = number;
		snd_cb->transmit_ts = jiffies_to_usecs(jiffies);
		fskb =  __skb_dequeue(head);
	}
	if (plen)
		memset(p, 0, plen);

	quic_timer_stop(sk, QUIC_TIMER_ACK);
	return skb;
}

static int quic_packet_number_check(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnmap *pnmap;

	pnmap = quic_pnmap(sk, packet->level);
	if (quic_pnmap_next_number(pnmap) + 1 <= QUIC_PN_MAP_MAX_PN)
		return 0;

	__skb_queue_purge(&packet->frame_list);
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
	struct quic_packet *packet;
	struct sk_buff *fskb, *skb;
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	struct quichdr *hdr;
	u32 number_len;
	int len, hlen;
	s64 number;
	u8 *p;

	packet = quic_packet(sk);
	if (packet->level)
		return quic_packet_handshake_create(sk);
	number = quic_pnmap(sk, packet->level)->next_number++;
	number_len = 4; /* make it fixed for easy coding */
	len = packet->len;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + QUIC_TAG_LEN, GFP_ATOMIC);
	if (!skb) {
		__skb_queue_purge(&packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 0;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->pnl = 0x3;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_data(p, quic_dest(sk)->active->id.data, quic_dest(sk)->active->id.len);

	snd_cb = QUIC_SND_CB(skb);
	snd_cb->number_offset = quic_dest(sk)->active->id.len + sizeof(struct quichdr);
	snd_cb->packet_number = number;
	snd_cb->level = packet->level;
	snd_cb->path_alt = packet->path_alt;

	p = quic_put_int(p, number, number_len);

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
		quic_outq_rtx_tail(sk, fskb);
		snd_cb->packet_number = number;
		snd_cb->transmit_ts = jiffies_to_usecs(jiffies);
		fskb =  __skb_dequeue(head);
	}

	return skb;
}

void quic_packet_mss_update(struct sock *sk, int mss)
{
	struct quic_packet *packet = quic_packet(sk);
	int max_udp, mss_dgram;

	max_udp = quic_outq_max_udp(quic_outq(sk));
	if (max_udp && mss > max_udp)
		mss = max_udp;
	packet->mss[0] = mss - QUIC_TAG_LEN;

	mss_dgram = quic_outq_max_dgram(quic_outq(sk));
	if (!mss_dgram)
		return;
	if (mss_dgram > mss)
		mss_dgram = mss;
	packet->mss[1] = mss_dgram - QUIC_TAG_LEN;
}

int quic_packet_route(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	int err, mss;

	packet->sa = quic_path_addr(quic_src(sk), packet->path_alt & QUIC_PATH_ALT_SRC);
	packet->da = quic_path_addr(quic_dst(sk), packet->path_alt & QUIC_PATH_ALT_DST);
	err = quic_flow_route(sk, packet->da, packet->sa);
	if (err)
		return err;

	mss = dst_mtu(__sk_dst_get(sk)) - quic_encap_len(sk);
	quic_packet_mss_update(sk, mss);

	quic_path_pl_reset(quic_dst(sk));
	quic_timer_setup(sk, QUIC_TIMER_PROBE, quic_inq(sk)->probe_timeout);
	quic_timer_reset(sk, QUIC_TIMER_PROBE);
	return 0;
}

void quic_packet_config(struct sock *sk, u8 level, u8 path_alt)
{
	struct quic_packet *packet = quic_packet(sk);
	int hlen = sizeof(struct quichdr);

	if (!quic_packet_empty(packet)) {
		if (level == packet->level && path_alt == packet->path_alt)
			return;
		quic_packet_build(sk);
	}
	packet->ipfragok = 0;
	packet->padding = 0;
	hlen += 4; /* packet number */
	hlen += quic_dest(sk)->active->id.len;
	if (level) {
		hlen += 1;
		hlen += 1 + quic_source(sk)->active->id.len;
		if (level == QUIC_CRYPTO_INITIAL)
			hlen += 1 + quic_token(sk)->len;
		hlen += 4; /* version */
		hlen += 4; /* length number */
		packet->ipfragok = !!quic_inq(sk)->probe_timeout;
	}
	packet->len = hlen;
	packet->overhead = hlen;
	packet->level = level;
	packet->path_alt = path_alt;

	quic_packet_route(sk);
}

static int quic_packet_xmit(struct sock *sk, struct sk_buff *skb, u8 resume);

#if KERNEL_VERSION(6, 2, 0) <= LINUX_VERSION_CODE
static void quic_packet_encrypt_done(void *data, int err)
{
	struct sk_buff *skb = data;
#else
static void quic_packet_encrypt_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;
#endif
	struct quic_snd_cb *snd_cb;
	struct sock *sk = skb->sk;

	lock_sock(sk);
	snd_cb = QUIC_SND_CB(skb);
	quic_packet_config(sk, snd_cb->level, snd_cb->path_alt);
	/* the skb here is ready to send */
	quic_packet_xmit(sk, skb, 1);
	quic_packet_flush(sk);
	release_sock(sk);

	pr_info_once("%s\n", __func__);
}

static int quic_packet_bundle(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *p;

	if (!packet->head) {
		packet->head = skb;
		NAPI_GRO_CB(packet->head)->last = skb;
		goto out;
	}

	if (packet->head->len + skb->len >= packet->mss[0]) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->count++;
		packet->head = skb;
		NAPI_GRO_CB(packet->head)->last = skb;
		goto out;
	}
	p = packet->head;
	if (NAPI_GRO_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NAPI_GRO_CB(p)->last->next = skb;
	NAPI_GRO_CB(p)->last = skb;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;

out:
	return !QUIC_SND_CB(skb)->level;
}

static int quic_packet_xmit(struct sock *sk, struct sk_buff *skb, u8 resume)
{
	struct quic_snd_cb *snd_cb = QUIC_SND_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_packet_info pki = {};
	int err;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	pki.number_len = 4;
	pki.number_offset = snd_cb->number_offset;
	pki.number = snd_cb->packet_number;
	pki.crypto_done = quic_packet_encrypt_done;
	pki.resume = resume;

	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb, &pki);
	if (err) {
		if (err != -EINPROGRESS)
			kfree_skb(skb);
		return err;
	}

	if (quic_packet_bundle(sk, skb)) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->count++;
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

void quic_packet_flush(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	if (packet->head) {
		packet->count++;
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = NULL;
	}
	if (packet->count) {
		quic_timer_start(sk, QUIC_TIMER_RTX);
		packet->count = 0;
	}
}

int quic_packet_tail(struct sock *sk, struct sk_buff *skb, u8 dgram)
{
	struct quic_snd_cb *snd_cb = QUIC_SND_CB(skb);
	struct quic_packet *packet = quic_packet(sk);

	if (snd_cb->level != (packet->level % QUIC_CRYPTO_EARLY) ||
	    snd_cb->path_alt != packet->path_alt || packet->padding)
		return 0;

	if (packet->len + skb->len > packet->mss[dgram]) {
		if (packet->len != packet->overhead)
			return 0;
		if (snd_cb->frame_type != QUIC_FRAME_PING)
			packet->ipfragok = 1;
	}
	if (snd_cb->padding)
		packet->padding = snd_cb->padding;
	packet->len += skb->len;
	__skb_queue_tail(&packet->frame_list, skb);
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
	int len, hlen, tokenlen = 17;
	u8 *p, token[17], tag[16];
	struct quichshdr *hdr;
	struct sk_buff *skb;

	p = token;
	p = quic_put_int(p, 1, 1); /* retry token */
	if (quic_crypto_generate_token(crypto, &req->da, "path_verification", p, 16))
		return NULL;

	len = 1 + 4 + 1 + req->scid.len + 1 + req->dcid.len + tokenlen + 16;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->type = quic_version_put_type(req->version, QUIC_PACKET_RETRY);
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, quic_local(sk)->version, 4);
	p = quic_put_int(p, req->scid.len, 1);
	p = quic_put_data(p, req->scid.data, req->scid.len);
	p = quic_put_int(p, req->dcid.len, 1);
	p = quic_put_data(p, req->dcid.data, req->dcid.len);
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
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
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

	if (quic_crypto_generate_token(crypto, req->dcid.data, "stateless_reset", token, 16))
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
