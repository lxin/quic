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
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close);
	inet_sk_set_state(sk, QUIC_SS_CLOSED);
	consume_skb(skb);
	pr_debug("%s: peer reset\n", __func__);
	return 0;
}

static int quic_packet_handshake_retry_process(struct sock *sk, struct sk_buff *skb)
{
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
	if (quic_crypto_get_retry_tag(skb, &scid, version, tag) || memcmp(tag, p + len - 16, 16))
		goto err;
	if (quic_data_dup(quic_token(sk), p, len - 16))
		goto err;

	quic_crypto_initial_keys_install(quic_crypto(sk, QUIC_CRYPTO_INITIAL), &scid, version, 0);
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
		quic_crypto_initial_keys_install(quic_crypto(sk, QUIC_CRYPTO_INITIAL),
						 &scid, best, 0);
		quic_outq_retransmit(sk);
	}

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet_info pki = {};
	u8 *p, level, *scid, type;
	struct quichshdr *hshdr;
	struct sk_buff *fskb;
	u64 dlen, slen, tlen;
	u32 version, len;
	int err = -EINVAL;

	while (skb->len > 0) {
		hshdr = quic_hshdr(skb);
		if (!hshdr->form) { /* handle it later when setting 1RTT key */
			QUIC_RCV_CB(skb)->number_offset =
				quic_source(sk)->active->id.len + sizeof(struct quichdr);
			return quic_packet_process(sk, skb);
		}
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
		if (type == QUIC_PACKET_INITIAL) {
			level = QUIC_CRYPTO_INITIAL;
		} else if (type == QUIC_PACKET_HANDSHAKE) {
			level = QUIC_CRYPTO_HANDSHAKE;
			if (!quic_crypto(sk, level)->recv_ready) {
				__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
				return 0;
			}
		} else if (type == QUIC_PACKET_0RTT) {
			level = QUIC_CRYPTO_EARLY;
			if (!quic_crypto(sk, QUIC_CRYPTO_APP)->recv_ready) {
				__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
				return 0;
			}
		} else if (type == QUIC_PACKET_RETRY) {
			return quic_packet_handshake_retry_process(sk, skb);
		} else
			goto err;
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
		err = quic_crypto_decrypt(quic_crypto(sk, level), skb, &pki);
		if (err)
			goto err;

		pr_debug("[QUIC] %s serv: %d number: %llu level: %d\n", __func__,
			 quic_is_serv(sk), pki.number, level);

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
			if (fskb)
				quic_outq_ctrl_tail(sk, fskb, true);
		}
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

int quic_packet_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet_info pki = {};
	u8 key_phase, level = 0;
	union quic_addr *saddr;
	struct sk_buff *fskb;
	int err = -EINVAL;

	if (quic_hdr(skb)->form)
		return quic_packet_handshake_process(sk, skb);

	if (!quic_hdr(skb)->fixed && !quic_inq(sk)->grease_quic_bit)
		goto err;

	if (!quic_crypto(sk, QUIC_CRYPTO_APP)->recv_ready) {
		__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
		return 0;
	}

	pki.number_offset = QUIC_RCV_CB(skb)->number_offset;
	pki.length = skb->len - pki.number_offset;
	pki.number_max = quic_pnmap_max_pn_seen(quic_pnmap(sk, QUIC_CRYPTO_APP));
	err = quic_crypto_decrypt(quic_crypto(sk, QUIC_CRYPTO_APP), skb, &pki);
	if (err) {
		if (!quic_packet_stateless_reset_process(sk, skb))
			return 0;
		goto err;
	}

	pr_debug("[QUIC] %s serv: %d number: %llu \n", __func__, quic_is_serv(sk), pki.number);
	err = quic_pnmap_check(quic_pnmap(sk, QUIC_CRYPTO_APP), pki.number);
	if (err) {
		err = -EINVAL;
		goto err;
	}

	skb_pull(skb, pki.number_offset + pki.number_len);
	pki.length -= pki.number_len;
	pki.length -= QUIC_TAG_LEN;
	QUIC_RCV_CB(skb)->level = 0;
	err = quic_frame_process(sk, skb, &pki);
	if (err)
		goto err;
	err = quic_pnmap_mark(quic_pnmap(sk, QUIC_CRYPTO_APP), pki.number);
	if (err)
		goto err;
	skb_pull(skb, QUIC_TAG_LEN);

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	if (!quic_dest(sk)->disable_active_migration && pki.non_probing &&
	    pki.number == quic_pnmap_max_pn_seen(quic_pnmap(sk, QUIC_CRYPTO_APP))) {
		saddr = QUIC_RCV_CB(skb)->saddr;
		if (memcmp(saddr, quic_path_addr(quic_dst(sk)), quic_addr_len(sk)))
			quic_sock_change_addr(sk, quic_dst(sk), saddr, quic_addr_len(sk), 0);
	}

	consume_skb(skb);

	if (pki.key_update) {
		key_phase = pki.key_phase;
		quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase);
	}

	if (!pki.ack_eliciting)
		goto out;

	if (!pki.ack_immediate && !quic_pnmap_has_gap(quic_pnmap(sk, QUIC_CRYPTO_APP))) {
		quic_timer_start(sk, QUIC_TIMER_ACK);
		goto out;
	}
	fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
	if (fskb)
		quic_outq_ctrl_tail(sk, fskb, true);
	quic_timer_stop(sk, QUIC_TIMER_ACK);

out:
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

static struct sk_buff *quic_packet_handshake_create(struct sock *sk, struct quic_packet_info *pki)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 *p, type, level = packet->level;
	struct sk_buff *fskb, *skb;
	struct sk_buff_head *head;
	int len, hlen, plen = 0;
	struct quichshdr *hdr;

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
	pki->number = quic_pnmap(sk, level)->next_number++;
	pki->number_len = 4; /* make it fixed for easy coding */
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

	pki->number_offset = p + 4 - skb->data;
	pki->length = len - pki->number_offset;
	p = quic_put_int(p, pki->length + 16, 4);
	*(p - 4) |= 0x80;
	p = quic_put_int(p, pki->number, pki->number_len);

	head = &packet->frame_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		p = quic_put_data(p, fskb->data, fskb->len);
		pr_debug("[QUIC] %s number: %llu type: %u packet_len: %u frame_len: %u level: %u\n", __func__,
			 pki->number, QUIC_SND_CB(fskb)->frame_type, skb->len, fskb->len, packet->level);
		if (!quic_frame_ack_eliciting(QUIC_SND_CB(fskb)->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		quic_outq_rtx_tail(sk, fskb);
		QUIC_SND_CB(fskb)->packet_number = pki->number;
		QUIC_SND_CB(fskb)->transmit_ts = jiffies_to_usecs(jiffies);
		fskb =  __skb_dequeue(head);
	}
	if (plen)
		memset(p, 0, plen);

	return skb;
}

static struct sk_buff *quic_packet_create(struct sock *sk, struct quic_packet_info *pki)
{
	struct quic_packet *packet;
	struct sk_buff *fskb, *skb;
	struct sk_buff_head *head;
	struct quichdr *hdr;
	int len, hlen;
	u8 *p;

	packet = quic_packet(sk);
	if (packet->level)
		return quic_packet_handshake_create(sk, pki);
	pki->number = quic_pnmap(sk, packet->level)->next_number++;
	pki->number_len = 4; /* make it fixed for easy coding */
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

	pki->number_offset = quic_dest(sk)->active->id.len + sizeof(struct quichdr);
	pki->length = len - pki->number_offset;
	p = quic_put_int(p, pki->number, pki->number_len);

	head = &packet->frame_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		p = quic_put_data(p, fskb->data, fskb->len);
		pr_debug("[QUIC] %s number: %llu type: %u packet_len: %u frame_len: %u\n", __func__,
			 pki->number, QUIC_SND_CB(fskb)->frame_type, skb->len, fskb->len);
		if (!quic_frame_ack_eliciting(QUIC_SND_CB(fskb)->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		quic_outq_rtx_tail(sk, fskb);
		QUIC_SND_CB(fskb)->packet_number = pki->number;
		QUIC_SND_CB(fskb)->transmit_ts = jiffies_to_usecs(jiffies);
		fskb =  __skb_dequeue(head);
	}

	return skb;
}

int quic_packet_route(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	int err, mss, mss_dgram, max_udp;;

	packet->da = quic_path_addr(quic_dst(sk));
	packet->sa = quic_path_addr(quic_src(sk));
	err = quic_flow_route(sk, packet->da, packet->sa);
	if (err)
		return err;

	mss = dst_mtu(__sk_dst_get(sk)) - quic_encap_len(sk);
	max_udp = quic_outq_max_udp(quic_outq(sk));
	if (max_udp && mss > max_udp)
		mss = max_udp;
	packet->mss = mss - QUIC_TAG_LEN;

	mss_dgram = quic_outq_max_dgram(quic_outq(sk));
	if (!mss_dgram)
		return 0;
	if (mss_dgram > mss)
		mss_dgram = mss;
	packet->mss_dgram = mss_dgram - QUIC_TAG_LEN;
	return 0;
}

void quic_packet_config(struct sock *sk, u8 level)
{
	struct quic_packet *packet = quic_packet(sk);
	int hlen = sizeof(struct quichdr);

	hlen += 4; /* version */
	hlen += quic_dest(sk)->active->id.len;
	if (level) {
		hlen += 1;
		hlen += 1 + quic_source(sk)->active->id.len;
		if (level == QUIC_CRYPTO_INITIAL)
			hlen += 1 + quic_token(sk)->len;
		hlen += 4; /* length number */
		hlen += 4; /* packet number */
	}
	packet->len = hlen;
	packet->overhead = hlen;
	packet->ipfragok = !!level;
	packet->level = level;

	quic_packet_route(sk);
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

		inet_sk_set_state(sk, QUIC_SS_CLOSED);
		close = (void *)frame;
		close->errcode = 0;
		quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close);
	}
	return -EPIPE;
}

void quic_packet_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_packet_info pki;
	u8 level = packet->level;
	struct sk_buff *skb, *p;
	int err;

	err = quic_packet_number_check(sk);
	if (err)
		goto err;

	skb = quic_packet_create(sk, &pki);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}
	err = quic_crypto_encrypt(quic_crypto(sk, level), skb, &pki);
	if (err) {
		kfree_skb(skb);
		goto err;
	}

	if (!packet->head) {
		packet->head = skb;
		NAPI_GRO_CB(packet->head)->last = skb;
		goto out;
	}

	/* packet bundle */
	if (packet->head->len + skb->len >= packet->mss) {
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
	if (!level) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->count++;
		packet->head = NULL;
	}
	return;
err:
	pr_warn("[QUIC] %s %d\n", __func__, err);
	sk->sk_err = err;
	sk->sk_state_change(sk);
}

void quic_packet_flush(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	if (!quic_packet_empty(packet))
		quic_packet_transmit(sk);

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

int quic_packet_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);

	if (packet->len + skb->len > packet->mss) {
		if (packet->len != packet->overhead)
			return 0;
		packet->ipfragok = 1;
	}
	packet->len += skb->len;
	__skb_queue_tail(&packet->frame_list, skb);
	return skb->len;
}

int quic_packet_tail_dgram(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);

	if (packet->len + skb->len > packet->mss_dgram) {
		if (packet->len != packet->overhead)
			return 0;
		packet->ipfragok = 1;
	}
	packet->len += skb->len;
	__skb_queue_tail(&packet->frame_list, skb);
	return skb->len;
}

static struct sk_buff *quic_packet_retry_create(struct sock *sk, struct quic_request_sock *req)
{
	int len, hlen, tokenlen = 17;
	u8 *p, token[17], tag[16];
	struct quichshdr *hdr;
	struct sk_buff *skb;

	p = token;
	p = quic_put_int(p, 1, 1); /* retry token */
	if (quic_crypto_generate_token(&req->da, "path_verification", p, 16))
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
	if (quic_crypto_get_retry_tag(skb, &req->dcid, req->version, tag)) {
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

static struct sk_buff *quic_packet_stateless_reset_create(struct sock *sk,
							  struct quic_request_sock *req)
{
	struct sk_buff *skb;
	u8 *p, token[16];
	int len, hlen;

	if (quic_crypto_generate_token(req->dcid.data, "stateless_reset", token, 16))
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
