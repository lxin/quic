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

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet_info pki = {};
	struct quichshdr *hshdr;
	struct sk_buff *fskb;
	u64 dlen, slen, tlen;
	u8 *p, level, *scid;
	u32 version, len;
	int err = -EINVAL;

	while (skb->len > 0) {
		hshdr = quic_hshdr(skb);
		if (!hshdr->form) { /* handle it later when setting 1RTT key*/
			__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
			return 0;
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
			goto err;
		len -= 4;
		if (hshdr->type == 0) {
			level = QUIC_CRYPTO_INITIAL;
		} else if (hshdr->type == 2) {
			level = QUIC_CRYPTO_HANDSHAKE;
			if (!quic_crypto(sk, level)->cipher) {
				__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
				return 0;
			}
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
			 quic_is_serv(sk),  pki.number, level);
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
		if (quic_pnmap_mark(quic_pnmap(sk, level), pki.number))
			goto err;
		skb_pull(skb, QUIC_TAG_LEN);
		if (pki.ack_eliciting) {
			fskb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
			if (fskb)
				quic_outq_ctrl_tail(sk, fskb, true);
		}
		quic_dest(sk)->active->id.len = slen;
		memcpy(quic_dest(sk)->active->id.data, scid, slen);
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
	int err;

	if (quic_hdr(skb)->form)
		return quic_packet_handshake_process(sk, skb);

	if (!quic_is_established(sk)) {
		__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
		return 0;
	}

	pki.number_offset = QUIC_RCV_CB(skb)->number_offset;
	pki.length = skb->len - pki.number_offset;
	pki.number_max = quic_pnmap_max_pn_seen(quic_pnmap(sk, 0));
	err = quic_crypto_decrypt(quic_crypto(sk, 0), skb, &pki);
	if (err)
		goto err;

	pr_debug("[QUIC] %s serv: %d number: %llu \n", __func__, quic_is_serv(sk), pki.number);
	err = quic_pnmap_check(quic_pnmap(sk, 0), pki.number);
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
	if (quic_pnmap_mark(quic_pnmap(sk, 0), pki.number))
		goto err;
	skb_pull(skb, QUIC_TAG_LEN);

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	if (!quic_dest(sk)->disable_active_migration && pki.non_probing &&
	    pki.number == quic_pnmap_max_pn_seen(quic_pnmap(sk, 0))) {
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

	if (!pki.ack_immediate && !quic_pnmap_has_gap(quic_pnmap(sk, 0))) {
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
	quic_outq_flush(sk);
	return 0;
err:
	pr_warn("[QUIC] %s serv: %d number: %llu err: %d\n", __func__,
		quic_is_serv(sk), pki.number, err);
	kfree_skb(skb);
	return err;
}

static struct sk_buff *quic_packet_handshake_create(struct sock *sk, struct quic_packet_info *pki)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *fskb, *skb;
	struct sk_buff_head *head;
	int len, hlen, plen = 0;
	struct quichshdr *hdr;
	u8 *p, type = 0;

	len = packet->len;
	if (packet->level == QUIC_CRYPTO_INITIAL &&
	    !quic_is_serv(sk) && len < 1184) {
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

	if (packet->level == QUIC_CRYPTO_HANDSHAKE)
		type = 2;
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = 1;
	hdr->type = type;
	hdr->reserved = 0;
	hdr->pnl = 0x3;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, 1, 4);
	p = quic_put_int(p, quic_dest(sk)->active->id.len, 1);
	p = quic_put_data(p, quic_dest(sk)->active->id.data, quic_dest(sk)->active->id.len);
	p = quic_put_int(p, quic_source(sk)->active->id.len, 1);
	p = quic_put_data(p, quic_source(sk)->active->id.data, quic_source(sk)->active->id.len);
	if (packet->level == QUIC_CRYPTO_INITIAL) {
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
	pki->number = quic_pnmap(sk, packet->level)->next_number++;
	pki->number_len = 4; /* make it fixed for easy coding */
	if (packet->level)
		return quic_packet_handshake_create(sk, pki);
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
	hdr->fixed = 1;
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

int quic_packet_route(struct sock *sk, union quic_addr *a)
{
	struct quic_packet *packet = quic_packet(sk);
	int err, mss, mss_dgram, max_udp;;

	err = quic_flow_route(sk, a);
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
	packet->ipfragok = !level;
	packet->level = level;

	quic_packet_route(sk, NULL);
}

static int quic_packet_number_check(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnmap *pnmap;

	pnmap = quic_pnmap(sk, packet->level);
	if (quic_pnmap_next_number(pnmap) + 1 <= QUIC_PN_MAP_MAX_PN)
		return 0;

	__skb_queue_purge(&packet->frame_list);
	if (sk->sk_state != QUIC_SS_CLOSED) {
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
		if (packet->head->len >= packet->mss || !level) {
			packet->count++;
			quic_lower_xmit(sk, packet->head);
			packet->head = NULL;
		}
		return;
	}
	if (packet->head->len + skb->len >= packet->mss || !level) {
		packet->count++;
		quic_lower_xmit(sk, packet->head);
		packet->head = skb;
		NAPI_GRO_CB(packet->head)->last = skb;
		return;
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
		quic_lower_xmit(sk, packet->head);
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
