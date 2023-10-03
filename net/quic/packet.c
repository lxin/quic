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

#include "socket.h"
#include "number.h"
#include "frame.h"

/* 1-RTT Packet {
 *     Header Form (1) = 0,
 *     Fixed Bit (1) = 1,
 *     Spin Bit (1),
 *     Reserved Bits (2),
 *     Key Phase (1),
 *     Packet Number Length (2),
 *     Destination Connection ID (0..160),
 *     Packet Number (8..32),
 *     Packet Payload (8..),
 * }
 */

void quic_packet_config(struct sock *sk)
{
	int mss, hlen = sizeof(struct quichdr);
	struct quic_sock *qs = quic_sk(sk);

	hlen += qs->dest.active->id.len;
	hlen += 4;
	qs->packet.len = hlen;
	qs->packet.overhead = hlen;
	qs->packet.ipfragok = 0;

	if (quic_flow_route(sk, NULL))
		return;

	mss = dst_mtu(__sk_dst_get(sk)) - quic_encap_len(sk);
	if (mss > quic_inq_max_udp(quic_inq(sk)))
		mss = quic_inq_max_udp(quic_inq(sk));
	qs->packet.mss = mss - QUIC_TAG_LEN;
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_packet_info pki = {};
	union quic_addr saddr;
	struct sk_buff *fskb;
	u8 key_phase;
	int err;

	pki.number_offset = QUIC_RCV_CB(skb)->number_offset;
	err = quic_crypto_decrypt(&qs->crypto, skb, &pki);
	if (err)
		goto err;

	pr_debug("[QUIC] %s number: %u serv: %d\n", __func__, pki.number, quic_is_serv(sk));
	err = quic_pnmap_check(&qs->pn_map, pki.number);
	if (err) {
		err = -EINVAL;
		goto err;
	}

	skb_pull(skb, pki.number_offset + pki.number_len);
	skb_trim(skb, skb->len - QUIC_TAG_LEN);
	err = quic_frame_process(sk, skb, &pki);
	if (err)
		goto err;

	if (quic_pnmap_mark(&qs->pn_map, pki.number))
		goto err;

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	if (pki.non_probing && pki.number == quic_pnmap_max_pn_seen(&qs->pn_map)) {
		qs->af_ops->get_msg_addr(&saddr, skb, 1);
		if (memcmp(&saddr, quic_path_addr(&qs->dst), quic_addr_len(sk)))
			quic_sock_change_addr(sk, &qs->dst, &saddr, quic_addr_len(sk), 0);
	}

	consume_skb(skb);

	if (pki.key_update) {
		key_phase = pki.key_phase;
		quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase);
	}

	if (!pki.ack_eliciting)
		goto out;

	if (!pki.ack_immediate && !quic_pnmap_has_gap(&qs->pn_map)) {
		quic_timer_start(sk, QUIC_TIMER_ACK);
		goto out;
	}
	fskb = quic_frame_create(sk, QUIC_FRAME_ACK, NULL);
	if (fskb)
		quic_outq_ctrl_tail(sk, fskb, true);
	quic_timer_stop(sk, QUIC_TIMER_ACK);

out:
	/* Since a packet was successfully processed, we can reset the idle
	 * timer.
	 */
	quic_timer_reset(sk, QUIC_TIMER_IDLE);
	quic_outq_reset(&qs->outq);
	quic_outq_flush(sk);
	return 0;
err:
	pr_warn("[QUIC] %s pktn: %d err: %d serv: %u\n", __func__, pki.number, err, quic_is_serv(sk));
	kfree_skb(skb);
	return err;
}

static struct sk_buff *quic_packet_create(struct sock *sk, struct quic_packet_info *pki)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_packet *packet;
	struct sk_buff *fskb, *skb;
	struct sk_buff_head *head;
	struct quichdr *hdr;
	int len, hlen;
	u8 *p;

	packet = &qs->packet;
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
	p = quic_put_data(p, qs->dest.active->id.data, qs->dest.active->id.len);

	pki->number = packet->next_number++;
	pki->number_len = 4; /* make it fixed for easy coding */
	pki->number_offset = qs->dest.active->id.len + sizeof(struct quichdr);
	p = quic_put_int(p, pki->number, pki->number_len);

	head = &packet->frame_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		p = quic_put_data(p, fskb->data, fskb->len);
		if (!quic_frame_ack_eliciting(QUIC_SND_CB(fskb)->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		pr_debug("[QUIC] %s offset: %llu number: %u\n", __func__,
			 QUIC_SND_CB(fskb)->stream_offset, pki->number);
		quic_outq_rtx_tail(sk, fskb);
		QUIC_SND_CB(fskb)->packet_number = pki->number;
		QUIC_SND_CB(fskb)->transmit_ts = jiffies_to_usecs(jiffies);
		fskb =  __skb_dequeue(head);
	}

	return skb;
}

void quic_packet_transmit(struct sock *sk)
{
	struct quic_packet_info pki;
	struct sk_buff *skb;
	int err;

	skb = quic_packet_create(sk, &pki);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}
	err = quic_crypto_encrypt(quic_crypto(sk), skb, &pki);
	if (err) {
		kfree_skb(skb);
		goto err;
	}

	quic_lower_xmit(sk, skb);
	return;
err:
	pr_warn("[QUIC] %s %d\n", __func__, err);
	sk->sk_err = err;
	sk->sk_state_change(sk);
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
