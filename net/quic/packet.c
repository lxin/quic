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

static void quic_packet_reset(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);
	int hlen = sizeof(struct quichdr);

	hlen += qs->dest.active->id.len;
	hlen += 4;
	qs->packet.len = hlen;
	qs->packet.overhead = hlen;

	qs->packet.ack_eliciting = 0;
	qs->packet.ack_immediate = 0;
	qs->packet.ipfragok = 0;
	skb_queue_head_init(&qs->packet.frame_list);
}

void quic_packet_init(struct sock *sk)
{
	quic_packet_reset(sk);
	quic_sk(sk)->packet.mss = quic_get_mss(sk);
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_packet_info pki;
	struct sk_buff *fskb;
	int err;

	pki.number_offset = qs->source.active->id.len + sizeof(struct quichdr);
	err = quic_crypto_decrypt(&qs->crypto, skb, &pki);
	if (err)
		goto err;

	err = quic_pnmap_check(&qs->pn_map, pki.number);
	if (err) {
		err = -EINVAL;
		goto err;
	}

	skb_pull(skb, pki.number_offset + pki.number_len);
	skb_trim(skb, skb->len - QUIC_TAG_LEN);
	err = quic_frame_process(sk, skb);
	if (err)
		goto err;

	if (quic_pnmap_mark(&qs->pn_map, pki.number))
		goto err;

	consume_skb(skb);

	if (!qs->packet.ack_eliciting)
		goto out;

	if (!qs->packet.ack_immediate) {
		quic_timer_start(sk, QUIC_TIMER_ACK);
		goto out;
	}
	fskb = quic_frame_create(sk, QUIC_FRAME_ACK, NULL, 0);
	if (fskb)
		quic_outq_ctrl_tail(sk, fskb, true);
	quic_timer_stop(sk, QUIC_TIMER_ACK);

out:
	quic_packet_reset(sk);
	quic_outq_flush(sk);
	return 0;
err:
	pr_debug("[QUIC] %s pktn: %d err: %d\n", __func__, pki.number, err);
	kfree_skb(skb);
	return err;
}

struct sk_buff *quic_packet_create(struct sock *sk, struct quic_packet_info *pki)
{
	struct sk_buff_head *head, *retransmit;
	struct quic_sock *qs = quic_sk(sk);
	struct quic_packet *packet;
	struct sk_buff *fskb, *skb;
	struct quichdr *hdr;
	int len, hlen;
	u8 *p;

	packet = &qs->packet;
	len = packet->len;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + QUIC_TAG_LEN, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 0;
	hdr->fixed = 1;
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->key = 0;
	hdr->pnl = 0x3;

	p = (u8 *)hdr + 1;
	p = quic_put_data(p, qs->dest.active->id.data, qs->dest.active->id.len);

	pki->number = packet->next_number++;
	pki->number_len = 4; /* make it fixed for easy coding */
	pki->number_offset = qs->dest.active->id.len + sizeof(struct quichdr);
	p = quic_put_int(p, pki->number, pki->number_len);

	head = &packet->frame_list;
	retransmit = &quic_sk(sk)->outq.retransmit_list;
	fskb =  __skb_dequeue(head);
	while (fskb) {
		p = quic_put_data(p, fskb->data, fskb->len);
		if (!quic_frame_ack_eliciting(QUIC_SND_CB(fskb)->frame_type)) {
			consume_skb(fskb);
			fskb =  __skb_dequeue(head);
			continue;
		}
		__skb_queue_tail(retransmit, fskb);
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
	err = quic_crypto_encrypt(&quic_sk(sk)->crypto, skb, &pki);
	if (err) {
		kfree_skb(skb);
		goto err;
	}

	quic_lower_xmit(sk, skb);
	quic_packet_reset(sk);
	return;
err:
	pr_warn("transmit %d\n", err);
	sk->sk_err = err;
	sk->sk_state_change(sk);
}

int quic_packet_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = &quic_sk(sk)->packet;

	if (packet->len + skb->len > packet->mss) {
		if (packet->len != packet->overhead)
			return 0;
		packet->ipfragok = 1;
	}
	packet->len += skb->len;
	if (quic_frame_ack_eliciting(QUIC_SND_CB(skb)->frame_type))
		packet->ack_eliciting = true;

	__skb_queue_tail(&packet->frame_list, skb);
	return skb->len;
}

void quic_packet_set_param(struct sock *sk, struct quic_transport_param *p, u8 send)
{
	struct quic_packet *packet = &quic_sk(sk)->packet;

	if (send) {
		packet->send.window = p->initial_max_data;
		packet->send.max_bytes = packet->send.window;
		sk->sk_sndbuf = 2 * p->initial_max_data;
		return;
	}
	packet->recv.window = p->initial_max_data;
	packet->recv.max_bytes = packet->recv.window;
	sk->sk_rcvbuf = 2 * p->initial_max_data;
}

void quic_packet_get_param(struct sock *sk, struct quic_transport_param *p, u8 send)
{
	struct quic_packet *packet = &quic_sk(sk)->packet;

	if (send) {
		p->initial_max_data = packet->send.window;
		return;
	}
	p->initial_max_data = packet->recv.window;
}
