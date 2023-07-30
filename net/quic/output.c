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
#include "frame.h"

#define QUIC_RTX_MAX	15

static void quic_outq_transmit_ctrl(struct sock *sk)
{
	struct sk_buff_head *head = &quic_sk(sk)->outq.control_list;
	struct sk_buff *skb;
	int ret = 0;

	skb = __skb_dequeue(head);
	while (skb) {
		ret = quic_packet_tail(sk, skb);
		if (!ret) {
			quic_packet_transmit(sk);
			quic_packet_config(sk);
			ret = quic_packet_tail(sk, skb);
			if (ret <= 0) {
				__skb_queue_head(head, skb);
				break;
			}
		}
		skb = __skb_dequeue(head);
	}
}

static int quic_outq_flow_control(struct sock *sk, struct sk_buff *skb)
{
	u32 len = QUIC_SND_CB(skb)->data_bytes;
	struct sk_buff *nskb = NULL;
	struct quic_packet *packet;
	struct quic_stream *stream;
	u8 requeue = 0;

	/* congestion control */
	packet = &quic_sk(sk)->packet;
	if (packet->send.inflight + len > packet->send.window)
		requeue = 1;

	/* send flow control */
	stream = quic_stream_find(&quic_sk(sk)->streams, QUIC_SND_CB(skb)->stream_id);
	if (stream->send.bytes + len > stream->send.max_bytes) {
		if (!stream->send.data_blocked) {
			nskb = quic_frame_create(sk, QUIC_FRAME_STREAM_DATA_BLOCKED, stream, 0);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			stream->send.data_blocked = 1;
		}
		requeue = 1;
	}
	if (packet->send.bytes + len > packet->send.max_bytes) {
		if (!packet->send.data_blocked) {
			nskb = quic_frame_create(sk, QUIC_FRAME_DATA_BLOCKED, packet, 0);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			packet->send.data_blocked = 1;
		}
		requeue = 1;
	}

	if (nskb)
		quic_outq_transmit_ctrl(sk);

	if (requeue) {
		__skb_queue_head(&sk->sk_write_queue, skb);
		return 1;
	}

	packet->send.inflight += len;
	packet->send.bytes += len;
	stream->send.bytes += len;
	return 0;
}

static void quic_outq_transmit_data(struct sock *sk)
{
	struct sk_buff_head *head = &sk->sk_write_queue;
	struct sk_buff *skb;
	u8 ret;

	skb = __skb_dequeue(head);
	while (skb) {
		if (quic_outq_flow_control(sk, skb))
			break;
		ret = quic_packet_tail(sk, skb);
		if (!ret) {
			quic_packet_transmit(sk);
			quic_packet_config(sk);
			ret = quic_packet_tail(sk, skb);
			if (ret <= 0) {
				__skb_queue_head(head, skb);
				break;
			}
		}
		skb = __skb_dequeue(head);
	}
}

void quic_outq_flush(struct sock *sk)
{
	struct quic_packet *packet = &quic_sk(sk)->packet;
	u32 next_number = packet->next_number;

	quic_packet_config(sk);

	quic_outq_transmit_ctrl(sk);

	quic_outq_transmit_data(sk);

	if (packet->len != packet->overhead)
		quic_packet_transmit(sk);

	if (packet->next_number != next_number)
		quic_timer_start(sk, QUIC_TIMER_RTX);
}

static void quic_outq_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	sk_wmem_queued_add(sk, -QUIC_SND_CB(skb)->data_bytes);
	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

static void quic_outq_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	sk_wmem_queued_add(sk, QUIC_SND_CB(skb)->data_bytes);

	skb->sk = sk;
	skb->destructor = quic_outq_wfree;
}

void quic_outq_data_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	quic_outq_set_owner_w(skb, sk);
	__skb_queue_tail(&sk->sk_write_queue, skb);
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_ctrl_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	__skb_queue_tail(&quic_sk(sk)->outq.control_list, skb);
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_retransmit_check(struct sock *sk, u32 largest, u32 smallest,
				u32 ack_largest, u32 ack_delay)
{
	struct sk_buff_head *head = &quic_sk(sk)->outq.retransmit_list;
	u32 acked_bytes = 0, acked_number = 0, transmit_ts = 0;
	struct sk_buff *skb, *tmp, *first = skb_peek(head);
	struct quic_packet *packet = &quic_sk(sk)->packet;

	skb_queue_reverse_walk_safe(head, skb, tmp) {
		if (QUIC_SND_CB(skb)->packet_number > largest)
			continue;
		if (QUIC_SND_CB(skb)->packet_number < smallest)
			break;
		if (!QUIC_SND_CB(skb)->rtx_count &&
		    QUIC_SND_CB(skb)->packet_number == ack_largest)
			quic_cong_rtt_update(sk, QUIC_SND_CB(skb)->transmit_ts, ack_delay);
		if (!acked_number) {
			acked_number = QUIC_SND_CB(skb)->packet_number;
			transmit_ts = QUIC_SND_CB(skb)->transmit_ts;
		}
		packet->send.inflight -= QUIC_SND_CB(skb)->data_bytes;
		acked_bytes += QUIC_SND_CB(skb)->data_bytes;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}

	if (skb_queue_empty(head))
		quic_timer_stop(sk, QUIC_TIMER_RTX);
	else if (first && first != skb_peek(head))
		quic_timer_reset(sk, QUIC_TIMER_RTX);

	if (!acked_bytes)
		return;
	quic_cong_cwnd_update_after_sack(sk, acked_number, transmit_ts, acked_bytes);
}

void quic_outq_retransmit(struct sock *sk)
{
	struct sk_buff_head *head = &quic_sk(sk)->outq.retransmit_list;
	struct quic_packet *packet = &quic_sk(sk)->packet;
	struct sk_buff *skb, *nskb;
	int ret;

	if (packet->rtx_count >= QUIC_RTX_MAX) {
		pr_warn("[QUIC] %s timeout!\n", __func__);
		sk->sk_err = -ETIMEDOUT;
		sk->sk_state_change(sk);
		return;
	}

	quic_packet_config(sk);

	skb = __skb_dequeue(head);
	while (skb) {
		if (QUIC_SND_CB(skb)->rtx_count >= QUIC_RTX_MAX)
			pr_warn("[QUIC] %s packet %u timeout\n", __func__,
				QUIC_SND_CB(skb)->packet_number);
		ret = quic_packet_tail(sk, skb);
		if (!ret) {
			__skb_queue_head(head, skb);
			break;
		}
		QUIC_SND_CB(skb)->rtx_count++;
		nskb = skb;
		skb = __skb_dequeue(head);
	}

	if (packet->len != packet->overhead) {
		packet->rtx_count++;
		quic_cong_cwnd_update_after_timeout(sk, QUIC_SND_CB(nskb)->packet_number,
						    QUIC_SND_CB(nskb)->transmit_ts);
		quic_packet_transmit(sk);
		quic_timer_start(sk, QUIC_TIMER_RTX);
	}
}
