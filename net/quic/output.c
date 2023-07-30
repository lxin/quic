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
	struct sk_buff_head *head = &quic_outq(sk)->control_list;
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
	struct quic_outqueue *outq = quic_outq(sk);
	u32 len = QUIC_SND_CB(skb)->data_bytes;
	struct sk_buff *nskb = NULL;
	struct quic_stream *stream;
	u8 requeue = 0;

	/* congestion control */
	if (outq->inflight + len > outq->window)
		requeue = 1;

	/* send flow control */
	stream = quic_stream_find(quic_streams(sk), QUIC_SND_CB(skb)->stream_id);
	if (stream->send.bytes + len > stream->send.max_bytes) {
		if (!stream->send.data_blocked) {
			nskb = quic_frame_create(sk, QUIC_FRAME_STREAM_DATA_BLOCKED, stream, 0);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			stream->send.data_blocked = 1;
		}
		requeue = 1;
	}
	if (outq->bytes + len > outq->max_bytes) {
		if (!outq->data_blocked) {
			nskb = quic_frame_create(sk, QUIC_FRAME_DATA_BLOCKED, outq, 0);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			outq->data_blocked = 1;
		}
		requeue = 1;
	}

	if (nskb)
		quic_outq_transmit_ctrl(sk);

	if (requeue) {
		__skb_queue_head(&sk->sk_write_queue, skb);
		return 1;
	}

	outq->inflight += len;
	outq->bytes += len;
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
	struct quic_packet *packet = quic_packet(sk);
	u32 number = quic_packet_next_number(packet);

	quic_packet_config(sk);

	quic_outq_transmit_ctrl(sk);

	quic_outq_transmit_data(sk);

	if (!quic_packet_empty(packet))
		quic_packet_transmit(sk);

	if (quic_packet_next_number(packet) != number)
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
	__skb_queue_tail(&quic_outq(sk)->control_list, skb);
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_rtx_tail(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_tail(&quic_outq(sk)->retransmit_list, skb);
}

void quic_outq_retransmit_check(struct sock *sk, u32 largest, u32 smallest,
				u32 ack_largest, u32 ack_delay)
{
	u32 acked_bytes = 0, acked_number = 0, transmit_ts = 0;
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff *skb, *tmp, *first;
	struct sk_buff_head *head;

	head = &outq->retransmit_list;
	first = skb_peek(head);
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
		outq->inflight -= QUIC_SND_CB(skb)->data_bytes;
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
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff *skb, *nskb;
	struct sk_buff_head *head;
	int ret;

	head = &outq->retransmit_list;
	if (outq->rtx_count >= QUIC_RTX_MAX) {
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

	if (!quic_packet_empty(quic_packet(sk))) {
		outq->rtx_count++;
		quic_cong_cwnd_update_after_timeout(sk, QUIC_SND_CB(nskb)->packet_number,
						    QUIC_SND_CB(nskb)->transmit_ts);
		quic_packet_transmit(sk);
		quic_timer_start(sk, QUIC_TIMER_RTX);
	}
}

void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);

	outq->ack_delay_exponent = p->ack_delay_exponent;
	outq->max_ack_delay = p->max_ack_delay;
	quic_timer_setup(sk, QUIC_TIMER_ACK, outq->max_ack_delay);

	outq->max_bytes = p->initial_max_data;
	sk->sk_sndbuf = 2 * p->initial_max_data;
}

void quic_outq_get_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);

	p->initial_max_data = quic_outq(sk)->window;
	p->max_ack_delay = outq->max_ack_delay;
	p->ack_delay_exponent = outq->ack_delay_exponent;
}
