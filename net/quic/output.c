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
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;

	skb = __skb_dequeue(head);
	if (!skb)
		return;
	if (!quic_packet_empty(packet))
		quic_packet_transmit(sk);
	quic_packet_config(sk, QUIC_SND_CB(skb)->level);
	while (skb) {
		if (QUIC_SND_CB(skb)->level == packet->level &&
		    quic_packet_tail(sk, skb)) {
			skb = __skb_dequeue(head);
			continue;
		}

		quic_packet_transmit(sk);
		quic_packet_config(sk, QUIC_SND_CB(skb)->level);
		WARN_ON_ONCE(!quic_packet_tail(sk, skb));

		skb = __skb_dequeue(head);
	}
}

static int quic_outq_transmit_dgram(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff_head *head;
	struct sk_buff *skb;

	head = &outq->datagram_list;
	skb = __skb_dequeue(head);
	if (!skb)
		return 0;
	if (!quic_packet_empty(packet)) {
		if (QUIC_SND_CB(skb)->level != packet->level) {
			quic_packet_transmit(sk);
			quic_packet_config(sk, QUIC_SND_CB(skb)->level);
		}
	} else {
		quic_packet_config(sk, QUIC_SND_CB(skb)->level);
	}
	while (skb) {
		if (outq->inflight + skb->len > outq->window) {
			__skb_queue_head(head, skb);
			return 1;
		}
		outq->inflight += QUIC_SND_CB(skb)->data_bytes;
		if (!quic_packet_tail_dgram(sk, skb)) {
			quic_packet_transmit(sk);
			quic_packet_config(sk, QUIC_SND_CB(skb)->level);
			WARN_ON_ONCE(!quic_packet_tail_dgram(sk, skb));
		}
		skb = __skb_dequeue(head);
	}
	return 0;
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
	stream = QUIC_SND_CB(skb)->stream;
	if (stream->send.bytes + len > stream->send.max_bytes) {
		if (!stream->send.data_blocked) {
			nskb = quic_frame_create(sk, QUIC_FRAME_STREAM_DATA_BLOCKED, stream);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			stream->send.data_blocked = 1;
		}
		requeue = 1;
	}
	if (outq->bytes + len > outq->max_bytes) {
		if (!outq->data_blocked) {
			nskb = quic_frame_create(sk, QUIC_FRAME_DATA_BLOCKED, outq);
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
	stream->send.frags++;
	outq->bytes += len;
	stream->send.bytes += len;
	return 0;
}

static void quic_outq_transmit_data(struct sock *sk)
{
	struct sk_buff_head *head = &sk->sk_write_queue;
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;

	skb = __skb_dequeue(head);
	if (!skb)
		return;
	if (!quic_packet_empty(packet)) {
		if (QUIC_SND_CB(skb)->level != packet->level) {
			quic_packet_transmit(sk);
			quic_packet_config(sk, QUIC_SND_CB(skb)->level);
		}
	} else {
		quic_packet_config(sk, QUIC_SND_CB(skb)->level);
	}
	while (skb) {
		if (quic_outq_flow_control(sk, skb))
			break;
		if (!quic_packet_tail(sk, skb)) {
			quic_packet_transmit(sk);
			quic_packet_config(sk, QUIC_SND_CB(skb)->level);
			WARN_ON_ONCE(!quic_packet_tail(sk, skb));
		}
		skb = __skb_dequeue(head);
	}
}

void quic_outq_flush(struct sock *sk)
{
	quic_outq_transmit_ctrl(sk);

	if (!quic_outq_transmit_dgram(sk))
		quic_outq_transmit_data(sk);

	quic_packet_flush(sk);
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
	struct quic_stream *stream = QUIC_SND_CB(skb)->stream;

	if (stream->send.state == QUIC_STREAM_SEND_STATE_READY)
		stream->send.state = QUIC_STREAM_SEND_STATE_SEND;

	if (QUIC_SND_CB(skb)->frame_type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		if (quic_streams(sk)->send.stream_active == stream->id)
			quic_streams(sk)->send.stream_active = -1;
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}

	quic_outq_set_owner_w(skb, sk);
	__skb_queue_tail(&sk->sk_write_queue, skb);
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_dgram_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	quic_outq_set_owner_w(skb, sk);
	__skb_queue_tail(&quic_outq(sk)->datagram_list, skb);
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_ctrl_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	struct sk_buff_head *list = &quic_outq(sk)->control_list;
	struct sk_buff *pos;

	if (QUIC_SND_CB(skb)->level) { /* prioritize handshake frames */
		skb_queue_walk(list, pos) {
			if (!QUIC_SND_CB(pos)->level) {
				__skb_queue_before(list, pos, skb);
				goto out;
			}
		}
	}
	__skb_queue_tail(list, skb);
out:
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_rtx_tail(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_tail(&quic_outq(sk)->retransmit_list, skb);
}

void quic_outq_retransmit_check(struct sock *sk, u8 level, s64 largest, s64 smallest,
				s64 ack_largest, u32 ack_delay)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 acked_bytes = 0, transmit_ts = 0;
	struct sk_buff *skb, *tmp, *first;
	struct quic_stream_update update;
	struct quic_stream *stream;
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	s64 acked_number = 0;

	head = &outq->retransmit_list;
	first = skb_peek(head);
	skb_queue_reverse_walk_safe(head, skb, tmp) {
		snd_cb = QUIC_SND_CB(skb);
		if (level != snd_cb->level)
			continue;
		if (snd_cb->packet_number > largest)
			continue;
		if (snd_cb->packet_number < smallest)
			break;
		if (!snd_cb->rtx_count && snd_cb->packet_number == ack_largest)
			quic_cong_rtt_update(sk, snd_cb->transmit_ts, ack_delay);
		if (outq->retransmit_skb == skb)
			outq->retransmit_skb = NULL;
		if (!acked_number) {
			acked_number = snd_cb->packet_number;
			transmit_ts = snd_cb->transmit_ts;
		}
		stream = snd_cb->stream;
		if (snd_cb->data_bytes) {
			outq->inflight -= snd_cb->data_bytes;
			acked_bytes += snd_cb->data_bytes;
			if (!stream)
				goto unlink;
			stream->send.frags--;
			if (stream->send.frags || stream->send.state != QUIC_STREAM_SEND_STATE_SENT)
				goto unlink;
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RECVD;
			quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);
			stream->send.state = update.state;
		}
		if (quic_frame_is_reset(snd_cb->frame_type)) {
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
			update.errcode = snd_cb->err_code;
			quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);
			stream->send.state = update.state;
		}
unlink:
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
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	struct sk_buff *skb;
	s64 packet_number;
	u32 transmit_ts;

	head = &outq->retransmit_list;
	if (outq->rtx_count >= QUIC_RTX_MAX) {
		pr_warn("[QUIC] %s timeout!\n", __func__);
		inet_sk_set_state(sk, QUIC_SS_CLOSED);
		sk->sk_err = -ETIMEDOUT;
		sk->sk_state_change(sk);
		return;
	}

next:
	skb = outq->retransmit_skb ?: skb_peek(head);
	if (!skb)
		return quic_outq_flush(sk);
	__skb_unlink(skb, head);

	snd_cb = QUIC_SND_CB(skb);
	transmit_ts = snd_cb->transmit_ts;
	packet_number = snd_cb->packet_number;
	if (quic_frame_is_dgram(snd_cb->frame_type)) { /* no need to retransmit dgram frame */
		outq->inflight -= snd_cb->data_bytes;
		kfree_skb(skb);
		quic_cong_cwnd_update_after_timeout(sk, packet_number, transmit_ts);
		goto next;
	}

	quic_packet_config(sk, snd_cb->level);
	quic_packet_tail(sk, skb);
	quic_packet_flush(sk);

	outq->retransmit_skb = skb;
	outq->rtx_count++;

	snd_cb->rtx_count++;
	if (snd_cb->rtx_count >= QUIC_RTX_MAX)
		pr_warn("[QUIC] %s packet %llu timeout\n", __func__, snd_cb->packet_number);
	quic_timer_start(sk, QUIC_TIMER_RTX);
	if (snd_cb->data_bytes)
		quic_cong_cwnd_update_after_timeout(sk, packet_number, transmit_ts);
}

void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	u32 local_ito = quic_inq_max_idle_timeout(quic_inq(sk));
	struct quic_outqueue *outq = quic_outq(sk);
	u32 remote_ito, min_ito = 0;

	outq->max_datagram_frame_size = p->max_datagram_frame_size;
	outq->max_udp_payload_size = p->max_udp_payload_size;
	outq->ack_delay_exponent = p->ack_delay_exponent;
	outq->max_idle_timeout = p->max_idle_timeout;
	outq->max_ack_delay = p->max_ack_delay;
	outq->grease_quic_bit = p->grease_quic_bit;
	quic_timer_setup(sk, QUIC_TIMER_ACK, outq->max_ack_delay);

	outq->max_bytes = p->initial_max_data;
	if (sk->sk_sndbuf > 2 * p->initial_max_data)
		sk->sk_sndbuf = 2 * p->initial_max_data;

	/* If neither the local endpoint nor the remote endpoint specified a
	 * max_idle_timeout, we don't set one. Effectively, this means that
	 * there is no idle timer.
	 */
	remote_ito = outq->max_idle_timeout;
	if (local_ito && !remote_ito)
		min_ito = local_ito;
	else if (!local_ito && remote_ito)
		min_ito = remote_ito;
	else if (local_ito && remote_ito)
		min_ito = min(local_ito, remote_ito);

	quic_timer_setup(sk, QUIC_TIMER_IDLE, min_ito);
}

void quic_outq_get_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);

	p->initial_max_data = outq->window;
	p->max_ack_delay = outq->max_ack_delay;
	p->ack_delay_exponent = outq->ack_delay_exponent;
	p->max_idle_timeout = outq->max_idle_timeout;
	p->max_udp_payload_size = outq->max_udp_payload_size;
	p->max_datagram_frame_size = outq->max_datagram_frame_size;
}
