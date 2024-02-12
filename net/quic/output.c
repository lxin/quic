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
	struct quic_snd_cb *snd_cb;
	struct sk_buff *skb;

	skb = __skb_dequeue(head);
	if (!skb)
		return;
	snd_cb = QUIC_SND_CB(skb);
	quic_packet_config(sk, snd_cb->level, snd_cb->path_alt);
	while (skb) {
		snd_cb = QUIC_SND_CB(skb);
		if (!quic_packet_tail(sk, skb, 0)) {
			quic_packet_build(sk);
			quic_packet_config(sk, snd_cb->level, snd_cb->path_alt);
			WARN_ON_ONCE(!quic_packet_tail(sk, skb, 0));
		}
		skb = __skb_dequeue(head);
	}
}

static int quic_outq_transmit_dgram(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff_head *head;
	u8 level = outq->level;
	struct sk_buff *skb;

	head = &outq->datagram_list;
	skb = __skb_dequeue(head);
	if (!skb)
		return 0;
	quic_packet_config(sk, level, 0);
	while (skb) {
		if (outq->inflight + skb->len > outq->window) {
			__skb_queue_head(head, skb);
			return 1;
		}
		outq->inflight += QUIC_SND_CB(skb)->data_bytes;
		if (!quic_packet_tail(sk, skb, 1)) {
			quic_packet_build(sk);
			quic_packet_config(sk, level, 0);
			WARN_ON_ONCE(!quic_packet_tail(sk, skb, 1));
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

	outq->bytes += len;
	outq->inflight += len;
	stream->send.frags++;
	stream->send.bytes += len;
	return 0;
}

static void quic_outq_transmit_data(struct sock *sk)
{
	struct sk_buff_head *head = &sk->sk_write_queue;
	u8 level = quic_outq(sk)->level;
	struct sk_buff *skb;

	if (!quic_crypto(sk, level)->send_ready)
		return;

	skb = __skb_dequeue(head);
	if (!skb)
		return;
	quic_packet_config(sk, level, 0);
	while (skb) {
		if (!level && quic_outq_flow_control(sk, skb))
			break;
		if (!quic_packet_tail(sk, skb, 0)) {
			quic_packet_build(sk);
			quic_packet_config(sk, level, 0);
			WARN_ON_ONCE(!quic_packet_tail(sk, skb, 0));
		}
		skb = __skb_dequeue(head);
	}
}

void quic_outq_flush(struct sock *sk)
{
	quic_outq_transmit_ctrl(sk);

	if (!quic_outq_transmit_dgram(sk))
		quic_outq_transmit_data(sk);

	if (!quic_packet_empty(quic_packet(sk)))
		quic_packet_build(sk);

	quic_packet_flush(sk);
}

static void quic_outq_wfree(struct sk_buff *skb)
{
	int len = QUIC_SND_CB(skb)->data_bytes;
	struct sock *sk = skb->sk;

	WARN_ON(refcount_sub_and_test(len, &sk->sk_wmem_alloc));
	sk_wmem_queued_add(sk, -len);
	sk_mem_uncharge(sk, len);

	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

static void quic_outq_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	int len = QUIC_SND_CB(skb)->data_bytes;

	refcount_add(len, &sk->sk_wmem_alloc);
	sk_wmem_queued_add(sk, len);
	sk_mem_charge(sk, len);

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
	struct sk_buff_head *head = &quic_outq(sk)->control_list;
	struct sk_buff *pos;

	if (QUIC_SND_CB(skb)->level) { /* prioritize handshake frames */
		skb_queue_walk(head, pos) {
			if (!QUIC_SND_CB(pos)->level) {
				__skb_queue_before(head, pos, skb);
				goto out;
			}
		}
	}
	__skb_queue_tail(head, skb);
out:
	if (!cork)
		quic_outq_flush(sk);
}

void quic_outq_rtx_tail(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff_head *head = &quic_outq(sk)->retransmit_list;
	struct sk_buff *pos;

	if (QUIC_SND_CB(skb)->level) { /* prioritize handshake frames */
		skb_queue_walk(head, pos) {
			if (!QUIC_SND_CB(pos)->level) {
				__skb_queue_before(head, pos, skb);
				return;
			}
		}
	}
	__skb_queue_tail(head, skb);
}

void quic_outq_transmit_probe(struct sock *sk)
{
	struct quic_path_dst *d = (struct quic_path_dst *)quic_dst(sk);
	struct sk_buff *skb;
	u32 pathmtu;

	if (!quic_is_established(sk))
		return;

	skb = quic_frame_create(sk, QUIC_FRAME_PING, &d->pl.probe_size);
	if (skb) {
		d->pl.number = quic_pnmap(sk, QUIC_CRYPTO_APP)->next_number;
		quic_outq_ctrl_tail(sk, skb, false);

		pathmtu = quic_path_pl_send(quic_dst(sk));
		if (pathmtu)
			quic_packet_mss_update(sk, pathmtu + QUIC_TAG_LEN);
	}

	quic_timer_setup(sk, QUIC_TIMER_PROBE, quic_inq(sk)->probe_timeout);
	quic_timer_reset(sk, QUIC_TIMER_PROBE);
}

void quic_outq_retransmit_check(struct sock *sk, u8 level, s64 largest, s64 smallest,
				s64 ack_largest, u32 ack_delay)
{
	u32 pathmtu, acked_bytes = 0, transmit_ts = 0;
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff *skb, *tmp, *first;
	struct quic_stream_update update;
	struct quic_stream *stream;
	struct quic_snd_cb *snd_cb;
	bool raise_timer, complete;
	struct sk_buff_head *head;
	s64 acked_number = 0;

	pr_debug("[QUIC] %s largest: %llu, smallest: %llu\n", __func__, largest, smallest);
	if (quic_path_pl_confirm(quic_dst(sk), largest, smallest)) {
		pathmtu = quic_path_pl_recv(quic_dst(sk), &raise_timer, &complete);
		if (pathmtu)
			quic_packet_mss_update(sk, pathmtu + QUIC_TAG_LEN);
		if (!complete)
			quic_outq_transmit_probe(sk);
		if (raise_timer) { /* reuse probe timer as raise timer */
			quic_timer_setup(sk, QUIC_TIMER_PROBE, quic_inq(sk)->probe_timeout * 30);
			quic_timer_reset(sk, QUIC_TIMER_PROBE);
		}
	}

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
			if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update)) {
				stream->send.frags++;
				outq->inflight += snd_cb->data_bytes;
				acked_bytes -= snd_cb->data_bytes;
				continue;
			}
			stream->send.state = update.state;
		} else if (snd_cb->frame_type == QUIC_FRAME_RESET_STREAM) {
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
			update.errcode = stream->send.errcode;
			if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
				continue;
			stream->send.state = update.state;
		} else if (snd_cb->frame_type == QUIC_FRAME_STREAM_DATA_BLOCKED) {
			stream->send.data_blocked = 0;
		} else if (snd_cb->frame_type == QUIC_FRAME_DATA_BLOCKED) {
			outq->data_blocked = 0;
		}
unlink:
		if (outq->retransmit_skb == skb)
			outq->retransmit_skb = NULL;
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
		sk->sk_err = -ETIMEDOUT;
		quic_set_state(sk, QUIC_SS_CLOSED);
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

	quic_packet_config(sk, (snd_cb->level ?: outq->level), snd_cb->path_alt);
	quic_packet_tail(sk, skb, 0);
	quic_packet_build(sk);
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

void quic_outq_stream_purge(struct sock *sk, struct quic_stream *stream)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff *skb, *tmp;
	struct sk_buff_head *head;

	head = &outq->retransmit_list;
	skb_queue_walk_safe(head, skb, tmp) {
		if (QUIC_SND_CB(skb)->stream != stream)
			continue;
		if (outq->retransmit_skb == skb)
			outq->retransmit_skb = NULL;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}

	head = &sk->sk_write_queue;
	skb_queue_walk_safe(head, skb, tmp) {
		if (QUIC_SND_CB(skb)->stream != stream)
			continue;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}
}

void quic_outq_validate_path(struct sock *sk, struct sk_buff *skb, struct quic_path_addr *path)
{
	u8 local = path->udp_bind, path_alt = QUIC_PATH_ALT_DST;
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff_head *head;
	struct sk_buff *fskb;

	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_MIGRATION, &local))
		return;

	if (local) {
		path->active = !path->active;
		path_alt = QUIC_PATH_ALT_SRC;
	}
	quic_path_addr_free(sk, path, 1);
	quic_set_sk_addr(sk, &path->addr[path->active], local);
	path->sent_cnt = 0;
	quic_timer_stop(sk, QUIC_TIMER_PATH);

	head = &outq->control_list;
	skb_queue_walk(head, fskb)
		QUIC_SND_CB(fskb)->path_alt &= ~path_alt;

	head = &outq->retransmit_list;
	skb_queue_walk(head, fskb)
		QUIC_SND_CB(fskb)->path_alt &= ~path_alt;

	QUIC_RCV_CB(skb)->path_alt &= ~path_alt;
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

	outq->max_bytes = p->max_data;
	if (sk->sk_sndbuf > 2 * p->max_data)
		sk->sk_sndbuf = 2 * p->max_data;

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

	p->max_data = outq->window;
	p->max_ack_delay = outq->max_ack_delay;
	p->ack_delay_exponent = outq->ack_delay_exponent;
	p->max_idle_timeout = outq->max_idle_timeout;
	p->max_udp_payload_size = outq->max_udp_payload_size;
	p->max_datagram_frame_size = outq->max_datagram_frame_size;
}
