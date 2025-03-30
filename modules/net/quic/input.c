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

static void quic_inq_rfree(int len, struct sock *sk)
{
	if (!len)
		return;

	atomic_sub(len, &sk->sk_rmem_alloc);
	sk_mem_uncharge(sk, len);
}

static void quic_inq_set_owner_r(int len, struct sock *sk)
{
	if (!len)
		return;

	atomic_add(len, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, len);
}

static void quic_inq_stream_tail(struct sock *sk, struct quic_stream *stream,
				 struct quic_frame *frame)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream_update update = {};
	u64 overlap;

	overlap = stream->recv.offset - frame->offset;
	if (overlap) {
		quic_inq_rfree((int)frame->len, sk);
		frame->data += overlap;
		frame->len -= overlap;
		quic_inq_set_owner_r((int)frame->len, sk);
		frame->offset += overlap;
	}
	stream->recv.offset += frame->len;

	if (frame->stream_fin) {
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECVD;
		update.finalsz = frame->offset + frame->len;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

		stream->recv.state = update.state;
		quic_stream_recv_put(quic_streams(sk), stream, quic_is_serv(sk));
	}

	frame->offset = 0;
	if (frame->level) {
		frame->level = 0;
		list_add_tail(&frame->list, &inq->early_list);
		return;
	}
	list_add_tail(&frame->list, &inq->recv_list);
	sk->sk_data_ready(sk);
}

#define QUIC_INQ_RWND_SHIFT	4

void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, u32 bytes)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	u32 mss, window;
	u8 frame = 0;

	if (!bytes)
		return;

	mss = quic_packet_mss(packet);
	stream->recv.bytes += bytes;
	inq->bytes += bytes;

	/* recv flow control */
	window = inq->max_data;
	if (inq->bytes + window - inq->max_bytes >=
	    max(mss, (window >> QUIC_INQ_RWND_SHIFT))) {
		if (quic_under_memory_pressure(sk))
			window >>= 1;
		inq->max_bytes = inq->bytes + window;
		if (!quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_DATA, inq, 0, true))
			frame = 1;
	}

	window = stream->recv.window;
	if (stream->recv.state < QUIC_STREAM_RECV_STATE_RECVD &&
	    stream->recv.bytes + window - stream->recv.max_bytes >=
	    max(mss, (window >> QUIC_INQ_RWND_SHIFT))) {
		if (quic_under_memory_pressure(sk))
			window >>= 1;
		stream->recv.max_bytes = stream->recv.bytes + window;
		if (!quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_STREAM_DATA, stream, 0, true))
			frame = 1;
	}

	if (frame)
		quic_outq_transmit(sk);
}

static bool quic_sk_rmem_schedule(struct sock *sk, int size)
{
	int delta;

	if (!sk_has_account(sk))
		return true;
	delta = size - sk->sk_forward_alloc;
	return delta <= 0 || __sk_mem_schedule(sk, delta, SK_MEM_RECV);
}

int quic_inq_stream_recv(struct sock *sk, struct quic_frame *frame)
{
	u64 offset = frame->offset, off, highest = 0;
	struct quic_stream *stream = frame->stream;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream_update update = {};
	struct net *net = sock_net(sk);
	s64 stream_id = stream->id;
	struct list_head *head;
	struct quic_frame *pos;

	if (stream->recv.offset >= offset + frame->len &&
	    (stream->recv.state == QUIC_STREAM_RECV_STATE_SIZE_KNOWN ||
	     !frame->stream_fin)) { /* dup */
		quic_frame_put(frame);
		return 0;
	}

	quic_inq_set_owner_r((int)frame->len, sk);
	if (sk_rmem_alloc_get(sk) > sk->sk_rcvbuf || !quic_sk_rmem_schedule(sk, frame->len)) {
		QUIC_INC_STATS(net, QUIC_MIB_FRM_RCVBUFDROP);
		quic_inq_rfree((int)frame->len, sk);
		return -ENOBUFS;
	}

	off = offset + frame->len;
	if (off > stream->recv.highest) {
		highest = off - stream->recv.highest;
		if (inq->highest + highest > inq->max_bytes ||
		    stream->recv.highest + highest > stream->recv.max_bytes) {
			frame->errcode = QUIC_TRANSPORT_ERROR_FLOW_CONTROL;
			quic_inq_rfree((int)frame->len, sk);
			return -ENOBUFS;
		}
		if (stream->recv.finalsz && off > stream->recv.finalsz) {
			frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
			quic_inq_rfree((int)frame->len, sk);
			return -EINVAL;
		}
	}
	if (!stream->recv.highest && !frame->stream_fin) {
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECV;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);
	}
	head = &inq->stream_list;
	if (stream->recv.offset < offset) {
		list_for_each_entry(pos, head, list) {
			if (pos->stream->id < stream_id)
				continue;
			if (pos->stream->id > stream_id) {
				head = &pos->list;
				break;
			}
			if (pos->offset > offset) {
				head = &pos->list;
				break;
			}
			if (pos->offset + pos->len >= offset + frame->len &&
			    (pos->stream_fin || !frame->stream_fin)) { /* dup */
				quic_inq_rfree((int)frame->len, sk);
				quic_frame_put(frame);
				return 0;
			}
		}
		if (frame->stream_fin) {
			if (off < stream->recv.highest ||
			    (stream->recv.finalsz && stream->recv.finalsz != off)) {
				frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
				quic_inq_rfree((int)frame->len, sk);
				return -EINVAL;
			}
			update.id = stream->id;
			update.state = QUIC_STREAM_RECV_STATE_SIZE_KNOWN;
			update.finalsz = off;
			quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

			stream->recv.state = update.state;
			stream->recv.finalsz = update.finalsz;
		}
		list_add_tail(&frame->list, head);
		stream->recv.frags++;
		inq->highest += highest;
		stream->recv.highest += highest;
		return 0;
	}

	/* fast path: stream->recv.offset == offset */
	inq->highest += highest;
	stream->recv.highest += highest;
	quic_inq_stream_tail(sk, stream, frame);
	if (!stream->recv.frags)
		return 0;

	list_for_each_entry_safe(frame, pos, head, list) {
		if (frame->stream->id < stream_id)
			continue;
		if (frame->stream->id > stream_id)
			break;
		if (frame->offset > stream->recv.offset)
			break;
		list_del(&frame->list);
		stream->recv.frags--;
		if (stream->recv.offset >= frame->offset + frame->len &&
		    (stream->recv.state == QUIC_STREAM_RECV_STATE_RECVD ||
		     !frame->stream_fin)) { /* dup */
			quic_inq_rfree((int)frame->len, sk);
			quic_frame_put(frame);
			continue;
		}
		quic_inq_stream_tail(sk, stream, frame);
	}
	return 0;
}

void quic_inq_stream_list_purge(struct sock *sk, struct quic_stream *stream)
{
	struct list_head *head = &quic_inq(sk)->stream_list;
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		if (frame->stream != stream)
			continue;
		list_del(&frame->list);
		bytes += frame->len;
		quic_frame_put(frame);
	}
	quic_inq_rfree(bytes, sk);
}

static void quic_inq_list_purge(struct sock *sk, struct list_head *head)
{
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		list_del(&frame->list);
		bytes += frame->len;
		quic_frame_put(frame);
	}
	quic_inq_rfree(bytes, sk);
}

static void quic_inq_handshake_tail(struct sock *sk, struct quic_frame *frame)
{
	struct quic_crypto *crypto = quic_crypto(sk, frame->level);
	struct quic_data *ticket = quic_ticket(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	u64 overlap, type, length;
	struct list_head *head;
	struct quic_frame *pos;
	u32 len;
	u8 *p;

	overlap = quic_crypto_recv_offset(crypto) - frame->offset;
	if (overlap) {
		quic_inq_rfree((int)frame->len, sk);
		frame->data += overlap;
		frame->len -= overlap;
		quic_inq_set_owner_r((int)frame->len, sk);
		frame->offset += overlap;
	}
	quic_crypto_inc_recv_offset(crypto, frame->len);

	if (frame->level) {
		/* always put handshake msg ahead of data and event */
		head = &inq->recv_list;
		list_for_each_entry(pos, head, list) {
			if (!pos->level) {
				head = &pos->list;
				break;
			}
		}

		frame->offset = 0;
		list_add_tail(&frame->list, head);
		sk->sk_data_ready(sk);
		return;
	}

	if (!quic_crypto_ticket_ready(crypto) && quic_crypto_recv_offset(crypto) <= 4096) {
		quic_data_append(ticket, frame->data, frame->len);
		if (ticket->len >= 4) {
			p = ticket->data;
			len = ticket->len;
			quic_get_int(&p, &len, &type, 1);
			quic_get_int(&p, &len, &length, 3);
			if (ticket->len >= length + 4) {
				quic_crypto_set_ticket_ready(crypto, 1);
				quic_inq_event_recv(sk, QUIC_EVENT_NEW_SESSION_TICKET, ticket);
			}
		}
	}
	quic_inq_rfree((int)frame->len, sk);
	quic_frame_put(frame);
}

int quic_inq_handshake_recv(struct sock *sk, struct quic_frame *frame)
{
	u64 offset = frame->offset, crypto_offset;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_crypto *crypto;
	u8 level = frame->level;
	struct list_head *head;
	struct quic_frame *pos;

	crypto = quic_crypto(sk, level);
	crypto_offset = quic_crypto_recv_offset(crypto);
	pr_debug("%s: recv_offset: %llu, offset: %llu, level: %u, len: %u\n",
		 __func__, crypto_offset, offset, level, frame->len);

	if (crypto_offset >= offset + frame->len) { /* dup */
		quic_frame_put(frame);
		return 0;
	}

	quic_inq_set_owner_r((int)frame->len, sk);
	if (sk_rmem_alloc_get(sk) > sk->sk_rcvbuf || !quic_sk_rmem_schedule(sk, frame->len)) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_RCVBUFDROP);
		frame->errcode = QUIC_TRANSPORT_ERROR_CRYPTO_BUF_EXCEEDED;
		quic_inq_rfree((int)frame->len, sk);
		return -ENOBUFS;
	}

	head = &inq->handshake_list;
	if (offset > crypto_offset) {
		list_for_each_entry(pos, head, list) {
			if (pos->level < level)
				continue;
			if (pos->level > level) {
				head = &pos->list;
				break;
			}
			if (pos->offset > offset) {
				head = &pos->list;
				break;
			}
			if (pos->offset + pos->len >= offset + frame->len) { /* dup */
				quic_inq_rfree((int)frame->len, sk);
				quic_frame_put(frame);
				return 0;
			}
		}
		list_add_tail(&frame->list, head);
		return 0;
	}

	quic_inq_handshake_tail(sk, frame);

	list_for_each_entry_safe(frame, pos, head, list) {
		if (frame->level < level)
			continue;
		if (frame->level > level)
			break;
		if (frame->offset > quic_crypto_recv_offset(crypto))
			break;
		list_del(&frame->list);
		if (quic_crypto_recv_offset(crypto) >= frame->offset + frame->len) { /* dup */
			quic_inq_rfree((int)frame->len, sk);
			quic_frame_put(frame);
			continue;
		}
		quic_inq_handshake_tail(sk, frame);
	}
	return 0;
}

void quic_inq_get_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_inqueue *inq = quic_inq(sk);

	if (p->remote)
		return;

	p->disable_compatible_version = inq->disable_compatible_version;
	p->disable_1rtt_encryption = inq->disable_1rtt_encryption;
	p->max_datagram_frame_size = inq->max_datagram_frame_size;
	p->max_udp_payload_size = inq->max_udp_payload_size;
	p->ack_delay_exponent = inq->ack_delay_exponent;
	p->max_idle_timeout = inq->max_idle_timeout;
	p->grease_quic_bit = inq->grease_quic_bit;
	p->stateless_reset = inq->stateless_reset;
	p->max_ack_delay = inq->max_ack_delay;
	p->max_data = inq->max_data;
}

void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);

	if (p->remote) {
		if (p->max_idle_timeout &&
		    (!inq->max_idle_timeout || p->max_idle_timeout < inq->max_idle_timeout))
			inq->timeout = p->max_idle_timeout;

		if (inq->disable_1rtt_encryption && p->disable_1rtt_encryption)
			quic_packet_set_taglen(packet, 0);
		return;
	}

	inq->disable_compatible_version = p->disable_compatible_version;
	inq->disable_1rtt_encryption = p->disable_1rtt_encryption;
	inq->max_datagram_frame_size = p->max_datagram_frame_size;
	inq->max_udp_payload_size = p->max_udp_payload_size;
	inq->ack_delay_exponent = p->ack_delay_exponent;
	inq->max_idle_timeout = p->max_idle_timeout;
	inq->grease_quic_bit = p->grease_quic_bit;
	inq->stateless_reset = p->stateless_reset;
	inq->max_ack_delay = p->max_ack_delay;
	inq->max_data = p->max_data;

	inq->timeout = inq->max_idle_timeout;
	inq->max_bytes = inq->max_data;
	sk->sk_rcvbuf = (int)p->max_data * 2;
}

int quic_inq_event_recv(struct sock *sk, u8 event, void *args)
{
	struct list_head *head = &quic_inq(sk)->recv_list;
	struct quic_frame *frame, *pos;
	u32 args_len = 0;
	u8 *p;

	if (!event || event > QUIC_EVENT_MAX)
		return -EINVAL;

	if (!(quic_inq(sk)->events & (1 << event)))
		return 0;

	switch (event) {
	case QUIC_EVENT_STREAM_UPDATE:
		args_len = sizeof(struct quic_stream_update);
		break;
	case QUIC_EVENT_STREAM_MAX_DATA:
		args_len = sizeof(struct quic_stream_max_data);
		break;
	case QUIC_EVENT_STREAM_MAX_STREAM:
		args_len = sizeof(u64);
		break;
	case QUIC_EVENT_CONNECTION_ID:
		args_len = sizeof(struct quic_connection_id_info);
		break;
	case QUIC_EVENT_CONNECTION_CLOSE:
		args_len = strlen(((struct quic_connection_close *)args)->phrase) + 1 +
			   sizeof(struct quic_connection_close);
		break;
	case QUIC_EVENT_CONNECTION_MIGRATION:
	case QUIC_EVENT_KEY_UPDATE:
		args_len = sizeof(u8);
		break;
	case QUIC_EVENT_NEW_SESSION_TICKET:
	case QUIC_EVENT_NEW_TOKEN:
		args_len = ((struct quic_data *)args)->len;
		args = ((struct quic_data *)args)->data;
		break;
	default:
		return -EINVAL;
	}

	frame = quic_frame_alloc(1 + args_len, NULL, GFP_ATOMIC);
	if (!frame) {
		pr_debug("%s: event: %u, args_len: %u\n", __func__, event, args_len);
		return -ENOMEM;
	}
	p = quic_put_data(frame->data, &event, 1);
	quic_put_data(p, args, args_len);
	frame->event = 1;
	frame->offset = 0;

	/* always put event ahead of data */
	list_for_each_entry(pos, head, list) {
		if (!pos->level && !pos->event) {
			head = &pos->list;
			break;
		}
	}
	quic_inq_set_owner_r((int)frame->len, sk);
	list_add_tail(&frame->list, head);
	sk->sk_data_ready(sk);
	return 0;
}

int quic_inq_dgram_recv(struct sock *sk, struct quic_frame *frame)
{
	quic_inq_set_owner_r((int)frame->len, sk);
	if (sk_rmem_alloc_get(sk) > sk->sk_rcvbuf || !quic_sk_rmem_schedule(sk, frame->len)) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_RCVBUFDROP);
		quic_inq_rfree((int)frame->len, sk);
		return -ENOBUFS;
	}

	frame->dgram = 1;
	frame->offset = 0;
	list_add_tail(&frame->list, &quic_inq(sk)->recv_list);
	sk->sk_data_ready(sk);
	return 0;
}

void quic_inq_data_read(struct sock *sk, u32 bytes)
{
	quic_inq_rfree((int)bytes, sk);
}

static void quic_inq_decrypted_work(struct work_struct *work)
{
	struct quic_sock *qs = container_of(work, struct quic_sock, inq.work);
	struct sock *sk = &qs->inet.sk;
	struct sk_buff_head *head;
	struct sk_buff *skb;

	lock_sock(sk);
	head = &sk->sk_receive_queue;
	if (sock_flag(sk, SOCK_DEAD)) {
		skb_queue_purge(head);
		goto out;
	}

	skb = skb_dequeue(head);
	while (skb) {
		QUIC_CRYPTO_CB(skb)->resume = 1;
		quic_packet_process(sk, skb);
		skb = skb_dequeue(head);
	}
out:
	release_sock(sk);
	sock_put(sk);
}

void quic_inq_decrypted_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_inqueue *inq = quic_inq(sk);

	sock_hold(sk);
	skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!schedule_work(&inq->work))
		sock_put(sk);
}

void quic_inq_backlog_tail(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_tail(&quic_inq(sk)->backlog_list, skb);
}

void quic_inq_init(struct sock *sk)
{
	struct quic_inqueue *inq = quic_inq(sk);

	skb_queue_head_init(&inq->backlog_list);
	INIT_LIST_HEAD(&inq->handshake_list);
	INIT_LIST_HEAD(&inq->stream_list);
	INIT_LIST_HEAD(&inq->early_list);
	INIT_LIST_HEAD(&inq->recv_list);
	INIT_WORK(&inq->work, quic_inq_decrypted_work);
}

void quic_inq_free(struct sock *sk)
{
	struct quic_inqueue *inq = quic_inq(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&inq->backlog_list);
	quic_inq_list_purge(sk, &inq->handshake_list);
	quic_inq_list_purge(sk, &inq->stream_list);
	quic_inq_list_purge(sk, &inq->early_list);
	quic_inq_list_purge(sk, &inq->recv_list);
}
