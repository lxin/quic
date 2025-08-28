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

/* Frees socket receive memory resources after read. */
static void quic_inq_rfree(int len, struct sock *sk)
{
	if (!len)
		return;

	atomic_sub(len, &sk->sk_rmem_alloc);
	sk_mem_uncharge(sk, len);
}

/* Charges socket receive memory for new frame. */
static void quic_inq_set_owner_r(int len, struct sock *sk)
{
	if (!len)
		return;

	atomic_add(len, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, len);
}

#define QUIC_INQ_RWND_SHIFT	4

/* Update receive flow control windows and send MAX_DATA or MAX_STREAM_DATA frames if needed. */
void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, u32 bytes)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	u32 mss, window;
	u8 frame = 0;

	if (!bytes)
		return;

	mss = quic_packet_mss(packet);
	/* Account for bytes read at both stream and connection levels. */
	stream->recv.bytes += bytes;
	inq->bytes += bytes;

	 /* Check and update connection-level flow control. */
	window = inq->max_data;
	if (inq->bytes + window - inq->max_bytes >=
	    max(mss, (window >> QUIC_INQ_RWND_SHIFT))) {
		/* Reduce window increment if memory pressure detected. */
		if (quic_under_memory_pressure(sk))
			window >>= 1;
		/* Increase advertised max data to received data + window. */
		inq->max_bytes = inq->bytes + window;
		if (!quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_DATA, inq, 0, true))
			frame = 1;
	}

	/* Check and update stream-level flow control. */
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

	if (frame) {
		space->need_sack = 1;  /* Request an ACK frame to be bundled with it. */
		quic_outq_transmit(sk);
	}
}

/* Handle in-order stream frame delivery. */
static void quic_inq_stream_tail(struct sock *sk, struct quic_stream *stream,
				 struct quic_frame *frame)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream_update update = {};
	u64 overlap;

	/* Calculate overlap between stream's current recv offset and frame offset. */
	overlap = stream->recv.offset - frame->offset;
	if (overlap) { /* Discard overlapping prefix and adjust memory accounting. */
		quic_inq_rfree((int)frame->len, sk);
		frame->data += overlap;
		frame->len -= overlap;
		quic_inq_set_owner_r((int)frame->len, sk);
		frame->offset += overlap;
	}
	stream->recv.offset += frame->len; /* Advance the stream's receive offset. */

	if (frame->stream_fin) {
		/* Notify that the stream has been fully received. */
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECVD;
		update.finalsz = frame->offset + frame->len;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

		/* rfc9000#section-3.2:
		 *
		 * Once all data for the stream has been received, the receiving part
		 * enters the "Data Recvd" state.
		 */
		stream->recv.state = update.state;
		/* Release stream and update limits to allow opening new streams. */
		quic_stream_recv_put(quic_streams(sk), stream, quic_is_serv(sk));
	}

	frame->offset = 0; /* Reset offset as it will be reused as read offset in recvmsg(). */
	if (frame->level) {
		/* Stream frame was received at encryption level 0-RTT (early data).  Queue it
		 * into early_list. After the handshake completes and 1-RTT keys are installed,
		 * these frames will be moved to recv_list for delivery to the application.
		 */
		frame->level = 0;
		list_add_tail(&frame->list, &inq->early_list);
		return;
	}
	/* Frame is ready for application delivery: queue in recv_list. */
	list_add_tail(&frame->list, &inq->recv_list);
	sk->sk_data_ready(sk); /* Notify socket that data is available. */
}

/* Check and optionally charge receive memory for a QUIC socket.
 * Equivalent to sk_rmem_schedule().
 */
static bool quic_sk_rmem_schedule(struct sock *sk, int size)
{
	int delta;

	if (!sk_has_account(sk))
		return true;
	delta = size - sk->sk_forward_alloc;
	return delta <= 0 || __sk_mem_schedule(sk, delta, SK_MEM_RECV);
}

/* Process an incoming QUIC stream frame.
 *
 * Validates memory limits, flow control limits, and deduplicates before queuing.  Inserts frame
 * either in-order or out-of-order depending on stream state.
 *
 * Returns 0 on success, -ENOBUFS if memory/flow limits are hit, or -EINVAL on protocol violation.
 */
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

	/* Discard duplicate frames that are fully covered by the current receive offset.
	 * However, do not discard if this frame carries a FIN and the stream has not yet
	 * received any FIN, to ensure proper handling of stream termination.
	 */
	if (stream->recv.offset >= offset + frame->len &&
	    (stream->recv.state == QUIC_STREAM_RECV_STATE_SIZE_KNOWN ||
	     !frame->stream_fin)) {
		quic_frame_put(frame);
		return 0;
	}

	/* Check receive buffer size and system limits. */
	quic_inq_set_owner_r((int)frame->len, sk);
	if (sk_rmem_alloc_get(sk) > sk->sk_rcvbuf || !quic_sk_rmem_schedule(sk, frame->len)) {
		QUIC_INC_STATS(net, QUIC_MIB_FRM_RCVBUFDROP);
		quic_inq_rfree((int)frame->len, sk);
		return -ENOBUFS;
	}

	off = offset + frame->len;
	if (off > stream->recv.highest) { /* New data beyond current highest seen. */
		/* rfc9000#section-4.1:
		 *
		 * A receiver MUST close the connection with an error of type
		 * FLOW_CONTROL_ERROR if the sender violates the advertised connection or
		 * stream data limits.
		 */
		highest = off - stream->recv.highest; /* New data beyond previous highest offset. */
		if (inq->highest + highest > inq->max_bytes ||
		    stream->recv.highest + highest > stream->recv.max_bytes) {
			frame->errcode = QUIC_TRANSPORT_ERROR_FLOW_CONTROL;
			quic_inq_rfree((int)frame->len, sk);
			return -ENOBUFS;
		}
		/* Check for violation of known final size (protocol error). */
		if (stream->recv.finalsz && off > stream->recv.finalsz) {
			frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
			quic_inq_rfree((int)frame->len, sk);
			return -EINVAL;
		}
	}
	if (!stream->recv.highest && !frame->stream_fin) {
		/* Notify if first data received on stream. Skip FIN frame, as it will trigger
		 * a "Size Known" state later.
		 */
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECV;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);
	}
	head = &inq->stream_list;
	if (stream->recv.offset < offset) { /* Out-of-order: insert in frame list in order. */
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
			    (pos->stream_fin || !frame->stream_fin)) {
				/* Duplicate or overlapping frame.  Keep if it has FIN while
				 * the other does not.
				 */
				quic_inq_rfree((int)frame->len, sk);
				quic_frame_put(frame);
				return 0;
			}
		}
		if (frame->stream_fin) {
			/* rfc9000#section-4.5:
			 *
			 * Once a final size for a stream is known, it cannot change. If a
			 * RESET_STREAM or STREAM frame is received indicating a change in the
			 * final size for the stream, an endpoint SHOULD respond with an error
			 * of type FINAL_SIZE_ERROR.
			 */
			if (off < stream->recv.highest ||
			    (stream->recv.finalsz && stream->recv.finalsz != off)) {
				frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
				quic_inq_rfree((int)frame->len, sk);
				return -EINVAL;
			}
			/* Notify that the stream has known the final size. */
			update.id = stream->id;
			update.state = QUIC_STREAM_RECV_STATE_SIZE_KNOWN;
			update.finalsz = off;
			quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

			/* rfc9000#section-3.2:
			 *
			 * When a STREAM frame with a FIN bit is received, the final size of
			 * the stream is known; The receiving part of the stream then enters
			 * the "Size Known" state.
			 */
			stream->recv.state = update.state;
			stream->recv.finalsz = update.finalsz;
		}
		list_add_tail(&frame->list, head);
		stream->recv.frags++;
		inq->highest += highest;
		stream->recv.highest += highest;
		return 0;
	}

	/* In-order: directly handled and queued. */
	inq->highest += highest;
	stream->recv.highest += highest;
	quic_inq_stream_tail(sk, stream, frame);
	if (!stream->recv.frags)
		return 0;

	/* Check the buffered frames list and merge any frames contiguous with the current
	 * stream offset to maintain ordered data delivery.
	 */
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
		     !frame->stream_fin)) {
			/* Duplicate frame. Do not discard if it has FIN and no FIN seen yet. */
			quic_inq_rfree((int)frame->len, sk);
			quic_frame_put(frame);
			continue;
		}
		quic_inq_stream_tail(sk, stream, frame);
	}
	return 0;
}

/* Purge frames from an inq list: only those for a given stream, or all if stream is NULL. */
void quic_inq_list_purge(struct sock *sk, struct list_head *head, struct quic_stream *stream)
{
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		if (stream && frame->stream != stream)
			continue;
		list_del(&frame->list);
		bytes += frame->len;
		quic_frame_put(frame);
	}
	quic_inq_rfree(bytes, sk);
}

/* Handle in-order crypto (handshake) frame delivery.
 *
 * Similar to quic_inq_stream_tail(), but with special handling for New Session Ticket Message
 * in crypto frame (level == 0). Tickets are saved in quic_ticket() and exposed to userspace
 * via getsockopt().
 */
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

	overlap = crypto->recv_offset - frame->offset;
	if (overlap) {
		quic_inq_rfree((int)frame->len, sk);
		frame->data += overlap;
		frame->len -= overlap;
		quic_inq_set_owner_r((int)frame->len, sk);
		frame->offset += overlap;
	}
	crypto->recv_offset += frame->len;

	if (frame->level) {
		/* For handshake messages, insert frame before any data/event frames. */
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

	/* Special handling for New Session Ticket Message (level == 0). */
	if (!crypto->ticket_ready && crypto->recv_offset <= QUIC_TICKET_MAX_LEN) {
		/* Append received frame data to ticket buffer. */
		quic_data_append(ticket, frame->data, frame->len);
		/* Attempt to parse the TLS message if we have at least the 4-byte header. */
		if (ticket->len >= 4) {
			p = ticket->data;
			len = ticket->len;
			quic_get_int(&p, &len, &type, 1);
			quic_get_int(&p, &len, &length, 3);
			/* If the full TLS message is available, mark the ticket as ready. */
			if (ticket->len >= length + 4) {
				/* Notify userspace with the full ticket message. Applications
				 * can receive it via the NEW_SESSION_TICKET event or getsockopt().
				 */
				crypto->ticket_ready  = 1;
				quic_inq_event_recv(sk, QUIC_EVENT_NEW_SESSION_TICKET, ticket);
			}
		}
	}
	quic_inq_rfree((int)frame->len, sk);
	quic_frame_put(frame); /* Data copied to ticket buffer; release the frame. */
}

/* Process an incoming QUIC crypto (handshake) frame.
 *
 * This function behaves similarly to quic_inq_stream_recv(), but operates on different crypto
 * levels instead of streams. It handles:
 *
 * Returns: 0 on success, or -ENOBUFS if buffer limits are exceeded.
 */
int quic_inq_handshake_recv(struct sock *sk, struct quic_frame *frame)
{
	u64 offset = frame->offset, crypto_offset;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_crypto *crypto;
	u8 level = frame->level;
	struct list_head *head;
	struct quic_frame *pos;

	crypto = quic_crypto(sk, level);
	crypto_offset = crypto->recv_offset;
	pr_debug("%s: recv_offset: %llu, offset: %llu, level: %u, len: %u\n",
		 __func__, crypto_offset, offset, level, frame->len);

	if (crypto_offset >= offset + frame->len) {
		quic_frame_put(frame);
		return 0;
	}

	quic_inq_set_owner_r((int)frame->len, sk);
	if (sk_rmem_alloc_get(sk) > sk->sk_rcvbuf || !quic_sk_rmem_schedule(sk, frame->len)) {
		/* rfc9000#section-7.5:
		 *
		 * If an endpoint's buffer is exceeded during the handshake, it can expand its
		 * buffer temporarily to complete the handshake. If an endpoint does not expand
		 * its buffer, it MUST close the connection with a CRYPTO_BUFFER_EXCEEDED error
		 * code.
		 */
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
			if (pos->offset + pos->len >= offset + frame->len) {
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
		if (frame->offset > crypto->recv_offset)
			break;
		list_del(&frame->list);
		if (crypto->recv_offset >= frame->offset + frame->len) {
			quic_inq_rfree((int)frame->len, sk);
			quic_frame_put(frame);
			continue;
		}
		quic_inq_handshake_tail(sk, frame);
	}
	return 0;
}

/* Populate transport parameters from inqueue. */
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

/* Configure inqueue from transport parameters. */
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

/* Process an incoming QUIC event and handle it for delivery. */
int quic_inq_event_recv(struct sock *sk, u8 event, void *args)
{
	struct list_head *head = &quic_inq(sk)->recv_list;
	struct quic_frame *frame, *pos;
	u32 args_len = 0;
	u8 *p;

	if (!event || event >= QUIC_EVENT_MAX)
		return -EINVAL;

	if (!(quic_inq(sk)->events & BIT(event)))
		return 0;  /* Event type not subscribed by user. */

	switch (event) { /* Determine size of the argument payload based on event type. */
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
		args_len = sizeof(struct quic_connection_close);
		p = ((struct quic_connection_close *)args)->phrase;
		if (*p)
			args_len += strlen(p) + 1;
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
	frame->event = 1; /* Mark this frame as an event. */
	frame->offset = 0;

	/* Insert event frame ahead of stream or dgram data. */
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

/* Process an incoming QUIC datagram frame. */
int quic_inq_dgram_recv(struct sock *sk, struct quic_frame *frame)
{
	quic_inq_set_owner_r((int)frame->len, sk);
	if (sk_rmem_alloc_get(sk) > sk->sk_rcvbuf || !quic_sk_rmem_schedule(sk, frame->len)) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_RCVBUFDROP);
		quic_inq_rfree((int)frame->len, sk);
		return -ENOBUFS;
	}

	frame->dgram = 1; /* Mark the frame as a datagram and prepare for delivery. */
	frame->offset = 0;
	list_add_tail(&frame->list, &quic_inq(sk)->recv_list);
	sk->sk_data_ready(sk);
	return 0;
}

void quic_inq_data_read(struct sock *sk, u32 bytes)
{
	quic_inq_rfree((int)bytes, sk);
}

/* Workqueue handler to process decrypted QUIC packets. */
static void quic_inq_decrypted_work(struct work_struct *work)
{
	struct quic_sock *qs = container_of(work, struct quic_sock, inq.work);
	struct sock *sk = &qs->inet.sk;
	struct sk_buff_head *head;
	struct sk_buff *skb;

	lock_sock(sk);
	head = &sk->sk_receive_queue;
	if (quic_is_closed(sk)) { /* If the socket is already closed, drop all pending skbs. */
		skb_queue_purge(head);
		goto out;
	}

	skb = skb_dequeue(head);
	while (skb) {
		QUIC_SKB_CB(skb)->resume = 1; /* Mark skb decrypted already before processing. */
		quic_packet_process(sk, skb);
		skb = skb_dequeue(head);
	}
out:
	release_sock(sk);
	sock_put(sk); /* Drop the hold from quic_inq_decrypted_tail(). */
}

/* Queue an decrypted SKB and schedule processing.
 *
 * This function queues a fully decrypted skb for asynchronous processing and schedules
 * the workqueue to process it.
 */
void quic_inq_decrypted_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_inqueue *inq = quic_inq(sk);

	sock_hold(sk);
	/* Add skb to receive queue, and process it later in quic_inq_decrypted_work(). */
	skb_queue_tail(&sk->sk_receive_queue, skb);

	/* Schedule work to process queued decrypted packets.  If work was already pending,
	 * drop the extra hold.
	 */
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
	quic_inq_list_purge(sk, &inq->handshake_list, NULL);
	quic_inq_list_purge(sk, &inq->stream_list, NULL);
	quic_inq_list_purge(sk, &inq->early_list, NULL);
	quic_inq_list_purge(sk, &inq->recv_list, NULL);
}
