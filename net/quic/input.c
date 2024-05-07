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

void quic_inq_rfree(struct quic_frame *frame, struct sock *sk)
{
	int len = frame->bytes;

	if (len) {
		atomic_sub(len, &sk->sk_rmem_alloc);
		sk_mem_uncharge(sk, len);
	}

	if (frame->skb) {
		kfree_skb(frame->skb);
		frame->data = NULL;
	}
	quic_frame_free(frame);
}

void quic_inq_set_owner_r(struct quic_frame *frame, struct sock *sk)
{
	if (frame->bytes) {
		atomic_sub(frame->bytes, &sk->sk_rmem_alloc);
		sk_mem_uncharge(sk, frame->bytes);
	}
	frame->bytes = frame->len;
	atomic_add(frame->len, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, frame->len);
}

int quic_rcv(struct sk_buff *skb)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_addr_family_ops *af_ops;
	struct quic_connection_id *conn_id;
	union quic_addr daddr, saddr;
	struct sock *sk = NULL;
	int err = -EINVAL;
	u8 *dcid;

	skb_pull(skb, skb_transport_offset(skb));
	af_ops = quic_af_ops_get_skb(skb);

	if (skb->len < sizeof(struct quichdr))
		goto err;

	if (!quic_hdr(skb)->form) { /* search scid hashtable for post-handshake packets */
		dcid = (u8 *)quic_hdr(skb) + 1;
		conn_id = quic_connection_id_lookup(dev_net(skb->dev), dcid, skb->len - 1);
		if (conn_id) {
			cb->number_offset = conn_id->len + sizeof(struct quichdr);
			sk = quic_connection_id_sk(conn_id);
		}
	}
	if (!sk) {
		af_ops->get_msg_addr(&daddr, skb, 0);
		af_ops->get_msg_addr(&saddr, skb, 1);
		sk = quic_sock_lookup(skb, &daddr, &saddr);
		if (!sk)
			goto err;
	}
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		cb->backlog = 1;
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			bh_unlock_sock(sk);
			goto err;
		}
	} else {
		sk->sk_backlog_rcv(sk, skb); /* quic_packet_process */
	}
	bh_unlock_sock(sk);
	return 0;

err:
	kfree_skb(skb);
	return err;
}

void quic_rcv_err_icmp(struct sock *sk)
{
	u8 taglen = quic_packet_taglen(quic_packet(sk));
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_path_addr *s = quic_src(sk);
	struct quic_path_addr *d = quic_dst(sk);
	u32 pathmtu, info;
	bool reset_timer;

	info = min_t(u32, quic_path_mtu_info(d), QUIC_PATH_MAX_PMTU);
	if (!inq->probe_timeout || quic_path_sent_cnt(s) || quic_path_sent_cnt(d)) {
		quic_packet_mss_update(sk, info - quic_encap_len(sk));
		return;
	}
	info = info - quic_encap_len(sk) - taglen;
	pathmtu = quic_path_pl_toobig(d, info, &reset_timer);
	if (reset_timer)
		quic_timer_reset(sk, QUIC_TIMER_PATH, inq->probe_timeout);
	if (pathmtu)
		quic_packet_mss_update(sk, pathmtu + taglen);
}

int quic_rcv_err(struct sk_buff *skb)
{
	struct quic_addr_family_ops *af_ops;
	union quic_addr daddr, saddr;
	struct quic_path_addr *path;
	struct sock *sk = NULL;
	int ret = 0;
	u32 info;

	af_ops = quic_af_ops_get_skb(skb);

	af_ops->get_msg_addr(&saddr, skb, 0);
	af_ops->get_msg_addr(&daddr, skb, 1);
	sk = quic_sock_lookup(skb, &daddr, &saddr);
	if (!sk)
		return -ENOENT;

	bh_lock_sock(sk);
	if (quic_is_listen(sk))
		goto out;

	if (quic_get_mtu_info(sk, skb, &info))
		goto out;

	ret = 1; /* processed with common mtud */
	path = quic_dst(sk);
	quic_path_set_mtu_info(path, info);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}
	quic_rcv_err_icmp(sk);
out:
	bh_unlock_sock(sk);
	return ret;
}

static void quic_inq_recv_tail(struct sock *sk, struct quic_stream *stream,
			       struct quic_frame *frame)
{
	struct quic_stream_update update = {};
	u64 overlap;

	overlap = stream->recv.offset - frame->offset;
	if (overlap) {
		frame->data += overlap;
		frame->len -= overlap;
		quic_inq_set_owner_r(frame, sk);
		frame->offset += overlap;
	}

	if (frame->stream_fin) {
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECVD;
		update.errcode = frame->offset + frame->len;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);
		stream->recv.state = update.state;
	}
	stream->recv.offset += frame->len;
	frame->offset = 0;
	list_add_tail(&frame->list, &quic_inq(sk)->stream_list);
	sk->sk_data_ready(sk);
}

void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, int len)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_frame *frame = NULL;
	u32 window;

	if (!len)
		return;

	stream->recv.bytes += len;
	inq->bytes += len;

	/* recv flow control */
	if (inq->max_bytes - inq->bytes < inq->window / 2) {
		window = inq->window;
		if (sk_under_memory_pressure(sk))
			window >>= 1;
		inq->max_bytes = inq->bytes + window;
		frame = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
		if (frame)
			quic_outq_ctrl_tail(sk, frame, true);
	}

	if (stream->recv.max_bytes - stream->recv.bytes < stream->recv.window / 2) {
		window = stream->recv.window;
		if (sk_under_memory_pressure(sk))
			window >>= 1;
		stream->recv.max_bytes = stream->recv.bytes + window;
		frame = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream);
		if (frame)
			quic_outq_ctrl_tail(sk, frame, true);
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

int quic_inq_reasm_tail(struct sock *sk, struct quic_frame *frame)
{
	u64 offset = frame->offset, off, highest = 0;
	struct quic_stream *stream = frame->stream;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream_update update = {};
	u64 stream_id = stream->id;
	struct list_head *head;
	struct quic_frame *pos;

	if (stream->recv.offset >= offset + frame->len) { /* dup */
		quic_inq_rfree(frame, sk);
		return 0;
	}

	if (atomic_read(&sk->sk_rmem_alloc) + frame->len > sk->sk_rcvbuf ||
	    !quic_sk_rmem_schedule(sk, frame->len))
		return -ENOBUFS;

	quic_inq_set_owner_r(frame, sk);
	off = offset + frame->len;
	if (off > stream->recv.highest) {
		highest = off - stream->recv.highest;
		if (inq->highest + highest > inq->max_bytes ||
		    stream->recv.highest + highest > stream->recv.max_bytes) {
			frame->errcode = QUIC_TRANSPORT_ERROR_FLOW_CONTROL;
			return -ENOBUFS;
		}
		if (stream->recv.finalsz && off > stream->recv.finalsz) {
			frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
			return -EINVAL;
		}
	}
	if (!stream->recv.highest && !frame->stream_fin) {
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECV;
		if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
			return -ENOMEM;
	}
	head = &inq->reassemble_list;
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
			if (pos->offset + pos->len >= offset + frame->len) { /* dup */
				quic_inq_rfree(frame, sk);
				return 0;
			}
		}
		if (frame->stream_fin) {
			if (off < stream->recv.highest ||
			    (stream->recv.finalsz && stream->recv.finalsz != off)) {
				frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
				return -EINVAL;
			}
			update.id = stream->id;
			update.state = QUIC_STREAM_RECV_STATE_SIZE_KNOWN;
			update.finalsz = off;
			if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
				return -ENOMEM;
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
	quic_inq_recv_tail(sk, stream, frame);
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
		if (frame->offset + frame->len <= stream->recv.offset) { /* dup */
			quic_inq_rfree(frame, sk);
			continue;
		}
		quic_inq_recv_tail(sk, stream, frame);
	}
	return 0;
}

void quic_inq_stream_purge(struct sock *sk, struct quic_stream *stream)
{
	struct list_head *head = &quic_inq(sk)->reassemble_list;
	struct quic_frame *frame, *next;

	list_for_each_entry_safe(frame, next, head, list) {
		if (frame->stream != stream)
			continue;
		list_del(&frame->list);
		quic_inq_rfree(frame, sk);
	}
}

static void quic_inq_list_purge(struct sock *sk, struct list_head *head)
{
	struct quic_frame *frame, *next;

	list_for_each_entry_safe(frame, next, head, list) {
		list_del(&frame->list);
		quic_inq_rfree(frame, sk);
	}
}

int quic_inq_handshake_tail(struct sock *sk, struct quic_frame *frame)
{
	u64 offset = frame->offset, crypto_offset;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_crypto *crypto;
	u8 level = frame->level;
	struct list_head *head;
	struct quic_frame *pos;

	crypto = quic_crypto(sk, level);
	crypto_offset = quic_crypto_recv_offset(crypto);
	pr_debug("[QUIC] %s recv_offset: %llu offset: %llu level: %u len: %u\n",
		 __func__, crypto_offset, offset, level, frame->len);
	if (offset < crypto_offset) { /* dup */
		quic_inq_rfree(frame, sk);
		return 0;
	}
	if (atomic_read(&sk->sk_rmem_alloc) + frame->len > sk->sk_rcvbuf) {
		frame->errcode = QUIC_TRANSPORT_ERROR_CRYPTO_BUF_EXCEEDED;
		return -ENOBUFS;
	}
	quic_inq_set_owner_r(frame, sk);
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
			if (pos->offset == offset) { /* dup */
				quic_inq_rfree(frame, sk);
				return 0;
			}
		}
		list_add_tail(&frame->list, head);
		return 0;
	}

	frame->offset = 0;
	list_add_tail(&frame->list, &inq->stream_list);
	sk->sk_data_ready(sk);
	quic_crypto_inc_recv_offset(crypto, frame->len);

	list_for_each_entry_safe(frame, pos, head, list) {
		if (frame->level < level)
			continue;
		if (frame->level > level)
			break;
		if (frame->offset > quic_crypto_recv_offset(crypto))
			break;
		frame->offset = 0;
		list_move_tail(&frame->list, &inq->stream_list);
		sk->sk_data_ready(sk);
		quic_crypto_inc_recv_offset(crypto, frame->len);
	}
	return 0;
}

void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_inqueue *inq = quic_inq(sk);

	inq->max_datagram_frame_size = p->max_datagram_frame_size;
	inq->max_udp_payload_size = p->max_udp_payload_size;
	inq->max_ack_delay = p->max_ack_delay;
	inq->ack_delay_exponent = p->ack_delay_exponent;
	inq->max_idle_timeout = p->max_idle_timeout;
	inq->grease_quic_bit = p->grease_quic_bit;
	inq->window = p->max_data;

	inq->max_bytes = p->max_data;
	sk->sk_rcvbuf = p->max_data * 2;

	inq->probe_timeout = p->plpmtud_probe_timeout;
	inq->version = p->version;
	inq->validate_peer_address = p->validate_peer_address;
	inq->receive_session_ticket = p->receive_session_ticket;
	inq->disable_1rtt_encryption = p->disable_1rtt_encryption;
}

int quic_inq_event_recv(struct sock *sk, u8 event, void *args)
{
	struct list_head *head = &quic_inq(sk)->stream_list;
	struct quic_stream *stream = NULL;
	struct quic_frame *frame;
	int args_len = 0;
	u8 *p;

	if (!event || event > QUIC_EVENT_MAX)
		return -EINVAL;

	if (!(quic_inq(sk)->events & (1 << event)))
		return 0;

	switch (event) {
	case QUIC_EVENT_STREAM_UPDATE:
		stream = quic_stream_find(quic_streams(sk),
					  ((struct quic_stream_update *)args)->id);
		if (!stream)
			return -EINVAL;
		args_len = sizeof(struct quic_stream_update);
		break;
	case QUIC_EVENT_STREAM_MAX_STREAM:
		args_len = sizeof(u64);
		break;
	case QUIC_EVENT_NEW_TOKEN:
		args_len = ((struct quic_data *)args)->len;
		args = ((struct quic_data *)args)->data;
		break;
	case QUIC_EVENT_CONNECTION_CLOSE:
		args_len = strlen(((struct quic_connection_close *)args)->phrase) +
			   1 + sizeof(struct quic_connection_close);
		break;
	case QUIC_EVENT_KEY_UPDATE:
		args_len = sizeof(u8);
		break;
	case QUIC_EVENT_CONNECTION_MIGRATION:
		args_len = sizeof(u8);
		break;
	default:
		return -EINVAL;
	}

	frame = quic_frame_alloc(1 + args_len, NULL, GFP_ATOMIC);
	if (!frame)
		return -ENOMEM;
	p = quic_put_data(frame->data, &event, 1);
	p = quic_put_data(p, args, args_len);

	frame->event = event;
	frame->stream = stream;

	/* always put event ahead of data */
	if (quic_inq(sk)->last_event)
		head = &quic_inq(sk)->last_event->list;
	list_add(&frame->list, head);
	quic_inq(sk)->last_event = frame;
	sk->sk_data_ready(sk);
	return 0;
}

int quic_inq_dgram_tail(struct sock *sk, struct quic_frame *frame)
{
	if (atomic_read(&sk->sk_rmem_alloc) + frame->len > sk->sk_rcvbuf ||
	    !quic_sk_rmem_schedule(sk, frame->len))
		return -ENOBUFS;

	quic_inq_set_owner_r(frame, sk);
	frame->dgram = 1;
	list_add_tail(&frame->list, &quic_inq(sk)->stream_list);
	sk->sk_data_ready(sk);
	return 0;
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
		skb->decrypted = 1;
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
	INIT_LIST_HEAD(&inq->reassemble_list);
	INIT_LIST_HEAD(&inq->handshake_list);
	INIT_LIST_HEAD(&inq->stream_list);
	INIT_WORK(&inq->work, quic_inq_decrypted_work);
}

void quic_inq_free(struct sock *sk)
{
	struct quic_inqueue *inq = quic_inq(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&inq->backlog_list);
	quic_inq_list_purge(sk, &inq->reassemble_list);
	quic_inq_list_purge(sk, &inq->handshake_list);
	quic_inq_list_purge(sk, &inq->stream_list);
}
