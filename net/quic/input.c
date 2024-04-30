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

static void quic_inq_rfree(struct sk_buff *skb)
{
	atomic_sub(skb->len, &skb->sk->sk_rmem_alloc);
	sk_mem_uncharge(skb->sk, skb->len);
}

void quic_inq_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	atomic_add(skb->len, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->len);
	skb->destructor = quic_inq_rfree;
}

int quic_rcv(struct sk_buff *skb)
{
	struct quic_rcv_cb *rcv_cb = QUIC_RCV_CB(skb);
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
			rcv_cb->number_offset = conn_id->len + sizeof(struct quichdr);
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
		rcv_cb->backlog = 1;
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

static void quic_inq_recv_tail(struct sock *sk, struct quic_stream *stream, struct sk_buff *skb)
{
	struct quic_rcv_cb *rcv_cb = QUIC_RCV_CB(skb);
	struct quic_stream_update update = {};
	u64 overlap;

	overlap = stream->recv.offset - rcv_cb->offset;
	if (overlap) {
		skb_orphan(skb);
		skb_pull(skb, overlap);
		quic_inq_set_owner_r(skb, sk);
		rcv_cb->offset += overlap;
	}

	if (rcv_cb->stream_fin) {
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECVD;
		update.errcode = rcv_cb->offset + skb->len;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);
		stream->recv.state = update.state;
	}
	stream->recv.offset += skb->len;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
}

void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, int len)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct sk_buff *nskb = NULL;
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
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
		if (nskb)
			quic_outq_ctrl_tail(sk, nskb, true);
	}

	if (stream->recv.max_bytes - stream->recv.bytes < stream->recv.window / 2) {
		window = stream->recv.window;
		if (sk_under_memory_pressure(sk))
			window >>= 1;
		stream->recv.max_bytes = stream->recv.bytes + window;
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream);
		if (nskb)
			quic_outq_ctrl_tail(sk, nskb, true);
	}

	if (nskb)
		quic_outq_transmit(sk);
}

int quic_inq_reasm_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_rcv_cb *rcv_cb = QUIC_RCV_CB(skb);
	u64 offset = rcv_cb->offset, off, highest = 0;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream_update update = {};
	u64 stream_id = rcv_cb->stream->id;
	struct quic_stream *stream;
	struct sk_buff_head *head;
	struct sk_buff *tmp;

	stream = rcv_cb->stream;
	if (stream->recv.offset >= offset + skb->len) { /* dup */
		kfree_skb(skb);
		return 0;
	}

	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf ||
	    !sk_rmem_schedule(sk, skb, skb->len))
		return -ENOBUFS;

	quic_inq_set_owner_r(skb, sk);
	off = offset + skb->len;
	if (off > stream->recv.highest) {
		highest = off - stream->recv.highest;
		if (inq->highest + highest > inq->max_bytes ||
		    stream->recv.highest + highest > stream->recv.max_bytes) {
			rcv_cb->errcode = QUIC_TRANSPORT_ERROR_FLOW_CONTROL;
			return -ENOBUFS;
		}
		if (stream->recv.finalsz && off > stream->recv.finalsz) {
			rcv_cb->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
			return -EINVAL;
		}
	}
	if (!stream->recv.highest && !rcv_cb->stream_fin) {
		update.id = stream->id;
		update.state = QUIC_STREAM_RECV_STATE_RECV;
		if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
			return -ENOMEM;
	}
	head = &inq->reassemble_list;
	if (stream->recv.offset < offset) {
		skb_queue_walk(head, tmp) {
			rcv_cb = QUIC_RCV_CB(tmp);
			if (rcv_cb->stream->id < stream_id)
				continue;
			if (rcv_cb->stream->id > stream_id)
				break;
			if (rcv_cb->offset > offset)
				break;
			if (rcv_cb->offset + tmp->len >= offset + skb->len) { /* dup */
				kfree_skb(skb);
				return 0;
			}
		}
		rcv_cb = QUIC_RCV_CB(skb);
		if (rcv_cb->stream_fin) {
			if (off < stream->recv.highest ||
			    (stream->recv.finalsz && stream->recv.finalsz != off)) {
				rcv_cb->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
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
		__skb_queue_before(head, tmp, skb);
		stream->recv.frags++;
		inq->highest += highest;
		stream->recv.highest += highest;
		return 0;
	}

	/* fast path: stream->recv.offset == offset */
	inq->highest += highest;
	stream->recv.highest += highest;
	quic_inq_recv_tail(sk, stream, skb);
	if (!stream->recv.frags)
		return 0;

	skb_queue_walk_safe(head, skb, tmp) {
		rcv_cb = QUIC_RCV_CB(skb);
		if (rcv_cb->stream->id < stream_id)
			continue;
		if (rcv_cb->stream->id > stream_id)
			break;
		if (rcv_cb->offset > stream->recv.offset)
			break;
		__skb_unlink(skb, head);
		stream->recv.frags--;
		if (rcv_cb->offset + skb->len <= stream->recv.offset) { /* dup */
			kfree_skb(skb);
			continue;
		}
		quic_inq_recv_tail(sk, stream, skb);
	}
	return 0;
}

void quic_inq_stream_purge(struct sock *sk, struct quic_stream *stream)
{
	struct sk_buff_head *head = &quic_inq(sk)->reassemble_list;
	struct sk_buff *skb, *tmp;

	skb_queue_walk_safe(head, skb, tmp) {
		if (QUIC_RCV_CB(skb)->stream != stream)
			continue;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}
}

int quic_inq_handshake_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_rcv_cb *rcv_cb = QUIC_RCV_CB(skb);
	u64 offset = rcv_cb->offset, crypto_offset;
	struct quic_crypto *crypto;
	struct sk_buff_head *head;
	u8 level = rcv_cb->level;
	struct sk_buff *tmp;

	crypto = quic_crypto(sk, level);
	crypto_offset = quic_crypto_recv_offset(crypto);
	pr_debug("[QUIC] %s recv_offset: %llu offset: %llu level: %u len: %u\n",
		 __func__, crypto_offset, offset, level, skb->len);
	if (offset < crypto_offset) { /* dup */
		kfree_skb(skb);
		return 0;
	}
	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf) {
		rcv_cb->errcode = QUIC_TRANSPORT_ERROR_CRYPTO_BUF_EXCEEDED;
		return -ENOBUFS;
	}
	quic_inq_set_owner_r(skb, sk);
	head = &quic_inq(sk)->handshake_list;
	if (offset > crypto_offset) {
		skb_queue_walk(head, tmp) {
			rcv_cb = QUIC_RCV_CB(tmp);
			if (rcv_cb->level < level)
				continue;
			if (rcv_cb->level > level)
				break;
			if (rcv_cb->offset > offset)
				break;
			if (rcv_cb->offset == offset) { /* dup */
				kfree_skb(skb);
				return 0;
			}
		}
		__skb_queue_before(head, tmp, skb);
		return 0;
	}

	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
	quic_crypto_inc_recv_offset(crypto, skb->len);

	skb_queue_walk_safe(head, skb, tmp) {
		rcv_cb = QUIC_RCV_CB(skb);
		if (rcv_cb->level < level)
			continue;
		if (rcv_cb->level > level)
			break;
		if (rcv_cb->offset > quic_crypto_recv_offset(crypto))
			break;
		__skb_unlink(skb, head);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		sk->sk_data_ready(sk);
		quic_crypto_inc_recv_offset(crypto, skb->len);
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
	struct quic_stream *stream = NULL;
	struct quic_rcv_cb *rcv_cb;
	struct sk_buff *skb, *last;
	int args_len = 0;

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

	skb = alloc_skb(1 + args_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_put_data(skb, &event, 1);
	skb_put_data(skb, args, args_len);

	rcv_cb = QUIC_RCV_CB(skb);
	rcv_cb->event = event;
	rcv_cb->stream = stream;

	/* always put event ahead of data */
	last = quic_inq(sk)->last_event ?: (struct sk_buff *)&sk->sk_receive_queue;
	__skb_queue_after(&sk->sk_receive_queue, last, skb);
	quic_inq(sk)->last_event = skb;
	sk->sk_data_ready(sk);
	return 0;
}

int quic_inq_dgram_tail(struct sock *sk, struct sk_buff *skb)
{
	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf ||
	    !sk_rmem_schedule(sk, skb, skb->len))
		return -ENOBUFS;

	quic_inq_set_owner_r(skb, sk);
	QUIC_RCV_CB(skb)->dgram = 1;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
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
	head = &quic_inq(sk)->decrypted_list;
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
	skb_queue_tail(&inq->decrypted_list, skb);

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

	skb_queue_head_init(&inq->reassemble_list);
	skb_queue_head_init(&inq->decrypted_list);
	skb_queue_head_init(&inq->handshake_list);
	skb_queue_head_init(&inq->backlog_list);
	INIT_WORK(&inq->work, quic_inq_decrypted_work);
}

void quic_inq_free(struct sock *sk)
{
	struct quic_inqueue *inq = quic_inq(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&inq->reassemble_list);
	__skb_queue_purge(&inq->handshake_list);
	__skb_queue_purge(&inq->backlog_list);
}
