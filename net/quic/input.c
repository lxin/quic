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
}

void quic_inq_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	atomic_add(skb->len, &sk->sk_rmem_alloc);
	skb->destructor = quic_inq_rfree;
}

static int quic_new_sock_do_rcv(struct sock *sk, struct sk_buff *skb,
				union quic_addr *da, union quic_addr *sa)
{
	struct sock *nsk;
	int ret = 0;

	local_bh_disable();
	nsk = quic_sock_lookup(skb, da, sa);
	if (nsk == sk)
		goto out;
	/* the request sock was just accepted */
	bh_lock_sock(nsk);
	if (sock_owned_by_user(nsk)) {
		if (sk_add_backlog(nsk, skb, READ_ONCE(nsk->sk_rcvbuf)))
			kfree_skb(skb);
	} else {
		sk->sk_backlog_rcv(nsk, skb);
	}
	bh_unlock_sock(nsk);
	ret = 1;
out:
	local_bh_enable();
	return ret;
}

int quic_handshake_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	union quic_addr da, sa;

	if (!quic_is_listen(sk))
		goto out;

	quic_af_ops(sk)->get_msg_addr(&da, skb, 0);
	quic_af_ops(sk)->get_msg_addr(&sa, skb, 1);
	if (quic_request_sock_exists(sk, &da, &sa))
		goto out;

	if (QUIC_RCV_CB(skb)->backlog &&
	    quic_new_sock_do_rcv(sk, skb, &da, &sa))
		return 0;

	if (quic_request_sock_enqueue(sk, &da, &sa)) {
		kfree_skb(skb);
		return -ENOMEM;
	}
out:
	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	quic_inq_set_owner_r(skb, sk);
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
	return 0;
}

int quic_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (!quic_is_connected(sk)) {
		kfree_skb(skb);
		return 0;
	}

	return quic_packet_process(sk, skb);
}

int quic_rcv(struct sk_buff *skb)
{
	struct quic_source_connection_id *s_conn_id;
	struct quic_addr_family_ops *af_ops;
	union quic_addr daddr, saddr;
	struct sock *sk = NULL;
	int err = -EINVAL;
	u8 *dcid;

	skb_pull(skb, skb_transport_offset(skb));
	af_ops = quic_af_ops_get(ip_hdr(skb)->version == 4 ? AF_INET : AF_INET6);

	if (!quic_hdr(skb)->form) {
		dcid = (uint8_t *)quic_hdr(skb) + 1;
		s_conn_id = quic_source_connection_id_lookup(dev_net(skb->dev), dcid);
		if (s_conn_id)
			sk = s_conn_id->sk;
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
		QUIC_RCV_CB(skb)->backlog = 1;
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			bh_unlock_sock(sk);
			goto err;
		}
	} else {
		sk->sk_backlog_rcv(sk, skb);
	}
	bh_unlock_sock(sk);
	return 0;

err:
	kfree_skb(skb);
	return err;
}

static void quic_inq_recv_tail(struct sock *sk, struct quic_stream *stream, struct sk_buff *skb)
{
	if (QUIC_RCV_CB(skb)->stream_fin)
		stream->recv.state = QUIC_STREAM_RECV_STATE_RECVD;
	stream->recv.offset += skb->len;
	quic_inq_set_owner_r(skb, sk);
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
}

int quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, struct sk_buff *skb)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct sk_buff *nskb = NULL;

	stream->recv.bytes += skb->len;
	inq->bytes += skb->len;

	/* recv flow control */
	if (inq->max_bytes - inq->bytes < inq->window / 2) {
		inq->max_bytes = inq->bytes + inq->window;
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
		if (nskb)
			quic_outq_ctrl_tail(sk, nskb, true);
	}

	if (stream->recv.max_bytes - stream->recv.bytes < stream->recv.window / 2) {
		stream->recv.max_bytes = stream->recv.bytes + stream->recv.window;
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream);
		if (nskb)
			quic_outq_ctrl_tail(sk, nskb, true);
	}

	if (!nskb)
		return 0;

	quic_outq_flush(sk);
	return 1;
}

int quic_inq_reasm_tail(struct sock *sk, struct sk_buff *skb)
{
	u64 stream_offset = QUIC_RCV_CB(skb)->stream_offset, offset;
	u32 stream_id = QUIC_RCV_CB(skb)->stream_id, highest = 0;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream *stream;
	struct sk_buff_head *head;
	struct sk_buff *tmp;

	stream = quic_stream_recv_get(quic_streams(sk), stream_id, quic_is_serv(sk));
	if (!stream || stream->recv.offset > stream_offset) {
		kfree_skb(skb);
		return 0;
	}

	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf)
		return -ENOBUFS;

	offset = stream_offset + skb->len;
	if (offset > stream->recv.highest) {
		highest = offset - stream->recv.highest;
		if (inq->highest + highest > inq->max_bytes ||
		    stream->recv.highest + highest > stream->recv.max_bytes)
			return -ENOBUFS;
	}

	head = &inq->reassemble_list;
	if (stream->recv.offset < stream_offset) {
		skb_queue_walk(head, tmp) {
			if (QUIC_RCV_CB(tmp)->stream_id < stream_id)
				continue;
			if (QUIC_RCV_CB(tmp)->stream_id > stream_id)
				break;
			if (QUIC_RCV_CB(tmp)->stream_offset > stream_offset)
				break;
			if (QUIC_RCV_CB(tmp)->stream_offset == stream_offset) { /* dup */
				kfree_skb(skb);
				return 0;
			}
		}
		__skb_queue_before(head, tmp, skb);
		stream->recv.frags++;
		if (QUIC_RCV_CB(skb)->stream_fin)
			stream->recv.state = QUIC_STREAM_RECV_STATE_SIZE_KNOWN;
		inq->highest += highest;
		stream->recv.highest += highest;
		return 0;
	}

	/* fast path: stream->recv.offset == stream_offset */
	inq->highest += highest;
	stream->recv.highest += highest;
	quic_inq_recv_tail(sk, stream, skb);
	if (!stream->recv.frags)
		return 0;

	skb_queue_walk_safe(head, skb, tmp) {
		if (QUIC_RCV_CB(skb)->stream_id < stream_id)
			continue;
		if (QUIC_RCV_CB(skb)->stream_id > stream_id)
			break;
		if (QUIC_RCV_CB(skb)->stream_offset > stream->recv.offset)
			break;
		__skb_unlink(skb, head);
		stream->recv.frags--;
		quic_inq_recv_tail(sk, stream, skb);
	}
	return 0;
}

void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_inqueue *inq = quic_inq(sk);

	inq->max_udp_payload_size = p->max_udp_payload_size;
	inq->max_ack_delay = p->max_ack_delay;
	inq->ack_delay_exponent = p->ack_delay_exponent;
	inq->window = p->initial_max_data;
	inq->max_bytes = p->initial_max_data;
	sk->sk_rcvbuf = 2 * p->initial_max_data;
}

void quic_inq_get_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_inqueue *inq = quic_inq(sk);

	p->initial_max_data = inq->window;
	p->max_ack_delay = inq->max_ack_delay;
	p->ack_delay_exponent = inq->ack_delay_exponent;
}
