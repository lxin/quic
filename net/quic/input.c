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

static void quic_recv_handshake_user(struct sock *sk, struct sk_buff *skb)
{
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	sk->sk_data_ready(sk);
}

int quic_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (quic_handshake_user(sk)) {
		quic_recv_handshake_user(sk, skb);
		return 0;
	}

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
	struct quic_sock *qs = NULL;
	union quic_addr daddr;
	int err = -EINVAL;
	u8 *dcid = NULL;
	struct sock *sk;

	skb_pull(skb, skb_transport_offset(skb));
	af_ops = quic_af_ops_get(ip_hdr(skb)->version == 4 ? AF_INET : AF_INET6);

	if (!quic_hdr(skb)->form) {
		dcid = (uint8_t *)quic_hdr(skb) + 1;
		s_conn_id = quic_source_connection_id_lookup(dev_net(skb->dev), dcid);
		if (s_conn_id)
			qs = quic_sk(s_conn_id->sk);
	}
	if (!qs) {
		af_ops->get_msg_addr(&daddr, skb, 0);
		qs = quic_sock_lookup_byaddr(skb, &daddr);
		if (!qs)
			goto err;
	}
	sk = &qs->inet.sk;
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			bh_unlock_sock(sk);
			goto err;
		}
	} else {
		quic_do_rcv(sk, skb);
	}
	bh_unlock_sock(sk);
	return 0;

err:
	kfree_skb(skb);
	return err;
}

static void quic_inq_rfree(struct sk_buff *skb)
{
	atomic_sub(skb->len, &skb->sk->sk_rmem_alloc);
}

static void quic_inq_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	atomic_add(skb->len, &sk->sk_rmem_alloc);
	skb->destructor = quic_inq_rfree;
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
	struct quic_packet *packet = &quic_sk(sk)->packet;
	struct sk_buff *nskb = NULL;

	stream->recv.bytes += skb->len;
	packet->recv.bytes += skb->len;

	/* recv flow control */
	if (packet->recv.max_bytes - packet->recv.bytes < packet->recv.window / 2) {
		packet->recv.max_bytes = packet->recv.bytes + packet->recv.window;
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, packet, 0);
		if (nskb)
			quic_outq_ctrl_tail(sk, nskb, true);
	}

	if (stream->recv.max_bytes - stream->recv.bytes < stream->recv.window / 2) {
		stream->recv.max_bytes = stream->recv.bytes + stream->recv.window;
		nskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream, 0);
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
	struct sk_buff_head *head = &quic_sk(sk)->inq.reassemble_list;
	u32 stream_offset = QUIC_RCV_CB(skb)->stream_offset, offset;
	u32 stream_id = QUIC_RCV_CB(skb)->stream_id, highest = 0;
	struct quic_packet *packet = &quic_sk(sk)->packet;
	struct quic_stream *stream;
	struct sk_buff *tmp;

	stream = quic_stream_recv_get(&quic_sk(sk)->streams, stream_id, quic_is_serv(sk));
	if (!stream || stream->recv.offset > stream_offset)
		return -EINVAL;

	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf)
		return -ENOBUFS;

	offset = stream_offset + skb->len;
	if (offset > stream->recv.highest) {
		highest = offset - stream->recv.highest;
		if (packet->recv.highest + highest > packet->recv.max_bytes ||
		    stream->recv.highest + highest > stream->recv.max_bytes)
			return -ENOBUFS;
	}

	if (stream->recv.offset < stream_offset) {
		skb_queue_walk(head, tmp) {
			if (QUIC_RCV_CB(tmp)->stream_id < stream_id)
				continue;
			if (QUIC_RCV_CB(tmp)->stream_id > stream_id)
				break;
			if (QUIC_RCV_CB(tmp)->stream_offset > stream_offset)
				break;
			if (QUIC_RCV_CB(tmp)->stream_offset == stream_offset)
				return -EINVAL; /* dup */
		}
		__skb_queue_before(head, tmp, skb);
		stream->recv.frags++;
		if (QUIC_RCV_CB(skb)->stream_fin)
			stream->recv.state = QUIC_STREAM_RECV_STATE_SIZE_KNOWN;
		packet->recv.highest += highest;
		stream->recv.highest += highest;
		return 0;
	}

	/* fast path: stream->recv.offset == stream_offset */
	packet->recv.highest += highest;
	stream->recv.highest += highest;
	quic_inq_recv_tail(sk, stream, skb);
	if (!stream->recv.frags)
		return 0;

	skb_queue_walk_safe(head, skb, tmp) {
		if (QUIC_RCV_CB(skb)->stream_id < stream_id)
			continue;
		if (QUIC_RCV_CB(skb)->stream_id > stream_id)
			break;
		if (QUIC_RCV_CB(skb)->stream_offset > stream_offset)
			break;
		__skb_unlink(skb, head);
		stream->recv.frags--;
		quic_inq_recv_tail(sk, stream, skb);
	}
	return 0;
}
