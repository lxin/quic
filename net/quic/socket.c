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
#include <net/inet_common.h>
#include <linux/version.h>

bool quic_request_sock_exists(struct sock *sk, union quic_addr *sa, union quic_addr *da)
{
	struct quic_request_sock *req;

	list_for_each_entry(req, quic_reqs(sk), list) {
		if (!memcmp(&req->src, sa, quic_addr_len(sk)) &&
		    !memcmp(&req->dst, da, quic_addr_len(sk)))
			return true;
	}
	return false;
}

int quic_request_sock_enqueue(struct sock *sk, union quic_addr *sa, union quic_addr *da)
{
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk))
		return -ENOMEM;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	memcpy(&req->src, sa, quic_addr_len(sk));
	memcpy(&req->dst, da, quic_addr_len(sk));
	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return 0;
}

struct quic_request_sock *quic_request_sock_dequeue(struct sock *sk)
{
	struct quic_request_sock *req;

	req = list_first_entry(quic_reqs(sk), struct quic_request_sock, list);

	list_del_init(&req->list);
	sk_acceptq_removed(sk);
	return req;
}

struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da)
{
	struct net *net = dev_net(skb->dev);
	struct sock *sk, *nsk = NULL;
	struct quic_hash_head *head;
	union quic_addr a = {};

	head = quic_listen_sock_head(net, sa);
	spin_lock(&head->lock);
	sk_for_each(sk,  &head->head) {
		if (net != sock_net(sk))
			continue;
		if (memcmp(quic_path_addr(quic_src(sk)), sa, quic_addr_len(sk)))
			continue;
		if (quic_is_listen(sk)) {
			nsk = sk;
			continue;
		}
		if (!memcmp(quic_path_addr(quic_dst(sk)), da, quic_addr_len(sk))) {
			nsk = sk;
			break;
		}
	}
	spin_unlock(&head->lock);
	if (nsk)
		return nsk;

	/* Search for socket binding to the same port with 0.0.0.0 or :: address */
	a.v4.sin_family = sa->v4.sin_family;
	a.v4.sin_port = sa->v4.sin_port;
	sa = &a;
	head = quic_listen_sock_head(net, sa);
	spin_lock(&head->lock);
	sk_for_each(sk,  &head->head) {
		if (net != sock_net(sk))
			continue;
		if (memcmp(quic_path_addr(quic_src(sk)), sa, quic_addr_len(sk)))
			continue;
		if (quic_is_listen(sk)) {
			nsk = sk;
			break;
		}
	}
	spin_unlock(&head->lock);
	return nsk;
}

static void quic_write_space(struct sock *sk)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND);
	rcu_read_unlock();
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);
	u8 len;

	qs->af_ops = quic_af_ops_get(sk->sk_family);
	quic_connection_id_set_init(&qs->source, 1);
	quic_connection_id_set_init(&qs->dest, 0);

	len = quic_addr_len(sk);
	quic_path_addr_init(&qs->src, len);
	quic_path_addr_init(&qs->dst, len);

	quic_outq_init(&qs->outq);
	quic_inq_init(&qs->inq);
	quic_packet_init(&qs->packet);

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	quic_pnmap_init(&qs->pn_map);
	quic_streams_init(&qs->streams);
	quic_timers_init(sk);
	INIT_LIST_HEAD(&qs->reqs);

	local_bh_disable();
	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);

	quic_timers_free(sk);

	quic_streams_free(&qs->streams);
	quic_pnmap_free(&qs->pn_map);
	quic_crypto_destroy(&qs->crypto);

	kfree(qs->token.data);
	kfree(qs->ticket.data);
	kfree(qs->alpn.data);

	local_bh_disable();
	quic_put_port(sock_net(sk), &qs->port);
	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	return -EOPNOTSUPP;
}

static int quic_handshake_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *a;
	__u32 err = 0;

	lock_sock(sk);

	a = quic_path_addr(&qs->src);
	if (a->v4.sin_port || addr_len < quic_addr_len(sk) ||
	    addr->sa_family != sk->sk_family || !quic_addr(addr)->v4.sin_port) {
		err = -EINVAL;
		goto out;
	}

	memcpy(a, addr, quic_addr_len(sk));
	err = quic_get_port(sock_net(sk), &qs->port, a);
	if (err)
		goto out;
	err = quic_udp_sock_set(sk, qs->udp_sk, &qs->src);
	if (err)
		goto out;
	quic_set_sk_addr(sk, a, true);

out:
	release_sock(sk);
	return err;
}

static int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	return -EOPNOTSUPP;
}

static int quic_handshake_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qs = quic_sk(sk);
	__u32 err = -EINVAL;
	union quic_addr *a;

	lock_sock(sk);
	if (quic_state(sk) != QUIC_STATE_USER_CLOSED ||
	    addr_len < quic_addr_len(sk))
		goto out;

	quic_path_addr_set(&qs->dst, quic_addr(addr));
	a = quic_path_addr(&qs->src);
	err = quic_flow_route(sk, a);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, quic_addr(addr), false);
	if (!a->v4.sin_port) { /* auto bind */
		err = quic_get_port(sock_net(sk), &qs->port, a);
		if (err)
			goto out;
		err = quic_udp_sock_set(sk, qs->udp_sk, &qs->src);
		if (err)
			goto out;
		quic_set_sk_addr(sk, a, true);
	}

	if (sk_hashed(sk)) {
		err = 0;
		goto out;
	}

	quic_set_state(sk, QUIC_STATE_USER_CONNECTING);
	inet_sk_set_state(sk, TCP_SYN_RECV);
	err = sk->sk_prot->hash(sk);
out:
	release_sock(sk);
	return err;
}

static int quic_hash(struct sock *sk)
{
	union quic_addr *saddr, *daddr;
	struct quic_hash_head *head;
	struct sock *nsk;
	int err = 0;

	saddr = quic_path_addr(quic_src(sk));
	daddr = quic_path_addr(quic_dst(sk));
	head = quic_listen_sock_head(sock_net(sk), saddr);
	spin_lock(&head->lock);

	sk_for_each(nsk,  &head->head) {
		if (sock_net(sk) == sock_net(nsk) &&
		    !memcmp(saddr, quic_path_addr(quic_src(nsk)), quic_addr_len(sk)) &&
		    !memcmp(daddr, quic_path_addr(quic_dst(nsk)), quic_addr_len(sk))) {
			err = -EADDRINUSE;
			goto out;
		}
	}

	__sk_add_node(sk, &head->head);
out:
	spin_unlock(&head->lock);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_hash_head *head;
	union quic_addr *addr;

	if (sk_unhashed(sk))
		return;

	addr = quic_path_addr(quic_src(sk));
	head = quic_listen_sock_head(sock_net(sk), addr);
	spin_lock(&head->lock);
	__sk_del_node_init(sk);
	spin_unlock(&head->lock);
}

static int quic_handshake_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	union quic_addr *daddr = msg->msg_name;
	struct sk_buff *skb;
	int hlen, err;

	if (!daddr)
		return -EINVAL;

	lock_sock(sk);
	hlen = quic_encap_len(sk) + MAX_HEADER;
	quic_path_addr_set(quic_dst(sk), daddr);
	err = quic_flow_route(sk, NULL);
	if (err < 0)
		goto err;

	skb = alloc_skb(msg_len + hlen, GFP_KERNEL);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}
	skb_reserve(skb, msg_len + hlen);
	if (!copy_from_iter_full(skb_push(skb, msg_len), msg_len, &msg->msg_iter)) {
		kfree(skb);
		err = -EFAULT;
		goto err;
	}

	skb->ignore_df = 1;
	quic_lower_xmit(sk, skb);
	err = (int)msg_len;
err:
	release_sock(sk);
	return err;
}

static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg, struct quic_sndinfo *info)
{
	struct quic_stream_table *streams;
	struct quic_sndinfo *s = NULL;
	struct cmsghdr *cmsg;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != IPPROTO_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_SNDINFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*s)))
				return -EINVAL;
			s = CMSG_DATA(cmsg);
			info->stream_id = s->stream_id;
			info->stream_flag = s->stream_flag;
			break;
		default:
			return -EINVAL;
		}
	}

	if (!s) { /* sndinfo is not set, try to use msg_flags*/
		if (msg->msg_flags & MSG_SYN)
			info->stream_flag |= QUIC_STREAM_FLAG_NEW;
		if (msg->msg_flags & MSG_FIN)
			info->stream_flag |= QUIC_STREAM_FLAG_FIN;
		if (msg->msg_flags & MSG_STREAM_UNI)
			info->stream_flag |= QUIC_STREAM_FLAG_UNI;
		if (msg->msg_flags & MSG_DONTWAIT)
			info->stream_flag |= QUIC_STREAM_FLAG_ASYNC;
		info->stream_id = -1;
	}

	if (info->stream_id != -1)
		return 0;

	streams = quic_streams(sk);
	if (streams->send.stream_active != -1) {
		info->stream_id = streams->send.stream_active;
		return 0;
	}
	info->stream_id = (streams->send.streams_bidi << 2);
	if (info->stream_flag & QUIC_STREAM_FLAG_UNI) {
		info->stream_id = (streams->send.streams_uni << 2);
		info->stream_id |= QUIC_STREAM_TYPE_UNI_MASK;
	}
	info->stream_id |= quic_is_serv(sk);
	return 0;
}

static int quic_wait_for_send(struct sock *sk, u64 stream_id, long timeo, u32 msg_len)
{
	u8 state;

	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (!timeo) {
			err = -EAGAIN;
			goto out;
		}
		if (sk->sk_err) {
			err = sk->sk_err;
			pr_warn("wait sndbuf sk_err %d\n", err);
			goto out;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			goto out;
		}
		if (!quic_is_connected(sk)) {
			err = -EPIPE;
			pr_warn("wait sndbuf state %u, %d\n", state, err);
			goto out;
		}

		if (stream_id) {
			if (!quic_stream_id_exceeds(quic_streams(sk), stream_id))
				goto out;
		} else {
			if ((int)msg_len <= sk_stream_wspace(sk))
				goto out;
		}

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

static struct quic_stream *quic_sock_send_stream(struct sock *sk, struct quic_sndinfo *sndinfo)
{
	u8 type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	struct quic_stream *stream;
	struct sk_buff *skb;
	long timeo;
	int err;

	stream = quic_stream_send_get(quic_streams(sk), sndinfo->stream_id,
				      sndinfo->stream_flag, quic_is_serv(sk));
	if (!IS_ERR(stream)) {
		if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
			return ERR_PTR(-EINVAL);
		return stream;
	} else if (PTR_ERR(stream) != -EAGAIN) {
		return stream;
	}

	if (sndinfo->stream_id & QUIC_STREAM_TYPE_UNI_MASK)
		type = QUIC_FRAME_STREAMS_BLOCKED_UNI;

	skb = quic_frame_create(sk, type, &sndinfo->stream_id);
	if (!skb)
		return ERR_PTR(-ENOMEM);
	quic_outq_ctrl_tail(sk, skb, false);

	timeo = sock_sndtimeo(sk, sndinfo->stream_flag & QUIC_STREAM_FLAG_ASYNC);
	err = quic_wait_for_send(sk, sndinfo->stream_id, timeo, 0);
	if (err)
		return ERR_PTR(err);

	return quic_stream_send_get(quic_streams(sk), sndinfo->stream_id,
				    sndinfo->stream_flag, quic_is_serv(sk));
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_sndinfo sndinfo = {};
	struct quic_msginfo msginfo;
	struct quic_stream *stream;
	struct sk_buff *skb;
	int err = 0;
	long timeo;

	lock_sock(sk);
	err = quic_msghdr_parse(sk, msg, &sndinfo);
	if (err)
		goto out;

	stream = quic_sock_send_stream(sk, &sndinfo);
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		goto out;
	}

	if (sk_stream_wspace(sk) <= 0) {
		timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
		err = quic_wait_for_send(sk, 0, timeo, msg_len);
		if (err)
			goto out;
	}

	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flag = sndinfo.stream_flag;

	while (iov_iter_count(msginfo.msg) > 0) {
		skb = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo);
		if (!skb) {
			err = -ENOMEM;
			goto out;
		}
		quic_outq_data_tail(sk, skb, true);
	}
	quic_outq_flush(sk);

	err = msg_len;
out:
	release_sock(sk);
	return err;
}

static int quic_wait_for_packet(struct sock *sk, long timeo)
{
	for (;;) {
		int err = 0, exit = 1;
		DEFINE_WAIT(wait);

		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

		if (!skb_queue_empty(&sk->sk_receive_queue))
			goto out;

		err = -EAGAIN;
		if (!timeo)
			goto out;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;

		if (sk->sk_err) {
			err = sk->sk_err;
			pr_warn("wait rcv pkt sk_err %d\n", err);
			goto out;
		}

		if (quic_state(sk) == QUIC_STATE_USER_CLOSED)
			goto out;

		exit = 0;
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
out:
		finish_wait(sk_sleep(sk), &wait);
		if (exit)
			return err;
	}
}

#if KERNEL_VERSION(5, 18, 0) >= LINUX_VERSION_CODE
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
			int flags, int *addr_len)
{
#else
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
			int *addr_len)
{
	int nonblock = flags & MSG_DONTWAIT;
#endif
	int copy, copied = 0, freed = 0;
	struct quic_rcvinfo info = {};
	struct quic_stream *stream;
	int err, fin, off, event;
	struct sk_buff *skb;
	long timeo;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, nonblock);
	err = quic_wait_for_packet(sk, timeo);
	if (err)
		goto out;

	skb = skb_peek(&sk->sk_receive_queue);
	stream = QUIC_RCV_CB(skb)->stream;
	do {
		off = QUIC_RCV_CB(skb)->offset;
		copy = min_t(int, skb->len - off, len - copied);
		err = skb_copy_datagram_msg(skb, off, msg, copy);
		if (err) {
			if (!copied)
				goto out;
			break;
		}
		copied += copy;
		fin = QUIC_RCV_CB(skb)->stream_fin;
		event = QUIC_RCV_CB(skb)->event;

		if (flags & MSG_PEEK)
			break;
		if (copy != skb->len - off) {
			QUIC_RCV_CB(skb)->offset += copy;
			break;
		}
		if (event) {
			if (skb == quic_inq(sk)->last_event)
				quic_inq(sk)->last_event = NULL; /* no more event on list */
			if (event == QUIC_EVENT_STREAM_UPDATE &&
			    stream->recv.state == QUIC_STREAM_RECV_STATE_RESET_RECVD)
				stream->recv.state = QUIC_STREAM_RECV_STATE_RESET_READ;
			msg->msg_flags |= MSG_NOTIFICATION;
			info.stream_flag |= QUIC_STREAM_FLAG_NOTIFICATION;
			kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
			break;
		}
		freed += skb->len;
		kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
		if (fin) {
			stream->recv.state = QUIC_STREAM_RECV_STATE_READ;
			msg->msg_flags |= MSG_EOR;
			info.stream_flag |= QUIC_STREAM_FLAG_FIN;
			break;
		}

		skb = skb_peek(&sk->sk_receive_queue);
		if (!skb || QUIC_RCV_CB(skb)->event ||
		    QUIC_RCV_CB(skb)->stream->id != stream->id)
			break;
	} while (copied < len);

	if (!event) {
		info.stream_id = stream->id;
		quic_inq_flow_control(sk, stream, freed);
	}
	put_cmsg(msg, IPPROTO_QUIC, QUIC_RCVINFO, sizeof(info), &info);
	err = copied;
out:
	release_sock(sk);
	return err;
}

#if KERNEL_VERSION(5, 18, 0) >= LINUX_VERSION_CODE
static int quic_handshake_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
				  int flags, int *addr_len)
{
#else
static int quic_handshake_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
				  int *addr_len)
{
	int nonblock = flags & MSG_DONTWAIT;
#endif
	union quic_addr *addr = msg->msg_name;
	struct sk_buff *skb;
	int copy, err;
	long timeo;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, nonblock);
	err = quic_wait_for_packet(sk, timeo);
	if (err)
		goto out;

	skb = skb_peek(&sk->sk_receive_queue);
	copy = min_t(int, skb->len, len);
	err = skb_copy_datagram_msg(skb, 0, msg, copy);
	if (err)
		goto out;

	if (copy != skb->len)
		msg->msg_flags |= MSG_TRUNC;

	if (addr) {
		quic_get_msg_addr(sk, addr, skb, 1);
		*addr_len = quic_addr_len(sk);
	}

	err = copy;
	if (flags & MSG_PEEK)
		goto out;

	kfree_skb(__skb_dequeue(&sk->sk_receive_queue));

out:
	release_sock(sk);
	return err;
}

static struct sock *quic_accept(struct sock *sk, int flags, int *err, bool kern)
{
	return NULL;
}

static int quic_wait_for_accept(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (list_empty(quic_reqs(sk))) {
			release_sock(sk);
			timeo = schedule_timeout(timeo);
			lock_sock(sk);
		}

		if (!quic_is_listen(sk)) {
			err = -EINVAL;
			break;
		}

		if (!list_empty(quic_reqs(sk))) {
			err = 0;
			break;
		}

		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}

		if (!timeo) {
			err = -EAGAIN;
			break;
		}
	}

	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_copy_sock(struct sock *nsk, struct sock *sk, struct quic_request_sock *req)
{
	struct sk_buff *skb, *tmp;
	union quic_addr sa, da;
	u8 *data, len;

	nsk->sk_type = sk->sk_type;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_family = sk->sk_family;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		quic_af_ops(sk)->get_msg_addr(&da, skb, 0);
		quic_af_ops(sk)->get_msg_addr(&sa, skb, 1);

		if (!memcmp(&req->src, &da, quic_addr_len(sk)) &&
		    !memcmp(&req->dst, &sa, quic_addr_len(sk))) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			__skb_queue_tail(&nsk->sk_receive_queue, skb);
			quic_inq_set_owner_r(skb, nsk);
		}
	}

	if (nsk->sk_family == AF_INET6)
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	len = quic_alpn(sk)->len;
	if (len) {
		data = kmemdup(quic_alpn(sk)->data, len, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
		quic_alpn(nsk)->data = data;
		quic_alpn(nsk)->len = len;
	}

	quic_inq(nsk)->events = quic_inq(sk)->events;
	quic_crypto(nsk)->cipher_type = quic_crypto(sk)->cipher_type;
	return 0;
}

static struct sock *quic_handshake_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct quic_request_sock *req = NULL;
	struct sock *nsk = NULL;
	int error = -EINVAL;
	long timeo;

	lock_sock(sk);

	if (!quic_is_listen(sk))
		goto out;

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
	error = quic_wait_for_accept(sk, timeo);
	if (error)
		goto out;
	req = quic_request_sock_dequeue(sk);

	nsk = sk_alloc(sock_net(sk), quic_addr_family(sk), GFP_KERNEL, sk->sk_prot, kern);
	if (!nsk) {
		error = -ENOMEM;
		goto out;
	}
	sock_init_data(NULL, nsk);
	error = nsk->sk_prot->init(nsk);
	if (error)
		goto free;

	error = quic_copy_sock(nsk, sk, req);
	if (error)
		goto free;
	error = nsk->sk_prot->bind(nsk, &req->src.sa, quic_addr_len(nsk));
	if (error)
		goto free;

	error = nsk->sk_prot->connect(nsk, &req->dst.sa, quic_addr_len(nsk));
	if (error)
		goto free;
out:
	release_sock(sk);
	*err = error;
	kfree(req);
	return nsk;
free:
	nsk->sk_prot->close(nsk, 0);
	nsk = NULL;
	goto out;
}

static void quic_close(struct sock *sk, long timeout)
{
	struct quic_sock *qs = quic_sk(sk);
	struct sk_buff *skb;

	lock_sock(sk);
	/* send close frame only when it's NOT idle timeout or closed by peer */
	if (quic_is_connected(sk)) {
		skb = quic_frame_create(sk, QUIC_FRAME_CONNECTION_CLOSE_APP, NULL);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
	}

	quic_set_state(sk, QUIC_STATE_USER_CLOSED);

	quic_outq_purge(sk, &qs->outq);
	quic_inq_purge(sk, &qs->inq);

	quic_udp_sock_put(qs->udp_sk[0]);
	quic_udp_sock_put(qs->udp_sk[1]);

	quic_connection_id_set_free(&qs->source);
	quic_connection_id_set_free(&qs->dest);

	release_sock(sk);
	sk_common_release(sk);
}

static void quic_handshake_close(struct sock *sk, long timeout)
{
	lock_sock(sk);
	quic_inq_purge(sk, quic_inq(sk));
	quic_udp_sock_put(quic_sk(sk)->udp_sk[0]);
	release_sock(sk);
	sk_common_release(sk);
}

static int quic_sock_set_addr(struct sock *sk, struct quic_path_addr *path,
			      union quic_addr *addr, bool udp_bind)
{
	if (quic_addr_family(sk) != addr->sa.sa_family)
		return -EINVAL;

	quic_path_addr_set(path, addr);

	if (udp_bind && quic_udp_sock_set(sk, quic_sk(sk)->udp_sk, path))
		return -EINVAL;
	return 0;
}

int quic_sock_change_addr(struct sock *sk, struct quic_path_addr *path, void *data,
			  u32 len, bool udp_bind)
{
	struct sk_buff *skb;
	u64 number;
	int err;

	if (path->pending)
		return -EINVAL;

	if (len != quic_addr_len(sk))
		return -EINVAL;

	path->active = !path->active;
	err = quic_sock_set_addr(sk, path, data, udp_bind);
	if (err)
		goto err;

	/* send a ping before path validation so that we can delete the old path
	 * when validation is complete with no worries that the peer hasn't been
	 * aware of the new path.
	 */
	skb = quic_frame_create(sk, QUIC_FRAME_PING, NULL);
	if (!skb)
		goto err;
	quic_outq_ctrl_tail(sk, skb, true);

	number = quic_connection_id_first_number(quic_dest(sk));
	skb = quic_frame_create(sk, QUIC_FRAME_RETIRE_CONNECTION_ID, &number);
	if (!skb)
		goto err;
	quic_outq_ctrl_tail(sk, skb, true);

	skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
	if (!skb)
		goto err;
	quic_outq_ctrl_tail(sk, skb, !udp_bind);
	path->pending = 1;
	return 0;
err:
	path->active = !path->active;
	return err;
}

static int quic_sock_set_context(struct sock *sk, struct quic_context *context, u32 len)
{
	struct quic_sock *qs = quic_sk(sk);
	int err, state, seqno;
	struct sk_buff *skb;
	u64 prior = 0;

	if (sizeof(*context) > len)
		return -EINVAL;

	quic_inq_set_param(sk, &context->local);
	quic_outq_set_param(sk, &context->remote);
	quic_cong_set_param(sk, &context->local);
	quic_connection_id_set_param(&qs->dest, &context->local);
	quic_connection_id_set_param(&qs->source, &context->remote);
	quic_streams_set_param(quic_streams(sk), &context->local, &context->remote);

	err = quic_connection_id_add(&qs->source, &context->source, sk);
	if (err)
		return err;
	err = quic_connection_id_add(&qs->dest, &context->dest, sk);
	if (err)
		return err;

	err = quic_crypto_set_secret(&qs->crypto, &context->send, &context->recv);
	if (err)
		return err;

	/* clean up all handshake packets before going to connected state */
	quic_inq_purge(sk, quic_inq(sk));
	sk_dst_reset(sk); /* clear the dst used in handshake */
	if (!context->is_serv) {
		state = QUIC_STATE_CLIENT_CONNECTED;
		goto out;
	}

	state = QUIC_STATE_SERVER_CONNECTED;
	skb = quic_frame_create(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL);
	if (!skb)
		return -ENOMEM;
	quic_outq_ctrl_tail(sk, skb, qs->source.max_count > 1);

out:
	for (seqno = 1; seqno < qs->source.max_count; seqno++) {
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &prior);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, seqno != qs->source.max_count - 1);
	}
	quic_update_proto_ops(sk);
	quic_set_state(sk, state);
	inet_sk_set_state(sk, TCP_ESTABLISHED);

	quic_unhash(sk);
	quic_cong_cwnd_update(sk, min_t(u32, quic_packet_mss(quic_packet(sk)) * 10, 14720));
	return 0;
}

static int quic_sock_set_token(struct sock *sk, void *data, u32 len)
{
	struct quic_token *token = quic_token(sk);
	u8 *p;

	if (!len || len > 120)
		return -EINVAL;

	p = kmemdup(data, len, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	kfree(token->data);
	token->data = p;
	token->len = len;
	return 0;
}

static int quic_sock_new_token(struct sock *sk, void *data, u32 len)
{
	struct quic_token token;
	struct sk_buff *skb;

	if (!len)
		return -EINVAL;

	token.data = data;
	token.len = len;
	skb = quic_frame_create(sk, QUIC_FRAME_NEW_TOKEN, &token);
	if (!skb)
		return -ENOMEM;

	quic_outq_ctrl_tail(sk, skb, false);
	return 0;
}

static int quic_sock_set_session_ticket(struct sock *sk, u8 *data, u32 len)
{
	struct quic_token *ticket = quic_ticket(sk);
	u8 *p;

	if (len < 4 + 4 + 1 + 2 || len > 4096)
		return -EINVAL;

	if (*data != 4)
		return -EINVAL;

	p = kmemdup(data, len, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	kfree(ticket->data);
	ticket->data = p;
	ticket->len = len;
	return 0;
}

static int quic_sock_new_session_ticket(struct sock *sk, u8 *data, u32 len)
{
	struct quic_token ticket;
	struct sk_buff *skb;

	if (len < 4 + 4 + 1 + 2)
		return -EINVAL;

	if (*data != 4) /* for TLS NEWSESSION_TICKET message only */
		return -EINVAL;

	ticket.data = data;
	ticket.len = len;
	skb = quic_frame_create(sk, QUIC_FRAME_CRYPTO, &ticket);
	if (!skb)
		return -ENOMEM;

	quic_outq_ctrl_tail(sk, skb, false);
	return 0;
}

static int quic_sock_retire_connection_id(struct sock *sk, struct quic_connection_id_info *info, u8 len)
{
	struct sk_buff *skb;
	u64 number, first;

	if (len < sizeof(*info))
		return -EINVAL;

	if (info->source) {
		number = info->source;
		if (number > quic_connection_id_last_number(quic_source(sk)) ||
				number <= quic_connection_id_first_number(quic_source(sk)))
			return -EINVAL;
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &number);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, false);
		return 0;
	}

	number = info->dest;
	first = quic_connection_id_first_number(quic_dest(sk));
	if (number > quic_connection_id_last_number(quic_dest(sk)) || number <= first)
		return -EINVAL;

	for (; first < number; first++) {
		skb = quic_frame_create(sk, QUIC_FRAME_RETIRE_CONNECTION_ID, &first);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, first != number - 1);
	}
	return 0;
}

static int quic_sock_set_alpn(struct sock *sk, char *data, u32 len)
{
	struct quic_token *alpn = quic_alpn(sk);
	u8 *p;

	if (!len || len > 20)
		return -EINVAL;

	p = kmemdup(data, len, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	kfree(alpn->data);
	alpn->data = p;
	alpn->len = len;
	return 0;
}

static int quic_sock_stream_reset(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream *stream;
	struct sk_buff *skb;

	if (len != sizeof(*info))
		return -EINVAL;

	stream = quic_stream_send_get(quic_streams(sk), info->stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (stream->send.state > QUIC_STREAM_SEND_STATE_SENT)
		return -EINVAL;

	skb = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, info);
	if (!skb)
		return -ENOMEM;

	stream->send.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	quic_outq_ctrl_tail(sk, skb, false);
	return 0;
}

static int quic_sock_stream_stop_sending(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream *stream;
	struct sk_buff *skb;

	if (len != sizeof(*info))
		return -EINVAL;

	stream = quic_stream_recv_get(quic_streams(sk), info->stream_id, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	skb = quic_frame_create(sk, QUIC_FRAME_STOP_SENDING, info);
	if (!skb)
		return -ENOMEM;

	quic_outq_ctrl_tail(sk, skb, false);
	return 0;
}

static int quic_sock_set_event(struct sock *sk, struct quic_event_option *event, u32 len)
{
	if (len != sizeof(*event))
		return -EINVAL;
	if (!event->type || event->type > QUIC_EVENT_MAX)
		return -EINVAL;

	if (event->on) {
		quic_inq(sk)->events |=  (1 << (event->type));
		return 0;
	}
	quic_inq(sk)->events &= ~(1 << event->type);
	return 0;
}

static int quic_sock_set_connection_close(struct sock *sk, struct quic_connection_close *close, u32 len)
{
	u8 *data;

	if (len < sizeof(*close))
		return -EINVAL;

	len -= sizeof(*close);
	if (len > 80 || close->phrase[len - 1])
		return -EINVAL;
	data = kmemdup(close->phrase, len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	quic_outq(sk)->close_phrase = data;
	quic_outq(sk)->close_errcode = close->errcode;
	return 0;
}

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	void *kopt = NULL;
	int retval = 0;

	if (level != SOL_QUIC)
		return quic_af_ops(sk)->setsockopt(sk, level, optname, optval, optlen);

	if (optlen > 0) {
		kopt = memdup_sockptr(optval, optlen);
		if (IS_ERR(kopt))
			return PTR_ERR(kopt);
	}

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_STREAM_RESET:
		retval = quic_sock_stream_reset(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_STREAM_STOP_SENDING:
		retval = quic_sock_stream_stop_sending(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_CLOSE:
		retval = quic_sock_set_connection_close(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_MIGRATION:
		retval = quic_sock_change_addr(sk, &qs->src, kopt, optlen, 1);
		break;
	case QUIC_SOCKOPT_CONGESTION_CONTROL:
		retval = quic_cong_set_cong_alg(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_KEY_UPDATE:
		retval = quic_crypto_key_update(&qs->crypto, kopt, optlen);
		break;
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_set_event(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_NEW_TOKEN:
		retval = quic_sock_new_token(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_NEW_SESSION_TICKET:
		retval = quic_sock_new_session_ticket(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_RETIRE_CONNECTION_ID:
		retval = quic_sock_retire_connection_id(sk, kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_handshake_setsockopt(struct sock *sk, int level, int optname,
				     sockptr_t optval, unsigned int optlen)
{
	void *kopt = NULL;
	int retval = 0;

	if (level != SOL_QUIC)
		return quic_af_ops(sk)->setsockopt(sk, level, optname, optval, optlen);

	if (optlen > 0) {
		kopt = memdup_sockptr(optval, optlen);
		if (IS_ERR(kopt))
			return PTR_ERR(kopt);
	}

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_CONTEXT:
		retval = quic_sock_set_context(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_set_event(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_ALPN:
		retval = quic_sock_set_alpn(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_TOKEN:
		retval = quic_sock_set_token(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_SESSION_TICKET:
		retval = quic_sock_set_session_ticket(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CIPHER:
		retval = quic_crypto_set_cipher(quic_crypto(sk), kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_sock_get_context(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_context context;

        if (len < sizeof(context))
                return -EINVAL;
	len = sizeof(context);
	memset(&context, 0, len);

	quic_inq_get_param(sk, &context.remote);
	quic_outq_get_param(sk, &context.local);
	quic_cong_get_param(sk, &context.local);
	quic_connection_id_set_param(&qs->dest, &context.local);
	quic_connection_id_set_param(&qs->source, &context.remote);
	quic_streams_get_param(quic_streams(sk), &context.local, &context.remote);

	quic_connection_id_get(&qs->source, &context.source);
	quic_connection_id_get(&qs->dest, &context.dest);

	quic_crypto_get_secret(&qs->crypto, &context.send, &context.recv);

	context.is_serv = quic_is_serv(sk);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &context, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_token(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_token *token = quic_token(sk);

	if (len < token->len)
		return -EINVAL;
	if (put_user(token->len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, token->data, token->len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_session_ticket(struct sock *sk, int len,
					char __user *optval, int __user *optlen)
{
	struct quic_token *ticket = quic_ticket(sk);

	if (len < ticket->len)
		return -EINVAL;
	if (put_user(ticket->len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, ticket->data, ticket->len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_active_connection_id(struct sock *sk, int len,
					      char __user *optval, int __user *optlen)
{
	struct quic_connection_id_info info;

	if (len < sizeof(info))
		return -EINVAL;

	len = sizeof(info);
	info.source = quic_source(sk)->active->id.number;
	info.dest = quic_dest(sk)->active->id.number;

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &info, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_alpn(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_token *alpn = quic_alpn(sk);

	if (len < alpn->len)
		return -EINVAL;
	if (put_user(alpn->len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, alpn->data, alpn->len))
		return -EFAULT;
	return 0;
}

static int quic_sock_stream_open(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_sndinfo sndinfo;
	struct quic_stream *stream;

	if (len < sizeof(sndinfo))
		return -EINVAL;

	len = sizeof(sndinfo);
	if (copy_from_user(&sndinfo, optval, len))
		return -EFAULT;

	if (sndinfo.stream_id == -1) {
		sndinfo.stream_id = (quic_streams(sk)->send.streams_bidi << 2);
		if (sndinfo.stream_flag & QUIC_STREAM_FLAG_UNI) {
			sndinfo.stream_id = (quic_streams(sk)->send.streams_uni << 2);
			sndinfo.stream_id |= QUIC_STREAM_TYPE_UNI_MASK;
		}
		sndinfo.stream_id |= quic_is_serv(sk);
	}

	sndinfo.stream_flag |= QUIC_STREAM_FLAG_NEW;
	stream = quic_sock_send_stream(sk, &sndinfo);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (put_user(len, optlen) || copy_to_user(optval, &sndinfo, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_event(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_event_option event;

	if (len < sizeof(event))
		return -EINVAL;

	len = sizeof(event);
	if (copy_from_user(&event, optval, len))
		return -EFAULT;

	if (!event.type || event.type > QUIC_EVENT_MAX)
		return -EINVAL;

	event.on = quic_inq(sk)->events & (1 << event.type);
	if (put_user(len, optlen) || copy_to_user(optval, &event, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_connection_close(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close *close;
	u8 phrase_len = 0, frame[100] = {};

	if (outq->close_phrase)
		phrase_len = strlen(outq->close_phrase) + 1;
	if (len < sizeof(close) + phrase_len)
		return -EINVAL;

	len = sizeof(close) + phrase_len;
	close = (void *)frame;
	close->errcode = outq->close_errcode;
	close->frame = outq->close_frame;

	if (phrase_len)
		strcpy(close->phrase, outq->close_phrase);

	if (put_user(len, optlen) || copy_to_user(optval, close, len))
		return -EFAULT;
	return 0;
}

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	int retval = 0;
	int len;

	if (level != SOL_QUIC)
		return quic_af_ops(sk)->getsockopt(sk, level, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_CONTEXT:
		retval = quic_sock_get_context(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_STREAM_OPEN:
		retval = quic_sock_stream_open(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_CLOSE:
		retval = quic_sock_get_connection_close(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CONGESTION_CONTROL:
		retval = quic_cong_get_cong_alg(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_get_event(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TOKEN:
		retval = quic_sock_get_token(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_SESSION_TICKET:
		retval = quic_sock_get_session_ticket(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_ACTIVE_CONNECTION_ID:
		retval = quic_sock_get_active_connection_id(sk, len, optval, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return retval;
}

static int quic_handshake_getsockopt(struct sock *sk, int level, int optname,
				     char __user *optval, int __user *optlen)
{
	int retval = 0;
	int len;

	if (level != SOL_QUIC)
		return quic_af_ops(sk)->getsockopt(sk, level, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_get_event(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_ALPN:
		retval = quic_sock_get_alpn(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TOKEN:
		retval = quic_sock_get_token(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_SESSION_TICKET:
		retval = quic_sock_get_session_ticket(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CIPHER:
		retval = quic_crypto_get_cipher(quic_crypto(sk), len, optval, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return retval;
}

struct proto quic_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_do_rcv,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_do_rcv,
	.no_autobind	=  true,
	.obj_size	= sizeof(struct quic6_sock),
#if KERNEL_VERSION(6, 5, 0) <= LINUX_VERSION_CODE
	.ipv6_pinfo_offset	= offsetof(struct quic6_sock, inet6),
#endif
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quic_handshake_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.setsockopt	=  quic_handshake_setsockopt,
	.getsockopt	=  quic_handshake_getsockopt,
	.connect	=  quic_handshake_connect,
	.bind		=  quic_handshake_bind,
	.close		=  quic_handshake_close,
	.sendmsg	=  quic_handshake_sendmsg,
	.recvmsg	=  quic_handshake_recvmsg,
	.accept		=  quic_handshake_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_handshake_do_rcv,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_handshake_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.setsockopt	=  quic_handshake_setsockopt,
	.getsockopt	=  quic_handshake_getsockopt,
	.connect	=  quic_handshake_connect,
	.bind		=  quic_handshake_bind,
	.close		=  quic_handshake_close,
	.sendmsg	=  quic_handshake_sendmsg,
	.recvmsg	=  quic_handshake_recvmsg,
	.accept		=  quic_handshake_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_handshake_do_rcv,
	.no_autobind	=  true,
	.obj_size	= sizeof(struct quic6_sock),
#if KERNEL_VERSION(6, 5, 0) <= LINUX_VERSION_CODE
	.ipv6_pinfo_offset	= offsetof(struct quic6_sock, inet6),
#endif
	.sockets_allocated	=  &quic_sockets_allocated,
};
