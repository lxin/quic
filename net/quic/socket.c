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

extern struct percpu_counter quic_sockets_allocated;

struct quic_sock *quic_sock_lookup_byaddr(struct sk_buff *skb, union quic_addr *a)
{
	struct net *net = dev_net(skb->dev);
	struct quic_sock *tmp, *qs = NULL;
	struct quic_hash_head *head;
	struct sock *sk;

	head = quic_listen_sock_head(net, a);
	spin_lock(&head->lock);
	hlist_for_each_entry(tmp, &head->head, node) {
		sk = &tmp->inet.sk;
		if (net == sock_net(sk) &&
		    !memcmp(quic_path_addr(&tmp->src), a, quic_addr_len(sk))) {
			qs = tmp;
			break;
		}
	}
	spin_unlock(&head->lock);
	return qs;
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

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	quic_pnmap_init(&qs->pn_map);
	quic_streams_init(&qs->streams);
	quic_timers_init(sk);

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

	local_bh_disable();
	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *a;
	__u32 err = 0;

	lock_sock(sk);

	a = quic_path_addr(&quic_sk(sk)->src);
	if (a->v4.sin_port || addr->sa_family != sk->sk_family ||
	    addr_len < quic_addr_len(sk) || !quic_addr(addr)->v4.sin_port) {
		err = -EINVAL;
		goto out;
	}

	memcpy(a, addr, quic_addr_len(sk));
	err = quic_udp_sock_set(sk, qs->udp_sk, a);
	if (err)
		goto out;

	quic_set_sk_addr(sk, a, true);
	quic_path_addr_set(&qs->src, a);

out:
	release_sock(sk);
	return err;
}

static int quic_hash(struct sock *sk)
{
	struct quic_hash_head *head;
	union quic_addr *addr, *a;
	struct quic_sock *qs;
	int err = 0;

	addr = quic_path_addr(&quic_sk(sk)->src);
	head = quic_listen_sock_head(sock_net(sk), addr);
	spin_lock(&head->lock);

	hlist_for_each_entry(qs, &head->head, node) {
		a = quic_path_addr(&qs->src);
		if (sock_net(sk) == sock_net(&qs->inet.sk) &&
		    !memcmp(addr, a, quic_addr_len(sk))) {
			err = -EADDRINUSE;
			goto out;
		}
	}

	hlist_add_head(&quic_sk(sk)->node, &head->head);
out:
	spin_unlock(&head->lock);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_hash_head *head;
	union quic_addr *addr;

	if (hlist_unhashed(&quic_sk(sk)->node))
		return;

	addr = quic_path_addr(&quic_sk(sk)->src);
	head = quic_listen_sock_head(sock_net(sk), addr);
	spin_lock(&head->lock);
	hlist_del_init(&quic_sk(sk)->node);
	spin_unlock(&head->lock);
}

static int quic_send_handshake_user(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	int hlen = quic_encap_len(sk) + MAX_HEADER;
	union quic_addr *daddr = msg->msg_name;
	struct sk_buff *skb;

	if (!daddr)
		return -EINVAL;

	quic_path_addr_set(&quic_sk(sk)->dst, daddr);
	if (quic_flow_route(sk))
		return -EHOSTUNREACH;

	skb = alloc_skb(msg_len + hlen, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, msg_len + hlen);
	if (!copy_from_iter_full(skb_push(skb, msg_len), msg_len, &msg->msg_iter)) {
		kfree(skb);
		return -EFAULT;
	}

	quic_lower_xmit(sk, skb);
	return msg_len;
}

static int quic_send_handshake_ack(struct sock *sk)
{
	struct sk_buff *skb;

	quic_inq_purge(sk, &quic_sk(sk)->inq);

	if (quic_pnmap_mark(&quic_sk(sk)->pn_map, 0))
		return -EFAULT;

	skb = quic_frame_create(sk, QUIC_FRAME_ACK, NULL, 0);
	if (!skb)
		return -ENOMEM;

	quic_outq_ctrl_tail(sk, skb, false);
	quic_unhash(sk);
	return 0;
}

static int quic_send_handshake_done(struct sock *sk)
{
	struct sk_buff *skb;

	quic_inq_purge(sk, &quic_sk(sk)->inq);

	skb = quic_frame_create(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL, 0);
	if (!skb)
		return -ENOMEM;

	quic_outq_ctrl_tail(sk, skb, false);
	quic_unhash(sk);
	return 0;
}

static int quic_msghdr_parse(struct msghdr *msg, struct quic_sndinfo *info)
{
	struct quic_sndinfo *s;
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

	return 0;
}

static int quic_wait_for_sndbuf(struct sock *sk, struct quic_stream *stream, long timeo, u32 msg_len)
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

		if ((int)msg_len <= sk_stream_wspace(sk))
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

int quic_get_mss(struct sock *sk)
{
	struct dst_entry *dst;

	dst = __sk_dst_check(sk, 0);
	if (!dst) {
		if (quic_flow_route(sk))
			return -EHOSTUNREACH;
		dst = __sk_dst_get(sk);
	}

	return dst_mtu(dst) - quic_sk(sk)->packet.len;
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_sndinfo sndinfo;
	struct quic_msginfo msginfo;
	struct quic_stream *stream;
	struct sk_buff *skb;
	int err = 0;
	long timeo;

	lock_sock(sk);
	if (quic_handshake_user(sk)) {
		err = quic_send_handshake_user(sk, msg, msg_len);
		goto out;
	}
	err = quic_msghdr_parse(msg, &sndinfo);
	if (err)
		goto out;

	stream = quic_stream_send_get(&quic_sk(sk)->streams, sndinfo.stream_id,
				      sndinfo.stream_flag, quic_is_serv(sk));
	if (!stream) {
		err = -EINVAL;
		goto out;
	}

	if (sk_stream_wspace(sk) <= 0) {
		timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
		err = quic_wait_for_sndbuf(sk, stream, timeo, msg_len);
		if (err)
			goto out;
	}

	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flag = sndinfo.stream_flag;

	while (iov_iter_count(msginfo.msg) > 0) {
		skb = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo, sizeof(msginfo));
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
	union quic_addr *addr = msg->msg_name;
	struct quic_rcvinfo info = {};
	struct quic_stream *stream;
	int copy, err, stream_id;
	struct sk_buff *skb;
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

	if (quic_handshake_user(sk))
		goto skip_stream;

	stream_id = QUIC_RCV_CB(skb)->stream_id;
	stream = quic_stream_recv_get(&quic_sk(sk)->streams, stream_id, quic_is_serv(sk));
	if (!stream) {
		err = -EPIPE;
		goto out;
	}
	if (QUIC_RCV_CB(skb)->stream_fin) {
		stream->recv.state = QUIC_STREAM_RECV_STATE_READ;
		msg->msg_flags |= MSG_EOR;
		info.stream_flag |= QUIC_STREAM_FLAG_FIN;
	}

	info.stream_id = stream_id;
	put_cmsg(msg, IPPROTO_QUIC, QUIC_RCVINFO, sizeof(info), &info);
	quic_inq_flow_control(sk, stream, skb);

skip_stream:
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

static void quic_close(struct sock *sk, long timeout)
{
	struct quic_sock *qs = quic_sk(sk);

	lock_sock(sk);
	qs->state = QUIC_STATE_USER_CLOSED;

	quic_outq_purge(sk, &qs->outq);
	quic_inq_purge(sk, &qs->inq);

	quic_udp_sock_put(qs->udp_sk[0]);
	quic_udp_sock_put(qs->udp_sk[1]);

	quic_connection_id_set_free(&qs->source);
	quic_connection_id_set_free(&qs->dest);

	release_sock(sk);
	sk_common_release(sk);
}

static int quic_set_transport_param(struct sock *sk, struct quic_transport_param *param,
				    u32 len, u8 send)
{
	struct quic_sock *qs = quic_sk(sk);

	if (len != sizeof(*param))
		return -EINVAL;

	quic_packet_set_param(sk, param, send);
	quic_streams_set_param(&qs->streams, param, send);
	return 0;
}

static int quic_sock_set_addr(struct sock *sk, struct quic_path_addr *path, void *data,
			      u32 len, bool udp_bind)
{
	if (len != quic_addr_len(sk))
		return -EINVAL;

	if (udp_bind && quic_udp_sock_set(sk, quic_sk(sk)->udp_sk, data))
		return -EINVAL;

	quic_path_addr_set(path, data);
	return 0;
}

static int quic_set_state(struct sock *sk, u8 *state, u32 len)
{
	int ret = 0;

	if (!len)
		return -EINVAL;

	if (quic_sk(sk)->state == *state)
		return -EINVAL;

	switch (*state) {
	case QUIC_STATE_USER_CLOSED:
		quic_unhash(sk);
		break;
	case QUIC_STATE_USER_CONNECTING:
		ret = quic_hash(sk);
		break;
	case QUIC_STATE_CLIENT_CONNECTED:
		ret = quic_send_handshake_ack(sk);
		break;
	case QUIC_STATE_SERVER_CONNECTED:
		ret = quic_send_handshake_done(sk);
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	quic_sk(sk)->state = *state;
	quic_sk(sk)->pn_map.is_serv = (*state == QUIC_STATE_SERVER_CONNECTED); /* debug */
	return 0;
}

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	void *kopt = NULL;
	int retval = 0;

	if (level != SOL_QUIC)
		return qs->af_ops->setsockopt(sk, level, optname, optval, optlen);

	if (optlen > 0) {
		kopt = memdup_sockptr(optval, optlen);
		if (IS_ERR(kopt))
			return PTR_ERR(kopt);
	}

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_SOURCE_CONNECTION_ID_NUMBERS:
		retval = quic_connection_id_set_numbers(&qs->source, kopt, optlen);
		break;
	case QUIC_SOCKOPT_DEST_CONNECTION_ID_NUMBERS:
		retval = quic_connection_id_set_numbers(&qs->dest, kopt, optlen);
		break;
	/* below is context setup from userspace after handshake */
	case QUIC_SOCKOPT_LOCAL_TRANSPORT_PARAMS:
		retval = quic_set_transport_param(sk, kopt, optlen, 1);
		break;
	case QUIC_SOCKOPT_PEER_TRANSPORT_PARAMS:
		retval = quic_set_transport_param(sk, kopt, optlen, 0);
		break;
	case QUIC_SOCKOPT_SOURCE_ADDRESS:
		retval = quic_sock_set_addr(sk, &qs->src, kopt, optlen, 1);
		break;
	case QUIC_SOCKOPT_DEST_ADDRESS:
		retval = quic_sock_set_addr(sk, &qs->dst, kopt, optlen, 0);
		break;
	case QUIC_SOCKOPT_SOURCE_CONNECTION_ID:
		retval = quic_connection_id_add(&qs->source, kopt, optlen, sk);
		break;
	case QUIC_SOCKOPT_DEST_CONNECTION_ID:
		retval = quic_connection_id_add(&qs->dest, kopt, optlen, sk);
		break;
	case QUIC_SOCKOPT_CRYPTO_SEND_SECRET:
		retval = quic_crypto_set_secret(&qs->crypto, kopt, optlen, 1);
		break;
	case QUIC_SOCKOPT_CRYPTO_RECV_SECRET:
		retval = quic_crypto_set_secret(&qs->crypto, kopt, optlen, 0);
		break;
	case QUIC_SOCKOPT_STATE:
		retval = quic_set_state(sk, kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_get_transport_param(struct sock *sk, int len,
				    char __user *optval, int __user *optlen, u8 send)
{
	struct quic_transport_param param;
	struct quic_sock *qs = quic_sk(sk);

	if (len < sizeof(param))
		return -EINVAL;
	len = sizeof(param);
	if (put_user(len, optlen))
		return -EFAULT;

	quic_packet_get_param(sk, &param, send);
	quic_streams_get_param(&qs->streams, &param, send);
	if (copy_to_user(optval, &param, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_addr(struct sock *sk, struct quic_path_addr *a, int len,
			      char __user *optval, int __user *optlen)
{
	union quic_addr *addr;

	if (len < quic_addr_len(sk))
		return -EINVAL;
	len = quic_addr_len(sk);
	if (put_user(len, optlen))
		return -EFAULT;

	addr = quic_path_addr(a);
	if (copy_to_user(optval, addr, len))
		return -EFAULT;
	return 0;
}

static int quic_get_state(struct sock *sk, int len, char __user *optval,
			  int __user *optlen, bool src)
{
	if (!len)
		return -EINVAL;
	len = 1;
	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &quic_sk(sk)->state, len))
		return -EFAULT;
	return 0;
}

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct quic_sock *qs = quic_sk(sk);
	int retval = 0;
	int len;

	if (level != SOL_QUIC)
		return qs->af_ops->getsockopt(sk, level, optname, optval, optlen);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	lock_sock(sk);
	switch (optname) {
	case QUIC_SOCKOPT_SOURCE_CONNECTION_ID_NUMBERS:
		retval = quic_connection_id_get_numbers(&qs->source, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_DEST_CONNECTION_ID_NUMBERS:
		retval = quic_connection_id_get_numbers(&qs->dest, len, optval, optlen);
		break;
	/* below is context setup from userspace after handshake */
	case QUIC_SOCKOPT_LOCAL_TRANSPORT_PARAMS:
		retval = quic_get_transport_param(sk, len, optval, optlen, 0);
		break;
	case QUIC_SOCKOPT_PEER_TRANSPORT_PARAMS:
		retval = quic_get_transport_param(sk, len, optval, optlen, 1);
		break;
	case QUIC_SOCKOPT_SOURCE_ADDRESS:
		retval = quic_sock_get_addr(sk, &quic_sk(sk)->src, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_DEST_ADDRESS:
		retval = quic_sock_get_addr(sk, &quic_sk(sk)->dst, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_SOURCE_CONNECTION_ID:
		retval = quic_connection_id_get(&qs->source, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_DEST_CONNECTION_ID:
		retval = quic_connection_id_get(&qs->dest, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CRYPTO_SEND_SECRET:
		retval = quic_crypto_get_secret(&qs->crypto, len, optval, optlen, 1);
		break;
	case QUIC_SOCKOPT_CRYPTO_RECV_SECRET:
		retval = quic_crypto_get_secret(&qs->crypto, len, optval, optlen, 0);
		break;
	case QUIC_SOCKOPT_STATE:
		retval = quic_get_state(sk, len, optval, optlen, 0);
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
