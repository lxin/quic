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
		if (!memcmp(&req->sa, sa, quic_addr_len(sk)) &&
		    !memcmp(&req->da, da, quic_addr_len(sk)))
			return true;
	}
	return false;
}

int quic_request_sock_enqueue(struct sock *sk, struct quic_request_sock *nreq)
{
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk))
		return -ENOMEM;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	*req = *nreq;
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

static void quic_transport_param_init(struct sock *sk)
{
	struct quic_transport_param *param = quic_local(sk);

	param->max_udp_payload_size = 65527;
	param->ack_delay_exponent = 3;
	param->max_ack_delay = 25000;
	param->active_connection_id_limit = 7;
	param->max_idle_timeout = 30000000;
	param->initial_max_data = 128 * 1024;
	param->initial_max_stream_data_bidi_local = 64 * 1024;
	param->initial_max_stream_data_bidi_remote = 64 * 1024;
	param->initial_max_stream_data_uni = 64 * 1024;
	param->initial_max_streams_bidi = 100;
	param->initial_max_streams_uni = 100;
	param->initial_smoothed_rtt = 333000;
	param->version = QUIC_VERSION_V1;

	quic_inq_set_param(sk, param);
	quic_cong_set_param(sk, param);
	quic_connection_id_set_param(quic_dest(sk), param);
	quic_streams_set_param(quic_streams(sk), param, NULL);
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_sock *qs = quic_sk(sk);
	u8 len, i;

	qs->af_ops = quic_af_ops_get(sk->sk_family);
	quic_connection_id_set_init(&qs->source, 1);
	quic_connection_id_set_init(&qs->dest, 0);

	len = quic_addr_len(sk);
	quic_path_addr_init(&qs->src, len);
	quic_path_addr_init(&qs->dst, len);

	quic_outq_init(&qs->outq);
	quic_inq_init(&qs->inq);
	quic_packet_init(&qs->packet);

	quic_transport_param_init(sk);

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	for (i = 0; i < QUIC_CRYPTO_MAX; i ++)
		quic_pnmap_init(quic_pnmap(sk, i));
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
	u8 i;

	for (i = 0; i < QUIC_CRYPTO_MAX; i ++) {
		quic_pnmap_free(quic_pnmap(sk, i));
		quic_crypto_destroy(quic_crypto(sk, i));
	}

	quic_timers_free(sk);
	quic_streams_free(&qs->streams);

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
	struct quic_sock *qs = quic_sk(sk);
	struct quic_connection_id conn_id;
	__u32 err = -EINVAL;
	union quic_addr *sa;

	lock_sock(sk);
	if (!quic_is_closed(sk) || addr_len < quic_addr_len(sk))
		goto out;

	quic_path_addr_set(&qs->dst, quic_addr(addr));
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, quic_addr(addr), false);
	sa = quic_path_addr(&qs->src);
	if (!sa->v4.sin_port) { /* auto bind */
		err = quic_get_port(sock_net(sk), &qs->port, sa);
		if (err)
			goto out;
		err = quic_udp_sock_set(sk, qs->udp_sk, &qs->src);
		if (err)
			goto out;
		quic_set_sk_addr(sk, sa, true);
	}

	quic_generate_id(&conn_id, 18);
	err = quic_connection_id_add(quic_dest(sk), &conn_id, 0, NULL);
	if (err)
		goto out;
	quic_outq(sk)->orig_dcid = conn_id;
	quic_generate_id(&conn_id, 16);
	err = quic_connection_id_add(quic_source(sk), &conn_id, 0, sk);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(quic_crypto(sk, QUIC_CRYPTO_INITIAL),
					       &quic_dest(sk)->active->id,
					       quic_local(sk)->version, 0);
	if (err)
		goto out;

	if (sk_hashed(sk)) {
		err = 0;
		goto out;
	}

	inet_sk_set_state(sk, QUIC_SS_ESTABLISHING);
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

static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg, struct quic_handshake_info *hinfo,
			     struct quic_stream_info *sinfo, bool *has_hinfo)
{
	struct quic_handshake_info *i = NULL;
	struct quic_stream_info *s = NULL;
	struct quic_stream_table *streams;
	struct cmsghdr *cmsg;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != IPPROTO_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_HANDSHAKE_INFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*i)))
				return -EINVAL;
			i = CMSG_DATA(cmsg);
			hinfo->crypto_level = i->crypto_level;
			*has_hinfo = true;
			break;
		case QUIC_STREAM_INFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*s)))
				return -EINVAL;
			s = CMSG_DATA(cmsg);
			sinfo->stream_id = s->stream_id;
			sinfo->stream_flag = s->stream_flag;
			break;
		default:
			return -EINVAL;
		}
	}
	if (i)
		return 0;

	if (!s) { /* stream info is not set, try to use msg_flags*/
		if (msg->msg_flags & MSG_SYN)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_NEW;
		if (msg->msg_flags & MSG_FIN)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_FIN;
		if (msg->msg_flags & MSG_STREAM_UNI)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_UNI;
		if (msg->msg_flags & MSG_DONTWAIT)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_ASYNC;
		if (msg->msg_flags & MSG_DATAGRAM)
			sinfo->stream_flag |= QUIC_STREAM_FLAG_DATAGRAM;
		sinfo->stream_id = -1;
	}

	if (sinfo->stream_id != -1)
		return 0;

	streams = quic_streams(sk);
	if (streams->send.stream_active != -1) {
		sinfo->stream_id = streams->send.stream_active;
		return 0;
	}
	sinfo->stream_id = (streams->send.streams_bidi << 2);
	if (sinfo->stream_flag & QUIC_STREAM_FLAG_UNI) {
		sinfo->stream_id = (streams->send.streams_uni << 2);
		sinfo->stream_id |= QUIC_STREAM_TYPE_UNI_MASK;
	}
	sinfo->stream_id |= quic_is_serv(sk);
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
		if (quic_is_closed(sk)) {
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

static struct quic_stream *quic_sock_send_stream(struct sock *sk, struct quic_stream_info *sinfo)
{
	u8 type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	struct quic_stream *stream;
	struct sk_buff *skb;
	long timeo;
	int err;

	stream = quic_stream_send_get(quic_streams(sk), sinfo->stream_id,
				      sinfo->stream_flag, quic_is_serv(sk));
	if (!IS_ERR(stream)) {
		if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
			return ERR_PTR(-EINVAL);
		return stream;
	} else if (PTR_ERR(stream) != -EAGAIN) {
		return stream;
	}

	/* 0rtt data should return err if stream is not found */
	if (!quic_crypto(sk, QUIC_CRYPTO_APP)->send_ready)
		return ERR_PTR(-EINVAL);

	if (sinfo->stream_id & QUIC_STREAM_TYPE_UNI_MASK)
		type = QUIC_FRAME_STREAMS_BLOCKED_UNI;

	skb = quic_frame_create(sk, type, &sinfo->stream_id);
	if (!skb)
		return ERR_PTR(-ENOMEM);
	quic_outq_ctrl_tail(sk, skb, false);

	timeo = sock_sndtimeo(sk, sinfo->stream_flag & QUIC_STREAM_FLAG_ASYNC);
	err = quic_wait_for_send(sk, sinfo->stream_id, timeo, 0);
	if (err)
		return ERR_PTR(err);

	return quic_stream_send_get(quic_streams(sk), sinfo->stream_id,
				    sinfo->stream_flag, quic_is_serv(sk));
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_msginfo msginfo;
	struct quic_stream *stream;
	bool has_hinfo = false;
	struct sk_buff *skb;
	int err = 0;
	long timeo;

	lock_sock(sk);
	err = quic_msghdr_parse(sk, msg, &hinfo, &sinfo, &has_hinfo);
	if (err)
		goto err;

	if (has_hinfo) {
		if (hinfo.crypto_level >= QUIC_CRYPTO_MAX ||
		    !quic_crypto(sk, hinfo.crypto_level)->send_ready) {
			err = -EINVAL;
			goto err;
		}
		msginfo.level = hinfo.crypto_level;
		msginfo.msg = &msg->msg_iter;
		while (iov_iter_count(&msg->msg_iter) > 0) {
			skb = quic_frame_create(sk, QUIC_FRAME_CRYPTO, &msginfo);
			if (!skb) {
				err = -ENOMEM;
				goto err;
			}
			quic_outq_ctrl_tail(sk, skb, true);
		}
		goto out;
	}

	if (sinfo.stream_flag & QUIC_STREAM_FLAG_DATAGRAM) {
		if (!quic_outq_max_dgram(quic_outq(sk))) {
			err = -EINVAL;
			goto err;
		}
		if (sk_stream_wspace(sk) <= 0) {
			timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
			err = quic_wait_for_send(sk, 0, timeo, msg_len);
			if (err)
				goto err;
		}
		while (iov_iter_count(&msg->msg_iter) > 0) {
			skb = quic_frame_create(sk, QUIC_FRAME_DATAGRAM_LEN, &msg->msg_iter);
			if (!skb) {
				err = -ENOMEM;
				goto err;
			}
			quic_outq_dgram_tail(sk, skb, true);
		}
		goto out;
	}

	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		goto err;
	}

	if (sk_stream_wspace(sk) <= 0) {
		timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
		err = quic_wait_for_send(sk, 0, timeo, msg_len);
		if (err)
			goto err;
	}

	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flag = sinfo.stream_flag;

	while (iov_iter_count(msginfo.msg) > 0) {
		skb = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo);
		if (!skb) {
			err = -ENOMEM;
			goto err;
		}
		quic_outq_data_tail(sk, skb, true);
	}
out:
	if (!(msg->msg_flags & MSG_MORE))
		quic_outq_flush(sk);
	err = msg_len;
err:
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

		if (quic_is_closed(sk))
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
	struct quic_handshake_info hinfo = {};
	int err, copy, copied = 0, freed = 0;
	struct quic_stream_info sinfo = {};
	int fin, off, event, dgram, level;
	struct quic_stream *stream;
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
		dgram = QUIC_RCV_CB(skb)->dgram;
		level = QUIC_RCV_CB(skb)->level;
		if (event) {
			msg->msg_flags |= MSG_NOTIFICATION;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_NOTIFICATION;
		} else if (dgram) {
			msg->msg_flags |= MSG_DATAGRAM;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_DATAGRAM;
		} else if (!stream) {
			hinfo.crypto_level = level;
			put_cmsg(msg, IPPROTO_QUIC, QUIC_HANDSHAKE_INFO, sizeof(hinfo), &hinfo);
		}
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
			msg->msg_flags |= MSG_EOR;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_FIN;
			kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
			break;
		} else if (dgram) {
			msg->msg_flags |= MSG_EOR;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_FIN;
			kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
			break;
		} else if (!stream) {
			kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
			break;
		}
		freed += skb->len;
		kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
		if (fin) {
			stream->recv.state = QUIC_STREAM_RECV_STATE_READ;
			msg->msg_flags |= MSG_EOR;
			sinfo.stream_flag |= QUIC_STREAM_FLAG_FIN;
			break;
		}

		skb = skb_peek(&sk->sk_receive_queue);
		if (!skb || QUIC_RCV_CB(skb)->event || QUIC_RCV_CB(skb)->dgram ||
		    !QUIC_RCV_CB(skb)->stream ||
		    QUIC_RCV_CB(skb)->stream->id != stream->id)
			break;
	} while (copied < len);

	if (!event && stream) {
		sinfo.stream_id = stream->id;
		quic_inq_flow_control(sk, stream, freed);
	}
	if (event || stream) {
		put_cmsg(msg, IPPROTO_QUIC, QUIC_STREAM_INFO, sizeof(sinfo), &sinfo);
	}
	err = copied;
out:
	release_sock(sk);
	return err;
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

#define quic_set_param_if_not_zero(param_name) \
	if (p->param_name) \
		param->param_name = p->param_name

static int quic_sock_set_transport_param(struct sock *sk, struct quic_transport_param *p, u32 len)
{
	struct quic_transport_param *param = quic_local(sk);

	if (len < sizeof(*param) || quic_is_established(sk))
		return -EINVAL;

	if (p->remote)
		param = quic_remote(sk);

	quic_set_param_if_not_zero(max_udp_payload_size);
	quic_set_param_if_not_zero(ack_delay_exponent);
	quic_set_param_if_not_zero(max_ack_delay);
	quic_set_param_if_not_zero(active_connection_id_limit);
	quic_set_param_if_not_zero(max_idle_timeout);
	quic_set_param_if_not_zero(max_datagram_frame_size);
	quic_set_param_if_not_zero(initial_max_data);
	quic_set_param_if_not_zero(initial_max_stream_data_bidi_local);
	quic_set_param_if_not_zero(initial_max_stream_data_bidi_remote);
	quic_set_param_if_not_zero(initial_max_stream_data_uni);
	quic_set_param_if_not_zero(initial_max_streams_bidi);
	quic_set_param_if_not_zero(initial_max_streams_uni);
	quic_set_param_if_not_zero(initial_smoothed_rtt);
	quic_set_param_if_not_zero(disable_active_migration);
	quic_set_param_if_not_zero(validate_address);
	quic_set_param_if_not_zero(grease_quic_bit);
	quic_set_param_if_not_zero(stateless_reset);
	quic_set_param_if_not_zero(recv_session_ticket);
	quic_set_param_if_not_zero(cert_request);
	quic_set_param_if_not_zero(version);

	if (p->remote) {
		param->remote = 1;
		quic_outq_set_param(sk, param);
		quic_connection_id_set_param(quic_source(sk), param);
		quic_streams_set_param(quic_streams(sk), NULL, param);
		return 0;
	}

	quic_inq_set_param(sk, param);
	quic_cong_set_param(sk, param);
	quic_connection_id_set_param(quic_dest(sk), param);
	quic_streams_set_param(quic_streams(sk), param, NULL);
	return 0;
}

static int quic_copy_sock(struct sock *nsk, struct sock *sk, struct quic_request_sock *req)
{
	struct sk_buff *skb, *tmp;
	union quic_addr sa, da;

	nsk->sk_type = sk->sk_type;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_family = sk->sk_family;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;

	skb_queue_walk_safe(&quic_inq(sk)->backlog_list, skb, tmp) {
		quic_get_msg_addr(sk, &da, skb, 0);
		quic_get_msg_addr(sk, &sa, skb, 1);

		if (!memcmp(&req->sa, &da, quic_addr_len(sk)) &&
		    !memcmp(&req->da, &sa, quic_addr_len(sk))) {
			__skb_unlink(skb, &quic_inq(sk)->backlog_list);
			__skb_queue_tail(&quic_inq(nsk)->backlog_list, skb);
		}
	}

	if (nsk->sk_family == AF_INET6)
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	if (quic_data_dup(quic_alpn(nsk), quic_alpn(sk)->data, quic_alpn(sk)->len))
		return -ENOMEM;

	quic_sock_set_transport_param(nsk, quic_local(sk),
				      sizeof(struct quic_transport_param));
	quic_inq(nsk)->events = quic_inq(sk)->events;
	quic_crypto(nsk, QUIC_CRYPTO_APP)->cipher_type =
		quic_crypto(sk, QUIC_CRYPTO_APP)->cipher_type;
	return 0;
}

static int quic_accept_sock_init(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_sock *qs = quic_sk(sk);
	struct quic_connection_id conn_id;
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	__u32 err;

	lock_sock(sk);
	quic_path_addr_set(&qs->dst, &req->da);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, quic_addr(&req->da.sa), false);

	quic_generate_id(&conn_id, 16);
	err = quic_connection_id_add(quic_source(sk), &conn_id, 0, sk);
	if (err)
		goto out;
	quic_outq(sk)->orig_dcid = req->dcid;
	quic_local(sk)->version = req->version;
	err = quic_connection_id_add(quic_dest(sk), &req->scid, 0, NULL);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(quic_crypto(sk, QUIC_CRYPTO_INITIAL),
					       &req->dcid, quic_local(sk)->version, 1);
	if (err)
		goto out;

	quic_port(sk)->serv = 1;
	quic_port(sk)->retry = req->retry;
	inet_sk_set_state(sk, QUIC_SS_ESTABLISHING);
	err = sk->sk_prot->hash(sk);

	__skb_queue_head_init(&tmpq);
	skb_queue_splice_init(&quic_inq(sk)->backlog_list, &tmpq);
	skb = __skb_dequeue(&tmpq);
	while (skb) {
		skb_orphan(skb);
		quic_packet_process(sk, skb);
		skb = __skb_dequeue(&tmpq);
	}

out:
	release_sock(sk);
	return err;
}

static struct sock *quic_accept(struct sock *sk, int flags, int *err, bool kern)
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
	error = nsk->sk_prot->bind(nsk, &req->sa.sa, quic_addr_len(nsk));
	if (error)
		goto free;

	error = quic_accept_sock_init(nsk, req);
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
	if (quic_is_established(sk)) {
		skb = quic_frame_create(sk, QUIC_FRAME_CONNECTION_CLOSE_APP, NULL);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
	}

	inet_sk_set_state(sk, QUIC_SS_CLOSED);

	quic_outq_purge(sk, &qs->outq);
	quic_inq_purge(sk, &qs->inq);

	quic_udp_sock_put(qs->udp_sk[0]);
	quic_udp_sock_put(qs->udp_sk[1]);

	quic_connection_id_set_free(&qs->source);
	quic_connection_id_set_free(&qs->dest);

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

	if (path->pending || !quic_is_established(sk))
		return -EINVAL;

	if (udp_bind && quic_source(sk)->disable_active_migration)
		return -EINVAL;

	if (len != quic_addr_len(sk))
		return -EINVAL;

	path->active = !path->active;
	err = quic_sock_set_addr(sk, path, data, udp_bind);
	if (err)
		goto err;

	err = -ENOMEM;
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

static int quic_sock_set_token(struct sock *sk, void *data, u32 len)
{
	struct sk_buff *skb;

	if (quic_is_serv(sk)) {
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_TOKEN, NULL);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, false);
		return 0;
	}

	if (!len || len > 120)
		return -EINVAL;

	return quic_data_dup(quic_token(sk), data, len);
}

static int quic_sock_set_session_ticket(struct sock *sk, u8 *data, u32 len)
{
	if (!len || len > 4096)
		return -EINVAL;

	return quic_data_dup(quic_ticket(sk), data, len);
}

static int quic_sock_set_transport_params_ext(struct sock *sk, u8 *p, u32 len)
{
	struct quic_transport_param *param = quic_remote(sk);

	if (!quic_is_establishing(sk))
		return -EINVAL;

	if (quic_frame_set_transport_params_ext(sk, param, p, len))
		return -1;

	param->remote = 1;
	quic_outq_set_param(sk, param);
	quic_connection_id_set_param(quic_source(sk), param);
	quic_streams_set_param(quic_streams(sk), NULL, param);
	return 0;
}

static int quic_sock_set_crypto_secret(struct sock *sk, struct quic_crypto_secret *secret, u32 len)
{
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	int err, seqno;
	u64 prior = 1;

	if (len != sizeof(*secret) || !quic_is_establishing(sk))
		return -EINVAL;

	err = quic_crypto_set_secret(quic_crypto(sk, secret->level), secret,
				     quic_local(sk)->version);
	if (err)
		return err;

	if (!secret->send) { /* recv key is ready */
		__skb_queue_head_init(&tmpq);
		skb_queue_splice_init(&quic_inq(sk)->backlog_list, &tmpq);
		skb = __skb_dequeue(&tmpq);
		while (skb) {
			skb_orphan(skb);
			if (!quic_hdr(skb)->form) {
				QUIC_RCV_CB(skb)->number_offset =
					quic_source(sk)->active->id.len + sizeof(struct quichdr);
			}
			QUIC_RCV_CB(skb)->saddr = quic_path_addr(quic_dst(sk));
			quic_packet_process(sk, skb);
			skb = __skb_dequeue(&tmpq);
		}
		if (secret->level)
			return 0;
		/* app recv key is ready */
		if (quic_is_serv(sk)) {
			quic_outq_retransmit_check(sk, QUIC_CRYPTO_INITIAL,
						   QUIC_PN_MAP_MAX_PN, 0, 0, 0);
			quic_outq_retransmit_check(sk, QUIC_CRYPTO_HANDSHAKE,
						   QUIC_PN_MAP_MAX_PN, 0, 0, 0);
			skb = quic_frame_create(sk, QUIC_FRAME_NEW_TOKEN, NULL);
			if (!skb)
				return -ENOMEM;
			quic_outq_ctrl_tail(sk, skb, true);
			skb = quic_frame_create(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL);
			if (!skb)
				return -ENOMEM;
			quic_outq_ctrl_tail(sk, skb, false);
		}
		inet_sk_set_state(sk, QUIC_SS_ESTABLISHED);
		return 0;
	}

	/* send key is ready */
	if (secret->level) {
		/* 0rtt send key is ready */
		if (secret->level == QUIC_CRYPTO_EARLY)
			quic_outq(sk)->level = QUIC_CRYPTO_EARLY;
		return 0;
	}

	/* app send key is ready */
	quic_outq(sk)->level = QUIC_CRYPTO_APP;
	for (seqno = 1; seqno <= quic_source(sk)->max_count; seqno++) {
		skb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &prior);
		if (!skb)
			return -ENOMEM;
		quic_outq_ctrl_tail(sk, skb, true);
	}
	quic_cong_cwnd_update(sk, min_t(u32, quic_packet_mss(quic_packet(sk)) * 10, 14720));
	return 0;
}

static int quic_sock_retire_connection_id(struct sock *sk, struct quic_connection_id_info *info, u8 len)
{
	struct sk_buff *skb;
	u64 number, first;

	if (len < sizeof(*info) || !quic_is_established(sk))
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
	if (!len || len > 20)
		return -EINVAL;

	return quic_data_dup(quic_alpn(sk), data, len);
}

static int quic_sock_stream_reset(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream *stream;
	struct sk_buff *skb;

	if (len != sizeof(*info) || !quic_is_established(sk))
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

	if (len != sizeof(*info) || !quic_is_established(sk))
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
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_set_event(sk, kopt, optlen);
		break;
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
		retval = quic_sock_change_addr(sk, quic_src(sk), kopt, optlen, 1);
		break;
	case QUIC_SOCKOPT_CONGESTION_CONTROL:
		retval = quic_cong_set_cong_alg(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_KEY_UPDATE:
		retval = quic_crypto_key_update(quic_crypto(sk, QUIC_CRYPTO_APP), kopt, optlen);
		break;
	case QUIC_SOCKOPT_RETIRE_CONNECTION_ID:
		retval = quic_sock_retire_connection_id(sk, kopt, optlen);
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
	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = quic_sock_set_transport_param(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM_EXT:
		retval = quic_sock_set_transport_params_ext(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CRYPTO_SECRET:
		retval = quic_sock_set_crypto_secret(sk, kopt, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	kfree(kopt);
	return retval;
}

static int quic_sock_get_token(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_data *token = quic_token(sk);

	if (quic_is_serv(sk) || len < token->len)
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
	u8 *ticket, key[64];
	u32 ticket_len;

	if (quic_is_serv(sk)) { /* get ticket_key for server */
		union quic_addr *da = quic_path_addr(quic_dst(sk));

		if (quic_crypto_generate_session_ticket_key(quic_crypto(sk, QUIC_CRYPTO_INITIAL),
							    da, key, 64))
			return -EINVAL;
		ticket = key;
		ticket_len = 64;
		goto out;
	}

	ticket_len = quic_ticket(sk)->len;
	ticket = quic_ticket(sk)->data;
out:
	if (len < ticket_len)
		return -EINVAL;
	if (put_user(ticket_len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, ticket, ticket_len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_param(struct sock *sk, int len,
					 char __user *optval, int __user *optlen)
{
	struct quic_transport_param param, *p = quic_local(sk);

	if (len < sizeof(param))
		return -EINVAL;

	len = sizeof(param);
	if (copy_from_user(&param, optval, len))
		return -EFAULT;

	if (param.remote)
		p = quic_remote(sk);

	if (len < sizeof(*p))
		return -EINVAL;
	len = sizeof(*p);
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, p, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_params_ext(struct sock *sk, int len,
					      char __user *optval, int __user *optlen)
{
	struct quic_transport_param *param = quic_local(sk);
	u8 data[256];
	u32 datalen;

	if (quic_frame_get_transport_params_ext(sk, param, data, &datalen))
		return -EINVAL;
	if (len < datalen)
		return -EINVAL;
	len = datalen;
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_crypto_secret(struct sock *sk, int len,
				       char __user *optval, int __user *optlen)
{
	struct quic_crypto_secret secret = {};

	if (len < sizeof(secret))
		return -EINVAL;
	len = sizeof(secret);
	if (copy_from_user(&secret, optval, len))
		return -EFAULT;

	if (quic_crypto_get_secret(quic_crypto(sk, secret.level), &secret))
		return -EINVAL;
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &secret, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_active_connection_id(struct sock *sk, int len,
					      char __user *optval, int __user *optlen)
{
	struct quic_connection_id_info info;

	if (len < sizeof(info) || !quic_is_established(sk))
		return -EINVAL;

	len = sizeof(info);
	info.source = quic_source(sk)->active->number;
	info.dest = quic_dest(sk)->active->number;

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &info, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_alpn(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct quic_data *alpn = quic_alpn(sk);

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
	struct quic_stream_info sinfo;
	struct quic_stream *stream;

	if (len < sizeof(sinfo))
		return -EINVAL;

	len = sizeof(sinfo);
	if (copy_from_user(&sinfo, optval, len))
		return -EFAULT;

	if (sinfo.stream_id == -1) {
		sinfo.stream_id = (quic_streams(sk)->send.streams_bidi << 2);
		if (sinfo.stream_flag & QUIC_STREAM_FLAG_UNI) {
			sinfo.stream_id = (quic_streams(sk)->send.streams_uni << 2);
			sinfo.stream_id |= QUIC_STREAM_TYPE_UNI_MASK;
		}
		sinfo.stream_id |= quic_is_serv(sk);
	}

	sinfo.stream_flag |= QUIC_STREAM_FLAG_NEW;
	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (put_user(len, optlen) || copy_to_user(optval, &sinfo, len))
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
	case QUIC_SOCKOPT_EVENT:
		retval = quic_sock_get_event(sk, len, optval, optlen);
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
	case QUIC_SOCKOPT_ACTIVE_CONNECTION_ID:
		retval = quic_sock_get_active_connection_id(sk, len, optval, optlen);
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
	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = quic_sock_get_transport_param(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM_EXT:
		retval = quic_sock_get_transport_params_ext(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CRYPTO_SECRET:
		retval = quic_sock_get_crypto_secret(sk, len, optval, optlen);
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
