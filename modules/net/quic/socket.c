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

#include <net/inet_common.h>
#include <linux/version.h>
#include <net/tls.h>

#include "socket.h"

static unsigned long quic_memory_pressure;
static atomic_long_t quic_memory_allocated;

static void quic_enter_memory_pressure(struct sock *sk)
{
	WRITE_ONCE(quic_memory_pressure, 1);
}

bool quic_request_sock_exists(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	list_for_each_entry(req, quic_reqs(sk), list) {
		if (!memcmp(&req->saddr, &packet->saddr, sizeof(req->saddr)) &&
		    !memcmp(&req->daddr, &packet->daddr, sizeof(req->daddr)) &&
		    !quic_conn_id_cmp(&req->dcid, &packet->dcid))
			return true;
	}
	return false;
}

int quic_request_sock_enqueue(struct sock *sk, struct quic_conn_id *odcid, u8 retry)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk))
		return -ENOMEM;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	req->version = packet->version;
	req->daddr = packet->daddr;
	req->saddr = packet->saddr;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->retry = retry;

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

int quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	int ret = 0;

	if (QUIC_CRYPTO_CB(skb)->time > quic_pnspace_time(space))
		return ret;

	local_bh_disable();
	sk = quic_sock_lookup(skb, &packet->saddr, &packet->daddr, &packet->dcid);
	if (!sk)
		goto out;

	/* the request sock was just accepted */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf)))
			kfree_skb(skb);
	} else {
		sk->sk_backlog_rcv(sk, skb);
	}
	bh_unlock_sock(sk);
	ret = 1;
out:
	local_bh_enable();
	return ret;
}

struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
			      struct quic_conn_id *dcid)
{
	struct net *net = dev_net(skb->dev);
	struct quic_path_group *paths;
	struct quic_hash_head *head;
	struct sock *sk;

	/* Search for regular socket first */
	head = quic_sock_head(net, sa, da);
	spin_lock(&head->lock);
	sk_for_each(sk, &head->head) {
		if (net != sock_net(sk))
			continue;
		paths = quic_paths(sk);
		if (!quic_path_cmp_saddr(paths, 0, sa) &&
		    !quic_path_cmp_daddr(paths, 0, da) &&
		    (!dcid || !quic_conn_id_cmp(quic_path_dcid(paths), dcid)))
			break;
	}
	spin_unlock(&head->lock);

	return sk;
}

struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da)
{
	struct net *net = dev_net(skb->dev);
	struct quic_data alpns = {}, alpn;
	struct sock *sk = NULL, *tmp;
	struct quic_hash_head *head;
	union quic_addr *a;
	u64 length;
	u32 len;
	u8 *p;

	head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
	spin_lock(&head->lock);

	if (hlist_empty(&head->head) || quic_packet_parse_alpn(skb, &alpns))
		goto unlock;

	if (!alpns.len) {
		sk_for_each(tmp, &head->head) {
			/* alpns.data != NULL means TLS parse succeed but no ALPN was found,
			 * in such case it only matches the sock with no ALPN set.
			 */
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) && quic_is_listen(tmp) &&
			    quic_cmp_sk_addr(tmp, a, sa) && (!alpns.data || !quic_alpn(tmp)->len)) {
				sk = tmp;
				if (!quic_is_any_addr(a))
					break;
			}
		}
		goto unlock;
	}

	for (p = alpns.data, len = alpns.len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&alpn, p, length);
		sk_for_each(tmp, &head->head) {
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) && quic_is_listen(tmp) &&
			    quic_cmp_sk_addr(tmp, a, sa) && quic_data_has(quic_alpn(tmp), &alpn)) {
				sk = tmp;
				if (!quic_is_any_addr(a))
					break;
			}
		}
		if (sk)
			break;
	}
unlock:
	spin_unlock(&head->lock);

	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_shash(net, da), skb, 1);
	return sk;
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

static void quic_sock_apply_transport_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set = p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_set_param(sk, p);
	quic_outq_set_param(sk, p);
	quic_conn_id_set_param(id_set, p);
	quic_path_set_param(quic_paths(sk), p);
	quic_stream_set_param(quic_streams(sk), p, quic_is_serv(sk));
}

static void quic_sock_fetch_transport_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set = p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_get_param(sk, p);
	quic_outq_get_param(sk, p);
	quic_conn_id_get_param(id_set, p);
	quic_path_get_param(quic_paths(sk), p);
	quic_stream_get_param(quic_streams(sk), p, quic_is_serv(sk));
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_transport_param *p = &quic_default_param;
	u32 i;

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	quic_conn_id_set_init(quic_source(sk), 1);
	quic_conn_id_set_init(quic_dest(sk), 0);
	quic_cong_init(quic_cong(sk));

	quic_sock_apply_transport_param(sk, p);

	quic_outq_init(sk);
	quic_inq_init(sk);
	quic_packet_init(sk);
	quic_timer_init(sk);

	for (i = 0; i < QUIC_PNSPACE_MAX; i++) {
		if (quic_pnspace_init(quic_pnspace(sk, (u8)i)))
			return -ENOMEM;
	}
	if (quic_stream_init(quic_streams(sk)))
		return -ENOMEM;
	INIT_LIST_HEAD(quic_reqs(sk));

	WRITE_ONCE(sk->sk_sndbuf, READ_ONCE(sysctl_quic_wmem[1]));
	WRITE_ONCE(sk->sk_rcvbuf, READ_ONCE(sysctl_quic_rmem[1]));

	local_bh_disable();
	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	u32 i;

	for (i = 0; i < QUIC_PNSPACE_MAX; i++)
		quic_pnspace_free(quic_pnspace(sk, (u8)i));
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_destroy(quic_crypto(sk, (u8)i));

	quic_timer_free(sk);
	quic_stream_free(quic_streams(sk));

	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));
	quic_data_free(quic_alpn(sk));

	local_bh_disable();
	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr a;
	int err = -EINVAL;

	lock_sock(sk);

	if (quic_path_saddr(paths, 0)->v4.sin_port || quic_get_user_addr(sk, &a, addr, addr_len))
		goto out;

	quic_path_set_saddr(paths, 0, &a);
	err = quic_path_bind(sk, paths, 0);
	if (err)
		goto out;
	quic_set_sk_addr(sk, &a, true);

out:
	release_sock(sk);
	return err;
}

static int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id, *active;
	union quic_addr *sa, a;
	int err = -EINVAL;

	lock_sock(sk);
	if (!quic_is_closed(sk) || quic_get_user_addr(sk, &a, addr, addr_len))
		goto out;

	quic_path_set_daddr(paths, 0, &a);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, &a, false);

	sa = quic_path_saddr(paths, 0);
	if (!sa->v4.sin_port) { /* auto bind */
		err = quic_path_bind(sk, paths, 0);
		if (err)
			goto out;
		quic_set_sk_addr(sk, sa, true);
	}

	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(dest, &conn_id, 0, NULL);
	if (err)
		goto out;
	quic_path_set_orig_dcid(paths, &conn_id);
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(source, &conn_id, 0, sk);
	if (err)
		goto free;
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
	active = quic_conn_id_active(dest);
	err = quic_crypto_initial_keys_install(crypto, active, packet->version, 0);
	if (err)
		goto free;

	quic_timer_start(sk, QUIC_TIMER_IDLE, quic_inq_timeout(inq));
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
out:
	release_sock(sk);
	return err;
free:
	quic_conn_id_set_free(dest);
	quic_conn_id_set_free(source);
	sk->sk_prot->unhash(sk);
	goto out;
}

static int quic_hash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_data *alpns = quic_alpn(sk);
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr *sa, *da;
	struct sock *nsk;
	int err = 0, any;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (!sk->sk_max_ack_backlog) {
		head = quic_sock_head(net, sa, da);
		spin_lock(&head->lock);
		__sk_add_node(sk, &head->head);
		spin_unlock(&head->lock);
		return 0;
	}

	head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
	spin_lock(&head->lock);

	any = quic_is_any_addr(sa);
	sk_for_each(nsk, &head->head) {
		if (net == sock_net(nsk) && quic_is_listen(nsk) &&
		    !quic_path_cmp_saddr(quic_paths(nsk), 0, sa)) {
			if (!quic_data_cmp(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				if (sk->sk_reuseport && nsk->sk_reuseport) {
					err = reuseport_add_sock(sk, nsk, any);
					if (!err)
						__sk_add_node(sk, &head->head);
				}
				goto out;
			}
			if (quic_data_match(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				goto out;
			}
		}
	}

	if (sk->sk_reuseport) {
		err = reuseport_alloc(sk, any);
		if (err)
			goto out;
	}
	__sk_add_node(sk, &head->head);
out:
	spin_unlock(&head->lock);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr *sa, *da;

	if (sk_unhashed(sk))
		return;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (sk->sk_max_ack_backlog) {
		head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
		goto out;
	}
	head = quic_sock_head(net, sa, da);

out:
	spin_lock(&head->lock);
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		reuseport_detach_sock(sk);
	__sk_del_node_init(sk);
	spin_unlock(&head->lock);
}

#define QUIC_MSG_STREAM_FLAGS \
	(MSG_STREAM_NEW | MSG_STREAM_FIN | MSG_STREAM_UNI | MSG_STREAM_DONTWAIT)

#define QUIC_MSG_FLAGS \
	(QUIC_MSG_STREAM_FLAGS | MSG_BATCH | MSG_MORE | MSG_DONTWAIT | MSG_DATAGRAM | MSG_NOSIGNAL)

static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg, struct quic_handshake_info *hinfo,
			     struct quic_stream_info *sinfo, bool *has_hinfo)
{
	struct quic_handshake_info *h = NULL;
	struct quic_stream_info *s = NULL;
	struct quic_stream_table *streams;
	struct cmsghdr *cmsg;
	s64 active;

	if (quic_is_closed(sk))
		return -EINVAL;
	if (msg->msg_flags & ~QUIC_MSG_FLAGS)
		return -EINVAL;

	sinfo->stream_id = -1;
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_HANDSHAKE_INFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*h)))
				return -EINVAL;
			h = CMSG_DATA(cmsg);
			hinfo->crypto_level = h->crypto_level;
			break;
		case QUIC_STREAM_INFO:
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*s)))
				return -EINVAL;
			s = CMSG_DATA(cmsg);
			if (s->stream_flags & ~QUIC_MSG_STREAM_FLAGS)
				return -EINVAL;
			sinfo->stream_id = s->stream_id;
			sinfo->stream_flags = s->stream_flags;
			break;
		default:
			return -EINVAL;
		}
	}

	if (h) {
		*has_hinfo = true;
		return 0;
	}

	if (!s) /* in case someone uses 'flags' argument to set stream_flags */
		sinfo->stream_flags |= msg->msg_flags;

	if (sinfo->stream_id != -1)
		return 0;

	streams = quic_streams(sk);
	active = quic_stream_send_active_id(streams);
	if (active != -1) {
		sinfo->stream_id = active;
		return 0;
	}
	sinfo->stream_id = quic_stream_send_next_bidi_id(streams);
	if (sinfo->stream_flags & MSG_STREAM_UNI)
		sinfo->stream_id = quic_stream_send_next_uni_id(streams);
	return 0;
}

static int quic_wait_for_stream(struct sock *sk, s64 stream_id, u32 flags)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_STREAM_DONTWAIT);
	struct quic_stream_table *streams = quic_streams(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EPIPE;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
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
		if (!quic_stream_id_send_exceeds(streams, stream_id) &&
		    !quic_stream_id_send_overflow(streams, stream_id))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static struct quic_stream *quic_sock_send_stream(struct sock *sk, struct quic_stream_info *sinfo)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_stream_table *streams = quic_streams(sk);
	u8 type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	struct quic_stream *stream;
	int err;

	stream = quic_stream_send_get(streams, sinfo->stream_id,
				      sinfo->stream_flags, quic_is_serv(sk));
	if (!IS_ERR(stream)) {
		if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
			return ERR_PTR(-EINVAL);
		return stream;
	} else if (PTR_ERR(stream) != -EAGAIN) {
		return stream;
	}

	/* 0rtt data should return err if stream is not found */
	if (!quic_crypto_send_ready(crypto))
		return ERR_PTR(-EINVAL);

	if ((sinfo->stream_flags & MSG_STREAM_SNDBLOCK) &&
	    quic_stream_id_send_exceeds(streams, sinfo->stream_id)) {
		if (sinfo->stream_id & QUIC_STREAM_TYPE_UNI_MASK)
			type = QUIC_FRAME_STREAMS_BLOCKED_UNI;

		if (quic_outq_transmit_frame(sk, type, &sinfo->stream_id, 0, false))
			return ERR_PTR(-ENOMEM);
	}

	err = quic_wait_for_stream(sk, sinfo->stream_id, sinfo->stream_flags);
	if (err)
		return ERR_PTR(err);

	return quic_stream_send_get(streams, sinfo->stream_id,
				    sinfo->stream_flags, quic_is_serv(sk));
}

static int quic_wait_for_send(struct sock *sk, u32 flags, u32 len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EPIPE;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
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
		if ((int)len <= sk_stream_wspace(sk) && sk_wmem_schedule(sk, (int)len))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_sock_stream_writable(struct sock *sk, struct quic_stream *stream,
				     u32 flags, u32 len)
{
	if (quic_outq_flow_control(sk, stream, len, flags & MSG_STREAM_SNDBLOCK))
		return 0;
	if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len))
		return 0;
	return 1;
}

static int quic_wait_for_stream_send(struct sock *sk, struct quic_stream *stream, u32 flags,
				     u32 len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EPIPE;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			err = -EAGAIN;
			if (quic_outq_wspace(sk, stream) < (u64)len)
				err = -ENOSPC;
			break;
		}
		if (quic_sock_stream_writable(sk, stream, flags, len))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	int err = 0, bytes = 0, len = 1;
	bool delay, has_hinfo = false;
	struct quic_msginfo msginfo;
	struct quic_crypto *crypto;
	struct quic_stream *stream;
	u32 flags = msg->msg_flags;
	struct quic_frame *frame;

	lock_sock(sk);
	err = quic_msghdr_parse(sk, msg, &hinfo, &sinfo, &has_hinfo);
	if (err)
		goto err;

	delay = !!(flags & MSG_MORE);
	if (has_hinfo) {
		if (hinfo.crypto_level >= QUIC_CRYPTO_EARLY) {
			err = -EINVAL;
			goto err;
		}
		crypto = quic_crypto(sk, hinfo.crypto_level);
		if (!quic_crypto_send_ready(crypto)) {
			err = -EINVAL;
			goto err;
		}
		if (quic_packet_config(sk, hinfo.crypto_level, 0)) {
			err = -ENETUNREACH;
			goto err;
		}

		msginfo.level = hinfo.crypto_level;
		msginfo.msg = &msg->msg_iter;
		while (iov_iter_count(&msg->msg_iter) > 0) {
			frame = quic_frame_create(sk, QUIC_FRAME_CRYPTO, &msginfo);
			if (!frame) {
				if (!bytes) {
					err = -ENOMEM;
					goto err;
				}
				goto out;
			}
			len = frame->bytes;
			if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len)) {
				if (delay) {
					quic_outq_set_force_delay(outq, 0);
					quic_outq_transmit(sk);
				}
				err = quic_wait_for_send(sk, flags, len);
				if (err) {
					quic_frame_put(frame);
					if (err == -EPIPE || !bytes)
						goto err;
					goto out;
				}
			}
			bytes += frame->bytes;
			quic_outq_set_force_delay(outq, delay);
			quic_outq_ctrl_tail(sk, frame, delay);
		}
		goto out;
	}

	if (quic_packet_config(sk, QUIC_CRYPTO_APP, 0)) {
		err = -ENETUNREACH;
		goto err;
	}

	if (flags & MSG_DATAGRAM) {
		if (!quic_outq_max_dgram(outq)) {
			err = -EINVAL;
			goto err;
		}
		frame = quic_frame_create(sk, QUIC_FRAME_DATAGRAM_LEN, &msg->msg_iter);
		if (!frame) {
			err = -EINVAL;
			goto err;
		}
		len = frame->bytes;
		if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len)) {
			err = quic_wait_for_send(sk, flags, len);
			if (err) {
				quic_frame_put(frame);
				goto err;
			}
		}
		bytes += frame->bytes;
		quic_outq_set_force_delay(outq, delay);
		quic_outq_dgram_tail(sk, frame, delay);
		goto out;
	}

	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		goto err;
	}

	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flags = sinfo.stream_flags;
	flags |= sinfo.stream_flags;

	do {
		if (!quic_sock_stream_writable(sk, stream, flags, len)) {
			if (delay) {
				quic_outq_set_force_delay(outq, 0);
				quic_outq_transmit(sk);
			}
			err = quic_wait_for_stream_send(sk, stream, flags, len);
			if (err) {
				if (err == -EPIPE || !bytes)
					goto err;
				goto out;
			}
		}

		len = quic_outq_stream_append(sk, &msginfo, 0);
		if (len >= 0) {
			if (!sk_wmem_schedule(sk, len))
				continue;
			bytes += quic_outq_stream_append(sk, &msginfo, 1);
			len = 1;
			continue;
		}

		frame = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo);
		if (!frame) {
			if (!bytes) {
				err = -ENOMEM;
				goto err;
			}
			goto out;
		}
		len = frame->bytes;
		if (!sk_wmem_schedule(sk, len)) {
			iov_iter_revert(msginfo.msg, len);
			quic_frame_put(frame);
			continue;
		}
		bytes += frame->bytes;
		quic_outq_set_force_delay(outq, delay);
		quic_outq_stream_tail(sk, frame, delay);
		len = 1;
	} while (iov_iter_count(msginfo.msg) > 0);
out:
	err = bytes;
err:
	if (err < 0 && !has_hinfo && !(flags & MSG_DATAGRAM))
		err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}

static int quic_wait_for_packet(struct sock *sk, int nonblock)
{
	struct list_head *head = quic_inq_recv_list(quic_inq(sk));
	long timeo = sock_rcvtimeo(sk, nonblock);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -ENOTCONN;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -ENOTCONN;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
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

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
			int *addr_len)
{
	int nonblock = flags & MSG_DONTWAIT;
#else
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
			int flags, int *addr_len)
{
#endif
	u32 off, flen, copy, copied = 0, freed = 0, bytes = 0;
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_stream *stream = NULL;
	struct quic_frame *frame, *next;
	u8 fin, dgram, level, event = 0;
	struct list_head *head;
	int err;

	lock_sock(sk);

	err = quic_wait_for_packet(sk, nonblock);
	if (err)
		goto out;

	head = quic_inq_recv_list(quic_inq(sk));
	list_for_each_entry_safe(frame, next, head, list) {
		off = (u32)frame->offset;
		flen = (u32)frame->len;
		copy = min((u32)(flen - off), (u32)(len - copied));
		if (copy) {
			copy = copy_to_iter(frame->data + off, copy, &msg->msg_iter);
			if (!copy) {
				if (!copied) {
					err = -EFAULT;
					goto out;
				}
				break;
			}
			copied += copy;
		}
		fin = frame->stream_fin;
		event = frame->event;
		dgram = frame->dgram;
		level = frame->level;
		stream = frame->stream;
		if (event) {
			msg->msg_flags |= MSG_NOTIFICATION;
		} else if (level) {
			hinfo.crypto_level = level;
			put_cmsg(msg, SOL_QUIC, QUIC_HANDSHAKE_INFO, sizeof(hinfo), &hinfo);
			if (msg->msg_flags & MSG_CTRUNC) {
				err = -EINVAL;
				goto out;
			}
		} else if (dgram) {
			msg->msg_flags |= MSG_DATAGRAM;
		}
		if (flags & MSG_PEEK)
			break;
		if (copy != flen - off) {
			frame->offset += copy;
			break;
		}
		msg->msg_flags |= MSG_EOR;
		bytes += flen;
		if (event) {
			list_del(&frame->list);
			quic_frame_put(frame);
			break;
		}
		if (level || dgram) {
			list_del(&frame->list);
			quic_frame_put(frame);
			break;
		}
		freed += flen;
		list_del(&frame->list);
		quic_frame_put(frame);
		if (fin) {
			stream->recv.state = QUIC_STREAM_RECV_STATE_READ;
			sinfo.stream_flags |= MSG_STREAM_FIN;
			break;
		}

		if (list_entry_is_head(next, head, list) || copied >= len)
			break;
		if (next->event || next->dgram || !next->stream || next->stream != stream)
			break;
	};

	if (stream) {
		sinfo.stream_id = stream->id;
		put_cmsg(msg, SOL_QUIC, QUIC_STREAM_INFO, sizeof(sinfo), &sinfo);
		if (msg->msg_flags & MSG_CTRUNC)
			msg->msg_flags |= sinfo.stream_flags;

		quic_inq_flow_control(sk, stream, freed);
		if (stream->recv.state == QUIC_STREAM_RECV_STATE_READ) {
			quic_inq_stream_list_purge(sk, stream);
			quic_stream_recv_put(quic_streams(sk), stream, quic_is_serv(sk));
		}
	}

	quic_inq_data_read(sk, bytes);
	err = (int)copied;
out:
	release_sock(sk);
	return err;
}

static int quic_wait_for_accept(struct sock *sk, u32 flags)
{
	long timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
	struct list_head *head = quic_reqs(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		if (!quic_is_listen(sk)) {
			err = -EINVAL;
			pr_debug("%s: sk not listening\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EINVAL;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
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

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_param_check_and_copy(struct quic_transport_param *p,
				     struct quic_transport_param *param)
{
	if (p->max_udp_payload_size) {
		if (p->max_udp_payload_size < QUIC_MIN_UDP_PAYLOAD ||
		    p->max_udp_payload_size > QUIC_MAX_UDP_PAYLOAD)
			return -EINVAL;
		param->max_udp_payload_size = p->max_udp_payload_size;
	}
	if (p->ack_delay_exponent) {
		if (p->ack_delay_exponent > QUIC_MAX_ACK_DELAY_EXPONENT)
			return -EINVAL;
		param->ack_delay_exponent = p->ack_delay_exponent;
	}
	if (p->max_ack_delay) {
		if (p->max_ack_delay >= QUIC_MAX_ACK_DELAY)
			return -EINVAL;
		param->max_ack_delay = p->max_ack_delay;
	}
	if (p->active_connection_id_limit) {
		if (p->active_connection_id_limit < QUIC_CONN_ID_LEAST ||
		    p->active_connection_id_limit > QUIC_CONN_ID_LIMIT)
			return -EINVAL;
		param->active_connection_id_limit = p->active_connection_id_limit;
	}
	if (p->max_idle_timeout) {
		if (p->max_idle_timeout < QUIC_MIN_IDLE_TIMEOUT)
			return -EINVAL;
		param->max_idle_timeout = p->max_idle_timeout;
	}
	if (p->max_datagram_frame_size) {
		if (p->max_datagram_frame_size < QUIC_PATH_MIN_PMTU)
			return -EINVAL;
		param->max_datagram_frame_size = p->max_datagram_frame_size;
	}
	if (p->max_data) {
		if (p->max_data < QUIC_PATH_MIN_PMTU ||
		    (!p->remote && p->max_data > (S32_MAX / 2)))
			return -EINVAL;
		param->max_data = p->max_data;
	}
	if (p->max_stream_data_bidi_local) {
		if (p->max_stream_data_bidi_local < QUIC_PATH_MIN_PMTU ||
		    (!p->remote && p->max_stream_data_bidi_local > (S32_MAX / 4)))
			return -EINVAL;
		param->max_stream_data_bidi_local = p->max_stream_data_bidi_local;
	}
	if (p->max_stream_data_bidi_remote) {
		if (p->max_stream_data_bidi_remote < QUIC_PATH_MIN_PMTU ||
		    (!p->remote && p->max_stream_data_bidi_remote > (S32_MAX / 4)))
			return -EINVAL;
		param->max_stream_data_bidi_remote = p->max_stream_data_bidi_remote;
	}
	if (p->max_stream_data_uni) {
		if (p->max_stream_data_uni < QUIC_PATH_MIN_PMTU ||
		    (!p->remote && p->max_stream_data_uni > (S32_MAX / 4)))
			return -EINVAL;
		param->max_stream_data_uni = p->max_stream_data_uni;
	}
	if (p->max_streams_bidi) {
		if (p->max_streams_bidi > QUIC_MAX_STREAMS) {
			if (!p->remote)
				return -EINVAL;
			p->max_streams_bidi = QUIC_MAX_STREAMS;
		}
		param->max_streams_bidi = p->max_streams_bidi;
	}
	if (p->max_streams_uni) {
		if (p->max_streams_uni > QUIC_MAX_STREAMS) {
			if (!p->remote)
				return -EINVAL;
			p->max_streams_uni = QUIC_MAX_STREAMS;
		}
		param->max_streams_uni = p->max_streams_uni;
	}
	if (p->disable_active_migration)
		param->disable_active_migration = p->disable_active_migration;
	if (p->disable_1rtt_encryption)
		param->disable_1rtt_encryption = p->disable_1rtt_encryption;
	if (p->disable_compatible_version)
		param->disable_compatible_version = p->disable_compatible_version;
	if (p->grease_quic_bit)
		param->grease_quic_bit = p->grease_quic_bit;
	if (p->stateless_reset)
		param->stateless_reset = p->stateless_reset;

	return 0;
}

static int quic_sock_set_config(struct sock *sk, struct quic_config *c, u32 len)
{
	struct quic_config *config = quic_config(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_cong *cong = quic_cong(sk);

	if (len < sizeof(*config) || quic_is_established(sk))
		return -EINVAL;

	if (c->validate_peer_address)
		config->validate_peer_address = c->validate_peer_address;
	if (c->receive_session_ticket)
		config->receive_session_ticket = c->receive_session_ticket;
	if (c->certificate_request) {
		if (c->certificate_request > 3)
			return -EINVAL;
		config->certificate_request = c->certificate_request;
	}
	if (c->initial_smoothed_rtt) {
		if (c->initial_smoothed_rtt < QUIC_RTO_MIN ||
		    c->initial_smoothed_rtt > QUIC_RTO_MAX)
			return -EINVAL;
		config->initial_smoothed_rtt = c->initial_smoothed_rtt;
		quic_cong_set_srtt(cong, config->initial_smoothed_rtt);
	}
	if (c->plpmtud_probe_interval) {
		if (c->plpmtud_probe_interval < QUIC_MIN_PROBE_TIMEOUT)
			return -EINVAL;
		config->plpmtud_probe_interval = c->plpmtud_probe_interval;
	}
	if (c->payload_cipher_type) {
		if (c->payload_cipher_type != TLS_CIPHER_AES_GCM_128 &&
		    c->payload_cipher_type != TLS_CIPHER_AES_GCM_256 &&
		    c->payload_cipher_type != TLS_CIPHER_AES_CCM_128 &&
		    c->payload_cipher_type != TLS_CIPHER_CHACHA20_POLY1305)
			return -EINVAL;
		config->payload_cipher_type = c->payload_cipher_type;
	}
	if (c->version) {
		config->version = c->version;
		quic_packet_set_version(packet, c->version);
	}
	if (c->congestion_control_algo) {
		config->congestion_control_algo = c->congestion_control_algo;
		quic_cong_set_algo(cong, config->congestion_control_algo);
	}
	if (c->stream_data_nodelay)
		config->stream_data_nodelay = c->stream_data_nodelay;

	return 0;
}

static int quic_sock_set_transport_param(struct sock *sk, struct quic_transport_param *p, u32 len)
{
	struct quic_transport_param param = {};

	if (len < sizeof(param) || quic_is_established(sk))
		return -EINVAL;

	if (p->remote && !quic_is_establishing(sk))
		return -EINVAL;

	param.remote = p->remote;
	quic_sock_fetch_transport_param(sk, &param);

	if (quic_param_check_and_copy(p, &param))
		return -EINVAL;

	quic_sock_apply_transport_param(sk, &param);
	return 0;
}

static int quic_copy_sock(struct sock *nsk, struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_transport_param param = {};
	struct sk_buff *skb, *tmp;
	u32 events, type;

	if (quic_data_dup(quic_alpn(nsk), quic_alpn(sk)->data, quic_alpn(sk)->len))
		return -ENOMEM;

	nsk->sk_type = sk->sk_type;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;

	inet_sk(nsk)->pmtudisc = inet_sk(sk)->pmtudisc;

	skb_queue_walk_safe(quic_inq_backlog_list(inq), skb, tmp) {
		quic_get_msg_addrs(&packet->saddr, &packet->daddr, skb);
		quic_packet_get_dcid(&packet->dcid, skb);
		if (!memcmp(&req->saddr, &packet->saddr, sizeof(req->saddr)) &&
		    !memcmp(&req->daddr, &packet->daddr, sizeof(req->daddr)) &&
		    !quic_conn_id_cmp(&req->dcid, &packet->dcid)) {
			__skb_unlink(skb, quic_inq_backlog_list(inq));
			quic_inq_backlog_tail(nsk, skb);
		}
	}

	if (sk->sk_family == AF_INET6) /* nsk uses quicv6 ops in this case */
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	quic_sock_set_config(nsk, quic_config(sk), sizeof(struct quic_config));
	quic_sock_fetch_transport_param(sk, &param);
	quic_sock_apply_transport_param(nsk, &param);
	events = quic_inq_events(inq);
	inq = quic_inq(nsk);
	quic_inq_set_events(inq, events);

	type = quic_crypto_cipher_type(crypto);
	crypto = quic_crypto(nsk, QUIC_CRYPTO_APP);
	quic_crypto_set_cipher_type(crypto, type);

	return 0;
}

static int quic_accept_sock_init(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id;
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	int err;

	lock_sock(sk);
	quic_path_set_daddr(paths, 0, &req->daddr);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, &req->daddr, false);

	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(quic_source(sk), &conn_id, 0, sk);
	if (err)
		goto out;
	err = quic_conn_id_add(quic_dest(sk), &req->scid, 0, NULL);
	if (err)
		goto out;

	err = quic_crypto_initial_keys_install(crypto, &req->dcid, req->version, 1);
	if (err)
		goto out;
	quic_packet_set_version(packet, req->version);

	quic_path_set_orig_dcid(paths, &req->orig_dcid);
	if (req->retry) {
		quic_path_set_retry(paths, 1);
		quic_path_set_retry_dcid(paths, &req->dcid);
	}

	err = sk->sk_prot->hash(sk);
	if (err)
		goto out;

	quic_timer_start(sk, QUIC_TIMER_IDLE, quic_inq_timeout(inq));
	quic_set_state(sk, QUIC_SS_ESTABLISHING);

	__skb_queue_head_init(&tmpq);
	skb_queue_splice_init(quic_inq_backlog_list(inq), &tmpq);
	skb = __skb_dequeue(&tmpq);
	while (skb) {
		quic_packet_process(sk, skb);
		skb = __skb_dequeue(&tmpq);
	}

out:
	release_sock(sk);
	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
static struct sock *quic_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	int flags = arg->flags, *errp = &arg->err;
	bool kern = arg->kern;
#else
static struct sock *quic_accept(struct sock *sk, int flags, int *errp, bool kern)
{
#endif
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_INITIAL);
	struct quic_request_sock *req = NULL;
	struct sock *nsk = NULL;
	int err = -EINVAL;

	lock_sock(sk);

	if (!quic_is_listen(sk))
		goto out;

	err = quic_wait_for_accept(sk, flags);
	if (err)
		goto out;
	req = quic_request_sock_dequeue(sk);

	nsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL, sk->sk_prot, kern);
	if (!nsk) {
		err = -ENOMEM;
		goto out;
	}
	sock_init_data(NULL, nsk);

	quic_path_set_serv(quic_paths(nsk));

	err = nsk->sk_prot->init(nsk);
	if (err)
		goto free;

	err = quic_copy_sock(nsk, sk, req);
	if (err)
		goto free;
	err = nsk->sk_prot->bind(nsk, &req->saddr.sa, sizeof(req->saddr));
	if (err)
		goto free;

	err = quic_accept_sock_init(nsk, req);
	if (err)
		goto free;

	quic_pnspace_set_time(space, jiffies_to_usecs(jiffies));
out:
	release_sock(sk);
	*errp = err;
	kfree(req);
	return nsk;
free:
	nsk->sk_prot->close(nsk, 0);
	nsk = NULL;
	goto out;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock(sk);

	quic_outq_transmit_app_close(sk);

	quic_set_state(sk, QUIC_SS_CLOSED);

	quic_outq_free(sk);
	quic_inq_free(sk);

	quic_path_free(sk, quic_paths(sk), 0);
	quic_path_free(sk, quic_paths(sk), 1);

	quic_conn_id_set_free(quic_source(sk));
	quic_conn_id_set_free(quic_dest(sk));

	release_sock(sk);
	sk_common_release(sk);
}

static int quic_sock_connection_migrate(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr a;
	int err;

	if (quic_get_user_addr(sk, &a, addr, addr_len))
		return -EINVAL;
	if (!quic_path_saddr(paths, 0)->v4.sin_port || !quic_path_cmp_saddr(paths, 0, &a))
		return -EINVAL;

	if (!quic_is_established(sk)) { /* set preferred address param */
		if (!quic_is_serv(sk) || quic_path_disable_saddr_alt(paths))
			return -EINVAL;
		quic_path_set_pref_addr(paths, 1);
		quic_path_set_saddr(paths, 1, &a);
		return 0;
	}

	if (a.sa.sa_family != quic_path_saddr(paths, 0)->sa.sa_family || !a.v4.sin_port)
		return -EINVAL;
	if (!quic_path_alt_state(paths, QUIC_PATH_ALT_NONE) || quic_path_pref_addr(paths))
		return -EAGAIN;

	quic_path_set_saddr(paths, 1, &a);
	quic_path_set_daddr(paths, 1, quic_path_daddr(paths, 0));

	if (quic_packet_config(sk, 0, 1))
		return -EINVAL;
	if (quic_path_bind(sk, paths, 1))
		return -EINVAL;
	err = quic_outq_probe_path_alt(sk, false);
	if (err)
		quic_path_free(sk, paths, 1);
	return err;
}

static int quic_sock_set_token(struct sock *sk, void *data, u32 len)
{
	if (quic_is_serv(sk)) {
		if (quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_TOKEN, NULL, 0, false))
			return -ENOMEM;
		return 0;
	}

	if (!len || len > 120)
		return -EINVAL;

	return quic_data_dup(quic_token(sk), data, len);
}

static int quic_sock_set_session_ticket(struct sock *sk, u8 *data, u32 len)
{
	if (len < 64 || len > 4096)
		return -EINVAL;

	return quic_data_dup(quic_ticket(sk), data, len);
}

static int quic_sock_set_transport_params_ext(struct sock *sk, u8 *p, u32 len)
{
	struct quic_transport_param param = {};
	u32 errcode;

	if (!quic_is_establishing(sk))
		return -EINVAL;

	param.remote = 1;
	if (quic_frame_parse_transport_params_ext(sk, &param, p, len)) {
		errcode = QUIC_TRANSPORT_ERROR_TRANSPORT_PARAM;
		quic_outq_transmit_close(sk, 0, errcode, QUIC_CRYPTO_INITIAL);
		return -EINVAL;
	}

	quic_sock_apply_transport_param(sk, &param);
	return 0;
}

static int quic_sock_set_crypto_secret(struct sock *sk, struct quic_crypto_secret *secret, u32 len)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_config *c = quic_config(sk);
	struct quic_crypto *crypto;
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	int err;

	if (len != sizeof(*secret))
		return -EINVAL;

	if (secret->level != QUIC_CRYPTO_APP &&
	    secret->level != QUIC_CRYPTO_EARLY &&
	    secret->level != QUIC_CRYPTO_HANDSHAKE)
		return -EINVAL;

	crypto = quic_crypto(sk, secret->level);
	err = quic_crypto_set_secret(crypto, secret, packet->version, 0);
	if (err)
		return err;

	if (secret->level != QUIC_CRYPTO_APP) {
		if (secret->send) { /* 0rtt or handshake send key is ready */
			if (secret->level == QUIC_CRYPTO_EARLY) /* 0rtt send key is ready */
				quic_outq_set_data_level(outq, QUIC_CRYPTO_EARLY);
			return 0;
		}
		__skb_queue_head_init(&tmpq);
		skb_queue_splice_init(quic_inq_backlog_list(inq), &tmpq);
		skb = __skb_dequeue(&tmpq);
		while (skb) {
			quic_packet_process(sk, skb);
			skb = __skb_dequeue(&tmpq);
		}
		return 0;
	}

	if (secret->send) { /* app send key is ready */
		quic_outq_set_data_level(outq, QUIC_CRYPTO_APP);
		if (!quic_crypto_recv_ready(crypto))
			return 0;
		goto out;
	}

	/* app recv key is ready */
	quic_data_free(quic_ticket(sk)); /* clean it to receive new session ticket msg */
	quic_data_free(quic_token(sk)); /* clean it to receive new token */
	if (!list_empty(quic_inq_early_list(inq))) {
		list_splice_init(quic_inq_early_list(inq), quic_inq_recv_list(inq));
		sk->sk_data_ready(sk);
	}
	__skb_queue_head_init(&tmpq);
	skb_queue_splice_init(quic_inq_backlog_list(inq), &tmpq);
	skb = __skb_dequeue(&tmpq);
	while (skb) {
		quic_packet_process(sk, skb);
		skb = __skb_dequeue(&tmpq);
	}

	/* enter established only when both send and recv keys are ready */
	if (!quic_crypto_send_ready(crypto))
		return 0;
	if (!quic_is_serv(sk))
		goto out;

	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAP_MAX_PN, 0, -1, 0);
	if (quic_path_pref_addr(paths)) {
		err = quic_path_bind(sk, paths, 1);
		if (err)
			return err;
	}

	if (quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_TOKEN, NULL, 0, true))
		return -ENOMEM;
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL, 0, true))
		return -ENOMEM;
out:
	if (quic_outq_transmit_new_conn_id(sk, 0, 0, false))
		return -ENOMEM;
	quic_timer_start(sk, QUIC_TIMER_PMTU, c->plpmtud_probe_interval);
	quic_set_state(sk, QUIC_SS_ESTABLISHED);
	quic_timer_reset_path(sk);
	return 0;
}

static int quic_sock_set_connection_id(struct sock *sk,
				       struct quic_connection_id_info *info, u32 len)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_conn_id *active, *old;
	u64 number, first, last;

	if (len < sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	if (info->dest) {
		id_set = quic_dest(sk);
		if (id_set->alt)
			return -EAGAIN;
	}
	old = quic_conn_id_active(id_set);
	if (info->active) {
		active = quic_conn_id_active(id_set);
		if (info->active <= quic_conn_id_number(active))
			return -EINVAL;
		active = quic_conn_id_find(id_set, info->active);
		if (!active)
			return -EINVAL;
		quic_conn_id_set_active(id_set, active);
	}

	if (!info->prior_to)
		return 0;

	number = info->prior_to;
	last = quic_conn_id_last_number(id_set);
	first = quic_conn_id_first_number(id_set);
	if (number > last || number <= first) {
		quic_conn_id_set_active(id_set, old);
		return -EINVAL;
	}

	if (!info->dest) {
		if (quic_outq_transmit_new_conn_id(sk, number, 0, false)) {
			quic_conn_id_set_active(id_set, old);
			return -ENOMEM;
		}
		return 0;
	}

	number--;
	if (quic_outq_transmit_retire_conn_id(sk, number, 0, false)) {
		quic_conn_id_set_active(id_set, old);
		return -ENOMEM;
	}

	return 0;
}

#define QUIC_ALPN_MAX_LEN	128

static int quic_sock_set_alpn(struct sock *sk, u8 *data, u32 len)
{
	struct quic_data *alpns = quic_alpn(sk);
	u8 *p;

	if (!len || len > QUIC_ALPN_MAX_LEN || quic_is_listen(sk))
		return -EINVAL;

	p = kzalloc(len + 1, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	kfree(alpns->data);
	alpns->data = p;
	alpns->len  = len + 1;

	quic_data_from_string(alpns, data, len);
	return 0;
}

static int quic_sock_stream_reset(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream;
	struct quic_frame *frame;

	if (len != sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	stream = quic_stream_send_get(streams, info->stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (stream->send.state >= QUIC_STREAM_SEND_STATE_RECVD)
		return -EINVAL;

	frame = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, info);
	if (!frame)
		return -ENOMEM;

	stream->send.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	quic_outq_stream_list_purge(sk, stream);
	quic_outq_ctrl_tail(sk, frame, false);
	return 0;
}

static int quic_sock_stream_stop_sending(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream;

	if (len != sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	stream = quic_stream_recv_get(streams, info->stream_id, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		return -EINVAL;

	return quic_outq_transmit_frame(sk, QUIC_FRAME_STOP_SENDING, info, 0, false);
}

static int quic_sock_set_event(struct sock *sk, struct quic_event_option *event, u32 len)
{
	struct quic_inqueue *inq = quic_inq(sk);
	u32 events;

	if (len != sizeof(*event))
		return -EINVAL;
	if (!event->type || event->type > QUIC_EVENT_MAX)
		return -EINVAL;

	events = quic_inq_events(inq);
	if (event->on) {
		quic_inq_set_events(inq, events | (1 << (event->type)));
		return 0;
	}
	quic_inq_set_events(inq, events & ~(1 << event->type));
	return 0;
}

static int quic_sock_set_connection_close(struct sock *sk, struct quic_connection_close *close,
					  u32 len)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *data;

	if (len < sizeof(*close))
		return -EINVAL;

	len -= sizeof(*close);
	if (len > QUIC_CLOSE_PHRASE_MAX_LEN + 1)
		return -EINVAL;

	if (len) {
		if (close->phrase[len - 1])
			return -EINVAL;
		data = kmemdup(close->phrase, len, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
		quic_outq_set_close_phrase(outq, data);
	}

	quic_outq_set_close_errcode(outq, close->errcode);
	return 0;
}

static int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval, unsigned int optlen)
{
	void *kopt = NULL;
	int retval = 0;

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
		retval = quic_sock_connection_migrate(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_KEY_UPDATE:
		retval = quic_crypto_key_update(quic_crypto(sk, QUIC_CRYPTO_APP));
		break;
	case QUIC_SOCKOPT_CONNECTION_ID:
		retval = quic_sock_set_connection_id(sk, kopt, optlen);
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
	case QUIC_SOCKOPT_CONFIG:
		retval = quic_sock_set_config(sk, kopt, optlen);
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

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	if (level != SOL_QUIC)
		return quic_common_setsockopt(sk, level, optname, optval, optlen);

	return quic_do_setsockopt(sk, optname, optval, optlen);
}

int quic_sock_setopt(struct sock *sk, int optname, void *optval, unsigned int optlen)
{
	return quic_do_setsockopt(sk, optname, KERNEL_SOCKPTR(optval), optlen);
}
EXPORT_SYMBOL_GPL(quic_sock_setopt);

static int quic_sock_get_token(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_data *token = quic_token(sk);

	if (quic_is_serv(sk) || len < token->len)
		return -EINVAL;
	len = token->len;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, token->data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_session_ticket(struct sock *sk, u32 len,
					sockptr_t optval, sockptr_t optlen)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	u8 *ticket = quic_ticket(sk)->data, key[64];
	u32 tlen = quic_ticket(sk)->len;
	union quic_addr a;

	if (!quic_is_serv(sk)) {
		if (quic_is_established(sk) && !quic_crypto_ticket_ready(crypto))
			tlen = 0;
		goto out;
	}

	if (tlen)
		goto out;

	crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	memcpy(&a, quic_path_daddr(quic_paths(sk), 0), sizeof(a));
	a.v4.sin_port = 0;
	if (quic_crypto_generate_session_ticket_key(crypto, &a, sizeof(a), key, 64))
		return -EINVAL;
	ticket = key;
	tlen = 64;
out:
	if (len < tlen)
		return -EINVAL;
	len = tlen;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, ticket, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_param(struct sock *sk, u32 len,
					 sockptr_t optval, sockptr_t optlen)
{
	struct quic_transport_param param = {};

	if (len < sizeof(param))
		return -EINVAL;
	len = sizeof(param);
	if (copy_from_sockptr(&param, optval, len))
		return -EFAULT;

	quic_sock_fetch_transport_param(sk, &param);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &param, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_config(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_config config, *c = quic_config(sk);

	if (len < sizeof(config))
		return -EINVAL;
	len = sizeof(config);

	config = *c;
	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &config, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_params_ext(struct sock *sk, u32 len,
					      sockptr_t optval, sockptr_t optlen)
{
	struct quic_transport_param param = {};
	u32 datalen = 0;
	u8 data[256];

	if (!quic_is_establishing(sk))
		return -EINVAL;

	quic_sock_fetch_transport_param(sk, &param);

	if (quic_frame_build_transport_params_ext(sk, &param, data, &datalen))
		return -EINVAL;
	if (len < datalen)
		return -EINVAL;
	len = datalen;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_crypto_secret(struct sock *sk, u32 len,
				       sockptr_t optval, sockptr_t optlen)
{
	struct quic_crypto_secret secret = {};

	if (len < sizeof(secret))
		return -EINVAL;
	len = sizeof(secret);
	if (copy_from_sockptr(&secret, optval, len))
		return -EFAULT;

	if (secret.level >= QUIC_CRYPTO_MAX)
		return -EINVAL;
	if (quic_crypto_get_secret(quic_crypto(sk, secret.level), &secret))
		return -EINVAL;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &secret, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_connection_id(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_connection_id_info info;
	struct quic_conn_id_set *id_set;
	struct quic_conn_id *active;

	if (len < sizeof(info) || !quic_is_established(sk))
		return -EINVAL;
	len = sizeof(info);
	if (copy_from_sockptr(&info, optval, len))
		return -EFAULT;

	id_set = info.dest ? quic_dest(sk) : quic_source(sk);
	active = quic_conn_id_active(id_set);
	info.active = quic_conn_id_number(active);
	info.prior_to = quic_conn_id_first_number(id_set);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &info, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_alpn(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_data *alpns = quic_alpn(sk);
	u8 data[128];

	if (!alpns->len) {
		len = 0;
		goto out;
	}
	if (len < alpns->len)
		return -EINVAL;

	quic_data_to_string(data, &len, alpns);

out:
	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_stream_open(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream_info sinfo;
	struct quic_stream *stream;

	if (len < sizeof(sinfo))
		return -EINVAL;
	len = sizeof(sinfo);
	if (copy_from_sockptr(&sinfo, optval, len))
		return -EFAULT;

	if (sinfo.stream_flags & ~QUIC_MSG_STREAM_FLAGS)
		return -EINVAL;

	if (sinfo.stream_id == -1) {
		sinfo.stream_id = quic_stream_send_next_bidi_id(streams);
		if (sinfo.stream_flags & MSG_STREAM_UNI)
			sinfo.stream_id = quic_stream_send_next_uni_id(streams);
	}
	sinfo.stream_flags |= MSG_STREAM_NEW;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &sinfo, len))
		return -EFAULT;

	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	return 0;
}

static int quic_sock_get_event(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_event_option event;

	if (len < sizeof(event))
		return -EINVAL;
	len = sizeof(event);
	if (copy_from_sockptr(&event, optval, len))
		return -EFAULT;

	if (!event.type || event.type > QUIC_EVENT_MAX)
		return -EINVAL;
	event.on = !!(quic_inq_events(inq) & (1 << event.type));

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &event, len))
		return -EFAULT;

	return 0;
}

static int quic_sock_get_connection_close(struct sock *sk, u32 len, sockptr_t optval,
					  sockptr_t optlen)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close *close;
	u8 *phrase, frame[100] = {};
	u32 phrase_len = 0;

	phrase = quic_outq_close_phrase(outq);
	if (phrase)
		phrase_len = strlen(phrase) + 1;
	if (len < sizeof(*close) + phrase_len)
		return -EINVAL;

	len = sizeof(*close) + phrase_len;
	close = (void *)frame;
	close->errcode = quic_outq_close_errcode(outq);
	close->frame = quic_outq_close_frame(outq);

	if (phrase_len)
		strscpy(close->phrase, phrase, phrase_len);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, close, len))
		return -EFAULT;
	return 0;
}

static int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval, sockptr_t optlen)
{
	int retval = 0;
	u32 len;

	if (copy_from_sockptr(&len, optlen, sizeof(len)))
		return -EFAULT;

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
	case QUIC_SOCKOPT_CONNECTION_ID:
		retval = quic_sock_get_connection_id(sk, len, optval, optlen);
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
	case QUIC_SOCKOPT_CONFIG:
		retval = quic_sock_get_config(sk, len, optval, optlen);
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

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	if (level != SOL_QUIC)
		return quic_common_getsockopt(sk, level, optname, optval, optlen);

	return quic_do_getsockopt(sk, optname, USER_SOCKPTR(optval), USER_SOCKPTR(optlen));
}

int quic_sock_getopt(struct sock *sk, int optname, void *optval, unsigned int *optlen)
{
	return quic_do_getsockopt(sk, optname, KERNEL_SOCKPTR(optval), KERNEL_SOCKPTR(optlen));
}
EXPORT_SYMBOL_GPL(quic_sock_getopt);

static void quic_release_cb(struct sock *sk)
{
	/* similar to tcp_release_cb */
	unsigned long nflags, flags = smp_load_acquire(&sk->sk_tsq_flags);

	do {
		if (!(flags & QUIC_DEFERRED_ALL))
			return;
		nflags = flags & ~QUIC_DEFERRED_ALL;
	} while (!try_cmpxchg(&sk->sk_tsq_flags, &flags, nflags));

	if (flags & QUIC_F_MTU_REDUCED_DEFERRED) {
		quic_packet_rcv_err_pmtu(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_LOSS_DEFERRED) {
		quic_timer_loss_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_SACK_DEFERRED) {
		quic_timer_sack_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PATH_DEFERRED) {
		quic_timer_path_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PMTU_DEFERRED) {
		quic_timer_pmtu_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_TSQ_DEFERRED) {
		quic_timer_pace_handler(sk);
		__sock_put(sk);
	}
}

static int quic_disconnect(struct sock *sk, int flags)
{
	quic_set_state(sk, QUIC_SS_CLOSED); /* for a listen socket only */
	return 0;
}

static void quic_shutdown(struct sock *sk, int how)
{
	if (!(how & SEND_SHUTDOWN))
		goto out;

	quic_outq_transmit_app_close(sk);
out:
	quic_set_state(sk, QUIC_SS_CLOSED);
}

struct proto quic_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_packet_process,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_packet_process,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	= sizeof(struct quic6_sock),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.sockets_allocated	=  &quic_sockets_allocated,
};
