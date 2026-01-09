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
#include <asm/ioctls.h>
#include <net/tls.h>

#include "socket.h"

static DEFINE_PER_CPU(int, quic_memory_per_cpu_fw_alloc);
static unsigned long quic_memory_pressure;
static atomic_long_t quic_memory_allocated;

static void quic_enter_memory_pressure(struct sock *sk)
{
	WRITE_ONCE(quic_memory_pressure, 1);
}

/* Check if a matching request sock already exists.  Match is based on source/destination
 * addresses and DCID.
 */
struct quic_request_sock *quic_request_sock_lookup(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	list_for_each_entry(req, quic_reqs(sk), list) {
		if (!memcmp(&req->saddr, &packet->saddr, sizeof(req->saddr)) &&
		    !memcmp(&req->daddr, &packet->daddr, sizeof(req->daddr)) &&
		    !quic_conn_id_cmp(&req->dcid, &packet->dcid))
			return req;
	}
	return NULL;
}

/* Create and enqueue a QUIC request sock for a new incoming connection. */
struct quic_request_sock *quic_request_sock_create(struct sock *sk, struct quic_conn_id *odcid,
						   u8 retry)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk)) /* Refuse new request if the accept queue is full. */
		return NULL;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return NULL;

	req->version = packet->version;
	req->daddr = packet->daddr;
	req->saddr = packet->saddr;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->retry = retry;

	skb_queue_head_init(&req->backlog_list);

	/* Enqueue request into the listen socket’s pending list for accept(). */
	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return req;
}

int quic_request_sock_backlog_tail(struct sock *sk, struct quic_request_sock *req,
				   struct sk_buff *skb)
{
	/* Use listen sock sk_rcvbuf to limit the request sock's backlog len. */
	if (req->blen + skb->len > sk->sk_rcvbuf)
		return -ENOMEM;

	__skb_queue_tail(&req->backlog_list, skb);
	req->blen += skb->len;
	sk->sk_data_ready(sk);
	return 0;
}

static void quic_request_sock_free(struct sock *sk, struct quic_request_sock *req)
{
	__skb_queue_purge(&req->backlog_list);
	list_del_init(&req->list);
	sk_acceptq_removed(sk);
	kfree(req);
}

/* Check if a matching accept socket exists.  This is needed because an accept socket
 * might have been created after this packet was enqueued in the listen socket's backlog.
 */
bool quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	bool exist = false;

	/* Skip if packet is newer than the last accept socket creation time.  No matching
	 * socket could exist in this case.
	 */
	if (QUIC_SKB_CB(skb)->time > quic_pnspace(sk, QUIC_CRYPTO_INITIAL)->time)
		return exist;

	/* Look up an accepted socket that matches the packet's addresses and DCID. */
	local_bh_disable();
	sk = quic_sock_lookup(skb, &packet->saddr, &packet->daddr, &packet->dcid);
	if (!sk)
		goto out;

	/* Found a matching accept socket. Process the packet with this socket. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf)))
			kfree_skb(skb);
		else
			cb->backlog = 1;
	} else {
		/* Socket not busy: process immediately. */
		cb->backlog = 0;
		sk->sk_backlog_rcv(sk, skb); /* quic_packet_process(). */
	}
	bh_unlock_sock(sk);
	sock_put(sk);
	exist = true;
out:
	local_bh_enable();
	return exist;
}

/* Lookup a connected QUIC socket based on address and dest connection ID.
 *
 * This function searches the established (non-listening) QUIC socket table for a socket that
 * matches the source and dest addresses and, optionally, the dest connection ID (DCID). The
 * value returned by quic_path_orig_dcid() might be the original dest connection ID from the
 * ClientHello or the Source Connection ID from a Retry packet before.
 *
 * The DCID is provided from a handshake packet when searching by source connection ID fails,
 * such as when the peer has not yet received server's response and updated the DCID.
 *
 * Return: A pointer to the matching connected socket, or NULL if no match is found.
 */
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
			      struct quic_conn_id *dcid)
{
	struct net *net = sock_net(skb->sk);
	struct quic_path_group *paths;
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	struct sock *sk = NULL, *tmp;
	unsigned int hash;

	hash = quic_sock_hash(net, sa, da);
	head = quic_sock_head(hash);

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(tmp, node, &head->head) {
		if (net != sock_net(tmp))
			continue;
		paths = quic_paths(tmp);
		if (quic_cmp_sk_addr(tmp, quic_path_saddr(paths, 0), sa) &&
		    quic_cmp_sk_addr(tmp, quic_path_daddr(paths, 0), da) &&
		    quic_path_usock(paths, 0) == skb->sk &&
		    (!dcid || !quic_conn_id_cmp(quic_path_orig_dcid(paths), dcid))) {
			sk = tmp;
			break;
		}
	}
	/* If the nulls value we got at the end of the iteration is different from the expected
	 * one, we must restart the lookup as the list was modified concurrently.
	 */
	if (!sk && get_nulls_value(node) != hash)
		goto begin;

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

/* Find the listening QUIC socket for an incoming packet.
 *
 * This function searches the QUIC socket table for a listening socket that matches the dest
 * address and port, and the ALPN(s) if presented in the ClientHello.  If multiple listening
 * sockets are bound to the same address, port, and ALPN(s) (e.g., via SO_REUSEPORT), this
 * function selects a socket from the reuseport group.
 *
 * Return: A pointer to the matching listening socket, or NULL if no match is found.
 */
struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
				     struct quic_data *alpns)
{
	struct net *net = sock_net(skb->sk);
	struct hlist_nulls_node *node;
	struct sock *sk = NULL, *tmp;
	struct quic_shash_head *head;
	struct quic_data alpn;
	union quic_addr *a;
	u32 hash, len;
	u64 length;
	u8 *p;

	hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
	head = quic_listen_sock_head(hash);

	rcu_read_lock();
begin:
	if (!alpns->len) { /* No ALPN entries present or failed to parse the ALPNs. */
		sk_nulls_for_each_rcu(tmp, node, &head->head) {
			/* If alpns->data != NULL, TLS parsing succeeded but no ALPN was found.
			 * In this case, only match sockets that have no ALPN set.
			 */
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) && quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    (!alpns->data || !quic_alpn(tmp)->len)) {
				sk = tmp;
				if (!quic_is_any_addr(a)) /* Prefer specific address match. */
					break;
			}
		}
		goto out;
	}

	/* ALPN present: loop through each ALPN entry. */
	for (p = alpns->data, len = alpns->len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&alpn, p, length);
		sk_nulls_for_each_rcu(tmp, node, &head->head) {
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) && quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    quic_data_has(quic_alpn(tmp), &alpn)) {
				sk = tmp;
				if (!quic_is_any_addr(a))
					break;
			}
		}
		if (sk)
			break;
	}
out:
	/* If the nulls value we got at the end of the iteration is different from the expected
	 * one, we must restart the lookup as the list was modified concurrently.
	 */
	if (!sk && get_nulls_value(node) != hash)
		goto begin;

	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_addr_hash(net, da), skb, 1);

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
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

/* Apply QUIC transport parameters to subcomponents of the socket. */
static void quic_sock_apply_transport_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set = p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_set_param(sk, p);
	quic_outq_set_param(sk, p);
	quic_conn_id_set_param(id_set, p);
	quic_path_set_param(quic_paths(sk), p);
	quic_stream_set_param(quic_streams(sk), p, quic_is_serv(sk));
}

/* Fetch QUIC transport parameters from subcomponents of the socket. */
static void quic_sock_fetch_transport_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set = p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_get_param(sk, p);
	quic_outq_get_param(sk, p);
	quic_conn_id_get_param(id_set, p);
	quic_path_get_param(quic_paths(sk), p);
	quic_stream_get_param(quic_streams(sk), p);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
static int quic_ioctl(struct sock *sk, int cmd, int *karg)
{
	int err = 0;

	lock_sock(sk);

	if (quic_is_listen(sk)) {
		err = -EINVAL;
		goto out;
	}

	switch (cmd) {
	case SIOCINQ:
		*karg = sk_rmem_alloc_get(sk);
		break;
	case SIOCOUTQ:
		*karg = sk_wmem_alloc_get(sk);
		break;
	case SIOCOUTQNSD:
		*karg = quic_outq(sk)->unsent_bytes;
		break;
	default:
		err = -ENOIOCTLCMD;
		break;
	}
out:
	release_sock(sk);
	return err;
}
#else
static int quic_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	int err = 0;

	lock_sock(sk);

	if (quic_is_listen(sk)) {
		err = -EINVAL;
		goto out;
	}

	switch (cmd) {
	case SIOCINQ:
		err = put_user(sk_rmem_alloc_get(sk), (int __user *)arg);
		break;
	case SIOCOUTQ:
		err = put_user(sk_wmem_alloc_get(sk), (int __user *)arg);
		break;
	case SIOCOUTQNSD:
		err = put_user(quic_outq(sk)->unsent_bytes, (int __user *)arg);
		break;
	default:
		err = -ENOIOCTLCMD;
		break;
	}
out:
	release_sock(sk);
	return err;
}
#endif

static int quic_init_sock(struct sock *sk)
{
	struct quic_transport_param *p = &quic_default_param;
	u8 i;

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	quic_conn_id_set_init(quic_source(sk), 1);
	quic_conn_id_set_init(quic_dest(sk), 0);
	quic_cong_init(quic_cong(sk));

	quic_sock_apply_transport_param(sk, p);

	quic_outq_init(sk);
	quic_inq_init(sk);
	quic_timer_init(sk);
	quic_packet_init(sk);

	if (quic_stream_init(quic_streams(sk)))
		return -ENOMEM;

	for (i = 0; i < QUIC_PNSPACE_MAX; i++) {
		if (quic_pnspace_init(quic_pnspace(sk, i)))
			return -ENOMEM;
	}

	WRITE_ONCE(sk->sk_sndbuf, READ_ONCE(sysctl_quic_wmem[1]));
	WRITE_ONCE(sk->sk_rcvbuf, READ_ONCE(sysctl_quic_rmem[1]));

	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	u8 i;

	quic_outq_free(sk);
	quic_inq_free(sk);
	quic_timer_free(sk);

	for (i = 0; i < QUIC_PNSPACE_MAX; i++)
		quic_pnspace_free(quic_pnspace(sk, i));
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_free(quic_crypto(sk, i));

	quic_path_unbind(sk, quic_paths(sk), 0);
	quic_path_unbind(sk, quic_paths(sk), 1);

	quic_conn_id_set_free(quic_source(sk));
	quic_conn_id_set_free(quic_dest(sk));

	quic_stream_free(quic_streams(sk));

	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));
	quic_data_free(quic_alpn(sk));

	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
}


#ifdef TLS_MIN_RECORD_SIZE_LIM
static int quic_bind(struct sock *sk, struct sockaddr_unsized *addr, int addr_len)
#else
static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
#endif
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr a;
	int err = -EINVAL;

	lock_sock(sk);

	if (quic_path_saddr(paths, 0)->v4.sin_port ||
	    quic_get_addr_from_user(sk, &a, (struct sockaddr *)addr, addr_len))
		goto out;

	quic_path_set_saddr(paths, 0, &a);
	err = quic_path_bind(sk, paths, 0);
	if (err) {
		memset(quic_path_saddr(paths, 0), 0, sizeof(a));
		goto out;
	}
	quic_set_sk_addr(sk, &a, true);

out:
	release_sock(sk);
	return err;
}

#ifdef TLS_MIN_RECORD_SIZE_LIM
static int quic_connect(struct sock *sk, struct sockaddr_unsized *addr, int addr_len)
#else
static int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
#endif
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
	if (!sk_unhashed(sk) || quic_get_addr_from_user(sk, &a, (struct sockaddr *)addr, addr_len))
		goto out;

	/* Set destination address and resolve route (may also auto-set source address). */
	quic_path_set_daddr(paths, 0, &a);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, &a, false);

	sa = quic_path_saddr(paths, 0);
	if (!sa->v4.sin_port) { /* Auto-bind if not already bound. */
		err = quic_path_bind(sk, paths, 0);
		if (err)
			goto out;
		quic_set_sk_addr(sk, sa, true);
	}

	/* Generate and add destination and source connection IDs. */
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(dest, &conn_id, 0, NULL);
	if (err)
		goto out;
	/* Save original DCID for validating server's transport parameters. */
	paths->orig_dcid = conn_id;
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(source, &conn_id, 0, sk);
	if (err)
		goto free;
	active = quic_conn_id_active(dest);

	/* Install initial encryption keys for handshake. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128, 0);
	if (err)
		goto free;
	err = quic_crypto_initial_keys_install(crypto, active, packet->version, 0);
	if (err)
		goto free;

	/* Add socket to hash table, change state to ESTABLISHING, and start idle timer. */
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);
out:
	release_sock(sk);
	return err;
free:
	quic_set_state(sk, QUIC_SS_CLOSED);
	quic_conn_id_set_free(source);
	quic_conn_id_set_free(dest);
	quic_crypto_free(crypto);
	goto out;
}

static int quic_hash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_data *alpns = quic_alpn(sk);
	struct net *net = sock_net(sk);
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	union quic_addr *sa, *da;
	struct sock *nsk;
	int err = 0, any;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (!quic_is_listen(sk)) { /* Hash a regular socket with source and dest addrs/ports. */
		head = quic_sock_head(quic_sock_hash(net, sa, da));
		spin_lock_bh(&head->lock);
		sock_set_flag(sk, SOCK_RCU_FREE);
		__sk_nulls_add_node_rcu(sk, &head->head);
		spin_unlock_bh(&head->lock);
		return 0;
	}

	/* Hash a listen socket with source port only. */
	head = quic_listen_sock_head(quic_listen_sock_hash(net, ntohs(sa->v4.sin_port)));
	spin_lock_bh(&head->lock);

	any = quic_is_any_addr(sa);
	sk_nulls_for_each(nsk, node, &head->head) {
		if (net == sock_net(nsk) && quic_cmp_sk_addr(nsk, quic_path_saddr(paths, 0), sa) &&
		    quic_path_usock(paths, 0) == quic_path_usock(quic_paths(nsk), 0)) {
			/* Take the ALPNs into account, which allows directing the request to
			 * different listening sockets based on the ALPNs.
			 */
			if (!quic_data_cmp(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				if (sk->sk_reuseport && nsk->sk_reuseport) {
					/* Support SO_REUSEPORT: allow multiple sockets with
					 * same addr/port/ALPNs.
					 */
					err = reuseport_add_sock(sk, nsk, any);
					if (!err) {
						sock_set_flag(sk, SOCK_RCU_FREE);
						__sk_nulls_add_node_rcu(sk, &head->head);
						INIT_LIST_HEAD(quic_reqs(sk));
					}
				}
				goto out;
			}
			/* If ALPNs partially match, also consider address in use. */
			if (quic_data_match(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				goto out;
			}
		}
	}

	if (sk->sk_reuseport) { /* If socket uses reuseport, allocate reuseport group. */
		err = reuseport_alloc(sk, any);
		if (err)
			goto out;
	}
	sock_set_flag(sk, SOCK_RCU_FREE);
	__sk_nulls_add_node_rcu(sk, &head->head);
	INIT_LIST_HEAD(quic_reqs(sk));
out:
	spin_unlock_bh(&head->lock);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_request_sock *req, *tmp;
	struct net *net = sock_net(sk);
	struct quic_shash_head *head;
	union quic_addr *sa, *da;

	if (sk_unhashed(sk))
		return;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (quic_is_listen(sk)) {
		/* Unhash a listen socket: clean up all pending connection requests. */
		list_for_each_entry_safe(req, tmp, quic_reqs(sk), list)
			quic_request_sock_free(sk, req);
		head = quic_listen_sock_head(quic_listen_sock_hash(net, ntohs(sa->v4.sin_port)));
		goto out;
	}
	head = quic_sock_head(quic_sock_hash(net, sa, da));

out:
	spin_lock_bh(&head->lock);
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		reuseport_detach_sock(sk); /* If socket was part of a reuseport group, detach it. */
	__sk_nulls_del_node_init_rcu(sk);
	spin_unlock_bh(&head->lock);
}

#define QUIC_MSG_STREAM_FLAGS \
	(MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_UNI | MSG_QUIC_STREAM_DONTWAIT)

#define QUIC_MSG_FLAGS \
	(QUIC_MSG_STREAM_FLAGS | MSG_BATCH | MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL | \
	 MSG_QUIC_DATAGRAM)

/* Parse control messages and extract stream or handshake metadata from msghdr. */
static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg, struct quic_handshake_info *hinfo,
			     struct quic_stream_info *sinfo, bool *has_hinfo)
{
	struct quic_handshake_info *h = NULL;
	struct quic_stream_info *s = NULL;
	struct quic_stream_table *streams;
	struct cmsghdr *cmsg;
	s64 active;

	if (msg->msg_flags & ~QUIC_MSG_FLAGS) /* Reject unsupported flags. */
		return -EINVAL;

	if (quic_is_closed(sk) || quic_is_listen(sk))
		return -EPIPE;

	sinfo->stream_id = -1;
	/* Iterate over control messages and parse recognized QUIC-level metadata. */
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

	if (h) { /* If handshake metadata was provided, skip stream handling. */
		*has_hinfo = true;
		return 0;
	}

	if (!s) /* If no stream info was provided, inherit stream_flags from msg_flags. */
		sinfo->stream_flags |= msg->msg_flags;

	if (sinfo->stream_id != -1)
		return 0;

	/* No explicit stream, fallback to the active stream (the most recently opened stream). */
	streams = quic_streams(sk);
	active = streams->send.active_stream_id;
	if (active != -1) {
		sinfo->stream_id = active;
		return 0;
	}
	/* No active stream, pick the next to open based on stream direction. */
	sinfo->stream_id = streams->send.next_bidi_stream_id;
	if (sinfo->stream_flags & MSG_QUIC_STREAM_UNI)
		sinfo->stream_id = streams->send.next_uni_stream_id;
	return 0;
}

/* Returns 1 if stream_id is within allowed limits or 0 otherwise.  If MSG_QUIC_STREAM_SNDBLOCK is
 * set, may send a STREAMS_BLOCKED frame.
 */
static int quic_sock_stream_available(struct sock *sk, s64 stream_id, u32 flags)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 type, blocked;

	if (!quic_stream_id_exceeds(streams, stream_id, true))
		return 1;

	if (!(flags & MSG_QUIC_STREAM_SNDBLOCK))
		return 0;

	blocked = streams->send.bidi_blocked;
	type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	if (stream_id & QUIC_STREAM_TYPE_UNI_MASK) {
		blocked = streams->send.uni_blocked;
		type = QUIC_FRAME_STREAMS_BLOCKED_UNI;
	}

	if (!blocked)
		quic_outq_transmit_frame(sk, type, &stream_id, 0, false);
	return 0;
}

/* Wait until the given stream ID becomes available for sending. */
static int quic_wait_for_stream(struct sock *sk, s64 stream_id, u32 flags)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_QUIC_STREAM_DONTWAIT);
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
		if (quic_sock_stream_available(sk, stream_id, flags))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/* Get the send stream object for the given stream ID.  May wait if the stream isn't
 * immediately available.
 */
static struct quic_stream *quic_sock_send_stream(struct sock *sk, struct quic_stream_info *sinfo)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream;
	int err;

	stream = quic_stream_send_get(streams, sinfo->stream_id,
				      sinfo->stream_flags, quic_is_serv(sk));
	if (!IS_ERR(stream)) {
		if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
			return ERR_PTR(-EINVAL); /* Can't send on a closed or finished stream. */
		return stream;
	} else if (PTR_ERR(stream) != -EAGAIN) {
		return stream;
	}

	/* App send keys are not ready yet, likely sending 0-RTT data.  Do not wait for stream
	 * availability if it's beyond the current limit; return an error immediately instead.
	 */
	if (!crypto->send_ready)
		return ERR_PTR(-EINVAL);

	if (!quic_sock_stream_available(sk, sinfo->stream_id, sinfo->stream_flags)) {
		err = quic_wait_for_stream(sk, sinfo->stream_id, sinfo->stream_flags);
		if (err)
			return ERR_PTR(err);
	}

	/* Stream should now be available, retry getting the stream. */
	stream = quic_stream_send_get(streams, sinfo->stream_id,
				      sinfo->stream_flags, quic_is_serv(sk));
	if (!IS_ERR(stream) && stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
		return ERR_PTR(-EINVAL); /* Can't send on a closed or finished stream. */
	return stream;
}

/* Wait until send buffer has enough space for sending. */
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

/* Check if a QUIC stream is writable. */
static int quic_sock_stream_writable(struct sock *sk, struct quic_stream *stream,
				     u32 flags, u32 len)
{
	/* Check if flow control limits allow sending 'len' bytes. */
	if (quic_outq_flow_control(sk, stream, len, flags & MSG_QUIC_STREAM_SNDBLOCK))
		return 0;
	/* Check socket send buffer space and memory scheduling capacity. */
	if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len))
		return 0;
	return 1;
}

/* Wait until a QUIC stream is writable for sending data. */
static int quic_wait_for_stream_send(struct sock *sk, struct quic_stream *stream, u32 flags,
				     u32 len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = stream->id;
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
			/* If the stream is blocked due to flow control limits (not socket
			 * buffer), return ENOSPC instead. This distinction helps applications
			 * detect when they should switch to sending on other streams (e.g., to
			 * implement fair scheduling).
			 */
			if (quic_outq_wspace(sk, stream) < (u64)len)
				err = -ENOSPC;
			break;
		}
		if (quic_sock_stream_writable(sk, stream, flags, len))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);

		/* Re-fetch the stream after sleeping. It may have been closed, reset, or freed
		 * while the socket lock was released.
		 */
		stream = quic_stream_find(streams, stream_id);
		if (!stream || stream->send.state >= QUIC_STREAM_SEND_STATE_SENT) {
			err = -EINVAL;
			break;
		}
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

	delay = !!(flags & MSG_MORE); /* Determine if this is a delayed send. */
	if (has_hinfo) { /* Handshake Messages Send Path. */
		/* Initial, Handshake and App (TLS NewSessionTicket) only. */
		if (hinfo.crypto_level >= QUIC_CRYPTO_EARLY) {
			err = -EINVAL;
			goto err;
		}
		crypto = quic_crypto(sk, hinfo.crypto_level);
		if (!crypto->send_ready) { /* Can't send if crypto keys aren't ready. */
			err = -EINVAL;
			goto err;
		}
		/* Set packet context (overhead, MSS, etc.) before fragmentation. */
		if (quic_packet_config(sk, hinfo.crypto_level, 0)) {
			err = -ENETUNREACH;
			goto err;
		}

		/* Prepare the message info used by the frame creator. */
		msginfo.level = hinfo.crypto_level;
		msginfo.msg = &msg->msg_iter;
		/* Keep sending until all data from the message iterator is consumed. */
		while (iov_iter_count(&msg->msg_iter) > 0) {
			if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len)) {
				if (delay) { /* Push buffered data if MSG_MORE was used. */
					outq->force_delay = 0;
					quic_outq_transmit(sk);
				}
				err = quic_wait_for_send(sk, flags, len);
				if (err) {
					/* Return error only if EPIPE or nothing was sent. */
					if (err == -EPIPE || !bytes)
						goto err;
					goto out;
				}
			}
			frame = quic_frame_create(sk, QUIC_FRAME_CRYPTO, &msginfo);
			if (!frame) {
				if (!bytes) { /* Return error only if nothing was sent. */
					err = -ENOMEM;
					goto err;
				}
				goto out;
			}
			len = frame->bytes;
			if (!sk_wmem_schedule(sk, len)) {
				/* Memory pressure: roll back the iterator and discard the frame. */
				iov_iter_revert(msginfo.msg, len);
				quic_frame_put(frame);
				continue; /* Go back to next frame check with len = frame->bytes. */
			}
			bytes += frame->bytes;
			outq->force_delay = delay; /* Pass the delay flag to outqueue. */
			crypto->send_offset += frame->bytes; /* Advance crypto offset. */
			quic_outq_ctrl_tail(sk, frame, delay); /* Queue frame for transmission. */
			len = 1; /* Reset minimal length guess for next frame check. */
		}
		goto out;
	}

	if (quic_packet_config(sk, QUIC_CRYPTO_APP, 0)) {
		err = -ENETUNREACH;
		goto err;
	}

	if (flags & MSG_QUIC_DATAGRAM) { /* Datagram Messages Send Path. */
		if (!outq->max_datagram_frame_size) { /* Peer doesn't allow datagrams. */
			err = -EINVAL;
			goto err;
		}
		len = iov_iter_count(&msg->msg_iter);
		if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len)) {
			err = quic_wait_for_send(sk, flags, len);
			if (err)
				goto err;
		}
		/* Only sending Datagram frames with a length field is supported for now. */
		frame = quic_frame_create(sk, QUIC_FRAME_DATAGRAM_LEN, &msg->msg_iter);
		if (!frame) {
			err = -EINVAL;
			goto err;
		}
		bytes += frame->bytes;
		outq->force_delay = delay;
		quic_outq_dgram_tail(sk, frame, delay);
		goto out;
	}

	/* Stream Messages Send Path. */
	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		goto err;
	}

	/* Logic is similar to handshake messages send path. */
	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flags = sinfo.stream_flags;
	flags |= sinfo.stream_flags;

	do {
		if (!quic_sock_stream_writable(sk, stream, flags, len)) {
			if (delay) {
				outq->force_delay = 0;
				quic_outq_transmit(sk);
			}
			err = quic_wait_for_stream_send(sk, stream, flags, len);
			if (err) {
				if (err == -EPIPE || !bytes)
					goto err;
				goto out;
			}
		}

		len = quic_outq_stream_append(sk, &msginfo, 0); /* Probe appendable size. */
		if (len >= 0) {
			if (!sk_wmem_schedule(sk, len))
				continue; /* Memory pressure: Retry with new len. */
			len = quic_outq_stream_append(sk, &msginfo, 1); /* Appended. */
			if (len >= 0) {
				bytes += len;
				len = 1; /* Reset minimal length guess for next frame check. */
				continue;
			}
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
		outq->force_delay = delay;
		quic_outq_stream_tail(sk, frame, delay);
		len = 1;
		/* Checking iov_iter_count() after sending allows a FIN-only Stream frame. */
	} while (iov_iter_count(msginfo.msg) > 0);
out:
	err = bytes; /* Return total bytes sent. */
err:
	if (err < 0 && !has_hinfo && !(flags & MSG_QUIC_DATAGRAM))
		err = sk_stream_error(sk, flags, err); /* Handle error and possibly send SIGPIPE. */
	release_sock(sk);
	return err;
}

/* Wait for an incoming QUIC packet. */
static int quic_wait_for_packet(struct sock *sk, struct list_head *head, u32 flags)
{
	long timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
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

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t msg_len, int flags,
			int *addr_len)
{
	u32 copy, copied = 0, freed = 0, bytes = 0;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_stream *stream = NULL;
	struct quic_frame *frame, *next;
	struct list_head *head;
	int err, fin;

	lock_sock(sk);

	head = &inq->recv_list;

	err = quic_wait_for_packet(sk, head, flags);
	if (err)
		goto out;

	/* Iterate over each received frame in the list. */
	list_for_each_entry_safe(frame, next, head, list) {
		/* Determine how much data to copy: the minimum of the remaining data in the frame
		 * and the remaining user buffer space.
		 */
		copy = min((u32)(frame->len - frame->offset), (u32)(msg_len - copied));
		if (copy) { /* Copy data from frame to user message iterator. */
			copy = copy_to_iter(frame->data + frame->offset, copy, &msg->msg_iter);
			if (!copy) {
				if (!copied) { /* Return error only if nothing was coplied. */
					err = -EFAULT;
					goto out;
				}
				break;
			}
			copied += copy; /* Accumulate total copied bytes. */
		}
		fin = frame->stream_fin;
		stream = frame->stream;
		if (frame->event) {
			msg->msg_flags |= MSG_QUIC_NOTIFICATION; /* An Event received. */
		} else if (frame->level) {
			/* Attach handshake info control message if crypto level present. */
			hinfo.crypto_level = frame->level;
			put_cmsg(msg, SOL_QUIC, QUIC_HANDSHAKE_INFO, sizeof(hinfo), &hinfo);
			if (msg->msg_flags & MSG_CTRUNC) {
				err = -EINVAL;
				goto out;
			}
		} else if (frame->dgram) {
			msg->msg_flags |= MSG_QUIC_DATAGRAM; /* A Datagram Message received. */
		}
		if (flags & MSG_PEEK) /* For peek, only look at first frame, don't consume data. */
			break;
		if (copy != frame->len - frame->offset) {
			/* Partial copy, update offset for next read and exit loop. */
			frame->offset += copy;
			break;
		}
		msg->msg_flags |= MSG_EOR;
		bytes += frame->len; /* Track bytes fully consumed. */
		if (frame->event || frame->level || frame->dgram) {
			/* For these frame types, only read only one frame at a time. */
			list_del(&frame->list);
			quic_frame_put(frame);
			break;
		}
		/* A Stream Message received. */
		freed += frame->len;
		list_del(&frame->list);
		quic_frame_put(frame);
		if (fin) {
			/* rfc9000#section-3.2:
			 *
			 * Once stream data has been delivered, the stream enters the "Data Read"
			 * state, which is a terminal state.
			 */
			stream->recv.state = QUIC_STREAM_RECV_STATE_READ;
			sinfo.stream_flags |= MSG_QUIC_STREAM_FIN;
			break;
		}

		/* Stop if next frame is not part of this stream or no more data to copy. */
		if (list_entry_is_head(next, head, list) || copied >= msg_len)
			break;
		if (next->event || next->dgram || !next->stream || next->stream != stream)
			break;
	};

	if (stream) {
		/* Attach stream info control message if stream data was processed. */
		sinfo.stream_id = stream->id;
		put_cmsg(msg, SOL_QUIC, QUIC_STREAM_INFO, sizeof(sinfo), &sinfo);
		if (msg->msg_flags & MSG_CTRUNC)
			msg->msg_flags |= sinfo.stream_flags;

		/* Update flow control accounting for freed bytes. */
		quic_inq_flow_control(sk, stream, freed);

		/* If stream read completed, purge and release resources. */
		if (stream->recv.state == QUIC_STREAM_RECV_STATE_READ) {
			quic_inq_list_purge(sk, &inq->stream_list, stream);
			quic_stream_recv_put(quic_streams(sk), stream, quic_is_serv(sk));
		}
	}

	quic_inq_data_read(sk, bytes); /* Release receive memory accounting. */
	err = (int)copied;
out:
	release_sock(sk);
	return err;
}

/* Wait until a new connection request is available on the listen socket. */
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

/* Apply QUIC configuration settings to a socket. */
static int quic_sock_apply_config(struct sock *sk, struct quic_config *c)
{
	struct quic_config *config = quic_config(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_cong *cong = quic_cong(sk);

	if (c->validate_peer_address)
		config->validate_peer_address = c->validate_peer_address;
	if (c->receive_session_ticket)
		config->receive_session_ticket = c->receive_session_ticket;
	if (c->certificate_request)
		config->certificate_request = c->certificate_request;
	if (c->initial_smoothed_rtt) {
		if (c->initial_smoothed_rtt < QUIC_RTT_MIN ||
		    c->initial_smoothed_rtt > QUIC_RTT_MAX)
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
		packet->version = c->version;
	}
	if (c->congestion_control_algo) {
		config->congestion_control_algo = c->congestion_control_algo;
		quic_cong_set_algo(cong, config->congestion_control_algo);
	}
	if (c->stream_data_nodelay)
		config->stream_data_nodelay = c->stream_data_nodelay;

	return 0;
}

/* Initialize an accept QUIC socket from a listen socket. */
static int quic_accept_sock_init(struct sock *nsk, struct sock *sk)
{
	struct quic_transport_param param = {};
	int err;

	err = quic_init_sock(nsk);
	if (err)
		return err;

	/* Duplicate ALPN from listen to accept socket for handshake. */
	if (quic_data_dup(quic_alpn(nsk), quic_alpn(sk)->data, quic_alpn(sk)->len))
		return -ENOMEM;

	/* Copy socket metadata. */
	nsk->sk_type = sk->sk_type;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
	nsk->sk_max_ack_backlog = sk->sk_max_ack_backlog;

	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;
	nsk->sk_bound_dev_if = sk->sk_bound_dev_if;

	inet_sk(nsk)->pmtudisc = inet_sk(sk)->pmtudisc;

	if (sk->sk_family == AF_INET6) /* Set IPv6 specific state if applicable. */
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	quic_inq(nsk)->events = quic_inq(sk)->events;

	/* Copy the QUIC settings and transport parameters to accept socket. */
	quic_sock_apply_config(nsk, quic_config(sk));
	quic_sock_fetch_transport_param(sk, &param);
	quic_sock_apply_transport_param(nsk, &param);

	return 0;
}

/* Finalize setup for an accept QUIC socket. */
static int quic_accept_sock_setup(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id;
	struct sk_buff *skb;
	int err;

	quic_path_set_saddr(paths, 0, &req->saddr);
	err = quic_path_bind(sk, paths, 0);
	if (err)
		return err;
	quic_set_sk_addr(sk, &req->saddr, true);

	lock_sock_nested(sk, SINGLE_DEPTH_NESTING);
	/* Set destination address and resolve route (may also auto-set source address). */
	quic_path_set_daddr(paths, 0, &req->daddr);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, &req->daddr, false);

	/* Generate and add destination and source connection IDs. */
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(quic_source(sk), &conn_id, 0, sk);
	if (err)
		goto out;
	err = quic_conn_id_add(quic_dest(sk), &req->scid, 0, NULL);
	if (err)
		goto out;

	/* Install initial encryption keys for handshake. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128, 0);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(crypto, &req->dcid, req->version, 1);
	if (err)
		goto out;
	/* Record the QUIC version offered by the peer. May later change if Compatible Version
	 * Negotiation is triggered.
	 */
	packet->version = req->version;

	/* Save original DCID and retry DCID for building transport parameters, and identifying
	 * the connection in quic_sock_lookup().
	 */
	paths->orig_dcid = req->orig_dcid;
	if (req->retry) {
		paths->retry = 1;
		paths->retry_dcid = req->dcid;
	}

	/* Add socket to hash table, change state to ESTABLISHING, and start idle timer. */
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	err = sk->sk_prot->hash(sk);
	if (err)
		goto out;
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);

	/* Process all packets in backlog list of this socket. */
	while ((skb = __skb_dequeue(&req->backlog_list)) != NULL)
		quic_packet_process(sk, skb);

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
	struct quic_request_sock *req;
	struct sock *nsk = NULL;
	int err = -EINVAL;

	lock_sock(sk);

	if (!quic_is_listen(sk))
		goto out;

	err = quic_wait_for_accept(sk, flags);
	if (err)
		goto out;
	nsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL, sk->sk_prot, kern);
	if (!nsk) {
		err = -ENOMEM;
		goto out;
	}
	sock_init_data(NULL, nsk);

	req = list_first_entry(quic_reqs(sk), struct quic_request_sock, list);

	err = quic_accept_sock_init(nsk, sk);
	if (err)
		goto free;

	err = quic_accept_sock_setup(nsk, req);
	if (err)
		goto free;

	/* Record the creation time of this accept socket in microseconds.  Used by
	 * quic_accept_sock_exists() to determine if a packet from sk_backlog of
	 * listen socket predates this socket.
	 */
	quic_pnspace(sk, QUIC_CRYPTO_INITIAL)->time = quic_ktime_get_us();
	quic_request_sock_free(sk, req);
out:
	release_sock(sk);
	*errp = err;
	return nsk;
free:
	quic_set_state(nsk, QUIC_SS_CLOSED);
	sk_common_release(nsk);
	nsk = NULL;
	goto out;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock(sk);

	quic_outq_transmit_app_close(sk);
	sk->sk_prot->unhash(sk);
	quic_set_state(sk, QUIC_SS_CLOSED);

	release_sock(sk);

	sk_common_release(sk);
}

static int quic_sock_set_event(struct sock *sk, struct quic_event_option *event, u32 len)
{
	struct quic_inqueue *inq = quic_inq(sk);

	if (len != sizeof(*event))
		return -EINVAL;
	if (!event->type || event->type >= QUIC_EVENT_MAX)
		return -EINVAL;

	if (event->on) { /* Enable the specified event by setting the corresponding bit. */
		inq->events |= BIT(event->type);
		return 0;
	}
	inq->events &= ~BIT(event->type); /* Disable the specified event by clearing the bit. */
	return 0;
}

static int quic_sock_stream_reset(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_stream *stream;
	struct quic_frame *frame;

	if (len != sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	stream = quic_stream_send_get(streams, info->stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	/* rfc9000#section-3.1:
	 *
	 * From any state that is one of "Ready", "Send", or "Data Sent", an application can
	 * signal that it wishes to abandon transmission of stream data.  The endpoint sends a
	 * RESET_STREAM frame, which causes the stream to enter the "Reset Sent" state.
	 */
	if (stream->send.state >= QUIC_STREAM_SEND_STATE_RECVD)
		return -EINVAL;

	frame = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, info);
	if (!frame)
		return -ENOMEM;

	stream->send.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	quic_outq_list_purge(sk, &outq->transmitted_list, stream);
	quic_outq_list_purge(sk, &outq->stream_list, stream);
	quic_outq_ctrl_tail(sk, frame, false);
	return 0;
}

static int quic_sock_stream_stop_sending(struct sock *sk, struct quic_errinfo *info, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream *stream;

	if (len != sizeof(*info) || !quic_is_established(sk))
		return -EINVAL;

	stream = quic_stream_recv_get(streams, info->stream_id, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	/* rfc9000#section-3.3:
	 *
	 * A receiver MAY send a STOP_SENDING frame in any state where it has not received a
	 * RESET_STREAM frame -- that is, states other than "Reset Recvd" or "Reset Read".
	 * However, there is little value in sending a STOP_SENDING frame in the "Data Recvd"
	 * state, as all stream data has been received.
	 */
	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		return -EINVAL;

	if (stream->recv.stop_sent) /* Defer sending; a STOP_SENDING frame is already in flight. */
		return -EAGAIN;

	quic_inq_list_purge(sk, &inq->stream_list, stream);
	quic_inq_list_purge(sk, &inq->recv_list, stream);

	return quic_outq_transmit_frame(sk, QUIC_FRAME_STOP_SENDING, info, 0, false);
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
		/* The alternative connection ID is reserved for the migration path.  Until the
		 * migration completes and this path becomes active, no modifications should be
		 * made to the destination connection ID set until then.
		 */
		if (id_set->alt)
			return -EAGAIN;
	}
	old = quic_conn_id_active(id_set);
	if (info->active) { /* Change active connection ID. */
		/* Ensure the new active ID is greater than the current one.  All lower-numbered
		 * IDs are implicitly treated as used.
		 */
		if (info->active <= quic_conn_id_number(old))
			return -EINVAL;
		active = quic_conn_id_find(id_set, info->active);
		if (!active)
			return -EINVAL;
		quic_conn_id_set_active(id_set, active);
	}

	if (!info->prior_to)
		return 0;

	/* Retire connection IDs up to (but not including) 'prior_to'. */
	number = info->prior_to;
	last = quic_conn_id_last_number(id_set);
	first = quic_conn_id_first_number(id_set);
	if (number > last || number <= first) {
		/* Invalid retirement range: revert any active ID change. */
		quic_conn_id_set_active(id_set, old);
		return -EINVAL;
	}

	if (!info->dest) { /* Retire source connection IDs by sending NEW_CONNECTION_ID frames. */
		if (quic_outq_transmit_new_conn_id(sk, number, 0, false)) {
			quic_conn_id_set_active(id_set, old);
			return -ENOMEM;
		}
		return 0;
	}

	/* Retire destination connection IDs by sending RETIRE_CONNECTION_ID frames. */
	if (quic_outq_transmit_retire_conn_id(sk, number, 0, false)) {
		quic_conn_id_set_active(id_set, old);
		return -ENOMEM;
	}

	return 0;
}

static int quic_sock_set_connection_close(struct sock *sk, struct quic_connection_close *close,
					  u32 len)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *data;

	if (len < sizeof(*close))
		return -EINVAL;

	/* Remaining length is the length of the phrase (if any). */
	len -= sizeof(*close);
	if (len > QUIC_CLOSE_PHRASE_MAX_LEN + 1)
		return -EINVAL;

	if (len) {
		if (close->phrase[len - 1]) /* Phrase must be ended with '\0'. */
			return -EINVAL;
		data = kmemdup(close->phrase, len, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
		kfree(outq->close_phrase);
		outq->close_phrase = data;
	}

	outq->close_errcode = close->errcode;
	return 0;
}

static int quic_sock_connection_migrate(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr a;
	int err;

	if (quic_get_addr_from_user(sk, &a, addr, addr_len))
		return -EINVAL;
	/* Reject if connection is closed or address matches the current path's source. */
	if (quic_is_closed(sk) || quic_cmp_sk_addr(sk, quic_path_saddr(paths, 0), &a))
		return -EINVAL;

	if (!quic_is_established(sk)) {
		/* Allows setting a preferred address before the handshake completes.
		 * The address may use a different address family (e.g., IPv4 vs IPv6).
		 */
		if (!quic_is_serv(sk) || paths->disable_saddr_alt)
			return -EINVAL;
		paths->pref_addr = 1;
		quic_path_set_saddr(paths, 1, &a);
		return 0;
	}

	/* Migration requires matching address family and a valid port. */
	if (a.sa.sa_family != quic_path_saddr(paths, 0)->sa.sa_family || !a.v4.sin_port)
		return -EINVAL;
	/* Reject if a migration is in progress or a preferred address is already active. */
	if (!quic_path_alt_state(paths, QUIC_PATH_ALT_NONE) || paths->pref_addr)
		return -EAGAIN;

	/* Setup path 1 with the new source address and existing destination address. */
	quic_path_set_saddr(paths, 1, &a);
	quic_path_set_daddr(paths, 1, quic_path_daddr(paths, 0));

	/* Configure routing and bind to the new source address. */
	if (quic_packet_config(sk, 0, 1))
		return -EINVAL;
	if (quic_path_bind(sk, paths, 1))
		return -EINVAL;
	err = quic_outq_probe_path_alt(sk, false); /* Start connection migration using new path. */
	if (err)
		quic_path_unbind(sk, paths, 1); /* Cleanup path 1 on failure. */
	return err;
}

/* Validate and copy QUIC transport parameters. */
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

static int quic_sock_set_transport_param(struct sock *sk, struct quic_transport_param *p, u32 len)
{
	struct quic_transport_param param = {};

	if (len < sizeof(param) || quic_is_established(sk))
		return -EINVAL;

	/* Manually setting remote transport parameters is required only to enable 0-RTT data
	 * transmission during handshake initiation.
	 */
	if (p->remote && !quic_is_establishing(sk))
		return -EINVAL;

	param.remote = p->remote;
	quic_sock_fetch_transport_param(sk, &param);

	if (quic_param_check_and_copy(p, &param))
		return -EINVAL;

	quic_sock_apply_transport_param(sk, &param);
	return 0;
}

static int quic_sock_set_config(struct sock *sk, struct quic_config *c, u32 len)
{
	if (len < sizeof(*c) || quic_is_established(sk))
		return -EINVAL;

	return quic_sock_apply_config(sk, c);
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

	return quic_data_from_string(alpns, data, len);
}

static int quic_sock_set_token(struct sock *sk, void *data, u32 len)
{
	if (quic_is_serv(sk)) {
		/* For servers, send a regular token to client via NEW_TOKEN frames after
		 * handshake.
		 */
		if (!quic_is_established(sk))
			return -EINVAL;
		/* Defer sending; a NEW_TOKEN frame is already in flight. */
		if (quic_outq(sk)->token_pending)
			return -EAGAIN;
		if (quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_TOKEN, NULL, 0, false))
			return -ENOMEM;
		return 0;
	}

	/* For clients, use the regular token next time before handshake. */
	if (!len || len > QUIC_TOKEN_MAX_LEN)
		return -EINVAL;

	return quic_data_dup(quic_token(sk), data, len);
}

static int quic_sock_set_session_ticket(struct sock *sk, u8 *data, u32 len)
{
	if (len < QUIC_TICKET_MIN_LEN || len > QUIC_TICKET_MAX_LEN)
		return -EINVAL;

	return quic_data_dup(quic_ticket(sk), data, len);
}

#define QUIC_TP_EXT_MAX_LEN	256

static int quic_sock_set_transport_params_ext(struct sock *sk, u8 *p, u32 len)
{
	struct quic_transport_param param = {};
	u32 errcode;

	if (!quic_is_establishing(sk) || len > QUIC_TP_EXT_MAX_LEN)
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
	union quic_addr *a;
	int err;

	if (!quic_is_establishing(sk) || len != sizeof(*secret))
		return -EINVAL;

	/* Accept only supported levels: Handshake, 0-RTT (Early), or 1-RTT (App).  The initial
	 * secret was already derived in-kernel using the original destination connection ID.
	 */
	if (secret->level != QUIC_CRYPTO_APP &&
	    secret->level != QUIC_CRYPTO_EARLY &&
	    secret->level != QUIC_CRYPTO_HANDSHAKE)
		return -EINVAL;

	/* Install keys into the crypto context. */
	crypto = quic_crypto(sk, secret->level);
	err = quic_crypto_set_secret(crypto, secret, packet->version, 0);
	if (err)
		return err;

	if (secret->level != QUIC_CRYPTO_APP) {
		if (secret->send) { /* 0-RTT or Handshake send key is ready. */
			/* If 0-RTT send key is ready, set data_level to EARLY.  This allows
			 * quic_outq_transmit_stream() to emit stream frames in 0-RTT packets.
			 */
			if (secret->level == QUIC_CRYPTO_EARLY)
				outq->data_level = QUIC_CRYPTO_EARLY;
			return 0;
		}
		/* 0-RTT or Handshake receive key is ready; decrypt and process all buffered
		 * 0-RTT or Handshake packets.
		 */
		__skb_queue_head_init(&tmpq);
		skb_queue_splice_init(&inq->backlog_list, &tmpq);
		while ((skb = __skb_dequeue(&tmpq)) != NULL)
			quic_packet_process(sk, skb);
		return 0;
	}

	if (secret->send) {
		/* App send key is ready, set data_level to APP. This allows
		 * quic_outq_transmit_stream() to emit stream frames in 1-RTT packets.
		 */
		outq->data_level = QUIC_CRYPTO_APP;
		if (!crypto->recv_ready)
			return 0;
		goto done; /* Both send and receive keys are ready; handshake complete. */
	}

	/* Free previously stored TLS session ticket and QUIC token data, allowing reception of
	 * fresh NewSessionTicket message and regular token in NEW_TOKEN frames from the peer
	 * during handshake completion.
	 */
	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));
	if (!list_empty(&inq->early_list)) {
		/* If any 0-RTT data was buffered (early_list), move it to the main receive
		 * list (recv_list) so it becomes available to the application.
		 */
		list_splice_init(&inq->early_list, &inq->recv_list);
		sk->sk_data_ready(sk);
	}
	/* App receive key is ready; decrypt and process all buffered App/1-RTT packets. */
	__skb_queue_head_init(&tmpq);
	skb_queue_splice_init(&inq->backlog_list, &tmpq);
	while ((skb = __skb_dequeue(&tmpq)) != NULL)
		quic_packet_process(sk, skb);

	if (!crypto->send_ready)
		return 0;
done:
	/* Both send and receive keys are ready; handshake complete. */
	if (!quic_is_serv(sk)) {
		if (!paths->pref_addr)
			goto out;
		/* The peer offered a preferred address (stored in path 1).  Reset the flag to
		 * avoid reprocessing, and Perform routing on new path and set the local address
		 * for new path.
		 */
		if (quic_packet_config(sk, 0, 1)) {
			paths->pref_addr = 0; /* Ignore the preferred address. */
			goto out;
		}
		/* If the local address for new path is different from the current one, bind to
		 * the new address.
		 */
		a = quic_path_saddr(paths, 1);
		a->v4.sin_port = quic_path_saddr(paths, 0)->v4.sin_port;
		if (!quic_cmp_sk_addr(sk, quic_path_saddr(paths, 0), a)) {
			a->v4.sin_port = 0;
			if (quic_path_bind(sk, paths, 1)) {
				paths->pref_addr = 0; /* Ignore the preferred address. */
				goto out;
			}
		}
		goto out;
	}

	/* Clean up transmitted handshake packets. */
	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAX, 0, -1, 0);
	if (paths->pref_addr) {
		/* If a preferred address is set, bind to it to allow client use at any time. */
		err = quic_path_bind(sk, paths, 1);
		if (err)
			return err;
	}

	/* Send NEW_TOKEN and HANDSHAKE_DONE frames (server only). */
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_TOKEN, NULL, 0, true))
		return -ENOMEM;
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL, 0, true))
		return -ENOMEM;
out:
	/* Send NEW_CONNECTION_ID frames to ensure maximum connection IDs are added. */
	if (quic_outq_transmit_new_conn_id(sk, 0, 0, false))
		return -ENOMEM;
	/* Enter established state, and start PLPMTUD timer and Path Challenge timer. */
	quic_set_state(sk, QUIC_SS_ESTABLISHED);
	quic_timer_start(sk, QUIC_TIMER_PMTU, c->plpmtud_probe_interval);
	quic_timer_reset_path(sk);
	return 0;
}

/**
 * quic_do_setsockopt - set a QUIC socket option
 * @sk: socket to configure
 * @optname: option name (QUIC-level)
 * @optval: user buffer containing the option value
 * @optlen: size of the option value
 *
 * Sets a QUIC socket option on a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval, unsigned int optlen)
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
	case QUIC_SOCKOPT_CONNECTION_ID:
		retval = quic_sock_set_connection_id(sk, kopt, optlen);
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
	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = quic_sock_set_transport_param(sk, kopt, optlen);
		break;
	case QUIC_SOCKOPT_CONFIG:
		retval = quic_sock_set_config(sk, kopt, optlen);
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
EXPORT_SYMBOL_GPL(quic_do_setsockopt);

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	if (level != SOL_QUIC)
		return quic_common_setsockopt(sk, level, optname, optval, optlen);

	return quic_do_setsockopt(sk, optname, optval, optlen);
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

	if (!event.type || event.type >= QUIC_EVENT_MAX)
		return -EINVAL;
	/* Set on if the corresponding event bit is set. */
	event.on = !!(inq->events & BIT(event.type));

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &event, len))
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

	if (sinfo.stream_flags & ~QUIC_MSG_STREAM_FLAGS) /* Reject unsupported flags. */
		return -EINVAL;

	/* If stream_id is -1, assign the next available ID (bidi or uni). */
	if (sinfo.stream_id == -1) {
		sinfo.stream_id = streams->send.next_bidi_stream_id;
		if (sinfo.stream_flags & MSG_QUIC_STREAM_UNI)
			sinfo.stream_id = streams->send.next_uni_stream_id;
	}
	sinfo.stream_flags |= MSG_QUIC_STREAM_NEW; /* Mark stream as to be created. */

	stream = quic_sock_send_stream(sk, &sinfo); /* Actually create or find the stream. */
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &sinfo, len))
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
	/* Use prior_to to indicate the smallest issued connection ID number.  Combined with
	 * the active_connection_id_limit (from the peer’s transport parameters), this allows
	 * userspace to infer the full set of valid connection IDs.
	 */
	info.prior_to = quic_conn_id_first_number(id_set);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, &info, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_connection_close(struct sock *sk, u32 len, sockptr_t optval,
					  sockptr_t optlen)
{
	u8 *phrase, frame[QUIC_FRAME_BUF_LARGE] = {};
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close *close;
	u32 phrase_len = 0;

	phrase = outq->close_phrase;
	if (phrase)
		phrase_len = strlen(phrase) + 1;
	if (len < sizeof(*close) + phrase_len) /* Check if output buffer is large enough. */
		return -EINVAL;

	len = sizeof(*close) + phrase_len;
	close = (void *)frame;
	close->errcode = outq->close_errcode;
	close->frame = outq->close_frame;

	if (phrase_len)
		strscpy(close->phrase, phrase, phrase_len);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, close, len))
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

static int quic_sock_get_alpn(struct sock *sk, u32 len, sockptr_t optval, sockptr_t optlen)
{
	struct quic_data *alpns = quic_alpn(sk);
	u8 data[QUIC_ALPN_MAX_LEN];
	int err;

	if (!alpns->len) {
		len = 0;
		goto out;
	}
	if (len < alpns->len)
		return -EINVAL;

	len = QUIC_ALPN_MAX_LEN;
	err = quic_data_to_string(data, &len, alpns);
	if (err)
		return err;

out:
	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, data, len))
		return -EFAULT;
	return 0;
}

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

#define QUIC_TICKET_MASTER_KEY_LEN		64

static int quic_sock_get_session_ticket(struct sock *sk, u32 len,
					sockptr_t optval, sockptr_t optlen)
{
	u8 *ticket = quic_ticket(sk)->data, key[QUIC_TICKET_MASTER_KEY_LEN];
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	u32 tlen = quic_ticket(sk)->len;
	union quic_addr a;

	if (!quic_is_serv(sk)) {
		/* For clients, retrieve the received TLS NewSessionTicket message. */
		if (quic_is_established(sk) && !crypto->ticket_ready)
			tlen = 0;
		goto out;
	}

	if (quic_is_closed(sk))
		return -EINVAL;

	/* For servers, return the master key used for session resumption.  If already set,
	 * reuse it.
	 */
	if (tlen)
		goto out;

	/* If not already set, derive the key using the peer address. */
	crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	memcpy(&a, quic_path_daddr(quic_paths(sk), 0), sizeof(a));
	a.v4.sin_port = 0;
	if (quic_crypto_generate_session_ticket_key(crypto, &a, sizeof(a), key,
						    QUIC_TICKET_MASTER_KEY_LEN))
		return -EINVAL;
	ticket = key;
	tlen = QUIC_TICKET_MASTER_KEY_LEN;
out:
	if (len < tlen)
		return -EINVAL;
	len = tlen;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) || copy_to_sockptr(optval, ticket, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_params_ext(struct sock *sk, u32 len,
					      sockptr_t optval, sockptr_t optlen)
{
	struct quic_transport_param param = {};
	u8 data[QUIC_TP_EXT_MAX_LEN];
	u32 datalen = 0;

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

/**
 * quic_do_getsockopt - get a QUIC socket option
 * @sk: socket to query
 * @optname: option name (QUIC-level)
 * @optval: user buffer to receive the option value
 * @optlen: in/out parameter for buffer size; updated with actual length on return
 *
 * Gets a QUIC socket option from a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval, sockptr_t optlen)
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
	case QUIC_SOCKOPT_CONNECTION_ID:
		retval = quic_sock_get_connection_id(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CONNECTION_CLOSE:
		retval = quic_sock_get_connection_close(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		retval = quic_sock_get_transport_param(sk, len, optval, optlen);
		break;
	case QUIC_SOCKOPT_CONFIG:
		retval = quic_sock_get_config(sk, len, optval, optlen);
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
EXPORT_SYMBOL_GPL(quic_do_getsockopt);

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	if (level != SOL_QUIC)
		return quic_common_getsockopt(sk, level, optname, optval, optlen);

	return quic_do_getsockopt(sk, optname, USER_SOCKPTR(optval), USER_SOCKPTR(optlen));
}

static void quic_release_cb(struct sock *sk)
{
	/* Similar to tcp_release_cb(). */
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
	if (flags & QUIC_F_PACE_DEFERRED) {
		quic_timer_pace_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_TXQ_DEFERRED) {
		quic_packet_flush_txq(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_RXQ_DEFERRED) {
		quic_packet_flush_rxq(sk);
		__sock_put(sk);
	}
}

static int quic_disconnect(struct sock *sk, int flags)
{
	return -EOPNOTSUPP;
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
	.ioctl		=  quic_ioctl,
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
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.ioctl		=  quic_ioctl,
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	.ipv6_pinfo_offset	=  offsetof(struct quic6_sock, inet6),
#endif
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};
