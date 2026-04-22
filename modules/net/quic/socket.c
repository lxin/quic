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

/* Check if a matching request sock already exists. Match is based on
 * source/destination addresses and DCID.
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
struct quic_request_sock *quic_request_sock_create(struct sock *sk,
						   struct quic_conn_id *odcid,
						   u8 retry)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk)) /* Refuse if accept queue full. */
		return ERR_PTR(-ENOBUFS);

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return ERR_PTR(-ENOMEM);

	req->version = packet->version;
	req->daddr = packet->daddr;
	req->saddr = packet->saddr;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->retry = retry;

	skb_queue_head_init(&req->backlog_list);

	/* Enqueue request into listen socket’s pending list for accept(). */
	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return req;
}

int quic_request_sock_backlog_tail(struct sock *sk,
				   struct quic_request_sock *req,
				   struct sk_buff *skb)
{
	/* Use listen sock sk_rcvbuf to limit the request sock's backlog len. */
	if (req->blen + skb->len > sk->sk_rcvbuf) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
		kfree_skb(skb);
		return -ENOBUFS;
	}

	__skb_queue_tail(&req->backlog_list, skb);
	req->blen += skb->len;
	sk->sk_data_ready(sk);
	return 0;
}

static void quic_request_sock_free(struct sock *sk,
				   struct quic_request_sock *req)
{
	__skb_queue_purge(&req->backlog_list);
	list_del_init(&req->list);
	sk_acceptq_removed(sk);
	kfree(req);
}

/* Check if a matching accept socket exists. This is needed because an accept
 * socket might have been created after this packet was enqueued in the listen
 * socket's backlog.
 */
bool quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	bool exist = false;

	/* Skip if packet is newer than the last accept socket creation time.
	 * No matching socket could exist in this case.
	 */
	if (QUIC_SKB_CB(skb)->time >
	    quic_pnspace(sk, QUIC_CRYPTO_INITIAL)->time)
		return exist;

	/* Look up accepted socket matching packet addresses and DCID. */
	local_bh_disable();
	sk = quic_sock_lookup(skb, &packet->saddr, &packet->daddr, skb->sk,
			      &packet->dcid);
	if (!sk)
		goto out;

	/* Found a matching accept socket. Process packet with this socket. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
			kfree_skb(skb);
		} else {
			cb->backlog = 1;
		}
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
 * This function searches the established (non-listening) QUIC socket table for
 * a socket that matches the source and dest addresses and, optionally, the
 * dest connection ID (DCID). The value returned by quic_path_orig_dcid() might
 * be the original dest connection ID from the ClientHello or the Source
 * Connection ID from a Retry packet before.
 *
 * The DCID is provided from a handshake packet when searching by source
 * connection ID fails, such as when the peer has not yet received server's
 * response and updated the DCID.
 *
 * Return: A pointer to the matching connected socket, or NULL if no match is
 * found.
 */
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa,
			      union quic_addr *da, struct sock *usk,
			      struct quic_conn_id *dcid)
{
	struct net *net = sock_net(usk);
	struct quic_path_group *paths;
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	struct sock *sk = NULL, *tmp;
	struct quic_conn_id *odcid;
	unsigned int hash;

	hash = quic_sock_hash(net, sa, da);
	head = quic_sock_head(hash);

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(tmp, node, &head->head) {
		if (net != sock_net(tmp))
			continue;
		paths = quic_paths(tmp);
		odcid = quic_path_orig_dcid(paths);
		if (quic_cmp_sk_addr(tmp, quic_path_saddr(paths, 0), sa) &&
		    quic_cmp_sk_addr(tmp, quic_path_daddr(paths, 0), da) &&
		    quic_path_usock(paths, 0) == usk &&
		    (!dcid || !quic_conn_id_cmp(odcid, dcid))) {
			sk = tmp;
			break;
		}
	}
	/* If the final nulls value differs from the expected one, restart the
	 * lookup as the node may have been rehashed (e.g., due to connection
	 * migration).
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
 * This function searches the QUIC socket table for a listening socket that
 * matches the dest address and port, and the ALPN(s) if presented in the
 * ClientHello.  If multiple listening sockets are bound to the same address,
 * port, and ALPN(s) (e.g., via SO_REUSEPORT), this function selects a socket
 * from the reuseport group.
 *
 * Return: A pointer to the matching listening socket, or NULL if no match is
 * found.
 */
struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa,
				     union quic_addr *da,
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
	if (!alpns->len) { /* No ALPNs or parse failed */
		sk_nulls_for_each_rcu(tmp, node, &head->head) {
			/* If alpns->data != NULL, TLS parsing succeeded but no
			 * ALPN was found.  In this case, only match sockets
			 * that have no ALPN set.
			 */
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) &&
			    quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    (!alpns->data || !quic_alpn(tmp)->len)) {
				if (!quic_is_any_addr(a)) {
					sk = tmp;
					break; /* Prefer specific addr match. */
				}
				/* Prefer ipv4 ANY over ipv6 ANY for v4 addr. */
				if (!sk || a->sa.sa_family == sa->sa.sa_family)
					sk = tmp;
			}
		}
		/* No need to check get_nulls_value(node) != hash for !sk, as
		 * hashtable size is fixed and a listen sk can not rehashed.
		 */
		goto out;
	}

	/* ALPN present: loop through each ALPN entry. */
	for (p = alpns->data, len = alpns->len; len;
	     len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&alpn, p, length);
		sk_nulls_for_each_rcu(tmp, node, &head->head) {
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) &&
			    quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    quic_data_has(quic_alpn(tmp), &alpn)) {
				if (!quic_is_any_addr(a)) {
					sk = tmp;
					break;
				}
				if (!sk || a->sa.sa_family == sa->sa.sa_family)
					sk = tmp;
			}
		}
		/* No need to check get_nulls_value(node) != hash for !sk, as
		 * hashtable size is fixed and a listen sk can not rehashed.
		 */
		if (sk)
			break;
	}
out:
	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_addr_hash(net, da), skb, 1);

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

static void quic_write_space(struct sock *sk)
{
	__poll_t mask = EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;
	struct socket_wq *wq;

	/* Do not check sock_writeable(). Also wakes stream-open waiters
	 * blocked on stream limits, where sock_writeable() may be false.
	 */
	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, mask);
	sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	rcu_read_unlock();
}

/* Apply QUIC transport parameters to subcomponents of the socket. */
static void quic_sock_apply_transport_param(struct sock *sk,
					    struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set =
		p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_set_param(sk, p);
	quic_outq_set_param(sk, p);
	quic_conn_id_set_param(id_set, p);
	quic_path_set_param(quic_paths(sk), p);
	quic_stream_set_param(quic_streams(sk), p, quic_is_serv(sk));
}

/* Fetch QUIC transport parameters from subcomponents of the socket. */
static void quic_sock_fetch_transport_param(struct sock *sk,
					    struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set =
		p->remote ? quic_source(sk) : quic_dest(sk);

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

static void quic_sock_destruct(struct sock *sk)
{
	u8 i;

	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_free(quic_crypto(sk, i));

	quic_sk_destruct(sk);
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_transport_param *p = &quic_default_param;
	u8 i;

	sk->sk_destruct = quic_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

	quic_conn_id_set_init(quic_source(sk), true);
	quic_conn_id_set_init(quic_dest(sk), false);
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
static int quic_bind(struct sock *sk, struct sockaddr_unsized *addr,
		     int addr_len)
#else
static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
#endif
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr *sa, a;
	int err = -EINVAL;

	lock_sock(sk);

	if (quic_path_saddr(paths, 0)->v4.sin_port ||
	    quic_get_user_addr(sk, &a, (struct sockaddr *)addr, addr_len, true))
		goto out;

	sa = quic_path_saddr(paths, 0);

	quic_path_set_saddr(paths, 0, &a);
	err = quic_path_bind(sk, paths, 0);
	if (err) {
		memset(sa, 0, sizeof(*sa));
		goto out;
	}
	quic_set_sk_addr(sk, sa, true);

out:
	release_sock(sk);
	return err;
}

#ifdef TLS_MIN_RECORD_SIZE_LIM
static int quic_connect(struct sock *sk, struct sockaddr_unsized *addr,
			int addr_len)
#else
static int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
#endif
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_conn_id_set *source = quic_source(sk);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_conn_id_set *dest = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id, *active;
	union quic_addr *sa, a;
	int err = -EINVAL;

	lock_sock(sk);
	if (!sk_unhashed(sk) ||
	    quic_get_user_addr(sk, &a, (struct sockaddr *)addr, addr_len,
			       false))
		goto out;

	/* Set destination address and resolve route (may also auto-set source
	 * address).
	 */
	quic_path_set_daddr(paths, 0, &a);
	err = quic_packet_route(sk);
	if (err)
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
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128);
	if (err)
		goto free;
	err = quic_crypto_initial_keys_install(crypto, active, packet->version,
					       false);
	if (err)
		goto free;

	/* Add socket to hash table, change state to ESTABLISHING, and start
	 * idle timer.
	 */
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
	struct quic_path_group *npaths, *paths = quic_paths(sk);
	struct quic_data *alpns = quic_alpn(sk);
	struct net *net = sock_net(sk);
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	union quic_addr *sa, *da;
	struct sock *nsk;
	int err = 0, any;
	u32 hash;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (!quic_is_listen(sk)) {
		/* Hash a regular socket with source and dest addrs/ports. */
		head = quic_sock_head(quic_sock_hash(net, sa, da));
		spin_lock_bh(&head->lock);
		sock_set_flag(sk, SOCK_RCU_FREE);
		__sk_nulls_add_node_rcu(sk, &head->head);
		spin_unlock_bh(&head->lock);
		return 0;
	}

	if (quic_alpn(sk)->data)
		static_branch_inc(&quic_alpn_demux_key);
	INIT_LIST_HEAD(quic_reqs(sk));

	/* Hash a listen socket with source port only. */
	hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
	head = quic_listen_sock_head(hash);
	spin_lock_bh(&head->lock);

	any = quic_is_any_addr(sa);
	sk_nulls_for_each(nsk, node, &head->head) {
		if (net != sock_net(nsk))
			continue;
		npaths = quic_paths(nsk);
		if (memcmp(quic_path_saddr(npaths, 0), sa, sizeof(*sa)))
			continue;
		if (quic_path_usock(paths, 0) != quic_path_usock(npaths, 0))
			continue;

		/* Take the ALPNs into account, which allows directing the
		 * request to different listening sockets based on the ALPNs.
		 */
		if (!quic_data_cmp(alpns, quic_alpn(nsk))) {
			err = -EADDRINUSE;
			if (!sk->sk_reuseport || !nsk->sk_reuseport)
				goto out;

			/* Support SO_REUSEPORT: allow multiple sockets with
			 * same addr/port/ALPNs.
			 */
			err = reuseport_add_sock(sk, nsk, any);
			if (err)
				goto out;
			sock_set_flag(sk, SOCK_RCU_FREE);
			__sk_nulls_add_node_rcu(sk, &head->head);
			goto out;
		}
		/* If ALPNs partially match, also consider address in use. */
		if (quic_data_match(alpns, quic_alpn(nsk))) {
			err = -EADDRINUSE;
			goto out;
		}
	}

	if (sk->sk_reuseport) { /* Allocate reuseport group if enabled. */
		err = reuseport_alloc(sk, any);
		if (err)
			goto out;
	}
	sock_set_flag(sk, SOCK_RCU_FREE);
	__sk_nulls_add_node_rcu(sk, &head->head);

out:
	spin_unlock_bh(&head->lock);

	if (err && quic_alpn(sk)->data)
		static_branch_dec(&quic_alpn_demux_key);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_request_sock *req, *tmp;
	struct net *net = sock_net(sk);
	struct quic_shash_head *head;
	union quic_addr *sa, *da;
	u32 hash;

	if (sk_unhashed(sk))
		return;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (quic_is_listen(sk)) {
		/* Unhash listening socket; drop pending requests. */
		list_for_each_entry_safe(req, tmp, quic_reqs(sk), list)
			quic_request_sock_free(sk, req);
		if (quic_alpn(sk)->data)
			static_branch_dec(&quic_alpn_demux_key);
		hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
		head = quic_listen_sock_head(hash);
		goto out;
	}
	head = quic_sock_head(quic_sock_hash(net, sa, da));

out:
	spin_lock_bh(&head->lock);
	/* If socket was part of a reuseport group, detach it. */
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		reuseport_detach_sock(sk);
	__sk_nulls_del_node_init_rcu(sk);
	spin_unlock_bh(&head->lock);
}

static inline void quic_copy_common(void *dst, size_t dlen, const void *src,
				    size_t slen)
{
	size_t len = min_t(size_t, dlen, slen);

	if (!len)
		return;
	memcpy(dst, src, len);
}

#define QUIC_MSG_STREAM_FLAGS \
	(MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_UNI | \
	 MSG_QUIC_STREAM_DONTWAIT | MSG_QUIC_STREAM_SNDBLOCK)

#define QUIC_MSG_FLAGS \
	(QUIC_MSG_STREAM_FLAGS | MSG_BATCH | MSG_MORE | MSG_DONTWAIT | \
	 MSG_NOSIGNAL | MSG_WAITALL | MSG_QUIC_DATAGRAM)

/* Parse control messages for stream or handshake metadata from msghdr. */
static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg,
			     struct quic_handshake_info *hinfo,
			     struct quic_stream_info *sinfo,
			     bool *has_hinfo, bool *has_sinfo)
{
	struct quic_stream_table *streams;
	struct cmsghdr *cmsg;
	s64 active;

	if (msg->msg_flags & ~QUIC_MSG_FLAGS) /* Reject unsupported flags. */
		return -EINVAL;

	if (quic_is_closed(sk) || quic_is_listen(sk))
		return -EPIPE;

	sinfo->stream_id = -1;
	/* Iterate over control messages and parse QUIC-level metadata. */
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_HANDSHAKE_INFO:
			quic_copy_common(hinfo, sizeof(*hinfo), CMSG_DATA(cmsg),
					 cmsg->cmsg_len - CMSG_LEN(0));
			*has_hinfo = true;
			break;
		case QUIC_STREAM_INFO:
			quic_copy_common(sinfo, sizeof(*sinfo), CMSG_DATA(cmsg),
					 cmsg->cmsg_len - CMSG_LEN(0));
			if (sinfo->stream_flags & ~QUIC_MSG_STREAM_FLAGS)
				return -EINVAL;
			*has_sinfo = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (*has_hinfo) /* Handshake metadata present; skip stream handling. */
		return 0;

	if (!*has_sinfo) /* No stream info; inherit flags from msg_flags. */
		sinfo->stream_flags |= (msg->msg_flags & QUIC_MSG_STREAM_FLAGS);

	if (sinfo->stream_id != -1)
		return 0;

	/* No explicit stream; use the most recently opened stream. */
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

/* Returns true if stream_id is within allowed limits or false otherwise.
 * If MSG_QUIC_STREAM_SNDBLOCK is set, may send a STREAMS_BLOCKED frame.
 */
static bool quic_sock_stream_available(struct sock *sk, s64 stream_id,
				       u32 flags)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 type, blocked;

	if (!quic_stream_id_exceeds(streams, stream_id, true))
		return true;

	if (!(flags & MSG_QUIC_STREAM_SNDBLOCK))
		return false;

	blocked = streams->send.bidi_blocked;
	type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	if (stream_id & QUIC_STREAM_TYPE_UNI_MASK) {
		blocked = streams->send.uni_blocked;
		type = QUIC_FRAME_STREAMS_BLOCKED_UNI;
	}

	if (!blocked)
		quic_outq_transmit_frame(sk, type, &stream_id, 0, false);
	return false;
}

/* Wait until the given stream ID becomes available for sending. */
static int quic_wait_for_stream(struct sock *sk, s64 stream_id, u32 flags)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_QUIC_STREAM_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
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

/* Get the send stream object for the given stream ID.  May wait if the stream
 * isn't immediately available.
 */
static struct quic_stream *quic_sock_send_stream(struct sock *sk,
						 struct quic_stream_info *sinfo)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_stream_table *streams = quic_streams(sk);
	bool is_serv = quic_is_serv(sk);
	struct quic_stream *stream;
	int err;

	stream = quic_stream_get(streams, sinfo->stream_id, sinfo->stream_flags,
				 is_serv, true);
	if (!IS_ERR(stream)) {
		if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
			return ERR_PTR(-EINVAL); /* Closed/finished stream. */
		return stream;
	} else if (PTR_ERR(stream) != -EAGAIN) {
		return stream;
	}

	/* App send keys are not ready yet, likely sending 0-RTT data.  Do not
	 * wait for stream availability if it's beyond the current limit;
	 * return an error immediately instead.
	 */
	if (!crypto->send_ready)
		return ERR_PTR(-EINVAL);

	if (!quic_sock_stream_available(sk, sinfo->stream_id,
					sinfo->stream_flags)) {
		err = quic_wait_for_stream(sk, sinfo->stream_id,
					   sinfo->stream_flags);
		if (err)
			return ERR_PTR(err);
	}

	/* Stream should now be available, retry getting the stream. */
	stream = quic_stream_get(streams, sinfo->stream_id, sinfo->stream_flags,
				 is_serv, true);
	if (!IS_ERR(stream) &&
	    stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
		return ERR_PTR(-EINVAL); /* Closed/finished stream. */
	return stream;
}

/* Wait until send buffer has enough space for sending. */
static int quic_wait_for_send(struct sock *sk, u32 flags, u32 len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
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
		if ((int)len <= sk_stream_wspace(sk) &&
		    sk_wmem_schedule(sk, (int)len))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/* Check if a QUIC stream is writable. */
static bool quic_sock_stream_writable(struct sock *sk,
				      struct quic_stream *stream,
				      u32 flags, u32 len)
{
	/* Check if flow control limits allow sending 'len' bytes. */
	if (quic_outq_flow_control(sk, stream, len,
				   flags & MSG_QUIC_STREAM_SNDBLOCK))
		return false;
	/* Check socket send buffer space and memory scheduling capacity. */
	if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len))
		return false;
	return true;
}

/* Wait until a QUIC stream is writable for sending data. */
static int quic_wait_for_stream_send(struct sock *sk,
				     struct quic_stream *stream,
				     u32 flags, u32 len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = stream->id;
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
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
			/* If the stream is blocked due to flow control limits
			 * (not socket buffer), return ENOSPC instead. This
			 * distinction helps applications detect when they
			 * should switch to sending on other streams (e.g., to
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

		/* Re-fetch the stream after sleeping. It may have been closed,
		 * reset, or freed while the socket lock was released.
		 */
		stream = quic_stream_find(streams, stream_id);
		if (!stream ||
		    stream->send.state >= QUIC_STREAM_SEND_STATE_SENT) {
			err = -EINVAL;
			break;
		}
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	bool delay, has_hinfo = false, has_sinfo = false;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	int err = 0, bytes = 0, len = 1;
	struct quic_msginfo msginfo;
	struct quic_crypto *crypto;
	struct quic_stream *stream;
	u32 flags = msg->msg_flags;
	struct quic_frame *frame;

	lock_sock(sk);
	err = quic_msghdr_parse(sk, msg, &hinfo, &sinfo, &has_hinfo,
				&has_sinfo);
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
		if (!crypto->send_ready) {
			/* Cannot send until crypto keys are ready. */
			err = -EINVAL;
			goto err;
		}
		/* Set packet context (overhead, MSS, etc.) before
		 * fragmentation.
		 */
		if (quic_packet_config(sk, hinfo.crypto_level, 0)) {
			err = -ENETUNREACH;
			goto err;
		}

		/* Prepare the message info used by the frame creator. */
		msginfo.level = hinfo.crypto_level;
		msginfo.msg = &msg->msg_iter;
		/* Send until all data from the message iterator is consumed. */
		while (iov_iter_count(&msg->msg_iter) > 0) {
			if (sk_stream_wspace(sk) < len ||
			    !sk_wmem_schedule(sk, len)) {
				if (delay) {
					/* Push buffered data if MSG_MORE was
					 * used.
					 */
					outq->force_delay = 0;
					quic_outq_transmit(sk);
				}
				err = quic_wait_for_send(sk, flags, len);
				if (err) {
					/* Return error only if EPIPE or
					 * nothing was sent.
					 */
					if (err == -EPIPE || !bytes)
						goto err;
					goto out;
				}
			}
			frame = quic_frame_create(sk, QUIC_FRAME_CRYPTO,
						  &msginfo);
			if (IS_ERR(frame)) {
				if (!bytes) {
					/* Return error only if nothing sent. */
					err = PTR_ERR(frame);
					goto err;
				}
				goto out;
			}
			len = frame->bytes;
			if (!sk_wmem_schedule(sk, len)) {
				/* Memory pressure: roll back the iterator and
				 * discard the frame.
				 */
				iov_iter_revert(msginfo.msg, len);
				quic_frame_put(frame);
				/* Retry next frame with len = frame->bytes. */
				continue;
			}
			bytes += frame->bytes;
			/* Pass the delay flag to outqueue. */
			outq->force_delay = delay;
			/* Advance crypto offset. */
			crypto->send_offset += frame->bytes;
			quic_outq_ctrl_tail(sk, frame, delay);
			len = 1; /* Reset minimal len guess for next frame. */
		}
		goto out;
	}

	if (quic_packet_config(sk, QUIC_CRYPTO_APP, 0)) {
		err = -ENETUNREACH;
		goto err;
	}

	if (flags & MSG_QUIC_DATAGRAM) { /* Datagram Messages Send Path. */
		if (!outq->max_datagram_frame_size) {
			/* Peer doesn't allow datagrams. */
			err = -EINVAL;
			goto err;
		}
		len = iov_iter_count(&msg->msg_iter);
		if (len > sk->sk_sndbuf) {
			err = -EMSGSIZE;
			goto err;
		}
		if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len)) {
			err = quic_wait_for_send(sk, flags, len);
			if (err)
				goto err;
		}
		/* Only Datagram frames with a length field are supported. */
		frame = quic_frame_create(sk, QUIC_FRAME_DATAGRAM_LEN,
					  &msg->msg_iter);
		if (IS_ERR(frame)) {
			err = PTR_ERR(frame);
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

	if (!iov_iter_count(msginfo.msg)) { /* Allow stream FIN without data. */
		if (!(flags & MSG_QUIC_STREAM_FIN)) {
			err = -EINVAL;
			goto err;
		}
		len = 0;
	}

	do {
		if (!quic_sock_stream_writable(sk, stream, flags, len)) {
			if (delay) {
				outq->force_delay = 0;
				quic_outq_transmit(sk);
			}
			err = quic_wait_for_stream_send(sk, stream, flags, len);
			if (err) {
				/* Return -ENOSPC (flow control limit hit) only
				 * if stream info cmsg was set; otherwise treat
				 * it as -EAGAIN.
				 */
				if (err == -ENOSPC && !has_sinfo)
					err = -EAGAIN;
				if (err == -EPIPE || !bytes)
					goto err;
				goto out;
			}
		}

		/* Probe appendable size. */
		len = quic_outq_stream_append(sk, &msginfo, false);
		if (len >= 0) {
			if (!sk_wmem_schedule(sk, len))
				continue; /* Retry on memory pressure. */
			len = quic_outq_stream_append(sk, &msginfo, true);
			if (len >= 0) { /* Appended. */
				bytes += len;
				 /* Reset minimal len guess for next frame. */
				len = 1;
				continue;
			}
		}

		frame = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo);
		if (IS_ERR(frame)) {
			if (!bytes) {
				err = PTR_ERR(frame);
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
		/* Allow FIN-only frame by checking iov_iter_count() after send
		 * with do-while.
		 */
	} while (iov_iter_count(msginfo.msg) > 0);
out:
	err = bytes; /* Return total bytes sent. */
err:
	/* Handle error and possibly send SIGPIPE. */
	if (err < 0 && !has_hinfo && !(flags & MSG_QUIC_DATAGRAM))
		err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}

/* Wait for an incoming QUIC packet. */
static int quic_wait_for_packet(struct sock *sk, struct list_head *head,
				u32 flags)
{
	long timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
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

#ifdef IP_TUNNEL_RECURSION_LIMIT
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t msg_len,
			int flags)
#else
static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t msg_len,
			int flags, int *addr_len)
#endif
{
	u32 copy, copied = 0, freed = 0, bytes = 0;
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_stream *stream = NULL;
	struct quic_frame *frame, *next;
	struct list_head *head;
	s64 stream_id = -1;
	int err, fin;

	lock_sock(sk);

	head = &quic_inq(sk)->recv_list;

	err = quic_wait_for_packet(sk, head, flags);
	if (err)
		goto out;

	/* Iterate over each received frame in the list. */
	list_for_each_entry_safe(frame, next, head, list) {
		/* Determine how much data to copy: the minimum of the
		 * remaining data in the frame and the remaining user buffer
		 * space.
		 */
		copy = min_t(u32, frame->len - frame->read_offset,
			     msg_len - copied);
		if (copy) { /* Copy data from frame to user message iterator. */
			copy = copy_to_iter(frame->data + frame->read_offset,
					    copy, &msg->msg_iter);
			if (!copy) {
				if (!copied) {
					/* Return err only if nothing copied. */
					err = -EFAULT;
					goto out;
				}
				break;
			}
			copied += copy; /* Accumulate total copied bytes. */
		}
		fin = frame->stream_fin;
		stream = frame->stream;
		stream_id = frame->stream_id;
		if (frame->event) { /* An Event received. */
			msg->msg_flags |= MSG_QUIC_NOTIFICATION;
		} else if (frame->level) {
			/* Attach handshake info if crypto level present. */
			hinfo.crypto_level = frame->level;
			put_cmsg(msg, SOL_QUIC, QUIC_HANDSHAKE_INFO,
				 sizeof(hinfo), &hinfo);
		} else if (frame->dgram) { /* A Datagram Message received. */
			msg->msg_flags |= MSG_QUIC_DATAGRAM;
		}
		if (flags & MSG_PEEK)
			break; /* Peek: look at first frame, do not consume. */
		if (copy != frame->len - frame->read_offset) {
			/* Partial copy: update read_offset and exit loop. */
			frame->read_offset += copy;
			break;
		}
		msg->msg_flags |= MSG_EOR;
		bytes += frame->len; /* Track bytes fully consumed. */
		if (frame->event || frame->level || frame->dgram) {
			/* Only read one frame at a time for these types. */
			list_del(&frame->list);
			quic_frame_put(frame);
			break;
		}
		/* A Stream Message received. */
		freed += frame->len;
		list_del(&frame->list);
		quic_frame_put(frame);
		if (fin) {
			sinfo.stream_flags |= MSG_QUIC_STREAM_FIN;
			break;
		}

		/* Stop if next frame is not part of this stream or no more
		 * data to copy.
		 */
		if (list_entry_is_head(next, head, list) || copied >= msg_len)
			break;
		if (next->event || next->dgram || next->stream_id == -1 ||
		    next->stream_id != stream_id)
			break;
	};

	if (stream_id != -1) {
		/* Attach stream info if stream data was processed. */
		sinfo.stream_id = stream_id;
		put_cmsg(msg, SOL_QUIC, QUIC_STREAM_INFO, sizeof(sinfo),
			 &sinfo);
		if (msg->msg_flags & MSG_CTRUNC)
			msg->msg_flags |= sinfo.stream_flags;

		/* Update flow control accounting for freed bytes. */
		quic_inq_flow_control(sk, stream, freed);
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
	long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
	struct list_head *head = quic_reqs(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
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

static void quic_sock_fetch_config(struct sock *sk, struct quic_config *config)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);

	config->receive_session_ticket = outq->receive_session_ticket;
	config->validate_peer_address = outq->validate_peer_address;
	config->certificate_request = outq->certificate_request;
	config->stream_data_nodelay = outq->stream_data_nodelay;
	config->payload_cipher_type = outq->payload_cipher_type;
	config->version = outq->version;

	config->initial_smoothed_rtt = cong->initial_srtt;
	config->congestion_control_algo = cong->algo;

	config->plpmtud_probe_interval = paths->plpmtud_interval;
}

/* Apply QUIC configuration settings to a socket. */
static int quic_sock_apply_config(struct sock *sk, struct quic_config *config)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);

	if (config->receive_session_ticket)
		outq->receive_session_ticket = config->receive_session_ticket;
	if (config->validate_peer_address)
		outq->validate_peer_address = config->validate_peer_address;
	if (config->certificate_request)
		outq->certificate_request = config->certificate_request;
	if (config->stream_data_nodelay)
		outq->stream_data_nodelay = config->stream_data_nodelay;
	if (config->payload_cipher_type) {
		if (config->payload_cipher_type != TLS_CIPHER_AES_GCM_128 &&
		    config->payload_cipher_type != TLS_CIPHER_AES_GCM_256 &&
		    config->payload_cipher_type != TLS_CIPHER_AES_CCM_128 &&
		    config->payload_cipher_type != TLS_CIPHER_CHACHA20_POLY1305)
			return -EINVAL;
		outq->payload_cipher_type = config->payload_cipher_type;
	}
	if (config->version)
		outq->version = config->version;

	if (config->initial_smoothed_rtt) {
		if (config->initial_smoothed_rtt < QUIC_RTT_MIN ||
		    config->initial_smoothed_rtt > QUIC_RTT_MAX)
			return -EINVAL;
		quic_cong_set_srtt(cong, config->initial_smoothed_rtt);
	}
	if (config->congestion_control_algo) {
		if (config->congestion_control_algo >= QUIC_CONG_ALG_MAX)
			return -EINVAL;
		quic_cong_set_algo(cong, config->congestion_control_algo);
	}

	if (config->plpmtud_probe_interval) {
		if (config->plpmtud_probe_interval < QUIC_MIN_PROBE_TIMEOUT)
			return -EINVAL;
		paths->plpmtud_interval = config->plpmtud_probe_interval;
	}

	return 0;
}

/* Initialize an accept QUIC socket from a listen socket. */
static int quic_accept_sock_init(struct sock *nsk, struct sock *sk)
{
	struct quic_data *alpn = quic_alpn(sk);
	struct quic_transport_param param = {};
	struct quic_config config = {};
	int err;

	if (sk->sk_family == AF_INET6) /* Set IPv6 state if applicable. */
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	err = quic_init_sock(nsk);
	if (err)
		return err;

	/* Duplicate ALPN from listen to accept socket for handshake. */
	if (quic_data_dup(quic_alpn(nsk), alpn->data, alpn->len))
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

	quic_inq(nsk)->events = quic_inq(sk)->events;

	/* Copy the QUIC settings and transport parameters to accept socket. */
	quic_sock_fetch_config(sk, &config);
	quic_sock_apply_config(nsk, &config);
	quic_sock_fetch_transport_param(sk, &param);
	quic_sock_apply_transport_param(nsk, &param);

	return 0;
}

/* Finalize setup for an accept QUIC socket. */
static int quic_accept_sock_setup(struct sock *sk,
				  struct quic_request_sock *req)
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
	/* Set destination address and resolve route (may also auto-set source
	 * address).
	 */
	quic_path_set_daddr(paths, 0, &req->daddr);
	err = quic_packet_route(sk);
	if (err)
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
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(crypto, &req->dcid, req->version,
					       true);
	if (err)
		goto out;
	/* Record the QUIC version offered by the peer. May later change if
	 * Compatible Version Negotiation is triggered.
	 */
	packet->version = req->version;

	/* Save original DCID and retry DCID for building transport parameters,
	 * and identifying the connection in quic_sock_lookup().
	 */
	paths->orig_dcid = req->orig_dcid;
	if (req->retry) {
		paths->retry = 1;
		paths->retry_dcid = req->dcid;
	}

	/* Add socket to hash table, change state to ESTABLISHING, and start
	 * idle timer.
	 */
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
static struct sock *quic_accept(struct sock *sk, int flags, int *errp,
				bool kern)
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

	nsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL, sk->sk_prot,
		       kern);
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

	/* Record the creation time of this accept socket in microseconds.
	 * Used by quic_accept_sock_exists() to determine if a packet from
	 * sk_backlog of listen socket predates this socket.
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

static int quic_sock_set_event(struct sock *sk, void *kopt, u32 len)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_event_option e = {};

	quic_copy_common(&e, sizeof(e), kopt, len);

	if (!e.type || e.type >= QUIC_EVENT_MAX)
		return -EINVAL;

	if (e.on) { /* Enable event by setting its bit. */
		inq->events |= BIT(e.type);
		return 0;
	}
	inq->events &= ~BIT(e.type); /* Disable by clearing its bit. */
	return 0;
}

static int quic_sock_stream_reset(struct sock *sk, void *kopt, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_errinfo info = {};
	struct quic_stream *stream;
	struct quic_frame *frame;

	if (!quic_is_established(sk))
		return -EINVAL;

	quic_copy_common(&info, sizeof(info), kopt, len);

	stream = quic_stream_get(streams, info.stream_id, 0, quic_is_serv(sk),
				 true);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	/* rfc9000#section-3.1:
	 *
	 * From any state that is one of "Ready", "Send", or "Data Sent", an
	 * application can signal that it wishes to abandon transmission of
	 * stream data.  The endpoint sends a RESET_STREAM frame, which causes
	 * the stream to enter the "Reset Sent" state.
	 */
	if (stream->send.state >= QUIC_STREAM_SEND_STATE_RECVD)
		return -EINVAL;

	frame = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, &info);
	if (IS_ERR(frame))
		return PTR_ERR(frame);

	stream->send.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	quic_outq_list_purge(sk, &outq->transmitted_list, stream);
	quic_outq_list_purge(sk, &outq->stream_list, stream);
	quic_outq_ctrl_tail(sk, frame, false);
	return 0;
}

static int quic_sock_stream_stop_sending(struct sock *sk, void *kopt, u32 len)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_errinfo info = {};
	struct quic_stream *stream;

	if (!quic_is_established(sk))
		return -EINVAL;

	quic_copy_common(&info, sizeof(info), kopt, len);

	stream = quic_stream_get(streams, info.stream_id, 0, quic_is_serv(sk),
				 false);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	/* rfc9000#section-3.3:
	 *
	 * A receiver MAY send a STOP_SENDING frame in any state where it has
	 * not received a RESET_STREAM frame -- that is, states other than
	 * "Reset Recvd" or "Reset Read".  However, there is little value in
	 * sending a STOP_SENDING frame in the "Data Recvd" state, as all
	 * stream data has been received.
	 */
	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		return -EINVAL;

	/* Defer sending; a STOP_SENDING frame is already in flight. */
	if (stream->recv.stop_sent)
		return -EAGAIN;

	quic_inq_list_purge(sk, &inq->stream_list, stream);
	quic_inq_list_purge(sk, &inq->recv_list, stream);

	return quic_outq_transmit_frame(sk, QUIC_FRAME_STOP_SENDING, &info, 0,
					false);
}

static int quic_sock_set_connection_id(struct sock *sk, void *kopt, u32 len)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_connection_id_info info = {};
	struct quic_conn_id *active;
	u64 number, first, last;

	if (!quic_is_established(sk))
		return -EINVAL;

	quic_copy_common(&info, sizeof(info), kopt, len);

	if (info.dest) {
		id_set = quic_dest(sk);
		/* The alternative connection ID is reserved for the migration
		 * path.  Until the migration completes and this path becomes
		 * active, no modifications should be made to the destination
		 * connection ID set until then.
		 */
		if (id_set->alt)
			return -EAGAIN;
	}

	if (info.prior_to) {
		/* Retire connection IDs up to (but not including) prior_to. */
		number = info.prior_to;
		last = quic_conn_id_last_number(id_set);
		first = quic_conn_id_first_number(id_set);
		if (number > last || number <= first ||
		    number + id_set->max_count > U32_MAX)
			return -EINVAL;
	}

	active = quic_conn_id_active(id_set);
	if (info.active) { /* Change active connection ID. */
		/* Ensure the new active ID is greater than the current one.
		 * All lower-numbered IDs are implicitly treated as used.
		 */
		if (info.active <= quic_conn_id_number(active))
			return -EINVAL;
		active = quic_conn_id_find(id_set, info.active);
		if (!active)
			return -EINVAL;
		quic_conn_id_set_active(id_set, active);
	}

	if (!info.prior_to)
		return 0;

	/* Retire source conn IDs via NEW_CONNECTION_ID frames. */
	if (!info.dest)
		return quic_outq_transmit_new_conn_id(sk, number, 0, false);

	/* Retire destination conn IDs via RETIRE_CONNECTION_ID frames. */
	return quic_outq_transmit_retire_conn_id(sk, number, 0, false);
}

static int quic_sock_set_connection_close(struct sock *sk, void *kopt, u32 len)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close c = {};
	u8 *data = NULL;

	quic_copy_common(&c, sizeof(c) - 1, kopt, len);

	if (strlen(c.phrase)) {
		data = kmemdup(c.phrase, strlen(c.phrase) + 1, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
	}

	kfree(outq->close_phrase);
	outq->close_phrase = data;
	outq->close_errcode = c.errcode;
	return 0;
}

static int quic_sock_connection_migrate(struct sock *sk, struct sockaddr *addr,
					u32 addr_len)
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr a;
	int err;

	if (quic_get_user_addr(sk, &a, addr, addr_len, false))
		return -EINVAL;
	/* Reject if connection is closed or address matches the current path's
	 * source.
	 */
	if (quic_is_closed(sk) ||
	    quic_cmp_sk_addr(sk, quic_path_saddr(paths, 0), &a))
		return -EINVAL;

	if (!quic_is_established(sk)) {
		/* Allows setting a preferred address before the handshake
		 * completes.  The address may use a different address family
		 * (e.g., IPv4 vs IPv6).
		 */
		if (!quic_is_serv(sk) || paths->disable_saddr_alt)
			return -EINVAL;
		paths->pref_addr = 1;
		quic_path_set_saddr(paths, 1, &a);
		return 0;
	}

	/* Migration requires matching address family and a valid port. */
	if (a.sa.sa_family != quic_path_saddr(paths, 0)->sa.sa_family ||
	    !a.v4.sin_port)
		return -EINVAL;
	/* Reject if migration in progress or preferred address active. */
	if (!quic_path_alt_state(paths, QUIC_PATH_ALT_NONE) || paths->pref_addr)
		return -EAGAIN;

	/* Setup the source address on path 1 and bind to it. */
	quic_path_set_saddr(paths, 1, &a);
	err = quic_path_bind(sk, paths, 1);
	if (err) {
		memset(quic_path_saddr(paths, 1), 0, sizeof(a));
		return err;
	}
	/* Set path 1 destination addr same as path 0 and configure routing. */
	quic_path_set_daddr(paths, 1, quic_path_daddr(paths, 0));
	if (quic_packet_config(sk, 0, 1)) {
		err = -EINVAL;
		goto err;
	}
	/* Start connection migration using new path. */
	err = quic_outq_probe_path_alt(sk, false);
	if (err)
		goto err;
	return 0;
err:
	quic_path_unbind(sk, paths, 1); /* Cleanup path 1 on failure. */
	return err;
}

static int quic_sock_key_update(struct sock *sk, void *kopt, u32 optlen)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	int err;

	err = quic_crypto_key_update(crypto);
	if (err)
		return err;

	crypto->key_pending = 1;
	crypto->key_phase = !crypto->key_phase;
	return 0;
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
		param->active_connection_id_limit =
			p->active_connection_id_limit;
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
		    (!p->remote &&
		     p->max_stream_data_bidi_local > (S32_MAX / 4)))
			return -EINVAL;
		param->max_stream_data_bidi_local =
			p->max_stream_data_bidi_local;
	}
	if (p->max_stream_data_bidi_remote) {
		if (p->max_stream_data_bidi_remote < QUIC_PATH_MIN_PMTU ||
		    (!p->remote &&
		     p->max_stream_data_bidi_remote > (S32_MAX / 4)))
			return -EINVAL;
		param->max_stream_data_bidi_remote =
			p->max_stream_data_bidi_remote;
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
		param->disable_compatible_version =
			p->disable_compatible_version;
	if (p->grease_quic_bit)
		param->grease_quic_bit = p->grease_quic_bit;
	if (p->stateless_reset)
		param->stateless_reset = p->stateless_reset;

	return 0;
}

static int quic_sock_set_transport_param(struct sock *sk, void *kopt, u32 len)
{
	struct quic_transport_param param = {}, p = {};
	int err;

	if (quic_is_established(sk))
		return -EINVAL;

	quic_copy_common(&p, sizeof(p), kopt, len);

	/* Manually setting remote transport parameters is required only to
	 * enable 0-RTT data transmission during handshake initiation.
	 */
	if (p.remote && !quic_is_establishing(sk))
		return -EINVAL;

	param.remote = p.remote;
	quic_sock_fetch_transport_param(sk, &param);

	err = quic_param_check_and_copy(&p, &param);
	if (err)
		return err;

	quic_sock_apply_transport_param(sk, &param);
	return 0;
}

static int quic_sock_set_config(struct sock *sk, void *kopt, u32 len)
{
	struct quic_config c = {};

	if (quic_is_established(sk))
		return -EINVAL;

	quic_copy_common(&c, sizeof(c), kopt, len);

	return quic_sock_apply_config(sk, &c);
}

static int quic_sock_set_alpn(struct sock *sk, u8 *data, u32 len)
{
	struct quic_data tmp, *alpns = quic_alpn(sk);
	int err;

	if (!len || len > QUIC_ALPN_MAX_LEN || quic_is_listen(sk))
		return -EINVAL;

	tmp.len  = len + 1;
	tmp.data = kzalloc(tmp.len, GFP_KERNEL);
	if (!tmp.data)
		return -ENOMEM;

	err = quic_data_from_string(&tmp, data, len);
	if (err) {
		quic_data_free(&tmp);
		return err;
	}

	kfree(alpns->data);
	*alpns = tmp;
	return 0;
}

static int quic_sock_set_token(struct sock *sk, void *data, u32 len)
{
	if (quic_is_serv(sk)) {
		/* For servers, send a regular token to client via NEW_TOKEN
		 * frames after handshake.
		 */
		if (!quic_is_established(sk))
			return -EINVAL;
		/* Defer sending; a NEW_TOKEN frame is already in flight. */
		if (quic_outq(sk)->token_pending)
			return -EAGAIN;
		return quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_TOKEN, NULL,
						0, false);
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

#define QUIC_TP_EXT_MAX_LEN	512

static int quic_sock_set_transport_params_ext(struct sock *sk, u8 *p, u32 len)
{
	struct quic_transport_param param = {};
	u32 errcode;
	int err;

	if (!quic_is_establishing(sk) || len > QUIC_TP_EXT_MAX_LEN)
		return -EINVAL;

	param.remote = 1;
	err = quic_frame_parse_transport_params_ext(sk, &param, p, len);
	if (err) {
		errcode = QUIC_TRANSPORT_ERROR_TRANSPORT_PARAM;
		quic_outq_transmit_close(sk, 0, errcode, QUIC_CRYPTO_INITIAL);
		return err;
	}

	quic_sock_apply_transport_param(sk, &param);
	return 0;
}

static int quic_sock_set_crypto_secret(struct sock *sk, void *kopt, u32 len)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_crypto_secret s = {};
	struct quic_crypto *crypto;
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	union quic_addr *a;
	int err;

	if (!quic_is_establishing(sk))
		return -EINVAL;

	quic_copy_common(&s, sizeof(s), kopt, len);

	/* Accept only supported levels: Handshake, 0-RTT (Early), or 1-RTT
	 * (App).  The initial secret was already derived in-kernel using the
	 * original destination connection ID.
	 */
	if (s.level != QUIC_CRYPTO_APP &&
	    s.level != QUIC_CRYPTO_EARLY &&
	    s.level != QUIC_CRYPTO_HANDSHAKE)
		return -EINVAL;

	/* Install keys into the crypto context. */
	crypto = quic_crypto(sk, s.level);
	err = quic_crypto_set_secret(crypto, &s, packet->version);
	if (err)
		return err;

	if (s.level != QUIC_CRYPTO_APP) {
		if (s.send) { /* 0-RTT or Handshake send key is ready. */
			/* If 0-RTT send key is ready, set data_level to EARLY.
			 * This allows quic_outq_transmit_stream() to emit
			 * stream frames in 0-RTT packets.
			 */
			if (s.level == QUIC_CRYPTO_EARLY) {
				outq->data_level = QUIC_CRYPTO_EARLY;
				quic_outq_transmit(sk);
			}
			return 0;
		}
		/* 0-RTT or Handshake receive key is ready; decrypt and process
		 * all buffered 0-RTT or Handshake packets.
		 */
		__skb_queue_head_init(&tmpq);
		skb_queue_splice_init(&inq->backlog_list, &tmpq);
		while ((skb = __skb_dequeue(&tmpq)) != NULL)
			quic_packet_process(sk, skb);
		return 0;
	}

	if (s.send) {
		/* App send key is ready, set data_level to APP. This allows
		 * quic_outq_transmit_stream() to emit stream frames in 1-RTT
		 * packets.
		 */
		outq->data_level = QUIC_CRYPTO_APP;
		if (!crypto->recv_ready)
			return 0;
		/* Both send and receive keys are ready; handshake complete. */
		goto done;
	}

	/* Free previously stored TLS session ticket and QUIC token data,
	 * allowing reception of fresh NewSessionTicket message and regular
	 * token in NEW_TOKEN frames from the peer during handshake completion.
	 */
	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));
	if (!list_empty(&inq->early_list)) {
		/* If any 0-RTT data was buffered (early_list), move it to the
		 * main receive list (recv_list) so it becomes available to the
		 * application.
		 */
		list_splice_init(&inq->early_list, &inq->recv_list);
		sk->sk_data_ready(sk);
	}
	/* App receive key is ready; decrypt and process all buffered App/1-RTT
	 * packets.
	 */
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
		/* The peer offered a preferred address (stored in path 1).
		 * Reset the flag to avoid reprocessing, and Perform routing on
		 * new path and set the local address for new path.
		 */
		if (quic_packet_config(sk, 0, 1)) {
			paths->pref_addr = 0; /* Ignore preferred address. */
			goto out;
		}
		/* If the local address for new path is different from the
		 * current one, bind to the new address.
		 */
		a = quic_path_saddr(paths, 1);
		a->v4.sin_port = quic_path_saddr(paths, 0)->v4.sin_port;
		if (!quic_cmp_sk_addr(sk, quic_path_saddr(paths, 0), a)) {
			a->v4.sin_port = 0;
			if (quic_path_bind(sk, paths, 1)) {
				/* Ignore preferred address. */
				paths->pref_addr = 0;
				goto out;
			}
		}
		goto out;
	}

	/* Clean up transmitted handshake packets. */
	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAX, 0,
				   -1, 0);
	if (paths->pref_addr) {
		/* If a preferred address is set, bind to it to allow client
		 * use at any time.
		 */
		err = quic_path_bind(sk, paths, 1);
		if (err)
			goto err;
	}

	/* Send NEW_TOKEN and HANDSHAKE_DONE frames (server only). */
	err = quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_TOKEN, NULL, 0, true);
	if (err)
		goto err;
	err = quic_outq_transmit_frame(sk, QUIC_FRAME_HANDSHAKE_DONE, NULL, 0,
				       true);
	if (err)
		goto err;
out:
	/* Send NEW_CONNECTION_ID frames to reach maximum connection IDs. */
	err = quic_outq_transmit_new_conn_id(sk, 0, 0, false);
	if (err)
		goto err;
	/* Enter established state, and start PLPMTUD timer and Path Challenge
	 * timer.
	 */
	quic_set_state(sk, QUIC_SS_ESTABLISHED);
	quic_timer_start(sk, QUIC_TIMER_PMTU, paths->plpmtud_interval);
	quic_timer_reset_path(sk);
	return 0;
err:
	quic_outq_transmit_close(sk, 0, QUIC_TRANSPORT_ERROR_INTERNAL,
				 QUIC_CRYPTO_APP);
	return err;
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
int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval,
		       unsigned int optlen)
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
		retval = quic_sock_key_update(sk, kopt, optlen);
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
		return quic_common_setsockopt(sk, level, optname, optval,
					      optlen);

	return quic_do_setsockopt(sk, optname, optval, optlen);
}

static int quic_sock_get_event(struct sock *sk, u32 len, sockptr_t optval,
			       sockptr_t optlen)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_event_option e = {};

	if (len > sizeof(e))
		len = sizeof(e);

	if (copy_from_sockptr(&e, optval, len))
		return -EFAULT;

	if (!e.type || e.type >= QUIC_EVENT_MAX)
		return -EINVAL;
	/* Set on if the corresponding event bit is set. */
	e.on = !!(inq->events & BIT(e.type));

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &e, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_stream_open(struct sock *sk, u32 len, sockptr_t optval,
				 sockptr_t optlen)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream_info sinfo = {};
	struct quic_stream *stream;

	if (len > sizeof(sinfo))
		len = sizeof(sinfo);

	if (copy_from_sockptr(&sinfo, optval, len))
		return -EFAULT;

	/* Reject unsupported flags. */
	if (sinfo.stream_flags & ~QUIC_MSG_STREAM_FLAGS)
		return -EINVAL;

	/* If stream_id is -1, assign the next available ID (bidi or uni). */
	if (sinfo.stream_id == -1) {
		sinfo.stream_id = streams->send.next_bidi_stream_id;
		if (sinfo.stream_flags & MSG_QUIC_STREAM_UNI)
			sinfo.stream_id = streams->send.next_uni_stream_id;
	}
	/* Mark stream as to be created. */
	sinfo.stream_flags |= MSG_QUIC_STREAM_NEW;

	/* Create or retrieve stream. */
	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &sinfo, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_connection_id(struct sock *sk, u32 len,
				       sockptr_t optval, sockptr_t optlen)
{
	struct quic_connection_id_info info = {};
	struct quic_conn_id_set *id_set;
	struct quic_conn_id *active;

	if (!quic_is_established(sk))
		return -EINVAL;

	if (len > sizeof(info))
		len = sizeof(info);

	if (copy_from_sockptr(&info, optval, len))
		return -EFAULT;

	id_set = info.dest ? quic_dest(sk) : quic_source(sk);
	active = quic_conn_id_active(id_set);
	info.active = quic_conn_id_number(active);
	/* Use prior_to to indicate the smallest issued connection ID number.
	 * Combined with the active_connection_id_limit (from the peer’s
	 * transport parameters), this allows userspace to infer the full set
	 * of valid connection IDs.
	 */
	info.prior_to = quic_conn_id_first_number(id_set);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &info, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_connection_close(struct sock *sk, u32 len,
					  sockptr_t optval, sockptr_t optlen)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close c = {};

	if (len > sizeof(c))
		len = sizeof(c);

	c.errcode = outq->close_errcode;
	c.frame = outq->close_frame;

	if (outq->close_phrase)
		strscpy(c.phrase, outq->close_phrase, sizeof(c.phrase));

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &c, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_param(struct sock *sk, u32 len,
					 sockptr_t optval, sockptr_t optlen)
{
	struct quic_transport_param param = {};

	if (len > sizeof(param))
		len = sizeof(param);

	if (copy_from_sockptr(&param, optval, len))
		return -EFAULT;

	quic_sock_fetch_transport_param(sk, &param);

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &param, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_config(struct sock *sk, u32 len, sockptr_t optval,
				sockptr_t optlen)
{
	struct quic_config config = {};

	if (len > sizeof(config))
		len = sizeof(config);

	quic_sock_fetch_config(sk, &config);
	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &config, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_alpn(struct sock *sk, u32 len, sockptr_t optval,
			      sockptr_t optlen)
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
	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_token(struct sock *sk, u32 len, sockptr_t optval,
			       sockptr_t optlen)
{
	struct quic_data *token = quic_token(sk);

	if (quic_is_serv(sk) || len < token->len)
		return -EINVAL;
	len = token->len;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, token->data, len))
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
		/* For clients, retrieve the received TLS NewSessionTicket
		 * message.
		 */
		if (quic_is_established(sk) && !crypto->ticket_ready)
			tlen = 0;
		goto out;
	}

	if (quic_is_closed(sk))
		return -EINVAL;

	/* For servers, return the master key used for session resumption.  If
	 * already set, reuse it.
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

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, ticket, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_transport_params_ext(struct sock *sk, u32 len,
					      sockptr_t optval,
					      sockptr_t optlen)
{
	struct quic_transport_param param = {};
	u8 data[QUIC_TP_EXT_MAX_LEN];
	u32 datalen = 0;
	int err;

	if (!quic_is_establishing(sk))
		return -EINVAL;

	quic_sock_fetch_transport_param(sk, &param);

	err = quic_frame_build_transport_params_ext(sk, &param, data, &datalen);
	if (err)
		return err;
	if (len < datalen)
		return -EINVAL;
	len = datalen;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, data, len))
		return -EFAULT;
	return 0;
}

static int quic_sock_get_crypto_secret(struct sock *sk, u32 len,
				       sockptr_t optval, sockptr_t optlen)
{
	struct quic_crypto_secret s = {};

	if (len > sizeof(s))
		len = sizeof(s);

	if (copy_from_sockptr(&s, optval, len))
		return -EFAULT;

	if (s.level >= QUIC_CRYPTO_MAX)
		return -EINVAL;
	if (quic_crypto_get_secret(quic_crypto(sk, s.level), &s))
		return -EINVAL;

	if (copy_to_sockptr(optlen, &len, sizeof(len)) ||
	    copy_to_sockptr(optval, &s, len))
		return -EFAULT;
	return 0;
}

/**
 * quic_do_getsockopt - get a QUIC socket option
 * @sk: socket to query
 * @optname: option name (QUIC-level)
 * @optval: user buffer to receive the option value
 * @optlen: pointer to buffer size; updated with actual size on return
 *
 * Gets a QUIC socket option from a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval,
		       sockptr_t optlen)
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
		retval = quic_sock_get_connection_close(sk, len, optval,
							optlen);
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
		retval = quic_sock_get_transport_params_ext(sk, len, optval,
							    optlen);
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
		return quic_common_getsockopt(sk, level, optname, optval,
					      optlen);

	return quic_do_getsockopt(sk, optname, USER_SOCKPTR(optval),
				  USER_SOCKPTR(optlen));
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
