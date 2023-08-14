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

#include <net/udp_tunnel.h>

#include <linux/version.h>

#include "uapi/linux/quic.h"
#include "hashtable.h"
#include "protocol.h"
#include "stream.h"
#include "input.h"
#include "path.h"

void quic_get_port(struct net *net, struct quic_bind_port *port, union quic_addr *addr)
{
	struct quic_hash_head *head;
	struct quic_bind_port *pp;
	int low, high, remaining;
	unsigned int rover;

	rover = ntohs(addr->v4.sin_port);
	if (rover) {
		head = quic_bind_port_head(net, rover);
		spin_lock_bh(&head->lock);
		goto found;
	}

	inet_get_local_port_range(net, &low, &high);
	remaining = (high - low) + 1;
#if KERNEL_VERSION(6, 1, 0) >= LINUX_VERSION_CODE
	rover = prandom_u32_max(remaining) + low;
#else
	rover = get_random_u32_below(remaining) + low;
#endif
	do {
		rover++;
		if ((rover < low) || (rover > high))
			rover = low;
		if (inet_is_local_reserved_port(net, rover))
			continue;
		head = quic_bind_port_head(net, rover);
		spin_lock_bh(&head->lock);
		hlist_for_each_entry(pp, &head->head, node)
			if ((pp->port == rover) && net_eq(net, pp->net))
				goto next;
		break;
	next:
		spin_unlock_bh(&head->lock);
		cond_resched();
	} while (--remaining > 0);

	/* not found, use the random one */
	addr->v4.sin_port = htons(rover);
found:
	port->net = net;
	port->port = rover;
	hlist_add_head(&port->node, &head->head);
	spin_unlock_bh(&head->lock);
}

void quic_put_port(struct net *net, struct quic_bind_port *pp)
{
	struct quic_hash_head *head;

	if (hlist_unhashed(&pp->node))
		return;

	head = quic_bind_port_head(net, pp->port);
	spin_lock(&head->lock);
	hlist_del(&pp->node);
	spin_unlock(&head->lock);
}

static int quic_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (skb_linearize(skb))
		return 0;

	skb_set_transport_header(skb, sizeof(struct udphdr));
	quic_rcv(skb);
	return 0;
}

static int quic_udp_err_lookup(struct sock *sk, struct sk_buff *skb)
{
	return -ENOENT;
}

static struct quic_udp_sock *quic_udp_sock_create(struct sock *sk, union quic_addr *a)
{
	struct udp_tunnel_sock_cfg tuncfg = {NULL};
	struct udp_port_cfg udp_conf = {0};
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	struct quic_udp_sock *us;
	struct socket *sock;

	us = kzalloc(sizeof(*us), GFP_ATOMIC);
	if (!us)
		return NULL;

	quic_udp_conf_init(sk, &udp_conf, a);
	if (udp_sock_create(net, &udp_conf, &sock)) {
		pr_err("[QUIC] Failed to create UDP sock for QUIC\n");
		kfree(us);
		return NULL;
	}

	tuncfg.encap_type = 1;
	tuncfg.encap_rcv = quic_udp_rcv;
	tuncfg.encap_err_lookup = quic_udp_err_lookup;
	setup_udp_tunnel_sock(net, sock, &tuncfg);

	refcount_set(&us->refcnt, 1);
	us->sk = sock->sk;
	memcpy(&us->addr, a, sizeof(*a));

	head = quic_udp_sock_head(net, a);
	spin_lock(&head->lock);
	hlist_add_head(&us->node, &head->head);
	spin_unlock(&head->lock);

	return us;
}

static struct quic_udp_sock *quic_udp_sock_lookup(struct sock *sk, union quic_addr *a)
{
	struct quic_udp_sock *tmp, *us = NULL;
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr sa = {};

	head = quic_udp_sock_head(net, a);
	spin_lock(&head->lock);
	hlist_for_each_entry(tmp, &head->head, node) {
		if (net == sock_net(tmp->sk) &&
		    !memcmp(&tmp->addr, a, quic_addr_len(sk))) {
			us = quic_udp_sock_get(tmp);
			break;
		}
	}
	spin_unlock(&head->lock);
	if (us)
		return us;

	/* Search for socket binding to the same port with 0.0.0.0 or :: address */
	sa.v4.sin_family = a->v4.sin_family;
	sa.v4.sin_port = a->v4.sin_port;
	head = quic_udp_sock_head(net, &sa);
	spin_lock(&head->lock);
	hlist_for_each_entry(tmp, &head->head, node) {
		if (net == sock_net(tmp->sk) &&
		    !memcmp(&tmp->addr, &sa, quic_addr_len(sk))) {
			us = quic_udp_sock_get(tmp);
			break;
		}
	}
	spin_unlock(&head->lock);

	if (!us)
		us = quic_udp_sock_create(sk, a);
	return us;
}

int quic_udp_sock_set(struct sock *sk, struct quic_udp_sock *udp_sk[], struct quic_path_addr *a)
{
	struct quic_udp_sock *usk;

	usk = quic_udp_sock_lookup(sk, quic_path_addr(a));
	if (!usk)
		return -EINVAL;

	quic_udp_sock_put(udp_sk[a->active]);
	udp_sk[a->active] = usk;

	return 0;
}

static void quic_udp_sock_destroy(struct quic_udp_sock *us)
{
	struct quic_hash_head *head = quic_udp_sock_head(sock_net(us->sk), &us->addr);

	spin_lock(&head->lock);
	__hlist_del(&us->node);
	spin_unlock(&head->lock);

	udp_tunnel_sock_release(us->sk->sk_socket);
	kfree(us);
}

struct quic_udp_sock *quic_udp_sock_get(struct quic_udp_sock *us)
{
	if (us)
		refcount_inc(&us->refcnt);
	return us;
}

void quic_udp_sock_put(struct quic_udp_sock *us)
{
	if (us && refcount_dec_and_test(&us->refcnt))
		quic_udp_sock_destroy(us);
}
