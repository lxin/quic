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

static int quic_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (skb_linearize(skb))
		return 0;

	memset(skb->cb, 0, sizeof(skb->cb));
	skb_set_transport_header(skb, sizeof(struct udphdr));
	quic_rcv(skb);
	return 0;
}

static int quic_udp_err(struct sock *sk, struct sk_buff *skb)
{
	int ret;

	skb->transport_header += sizeof(struct udphdr);
	ret = quic_rcv_err(skb);
	skb->transport_header -= sizeof(struct udphdr);

	return ret;
}

static void quic_udp_sock_destroy(struct work_struct *work)
{
	struct quic_udp_sock *us = container_of(work, struct quic_udp_sock, work);
	struct quic_hash_head *head;

	head = quic_udp_sock_head(sock_net(us->sk), &us->addr);

	spin_lock(&head->lock);
	__hlist_del(&us->node);
	spin_unlock(&head->lock);

	udp_tunnel_sock_release(us->sk->sk_socket);
	kfree(us);
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
	tuncfg.encap_err_lookup = quic_udp_err;
	setup_udp_tunnel_sock(net, sock, &tuncfg);

	refcount_set(&us->refcnt, 1);
	us->sk = sock->sk;
	memcpy(&us->addr, a, sizeof(*a));

	head = quic_udp_sock_head(net, a);
	spin_lock(&head->lock);
	hlist_add_head(&us->node, &head->head);
	spin_unlock(&head->lock);
	INIT_WORK(&us->work, quic_udp_sock_destroy);

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

struct quic_udp_sock *quic_udp_sock_get(struct quic_udp_sock *us)
{
	if (us)
		refcount_inc(&us->refcnt);
	return us;
}

void quic_udp_sock_put(struct quic_udp_sock *us)
{
	if (us && refcount_dec_and_test(&us->refcnt))
		queue_work(quic_wq, &us->work);
}

int quic_path_set_udp_sock(struct sock *sk, struct quic_path_addr *a)
{
	struct quic_path_src *s = (struct quic_path_src *)a;
	struct quic_udp_sock *usk;

	usk = quic_udp_sock_lookup(sk, quic_path_addr(a));
	if (!usk)
		return -EINVAL;

	quic_udp_sock_put(s->udp_sk[s->a.active]);
	s->udp_sk[s->a.active] = usk;
	a->udp_bind = 1;
	return 0;
}

void quic_bind_port_put(struct sock *sk, struct quic_bind_port *pp)
{
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;

	if (hlist_unhashed(&pp->node))
		return;

	head = quic_bind_port_head(net, pp->port);
	spin_lock(&head->lock);
	hlist_del_init(&pp->node);
	spin_unlock(&head->lock);
}

int quic_path_set_bind_port(struct sock *sk, struct quic_path_addr *a)
{
	struct quic_bind_port *port = quic_path_port(a);
	union quic_addr *addr = quic_path_addr(a);
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	struct quic_bind_port *pp;
	int low, high, remaining;
	unsigned int rover;

	quic_bind_port_put(sk, port);

	rover = ntohs(addr->v4.sin_port);
	if (rover) {
		head = quic_bind_port_head(net, rover);
		spin_lock_bh(&head->lock);
		port->net = net;
		port->port = rover;
		hlist_add_head(&port->node, &head->head);
		spin_unlock_bh(&head->lock);
		return 0;
	}

	inet_get_local_port_range(net, &low, &high);
	remaining = (high - low) + 1;
	rover = (u32)(((u64)get_random_u32() * remaining) >> 32) + low;
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
		addr->v4.sin_port = htons(rover);
		port->net = net;
		port->port = rover;
		hlist_add_head(&port->node, &head->head);
		spin_unlock_bh(&head->lock);
		return 0;
	next:
		spin_unlock_bh(&head->lock);
		cond_resched();
	} while (--remaining > 0);

	return -EADDRINUSE;
}

void quic_path_free(struct sock *sk, struct quic_path_addr *a)
{
	struct quic_path_src *s;

	if (!a->udp_bind)
		return;

	s = (struct quic_path_src *)a;
	quic_udp_sock_put(s->udp_sk[0]);
	quic_udp_sock_put(s->udp_sk[1]);
	quic_bind_port_put(sk, &s->port[0]);
	quic_bind_port_put(sk, &s->port[1]);
}
