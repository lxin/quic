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

	if (!us)
		us = quic_udp_sock_create(sk, a);

	return us;
}

void quic_path_addr_set(struct quic_path_addr *a, union quic_addr *addr)
{
	memcpy(&a->addr[0], addr, a->addr_len);
}

union quic_addr *quic_path_addr(struct quic_path_addr *a)
{
	return &a->addr[0];
}

void quic_path_addr_init(struct quic_path_addr *a, u8 addr_len)
{
	a->addr_len = addr_len;
}

int quic_udp_sock_set(struct sock *sk, struct quic_udp_sock *udp_sk[], union quic_addr *addr)
{
	struct quic_udp_sock *usk;

	usk = quic_udp_sock_lookup(sk, addr);
	if (!usk)
		return -EINVAL;

	quic_udp_sock_put(udp_sk[0]);
	udp_sk[0] = usk;

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
