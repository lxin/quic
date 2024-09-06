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

#include <uapi/linux/quic.h>
#include <net/udp_tunnel.h>
#include <linux/version.h>

#include "hashtable.h"
#include "protocol.h"
#include "connid.h"
#include "stream.h"
#include "crypto.h"
#include "input.h"
#include "path.h"

static int quic_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (skb_linearize(skb))
		return 0;

	memset(skb->cb, 0, sizeof(skb->cb));
	QUIC_CRYPTO_CB(skb)->udph_offset = skb->transport_header;
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

	head = quic_udp_sock_head(sock_net(us->sk), ntohs(us->addr.v4.sin_port));

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
		pr_debug("%s: failed to create udp sock\n", __func__);
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

	head = quic_udp_sock_head(net, ntohs(a->v4.sin_port));
	spin_lock(&head->lock);
	hlist_add_head(&us->node, &head->head);
	spin_unlock(&head->lock);
	INIT_WORK(&us->work, quic_udp_sock_destroy);

	return us;
}

static struct quic_udp_sock *quic_udp_sock_get(struct quic_udp_sock *us)
{
	if (us)
		refcount_inc(&us->refcnt);
	return us;
}

static void quic_udp_sock_put(struct quic_udp_sock *us)
{
	if (us && refcount_dec_and_test(&us->refcnt))
		queue_work(quic_wq, &us->work);
}

static struct quic_udp_sock *quic_udp_sock_lookup(struct sock *sk, union quic_addr *a)
{
	struct quic_udp_sock *tmp, *us = NULL;
	struct quic_addr_family_ops *af_ops;
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;

	head = quic_udp_sock_head(net, ntohs(a->v4.sin_port));
	spin_lock(&head->lock);
	hlist_for_each_entry(tmp, &head->head, node) {
		if (net != sock_net(tmp->sk))
			continue;

		af_ops = quic_af_ops_get(tmp->sk->sk_family);
		if (af_ops->cmp_sk_addr(sk, &tmp->addr, a)) {
			us = quic_udp_sock_get(tmp);
			break;
		}
	}
	spin_unlock(&head->lock);
	if (!us)
		us = quic_udp_sock_create(sk, a);
	return us;
}

int quic_path_set_udp_sock(struct sock *sk, struct quic_path_addr *path, bool alt)
{
	struct quic_path_src *src = (struct quic_path_src *)path;
	struct quic_udp_sock *usk;

	usk = quic_udp_sock_lookup(sk, quic_path_addr(path, alt));
	if (!usk)
		return -EINVAL;

	quic_udp_sock_put(src->udp_sk[src->a.active ^ alt]);
	src->udp_sk[src->a.active ^ alt] = usk;
	return 0;
}

static void quic_path_put_bind_port(struct sock *sk, struct quic_bind_port *pp)
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

int quic_path_set_bind_port(struct sock *sk, struct quic_path_addr *path, bool alt)
{
	struct quic_bind_port *port = quic_path_port(path, alt);
	union quic_addr *addr = quic_path_addr(path, alt);
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	struct quic_bind_port *pp;
	int low, high, remaining;
	unsigned int rover;

	quic_path_put_bind_port(sk, port);

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
		if (rover < low || rover > high)
			rover = low;
		if (inet_is_local_reserved_port(net, rover))
			continue;
		head = quic_bind_port_head(net, rover);
		spin_lock_bh(&head->lock);
		hlist_for_each_entry(pp, &head->head, node)
			if (pp->port == rover && net_eq(net, pp->net))
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

void quic_path_addr_free(struct sock *sk, struct quic_path_addr *path, bool alt)
{
	struct quic_path_src *src;

	if (!path->udp_bind)
		goto out;

	src = (struct quic_path_src *)path;
	quic_udp_sock_put(src->udp_sk[path->active ^ alt]);
	src->udp_sk[path->active ^ alt] = NULL;
	quic_path_put_bind_port(sk, &src->port[path->active ^ alt]);
out:
	memset(&path->addr[path->active ^ alt], 0, path->addr_len);
}

void quic_path_free(struct sock *sk, struct quic_path_addr *path)
{
	quic_path_addr_free(sk, path, 0);
	quic_path_addr_free(sk, path, 1);
}

enum quic_plpmtud_state {
	QUIC_PL_DISABLED,
	QUIC_PL_BASE,
	QUIC_PL_SEARCH,
	QUIC_PL_COMPLETE,
	QUIC_PL_ERROR,
};

#define QUIC_BASE_PLPMTU        1200
#define QUIC_MAX_PLPMTU         9000
#define QUIC_MIN_PLPMTU         512

#define QUIC_MAX_PROBES         3

#define QUIC_PL_BIG_STEP        32
#define QUIC_PL_MIN_STEP        4

int quic_path_pl_send(struct quic_path_addr *a, s64 number)
{
	struct quic_path_dst *d = (struct quic_path_dst *)a;
	int pathmtu = 0;

	d->pl.number = number;
	if (d->pl.probe_count < QUIC_MAX_PROBES)
		goto out;

	d->pl.probe_count = 0;
	if (d->pl.state == QUIC_PL_BASE) {
		if (d->pl.probe_size == QUIC_BASE_PLPMTU) { /* BASE_PLPMTU Confirmation Failed */
			d->pl.state = QUIC_PL_ERROR; /* Base -> Error */

			d->pl.pmtu = QUIC_BASE_PLPMTU;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
		}
	} else if (d->pl.state == QUIC_PL_SEARCH) {
		if (d->pl.pmtu == d->pl.probe_size) { /* Black Hole Detected */
			d->pl.state = QUIC_PL_BASE;  /* Search -> Base */
			d->pl.probe_size = QUIC_BASE_PLPMTU;
			d->pl.probe_high = 0;

			d->pl.pmtu = QUIC_BASE_PLPMTU;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
		} else { /* Normal probe failure. */
			d->pl.probe_high = d->pl.probe_size;
			d->pl.probe_size = d->pl.pmtu;
		}
	} else if (d->pl.state == QUIC_PL_COMPLETE) {
		if (d->pl.pmtu == d->pl.probe_size) { /* Black Hole Detected */
			d->pl.state = QUIC_PL_BASE;  /* Search Complete -> Base */
			d->pl.probe_size = QUIC_BASE_PLPMTU;

			d->pl.pmtu = QUIC_BASE_PLPMTU;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
		}
	}

out:
	pr_debug("%s: dst: %p, state: %d, pmtu: %d, size: %d, high: %d\n",
		 __func__, d, d->pl.state, d->pl.pmtu, d->pl.probe_size, d->pl.probe_high);
	d->pl.probe_count++;
	return pathmtu;
}

int quic_path_pl_recv(struct quic_path_addr *a, bool *raise_timer, bool *complete)
{
	struct quic_path_dst *d = (struct quic_path_dst *)a;
	int pathmtu = 0;

	pr_debug("%s: dst: %p, state: %d, pmtu: %d, size: %d, high: %d\n",
		 __func__, d, d->pl.state, d->pl.pmtu, d->pl.probe_size, d->pl.probe_high);

	*raise_timer = false;
	d->pl.number = 0;
	d->pl.pmtu = d->pl.probe_size;
	d->pl.probe_count = 0;
	if (d->pl.state == QUIC_PL_BASE) {
		d->pl.state = QUIC_PL_SEARCH; /* Base -> Search */
		d->pl.probe_size += QUIC_PL_BIG_STEP;
	} else if (d->pl.state == QUIC_PL_ERROR) {
		d->pl.state = QUIC_PL_SEARCH; /* Error -> Search */

		d->pl.pmtu = d->pl.probe_size;
		d->pathmtu = d->pl.pmtu;
		pathmtu = d->pathmtu;
		d->pl.probe_size += QUIC_PL_BIG_STEP;
	} else if (d->pl.state == QUIC_PL_SEARCH) {
		if (!d->pl.probe_high) {
			if (d->pl.probe_size < QUIC_MAX_PLPMTU) {
				d->pl.probe_size = min(d->pl.probe_size + QUIC_PL_BIG_STEP,
						       QUIC_MAX_PLPMTU);
				*complete = false;
				return pathmtu;
			}
			d->pl.probe_high = QUIC_MAX_PLPMTU;
		}
		d->pl.probe_size += QUIC_PL_MIN_STEP;
		if (d->pl.probe_size >= d->pl.probe_high) {
			d->pl.probe_high = 0;
			d->pl.state = QUIC_PL_COMPLETE; /* Search -> Search Complete */

			d->pl.probe_size = d->pl.pmtu;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
			*raise_timer = true;
		}
	} else if (d->pl.state == QUIC_PL_COMPLETE) {
		/* Raise probe_size again after 30 * interval in Search Complete */
		d->pl.state = QUIC_PL_SEARCH; /* Search Complete -> Search */
		d->pl.probe_size = min(d->pl.probe_size + QUIC_PL_MIN_STEP, QUIC_MAX_PLPMTU);
	}

	*complete = (d->pl.state == QUIC_PL_COMPLETE);
	return pathmtu;
}

int quic_path_pl_toobig(struct quic_path_addr *a, u32 pmtu, bool *reset_timer)
{
	struct quic_path_dst *d = (struct quic_path_dst *)a;
	int pathmtu = 0;

	pr_debug("%s: dst: %p, state: %d, pmtu: %d, size: %d, ptb: %d\n",
		 __func__, d, d->pl.state, d->pl.pmtu, d->pl.probe_size, pmtu);

	*reset_timer = false;
	if (pmtu < QUIC_MIN_PLPMTU || pmtu >= d->pl.probe_size)
		return pathmtu;

	if (d->pl.state == QUIC_PL_BASE) {
		if (pmtu >= QUIC_MIN_PLPMTU && pmtu < QUIC_BASE_PLPMTU) {
			d->pl.state = QUIC_PL_ERROR; /* Base -> Error */

			d->pl.pmtu = QUIC_BASE_PLPMTU;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
		}
	} else if (d->pl.state == QUIC_PL_SEARCH) {
		if (pmtu >= QUIC_BASE_PLPMTU && pmtu < d->pl.pmtu) {
			d->pl.state = QUIC_PL_BASE;  /* Search -> Base */
			d->pl.probe_size = QUIC_BASE_PLPMTU;
			d->pl.probe_count = 0;

			d->pl.probe_high = 0;
			d->pl.pmtu = QUIC_BASE_PLPMTU;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
		} else if (pmtu > d->pl.pmtu && pmtu < d->pl.probe_size) {
			d->pl.probe_size = pmtu;
			d->pl.probe_count = 0;
		}
	} else if (d->pl.state == QUIC_PL_COMPLETE) {
		if (pmtu >= QUIC_BASE_PLPMTU && pmtu < d->pl.pmtu) {
			d->pl.state = QUIC_PL_BASE;  /* Complete -> Base */
			d->pl.probe_size = QUIC_BASE_PLPMTU;
			d->pl.probe_count = 0;

			d->pl.probe_high = 0;
			d->pl.pmtu = QUIC_BASE_PLPMTU;
			d->pathmtu = d->pl.pmtu;
			pathmtu = d->pathmtu;
			*reset_timer = true;
		}
	}
	return pathmtu;
}

void quic_path_pl_reset(struct quic_path_addr *a)
{
	struct quic_path_dst *d = (struct quic_path_dst *)a;

	d->pl.number = 0;
	d->pl.state = QUIC_PL_BASE;
	d->pl.pmtu = QUIC_BASE_PLPMTU;
	d->pl.probe_size = QUIC_BASE_PLPMTU;
}

bool quic_path_pl_confirm(struct quic_path_addr *a, s64 largest, s64 smallest)
{
	struct quic_path_dst *d = (struct quic_path_dst *)a;

	return d->pl.number && d->pl.number >= smallest && d->pl.number <= largest;
}
