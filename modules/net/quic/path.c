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
#include <linux/quic.h>

#include "common.h"
#include "family.h"
#include "path.h"

static int (*quic_path_rcv)(struct sk_buff *skb, u8 err);

static int quic_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
	/* Save the UDP socket to skb->sk for later QUIC socket lookup. */
	if (skb_linearize(skb) || !skb_set_owner_sk_safe(skb, sk))
		return 0;

	memset(skb->cb, 0, sizeof(skb->cb));
	QUIC_SKB_CB(skb)->seqno = -1;
	QUIC_SKB_CB(skb)->udph_offset = skb->transport_header;
	QUIC_SKB_CB(skb)->time = quic_ktime_get_us();

	skb_set_transport_header(skb, sizeof(struct udphdr));
	skb_dst_force(skb);
	quic_path_rcv(skb, 0);
	return 0;
}

static int quic_udp_err(struct sock *sk, struct sk_buff *skb)
{
	/* Save the UDP socket to skb->sk for later QUIC socket lookup. */
	if (skb_linearize(skb) || !skb_set_owner_sk_safe(skb, sk))
		return 0;

	QUIC_SKB_CB(skb)->udph_offset = skb->transport_header;
	return quic_path_rcv(skb, 1);
}

static void quic_udp_sock_put_work(struct work_struct *work)
{
	struct quic_udp_sock *us = container_of(work, struct quic_udp_sock, work);
	struct quic_uhash_head *head;
	struct sock *sk = us->sk;

	/* Hold the sock to safely access it in quic_udp_sock_lookup() even after
	 * udp_tunnel_sock_release(). The release must occur before __hlist_del()
	 * so a new UDP tunnel socket can be created for the same address and port
	 * if quic_udp_sock_lookup() fails to find one.
	 *
	 * Note: udp_tunnel_sock_release() cannot be called under the mutex due to
	 * some lockdep warnings.
	 */
	sock_hold(sk);
	udp_tunnel_sock_release(sk->sk_socket);

	head = quic_udp_sock_head(sock_net(sk), ntohs(us->addr.v4.sin_port));
	mutex_lock(&head->lock);
	__hlist_del(&us->node);
	mutex_unlock(&head->lock);

	sock_put(sk);
	kfree(us);
}

static struct quic_udp_sock *quic_udp_sock_create(struct sock *sk, union quic_addr *a)
{
	struct udp_tunnel_sock_cfg tuncfg = {};
	struct udp_port_cfg udp_conf = {};
	struct net *net = sock_net(sk);
	struct quic_uhash_head *head;
	struct quic_udp_sock *us;
	struct socket *sock;

	us = kzalloc(sizeof(*us), GFP_KERNEL);
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
	us->bind_ifindex = sk->sk_bound_dev_if;

	head = quic_udp_sock_head(net, ntohs(a->v4.sin_port));
	hlist_add_head(&us->node, &head->head);
	INIT_WORK(&us->work, quic_udp_sock_put_work);

	return us;
}

static bool quic_udp_sock_get(struct quic_udp_sock *us)
{
	return refcount_inc_not_zero(&us->refcnt);
}

static void quic_udp_sock_put(struct quic_udp_sock *us)
{
	if (refcount_dec_and_test(&us->refcnt))
		queue_work(quic_wq, &us->work);
}

/* Lookup a quic_udp_sock in the global hash table by port or address.  If 'a' is provided, it
 * searches for a socket whose local address matches 'a' and, if applicable, matches the device
 * binding. If 'a' is NULL, it searches only by port.
 */
static struct quic_udp_sock *quic_udp_sock_lookup(struct sock *sk, union quic_addr *a, u16 port)
{
	struct net *net = sock_net(sk);
	struct quic_uhash_head *head;
	struct quic_udp_sock *us;

	head = quic_udp_sock_head(net, port);
	hlist_for_each_entry(us, &head->head, node) {
		if (net != sock_net(us->sk))
			continue;
		if (a) {
			if (quic_cmp_sk_addr(us->sk, &us->addr, a) &&
			    (!us->bind_ifindex || !sk->sk_bound_dev_if ||
			     us->bind_ifindex == sk->sk_bound_dev_if))
				return us;
			continue;
		}
		if (ntohs(us->addr.v4.sin_port) == port)
			return us;
	}
	return NULL;
}

static void quic_path_set_udp_sk(struct quic_path *path, struct quic_udp_sock *us)
{
	if (path->udp_sk)
		quic_udp_sock_put(path->udp_sk);

	path->udp_sk = us;
	if (!us) {
		path->usk = NULL;
		memset(&path->uaddr, 0, sizeof(path->uaddr));
		return;
	}
	path->usk = us->sk;
	memcpy(&path->uaddr, &us->addr, sizeof(us->addr));
}

/* Binds a QUIC path to a local port and sets up a UDP socket. */
int quic_path_bind(struct sock *sk, struct quic_path_group *paths, u8 path)
{
	union quic_addr *a = quic_path_saddr(paths, path);
	int rover, low, high, remaining;
	struct net *net = sock_net(sk);
	struct quic_uhash_head *head;
	struct quic_udp_sock *us;
	u16 port;

	port = ntohs(a->v4.sin_port);
	if (port) {
		head = quic_udp_sock_head(net, port);
		mutex_lock(&head->lock);
		us = quic_udp_sock_lookup(sk, a, port);
		if (us) {
			if (!quic_udp_sock_get(us)) { /* Releasing in workqueue; retry later. */
				mutex_unlock(&head->lock);
				return -EAGAIN;
			}
		} else {
			us = quic_udp_sock_create(sk, a);
			if (!us) {
				mutex_unlock(&head->lock);
				return -EINVAL;
			}
		}
		mutex_unlock(&head->lock);
		quic_path_set_udp_sk(&paths->path[path], us);
		return 0;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	inet_sk_get_local_port_range(sk, &low, &high);
#else
	inet_get_local_port_range(net, &low, &high);
#endif
	remaining = (high - low) + 1;
	rover = (int)(((u64)get_random_u32() * remaining) >> 32) + low;
	do {
		rover++;
		if (rover < low || rover > high)
			rover = low;
		port = (u16)rover;
		if (inet_is_local_reserved_port(net, port))
			continue;

		head = quic_udp_sock_head(net, port);
		mutex_lock(&head->lock);
		if (quic_udp_sock_lookup(sk, NULL, port)) {
			mutex_unlock(&head->lock);
			cond_resched();
			continue;
		}
		a->v4.sin_port = htons(port);
		us = quic_udp_sock_create(sk, a);
		if (!us) {
			a->v4.sin_port = 0;
			mutex_unlock(&head->lock);
			return -EINVAL;
		}
		mutex_unlock(&head->lock);

		quic_path_set_udp_sk(&paths->path[path], us);
		__sk_dst_reset(sk);
		return 0;
	} while (--remaining > 0);

	return -EADDRINUSE;
}

/* Swaps the active and alternate QUIC paths.
 *
 * Promotes the alternate path (path[1]) to become the new active path (path[0]).  If the
 * alternate path has a valid UDP socket, the entire path is swapped.  Otherwise, only the
 * destination address is exchanged, assuming the source address is the same and no rebind is
 * needed.
 *
 * This is typically used during path migration or alternate path promotion.
 */
void quic_path_swap(struct quic_path_group *paths)
{
	struct quic_path path = paths->path[0];

	paths->alt_probes = 0;
	paths->alt_state = QUIC_PATH_ALT_SWAPPED;

	if (paths->path[1].udp_sk) {
		paths->path[0] = paths->path[1];
		paths->path[1] = path;
		return;
	}

	paths->path[0].daddr = paths->path[1].daddr;
	paths->path[1].daddr = path.daddr;
}

/* Frees resources associated with a QUIC path.
 *
 * This is used for cleanup during error handling or when the path is no longer needed.
 */
void quic_path_unbind(struct sock *sk, struct quic_path_group *paths, u8 path)
{
	paths->alt_probes = 0;
	paths->alt_state = QUIC_PATH_ALT_NONE;

	quic_path_set_udp_sk(&paths->path[path], NULL);

	memset(quic_path_daddr(paths, path), 0, sizeof(union quic_addr));
	memset(quic_path_saddr(paths, path), 0, sizeof(union quic_addr));
}

/* Detects and records a potential alternate path.
 *
 * If the new source or destination address differs from the active path, and alternate path
 * detection is not disabled, the function updates the alternate path slot (path[1]) with the
 * new addresses.
 *
 * This is typically called on packet receive to detect new possible network paths (e.g., NAT
 * rebinding, mobility).
 *
 * Returns 1 if a new alternate path was detected and updated, 0 otherwise.
 */
int quic_path_detect_alt(struct quic_path_group *paths, union quic_addr *sa, union quic_addr *da,
			 struct sock *sk)
{
	if ((!quic_cmp_sk_addr(sk, quic_path_saddr(paths, 0), sa) && !paths->disable_saddr_alt) ||
	    (!quic_cmp_sk_addr(sk, quic_path_daddr(paths, 0), da) && !paths->disable_daddr_alt)) {
		if (!quic_path_saddr(paths, 1)->v4.sin_port)
			quic_path_set_saddr(paths, 1, sa);

		if (!quic_cmp_sk_addr(sk, quic_path_saddr(paths, 1), sa))
			return 0;

		if (!quic_path_daddr(paths, 1)->v4.sin_port)
			quic_path_set_daddr(paths, 1, da);

		return quic_cmp_sk_addr(sk, quic_path_daddr(paths, 1), da);
	}
	return 0;
}

void quic_path_get_param(struct quic_path_group *paths, struct quic_transport_param *p)
{
	if (p->remote) {
		p->disable_active_migration = paths->disable_saddr_alt;
		return;
	}
	p->disable_active_migration = paths->disable_daddr_alt;
}

void quic_path_set_param(struct quic_path_group *paths, struct quic_transport_param *p)
{
	if (p->remote) {
		paths->disable_saddr_alt = p->disable_active_migration;
		return;
	}
	paths->disable_daddr_alt = p->disable_active_migration;
}

/* State Machine defined in rfc8899#section-5.2 */
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

/* Handle PLPMTUD probe failure on a QUIC path.
 *
 * Called immediately after sending a probe packet in QUIC Path MTU Discovery.  Tracks probe
 * count and manages state transitions based on the number of probes sent and current PLPMTUD
 * state (BASE, SEARCH, COMPLETE, ERROR).  Detects probe failures and black holes, adjusting
 * PMTU and probe sizes accordingly.
 *
 * Return: New PMTU value if updated, else 0.
 */
u32 quic_path_pl_send(struct quic_path_group *paths, s64 number)
{
	u32 pathmtu = 0;

	paths->pl.number = number;
	if (paths->pl.probe_count < QUIC_MAX_PROBES)
		goto out;

	paths->pl.probe_count = 0;
	if (paths->pl.state == QUIC_PL_BASE) {
		if (paths->pl.probe_size == QUIC_BASE_PLPMTU) { /* BASE_PLPMTU Confirming Failed */
			paths->pl.state = QUIC_PL_ERROR; /* Base -> Error */

			paths->pl.pmtu = QUIC_BASE_PLPMTU;
			pathmtu = QUIC_BASE_PLPMTU;
		}
	} else if (paths->pl.state == QUIC_PL_SEARCH) {
		if (paths->pl.pmtu == paths->pl.probe_size) { /* Black Hole Detected */
			paths->pl.state = QUIC_PL_BASE;  /* Search -> Base */
			paths->pl.probe_size = QUIC_BASE_PLPMTU;
			paths->pl.probe_high = 0;

			paths->pl.pmtu = QUIC_BASE_PLPMTU;
			pathmtu = QUIC_BASE_PLPMTU;
		} else { /* Normal probe failure. */
			paths->pl.probe_high = paths->pl.probe_size;
			paths->pl.probe_size = paths->pl.pmtu;
		}
	} else if (paths->pl.state == QUIC_PL_COMPLETE) {
		if (paths->pl.pmtu == paths->pl.probe_size) { /* Black Hole Detected */
			paths->pl.state = QUIC_PL_BASE;  /* Search Complete -> Base */
			paths->pl.probe_size = QUIC_BASE_PLPMTU;

			paths->pl.pmtu = QUIC_BASE_PLPMTU;
			pathmtu = QUIC_BASE_PLPMTU;
		}
	}

out:
	pr_debug("%s: dst: %p, state: %d, pmtu: %d, size: %d, high: %d\n", __func__, paths,
		 paths->pl.state, paths->pl.pmtu, paths->pl.probe_size, paths->pl.probe_high);
	paths->pl.probe_count++;
	return pathmtu;
}

/* Handle successful reception of a PMTU probe.
 *
 * Called when a probe packet is acknowledged. Updates probe size and transitions state if
 * needed (e.g., from SEARCH to COMPLETE).  Expands PMTU using binary or linear search
 * depending on state.
 *
 * Return: New PMTU to apply if search completes, or 0 if no change.
 */
u32 quic_path_pl_recv(struct quic_path_group *paths, bool *raise_timer, bool *complete)
{
	u32 pathmtu = 0;

	pr_debug("%s: dst: %p, state: %d, pmtu: %d, size: %d, high: %d\n", __func__, paths,
		 paths->pl.state, paths->pl.pmtu, paths->pl.probe_size, paths->pl.probe_high);

	*raise_timer = false;
	paths->pl.number = 0;
	paths->pl.pmtu = paths->pl.probe_size;
	paths->pl.probe_count = 0;
	if (paths->pl.state == QUIC_PL_BASE) {
		paths->pl.state = QUIC_PL_SEARCH; /* Base -> Search */
		paths->pl.probe_size += QUIC_PL_BIG_STEP;
	} else if (paths->pl.state == QUIC_PL_ERROR) {
		paths->pl.state = QUIC_PL_SEARCH; /* Error -> Search */

		paths->pl.pmtu = paths->pl.probe_size;
		pathmtu = (u32)paths->pl.pmtu;
		paths->pl.probe_size += QUIC_PL_BIG_STEP;
	} else if (paths->pl.state == QUIC_PL_SEARCH) {
		if (!paths->pl.probe_high) {
			if (paths->pl.probe_size < QUIC_MAX_PLPMTU) {
				paths->pl.probe_size =
					(u16)min(paths->pl.probe_size + QUIC_PL_BIG_STEP,
						 QUIC_MAX_PLPMTU);
				*complete = false;
				return pathmtu;
			}
			paths->pl.probe_high = QUIC_MAX_PLPMTU;
		}
		paths->pl.probe_size += QUIC_PL_MIN_STEP;
		if (paths->pl.probe_size >= paths->pl.probe_high) {
			paths->pl.probe_high = 0;
			paths->pl.state = QUIC_PL_COMPLETE; /* Search -> Search Complete */

			paths->pl.probe_size = paths->pl.pmtu;
			pathmtu = (u32)paths->pl.pmtu;
			*raise_timer = true;
		}
	} else if (paths->pl.state == QUIC_PL_COMPLETE) {
		/* Raise probe_size again after 30 * interval in Search Complete */
		paths->pl.state = QUIC_PL_SEARCH; /* Search Complete -> Search */
		paths->pl.probe_size = (u16)min(paths->pl.probe_size + QUIC_PL_MIN_STEP,
						QUIC_MAX_PLPMTU);
	}

	*complete = (paths->pl.state == QUIC_PL_COMPLETE);
	return pathmtu;
}

/* Handle ICMP "Packet Too Big" messages.
 *
 * Responds to an incoming ICMP error by reducing the probe size or falling back to a safe
 * baseline PMTU depending on current state.  Also handles cases where the PMTU hint lies
 * between probe and current PMTU.
 *
 * Return: New PMTU to apply if state changes, or 0 if no change.
 */
u32 quic_path_pl_toobig(struct quic_path_group *paths, u32 pmtu, bool *reset_timer)
{
	u32 pathmtu = 0;

	pr_debug("%s: dst: %p, state: %d, pmtu: %d, size: %d, ptb: %d\n", __func__, paths,
		 paths->pl.state, paths->pl.pmtu, paths->pl.probe_size, pmtu);

	*reset_timer = false;
	if (pmtu < QUIC_MIN_PLPMTU || pmtu >= (u32)paths->pl.probe_size)
		return pathmtu;

	if (paths->pl.state == QUIC_PL_BASE) {
		if (pmtu >= QUIC_MIN_PLPMTU && pmtu < QUIC_BASE_PLPMTU) {
			paths->pl.state = QUIC_PL_ERROR; /* Base -> Error */

			paths->pl.pmtu = QUIC_BASE_PLPMTU;
			pathmtu = QUIC_BASE_PLPMTU;
		}
	} else if (paths->pl.state == QUIC_PL_SEARCH) {
		if (pmtu >= QUIC_BASE_PLPMTU && pmtu < (u32)paths->pl.pmtu) {
			paths->pl.state = QUIC_PL_BASE;  /* Search -> Base */
			paths->pl.probe_size = QUIC_BASE_PLPMTU;
			paths->pl.probe_count = 0;

			paths->pl.probe_high = 0;
			paths->pl.pmtu = QUIC_BASE_PLPMTU;
			pathmtu = QUIC_BASE_PLPMTU;
		} else if (pmtu > (u32)paths->pl.pmtu && pmtu < (u32)paths->pl.probe_size) {
			paths->pl.probe_size = (u16)pmtu;
			paths->pl.probe_count = 0;
		}
	} else if (paths->pl.state == QUIC_PL_COMPLETE) {
		if (pmtu >= QUIC_BASE_PLPMTU && pmtu < (u32)paths->pl.pmtu) {
			paths->pl.state = QUIC_PL_BASE;  /* Complete -> Base */
			paths->pl.probe_size = QUIC_BASE_PLPMTU;
			paths->pl.probe_count = 0;

			paths->pl.probe_high = 0;
			paths->pl.pmtu = QUIC_BASE_PLPMTU;
			pathmtu = QUIC_BASE_PLPMTU;
			*reset_timer = true;
		}
	}
	return pathmtu;
}

/* Reset PLPMTUD state for a path.
 *
 * Resets all PLPMTUD-related state to its initial configuration.  Called when a new path is
 * initialized or when recovering from errors.
 */
void quic_path_pl_reset(struct quic_path_group *paths)
{
	paths->pl.number = 0;
	paths->pl.state = QUIC_PL_BASE;
	paths->pl.pmtu = QUIC_BASE_PLPMTU;
	paths->pl.probe_size = QUIC_BASE_PLPMTU;
}

/* Check if a packet number confirms PLPMTUD probe.
 *
 * Checks whether the last probe (tracked by .number) has been acknowledged.  If the probe
 * number lies within the ACK range, confirmation is successful.
 *
 * Return: true if probe is confirmed, false otherwise.
 */
bool quic_path_pl_confirm(struct quic_path_group *paths, s64 largest, s64 smallest)
{
	return paths->pl.number && paths->pl.number >= smallest && paths->pl.number <= largest;
}

void quic_path_init(int (*rcv)(struct sk_buff *skb, u8 err))
{
	quic_path_rcv = rcv;
}
