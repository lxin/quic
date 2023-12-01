/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_bind_port {
	unsigned short		port;
	struct hlist_node	node;
	struct net		*net;
	u8			serv:1;
	u8			retry:1;
};

struct quic_udp_sock {
	struct work_struct work;
	struct hlist_node node;
	union quic_addr addr;
	refcount_t refcnt;
	struct sock *sk;
};

struct quic_path_addr {
	union quic_addr addr[2];
	u8 addr_len;
	u8 active:1,
	   pending:1;
	u8 entropy[8];
};

static inline struct udphdr *quic_udp_hdr(struct sk_buff *skb)
{
	return (struct udphdr *)(skb_transport_header(skb) - sizeof(struct udphdr));
}

static inline void quic_path_addr_set(struct quic_path_addr *a, union quic_addr *addr)
{
	memcpy(&a->addr[a->active], addr, a->addr_len);
}

static inline union quic_addr *quic_path_addr(struct quic_path_addr *a)
{
	return &a->addr[a->active];
}

static inline void quic_path_addr_init(struct quic_path_addr *a, u8 addr_len)
{
	a->addr_len = addr_len;
}

int quic_get_port(struct net *net, struct quic_bind_port *pp, union quic_addr *addr);
void quic_put_port(struct net *net, struct quic_bind_port *pp);
void quic_udp_sock_put(struct quic_udp_sock *us);
struct quic_udp_sock *quic_udp_sock_get(struct quic_udp_sock *us);
int quic_udp_sock_set(struct sock *sk, struct quic_udp_sock *udp_sk[], struct quic_path_addr *a);
