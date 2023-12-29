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
	u8 active:1;
	u8 pending:1;
	u8 udp_bind:1;
	u8 entropy[8];
};

struct quic_path_src {
	struct quic_path_addr a;
	struct quic_bind_port port[2];
	struct quic_udp_sock *udp_sk[2];
};

struct quic_path_dst {
	struct quic_path_addr a;
	u32 mtu_info;
	u32 pathmtu;
	struct {
		u64 number;
		u16 pmtu;
		u16 probe_size;
		u16 probe_high;
		u8 probe_count;
		u8 state;
	} pl; /* plpmtud related */
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

static inline struct quic_bind_port *quic_path_port(struct quic_path_addr *a)
{
	return &((struct quic_path_src *)a)->port[a->active];
}

static inline void quic_path_addr_init(struct quic_path_addr *a, u8 addr_len)
{
	a->addr_len = addr_len;
}

void quic_udp_sock_put(struct quic_udp_sock *us);
struct quic_udp_sock *quic_udp_sock_get(struct quic_udp_sock *us);
int quic_path_set_udp_sock(struct sock *sk, struct quic_path_addr *a);
void quic_bind_port_put(struct sock *sk, struct quic_bind_port *pp);
int quic_path_set_bind_port(struct sock *sk, struct quic_path_addr *a);
void quic_path_free(struct sock *sk, struct quic_path_addr *a);
int quic_path_pl_send(struct quic_path_addr *a);
int quic_path_pl_recv(struct quic_path_addr *a, bool *raise_timer, bool *complete);
int quic_path_pl_toobig(struct quic_path_addr *a, u32 pmtu, bool *reset_timer);
void quic_path_pl_reset(struct quic_path_addr *a);
bool quic_path_pl_confirm(struct quic_path_addr *a, s64 largest, s64 smallest);
