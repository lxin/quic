/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_udp_sock {
	struct hlist_node node;
	union quic_addr addr;
	refcount_t refcnt;
	struct sock *sk;
};

struct quic_path_addr {
	union quic_addr addr[2];
	u8 addr_len;
	u8 active;
};

static inline struct udphdr *quic_udp_hdr(struct sk_buff *skb)
{
	return (struct udphdr *)(skb_transport_header(skb) - sizeof(struct udphdr));
}

void quic_path_addr_init(struct quic_path_addr *a, u8 addr_len);
void quic_path_addr_set(struct quic_path_addr *a, union quic_addr *addr);
union quic_addr *quic_path_addr(struct quic_path_addr *a);
void quic_udp_sock_put(struct quic_udp_sock *us);
struct quic_udp_sock *quic_udp_sock_get(struct quic_udp_sock *us);
int quic_udp_sock_set(struct sock *sk, struct quic_udp_sock *udp_sk[], union quic_addr *addr);
