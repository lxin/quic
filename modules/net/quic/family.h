/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PORT_LEN		2
#define QUIC_ADDR4_LEN		4
#define QUIC_ADDR6_LEN		16

#define QUIC_PREF_ADDR_LEN	(QUIC_ADDR4_LEN + QUIC_PORT_LEN + QUIC_ADDR6_LEN + QUIC_PORT_LEN)

void quic_seq_dump_addr(struct seq_file *seq, union quic_addr *addr);
int quic_is_any_addr(union quic_addr *a);
u32 quic_encap_len(union quic_addr *a);

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da, struct flowi *fl);
int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa, struct flowi *fl);
void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a);

void quic_get_msg_addrs(struct sk_buff *skb, union quic_addr *da, union quic_addr *sa);
int quic_get_mtu_info(struct sk_buff *skb, u32 *info);
u8 quic_get_msg_ecn(struct sk_buff *skb);

int quic_get_user_addr(struct sock *sk, union quic_addr *a, struct sockaddr *addr, int addr_len);
void quic_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen);
void quic_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr);

bool quic_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr);
int quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer);
void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src);
void quic_set_sk_ecn(struct sock *sk, u8 ecn);

int quic_common_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
			   unsigned int optlen);
int quic_common_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
			   int __user *optlen);
