/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

int quic_common_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
			   unsigned int optlen);
int quic_common_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
			   int __user *optlen);
int quic_is_any_addr(union quic_addr *a);
u32 quic_encap_len(union quic_addr *a);

void quic_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen);
void quic_get_msg_addr(union quic_addr *addr, struct sk_buff *skb, bool src);
void quic_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr);
void quic_seq_dump_addr(struct seq_file *seq, union quic_addr *addr);

int quic_get_user_addr(struct sock *sk, union quic_addr *a, struct sockaddr *addr, int addr_len);
bool quic_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr);
int quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer);
void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src);

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
		     union quic_addr *sa);
int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa);

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a);
int quic_get_mtu_info(struct sk_buff *skb, u32 *info);
void quic_set_sk_ecn(struct sock *sk, u8 ecn);
u8 quic_get_msg_ecn(struct sk_buff *skb);
