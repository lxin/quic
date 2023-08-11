/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_addr_family_ops {
	sa_family_t sa_family;
	int	addr_len;
	int	iph_len;

	void	(*udp_conf_init)(struct udp_port_cfg *udp_config, union quic_addr *addr);
	int	(*flow_route)(struct sock *sk, union quic_addr *a);
	void	(*lower_xmit)(struct sock *sk, struct sk_buff *skb);

	void	(*get_msg_addr)(union quic_addr *addr, struct sk_buff *skb, bool src);
	void	(*set_sk_addr)(struct sock *sk, union quic_addr *addr, bool src);
	int	(*get_sk_addr)(struct socket *sock, struct sockaddr *addr, int peer);

	int	(*setsockopt)(struct sock *sk, int level, int optname, sockptr_t optval,
			      unsigned int optlen);
	int	(*getsockopt)(struct sock *sk, int level, int optname, char __user *optval,
			      int __user *optlen);
	void	(*update_proto_ops)(struct sock *sk);
};

int quic_encap_len(struct sock *sk);
int quic_addr_len(struct sock *sk);
int quic_addr_family(struct sock *sk);
void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src);
void quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer);
void quic_get_msg_addr(struct sock *sk, union quic_addr *addr, struct sk_buff *skb, bool src);
void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *udp_conf, union quic_addr *a);
void quic_lower_xmit(struct sock *sk, struct sk_buff *skb);
int quic_flow_route(struct sock *sk, union quic_addr *a);
void quic_update_proto_ops(struct sock *sk);
struct quic_addr_family_ops *quic_af_ops_get(sa_family_t family);
