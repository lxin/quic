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

#include "socket.h"
#include <net/inet_common.h>
#include <net/protocol.h>

struct quic_hash_table quic_hash_tables[QUIC_HT_MAX_TABLES] __read_mostly;
struct percpu_counter quic_sockets_allocated;

static int quic_v6_flow_route(struct sock *sk, union quic_addr *a)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *addr;
	struct dst_entry *dst;
	struct flowi6 *fl6;
	struct flowi _fl;

	fl6 = &_fl.u.ip6;
	memset(&_fl, 0x0, sizeof(_fl));
	addr = quic_path_addr(&qs->src);
	fl6->daddr = addr->v6.sin6_addr;
	fl6->fl6_dport = addr->v6.sin6_port;

	addr = quic_path_addr(&qs->dst);
	fl6->saddr = addr->v6.sin6_addr;
	fl6->fl6_sport = addr->v6.sin6_port;

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	if (a) {
		a->v6.sin6_family = AF_INET6;
		a->v6.sin6_addr = fl6->daddr;;
		a->v6.sin6_port = fl6->fl6_dport;
	}
	sk_dst_set(sk, dst);
	return 0;
}

static int quic_v4_flow_route(struct sock *sk, union quic_addr *a)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *addr;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct flowi _fl;

	fl4 = &_fl.u.ip4;
	memset(&_fl, 0x00, sizeof(_fl));
	addr = quic_path_addr(&qs->src);
	fl4->saddr = addr->v4.sin_addr.s_addr;
	fl4->fl4_sport = addr->v4.sin_port;

	addr = quic_path_addr(&qs->dst);
	fl4->daddr = addr->v4.sin_addr.s_addr;
	fl4->fl4_dport = addr->v4.sin_port;

	rt = ip_route_output_key(sock_net(sk), fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	if (a) {
		a->v4.sin_family = AF_INET;
		a->v4.sin_addr.s_addr = fl4->saddr;
		a->v4.sin_port = fl4->fl4_sport;
	}
	sk_dst_set(sk, &rt->dst);
	return 0;
}

static void quic_v4_lower_xmit(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *saddr, *daddr;
	struct inet_sock *inet;
	struct dst_entry *dst;
	__be16 df = 0;

	saddr = quic_path_addr(&qs->src);
	daddr = quic_path_addr(&qs->dst);

	pr_debug("[QUIC] %s: skb: %p len: %d | path: %pI4:%d -> %pI4:%d\n", __func__, skb, skb->len,
		 &saddr->v4.sin_addr.s_addr, ntohs(saddr->v4.sin_port),
		 &daddr->v4.sin_addr.s_addr, ntohs(daddr->v4.sin_port));

	dst = sk_dst_get(sk);
	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	inet = inet_sk(sk);
	skb->encapsulation = 1;
	skb_reset_inner_mac_header(skb);
	skb_reset_inner_transport_header(skb);
	skb_set_inner_ipproto(skb, IPPROTO_QUIC);
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, saddr->v4.sin_addr.s_addr,
			    daddr->v4.sin_addr.s_addr, inet->tos, ip4_dst_hoplimit(dst), df,
			    saddr->v4.sin_port, daddr->v4.sin_port, false, false);
}

static void quic_v6_lower_xmit(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qs = quic_sk(sk);
	union quic_addr *saddr, *daddr;
	struct dst_entry *dst;

	saddr = quic_path_addr(&qs->src);
	daddr = quic_path_addr(&qs->dst);

	pr_debug("[QUIC] %s: skb: %p len: %d | path: %pI6:%d -> %pI6:%d\n", __func__, skb, skb->len,
		 &saddr->v6.sin6_addr, ntohs(saddr->v6.sin6_port),
		 &daddr->v6.sin6_addr, ntohs(daddr->v6.sin6_port));

	dst = sk_dst_get(sk);
	skb->encapsulation = 1;
	skb_reset_inner_mac_header(skb);
	skb_reset_inner_transport_header(skb);
	skb_set_inner_ipproto(skb, IPPROTO_QUIC);
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &saddr->v6.sin6_addr,
			     &daddr->v6.sin6_addr, inet6_sk(sk)->tclass, ip6_dst_hoplimit(dst),
			     0, saddr->v6.sin6_port, daddr->v6.sin6_port, false);
}

static void quic_v4_udp_conf_init(struct udp_port_cfg *udp_conf, union quic_addr *a)
{
	udp_conf->family = AF_INET;
	udp_conf->local_ip.s_addr = a->v4.sin_addr.s_addr;
	udp_conf->local_udp_port = a->v4.sin_port;
	udp_conf->use_udp6_rx_checksums = true;
}

static void quic_v6_udp_conf_init(struct udp_port_cfg *udp_conf, union quic_addr *a)
{
	udp_conf->family = AF_INET6;
	udp_conf->local_ip6 = a->v6.sin6_addr;
	udp_conf->local_udp_port = a->v6.sin6_port;
	udp_conf->use_udp6_rx_checksums = true;
}

static void quic_v4_get_msg_addr(union quic_addr *a, struct sk_buff *skb, bool src)
{
	struct udphdr *uh = quic_udp_hdr(skb);
	struct sockaddr_in *sa = &a->v4;

	a->v4.sin_family = AF_INET;
	if (src) {
		sa->sin_port = uh->source;
		sa->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sa->sin_zero, 0, sizeof(sa->sin_zero));
		return;
	}

	sa->sin_port = uh->dest;
	sa->sin_addr.s_addr = ip_hdr(skb)->daddr;
	memset(sa->sin_zero, 0, sizeof(sa->sin_zero));
}

static void quic_v6_get_msg_addr(union quic_addr *a, struct sk_buff *skb, bool src)
{
	struct udphdr *uh = quic_udp_hdr(skb);
	struct sockaddr_in6 *sa = &a->v6;

	a->v6.sin6_family = AF_INET6;
	a->v6.sin6_flowinfo = 0;
	a->v6.sin6_scope_id = ((struct inet6_skb_parm *)skb->cb)->iif;
	if (src) {
		sa->sin6_port = uh->source;
		sa->sin6_addr = ipv6_hdr(skb)->saddr;
		return;
	}

	sa->sin6_port = uh->dest;
	sa->sin6_addr = ipv6_hdr(skb)->daddr;
}

static int quic_v4_get_sk_addr(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return inet_getname(sock, uaddr, peer);
}

static int quic_v6_get_sk_addr(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return inet6_getname(sock, uaddr, peer);
}

static void quic_v4_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	if (src) {
		inet_sk(sk)->inet_sport = a->v4.sin_port;
		inet_sk(sk)->inet_saddr = a->v4.sin_addr.s_addr;
	} else {
		inet_sk(sk)->inet_dport = a->v4.sin_port;
		inet_sk(sk)->inet_daddr = a->v4.sin_addr.s_addr;
	}
}

static void quic_v6_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	if (src) {
		inet_sk(sk)->inet_sport = a->v6.sin6_port;
		sk->sk_v6_rcv_saddr = a->v6.sin6_addr;
	} else {
		inet_sk(sk)->inet_dport = a->v6.sin6_port;
		sk->sk_v6_daddr = a->v6.sin6_addr;
	}
}

static struct quic_addr_family_ops quic_af_inet = {
	.sa_family		= AF_INET,
	.addr_len		= sizeof(struct sockaddr_in),
	.iph_len		= sizeof(struct iphdr),
	.udp_conf_init		= quic_v4_udp_conf_init,
	.flow_route		= quic_v4_flow_route,
	.lower_xmit		= quic_v4_lower_xmit,
	.get_msg_addr		= quic_v4_get_msg_addr,
	.set_sk_addr		= quic_v4_set_sk_addr,
	.get_sk_addr		= quic_v4_get_sk_addr,
	.setsockopt		= ip_setsockopt,
	.getsockopt		= ip_getsockopt,
};

static struct quic_addr_family_ops quic_af_inet6 = {
	.sa_family		= AF_INET6,
	.addr_len		= sizeof(struct sockaddr_in6),
	.iph_len		= sizeof(struct ipv6hdr),
	.udp_conf_init		= quic_v6_udp_conf_init,
	.flow_route		= quic_v6_flow_route,
	.lower_xmit		= quic_v6_lower_xmit,
	.get_msg_addr		= quic_v6_get_msg_addr,
	.set_sk_addr		= quic_v6_set_sk_addr,
	.get_sk_addr		= quic_v6_get_sk_addr,
	.setsockopt		= ipv6_setsockopt,
	.getsockopt		= ipv6_getsockopt,
};

struct quic_addr_family_ops *quic_af_ops_get(sa_family_t family)
{
	switch (family) {
	case AF_INET:
		return &quic_af_inet;
	case AF_INET6:
		return &quic_af_inet6;
	default:
		return NULL;
	}
}

static int quic_inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot;

	if (addr_len < sizeof(addr->sa_family))
		return -EINVAL;

	prot = READ_ONCE(sk->sk_prot);

	return prot->connect(sk, addr, addr_len);
}

static int quic_inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	int err = 0;

	lock_sock(sk);

	sk->sk_max_ack_backlog = backlog;
	if (!backlog) {
		quic_sk(sk)->state = QUIC_STATE_USER_CLOSED;
		sk->sk_prot->unhash(sk);
		release_sock(sk);
		return 0;
	}

	quic_sk(sk)->state = QUIC_STATE_USER_CONNECTING;
	err = sk->sk_prot->hash(sk);
	release_sock(sk);
	return err;
}

int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return quic_sk(sock->sk)->af_ops->get_sk_addr(sock, uaddr, peer);
}

int quic_encap_len(struct sock *sk)
{
	return sizeof(struct udphdr) + quic_sk(sk)->af_ops->iph_len;
}

int quic_addr_len(struct sock *sk)
{
	return quic_sk(sk)->af_ops->addr_len;
}

void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	return quic_sk(sk)->af_ops->set_sk_addr(sk, a, src);
}

void quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer)
{
	quic_sk(sock->sk)->af_ops->get_sk_addr(sock, a, peer);
}

void quic_get_msg_addr(struct sock *sk, union quic_addr *addr, struct sk_buff *skb, bool src)
{
	quic_sk(sk)->af_ops->get_msg_addr(addr, skb, src);
}

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *udp_conf, union quic_addr *a)
{
	quic_sk(sk)->af_ops->udp_conf_init(udp_conf, a);
}

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb)
{
	skb_set_owner_w(skb, sk);
	quic_sk(sk)->af_ops->lower_xmit(sk, skb);
}

int quic_flow_route(struct sock *sk, union quic_addr *a)
{
	return quic_sk(sk)->af_ops->flow_route(sk, a);
}

static const struct proto_ops quic_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
};

static struct inet_protosw quic_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_prot,
	.ops        = &quic_proto_ops,
};

static struct inet_protosw quic_seqpacket_protosw = {
	.type       = SOCK_DGRAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_prot,
	.ops        = &quic_proto_ops,
};

static const struct proto_ops quicv6_proto_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet6_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
};

static struct inet_protosw quicv6_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quicv6_prot,
	.ops        = &quicv6_proto_ops,
};

static struct inet_protosw quicv6_seqpacket_protosw = {
	.type       = SOCK_DGRAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quicv6_prot,
	.ops        = &quicv6_proto_ops,
};

static int quic_protosw_init(void)
{
	int err;

	err = proto_register(&quic_prot, 1);
	if (err)
		return err;

	err = proto_register(&quicv6_prot, 1);
	if (err) {
		proto_unregister(&quic_prot);
		return err;
	}

	inet_register_protosw(&quic_stream_protosw);
	inet_register_protosw(&quic_seqpacket_protosw);
	inet6_register_protosw(&quicv6_stream_protosw);
	inet6_register_protosw(&quicv6_seqpacket_protosw);

	return 0;
}

static void quic_protosw_exit(void)
{
	inet_unregister_protosw(&quic_seqpacket_protosw);
	inet_unregister_protosw(&quic_stream_protosw);
	proto_unregister(&quic_prot);

	inet6_unregister_protosw(&quicv6_seqpacket_protosw);
	inet6_unregister_protosw(&quicv6_stream_protosw);
	proto_unregister(&quicv6_prot);
}

static int __net_init quic_net_init(struct net *net)
{
	return 0;
}

static void __net_exit quic_net_exit(struct net *net)
{
	;
}

static struct pernet_operations quic_net_ops = {
	.init = quic_net_init,
	.exit = quic_net_exit,
};

static void quic_hash_tables_destroy(void)
{
	struct quic_hash_table *ht;
	int table;

	for (table = 0; table < QUIC_HT_MAX_TABLES; table++) {
		ht = &quic_hash_tables[table];
		ht->size = 64;
		kfree(ht->hash);
	}
}

static int quic_hash_tables_init(void)
{
	struct quic_hash_head *head;
	struct quic_hash_table *ht;
	int table, i;

	for (table = 0; table < QUIC_HT_MAX_TABLES; table++) {
		ht = &quic_hash_tables[table];
		ht->size = 64;
		head = kmalloc_array(ht->size, sizeof(*head), GFP_KERNEL);
		if (!head)
			goto err;
		for (i = 0; i < ht->size; i++) {
			spin_lock_init(&head[i].lock);
			INIT_HLIST_HEAD(&head[i].head);
		}
		ht->hash = head;
	}

	return 0;

err:
	quic_hash_tables_destroy();
	return -ENOMEM;
}

static __init int quic_init(void)
{
	int err = -ENOMEM;

	if (quic_hash_tables_init())
		goto err;

	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		goto err_percpu_counter;

	err = quic_protosw_init();
	if (err)
		goto err_protosw;

	err = register_pernet_subsys(&quic_net_ops);
	if (err)
		goto err_def_ops;

	pr_info("[QUIC] init\n");
	return 0;

err_def_ops:
	quic_protosw_exit();
err_protosw:
	percpu_counter_destroy(&quic_sockets_allocated);
err_percpu_counter:
	quic_hash_tables_destroy();
err:
	pr_err("[QUIC] init error\n");
	return err;
}

static __exit void quic_exit(void)
{
	unregister_pernet_subsys(&quic_net_ops);
	quic_protosw_exit();
	percpu_counter_destroy(&quic_sockets_allocated);
	quic_hash_tables_destroy();
	pr_info("[QUIC] exit\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_ALIAS("net-pf-" __stringify(PF_INET) "-proto-144");
MODULE_ALIAS("net-pf-" __stringify(PF_INET6) "-proto-144");
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
