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
#include <linux/icmp.h>
#include <net/tls.h>

struct quic_hash_table quic_hash_tables[QUIC_HT_MAX_TABLES] __read_mostly;
struct percpu_counter quic_sockets_allocated;
struct workqueue_struct *quic_wq;
u8 random_data[16];

long sysctl_quic_mem[3];
int sysctl_quic_rmem[3];
int sysctl_quic_wmem[3];

static int quic_v6_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa)
{
	struct dst_entry *dst;
	struct flowi6 *fl6;
	struct flowi _fl;

	if (__sk_dst_check(sk, inet6_sk(sk)->dst_cookie))
		return 1;

	fl6 = &_fl.u.ip6;
	memset(&_fl, 0x0, sizeof(_fl));
	fl6->saddr = sa->v6.sin6_addr;
	fl6->fl6_sport = sa->v6.sin6_port;
	fl6->daddr = da->v6.sin6_addr;
	fl6->fl6_dport = da->v6.sin6_port;

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	if (!sa->v6.sin6_family) {
		sa->v6.sin6_family = AF_INET6;
		sa->v6.sin6_addr = fl6->saddr;
	}
	ip6_dst_store(sk, dst, NULL, NULL);
	return 0;
}

static int quic_v4_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa)
{
	struct flowi4 *fl4;
	struct rtable *rt;
	struct flowi _fl;

	if (__sk_dst_check(sk, 0))
		return 1;

	fl4 = &_fl.u.ip4;
	memset(&_fl, 0x00, sizeof(_fl));
	fl4->saddr = sa->v4.sin_addr.s_addr;
	fl4->fl4_sport = sa->v4.sin_port;
	fl4->daddr = da->v4.sin_addr.s_addr;
	fl4->fl4_dport = da->v4.sin_port;

	rt = ip_route_output_key(sock_net(sk), fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	if (!sa->v4.sin_family) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_addr.s_addr = fl4->saddr;
	}
	sk_setup_caps(sk, &rt->dst);
	return 0;
}

static void quic_v4_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
			       union quic_addr *sa)
{
	struct dst_entry *dst;
	__be16 df = 0;

	pr_debug("[QUIC] %s: skb: %p len: %d | path: %pI4:%d -> %pI4:%d\n", __func__, skb, skb->len,
		 &sa->v4.sin_addr.s_addr, ntohs(sa->v4.sin_port),
		 &da->v4.sin_addr.s_addr, ntohs(da->v4.sin_port));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}
	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, sa->v4.sin_addr.s_addr,
			    da->v4.sin_addr.s_addr, inet_sk(sk)->tos, ip4_dst_hoplimit(dst), df,
			    sa->v4.sin_port, da->v4.sin_port, false, false);
}

static void quic_v6_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
			       union quic_addr *sa)
{
	struct dst_entry *dst = sk_dst_get(sk);

	if (!dst) {
		kfree_skb(skb);
		return;
	}
	pr_debug("[QUIC] %s: skb: %p len: %d | path: %pI6:%d -> %pI6:%d\n", __func__, skb, skb->len,
		 &sa->v6.sin6_addr, ntohs(sa->v6.sin6_port),
		 &da->v6.sin6_addr, ntohs(da->v6.sin6_port));

	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &sa->v6.sin6_addr, &da->v6.sin6_addr,
			     inet6_sk(sk)->tclass, ip6_dst_hoplimit(dst), 0,
			     sa->v6.sin6_port, da->v6.sin6_port, false);
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
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_RCV_CB(skb)->udph_offset);
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
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_RCV_CB(skb)->udph_offset);
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

static int quic_v4_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	struct icmphdr *hdr;

	hdr = (struct icmphdr *)(skb_network_header(skb) - sizeof(struct icmphdr));
	if (hdr->type == ICMP_DEST_UNREACH && hdr->code == ICMP_FRAG_NEEDED) {
		*info = ntohs(hdr->un.frag.mtu);
		return 0;
	}

	/* can't be handled without outer iphdr known, leave it to udp_err */
	return 1;
}

static int quic_v6_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	struct icmp6hdr *hdr;

	hdr = (struct icmp6hdr *)(skb_network_header(skb) - sizeof(struct icmp6hdr));
	if (hdr->icmp6_type == ICMPV6_PKT_TOOBIG) {
		*info = ntohl(hdr->icmp6_mtu);
		return 0;
	}

	/* can't be handled without outer ip6hdr known, leave it to udpv6_err */
	return 1;
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
	.get_mtu_info		= quic_v4_get_mtu_info,
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
	.get_mtu_info		= quic_v6_get_mtu_info,
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
	struct quic_crypto *crypto;
	int err = 0;

	lock_sock(sk);

	crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	sk->sk_max_ack_backlog = backlog;
	if (!backlog) {
		quic_crypto_destroy(crypto);
		sk->sk_prot->unhash(sk);
		quic_set_state(sk, QUIC_SS_CLOSED);
		goto out;
	}

	if (!hlist_unhashed(&quic_sk(sk)->inet.sk.sk_node))
		goto out;
	err = sk->sk_prot->hash(sk);
	if (err)
		goto out;
	err = quic_crypto_set_tfms(crypto, TLS_CIPHER_AES_GCM_128);
	if (err) {
		sk->sk_prot->unhash(sk);
		goto out;
	}
	quic_set_state(sk, QUIC_SS_LISTENING);
out:
	release_sock(sk);
	return err;
}

static int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return quic_af_ops(sock->sk)->get_sk_addr(sock, uaddr, peer);
}

int quic_encap_len(struct sock *sk)
{
	return sizeof(struct udphdr) + quic_af_ops(sk)->iph_len;
}

int quic_addr_len(struct sock *sk)
{
	return quic_af_ops(sk)->addr_len;
}

int quic_addr_family(struct sock *sk)
{
	return quic_af_ops(sk)->sa_family;
}

void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	return quic_af_ops(sk)->set_sk_addr(sk, a, src);
}

void quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer)
{
	quic_af_ops(sock->sk)->get_sk_addr(sock, a, peer);
}

void quic_get_msg_addr(struct sock *sk, union quic_addr *addr, struct sk_buff *skb, bool src)
{
	quic_af_ops(sk)->get_msg_addr(addr, skb, src);
}

int quic_get_mtu_info(struct sock *sk, struct sk_buff *skb, u32 *info)
{
	return quic_af_ops(sk)->get_mtu_info(skb, info);
}

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *udp_conf, union quic_addr *a)
{
	quic_af_ops(sk)->udp_conf_init(udp_conf, a);
}

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
		     union quic_addr *sa)
{
	quic_af_ops(sk)->lower_xmit(sk, skb, da, sa);
}

int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa)
{
	return quic_af_ops(sk)->flow_route(sk, da, sa);
}

static struct ctl_table quic_table[] = {
	{
		.procname	= "quic_mem",
		.data		= &sysctl_quic_mem,
		.maxlen		= sizeof(sysctl_quic_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax
	},
	{
		.procname	= "quic_rmem",
		.data		= &sysctl_quic_rmem,
		.maxlen		= sizeof(sysctl_quic_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "quic_wmem",
		.data		= &sysctl_quic_wmem,
		.maxlen		= sizeof(sysctl_quic_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},

	{ /* sentinel */ }
};

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
		if (!head) {
			quic_hash_tables_destroy();
			return -ENOMEM;
		}
		for (i = 0; i < ht->size; i++) {
			spin_lock_init(&head[i].lock);
			INIT_HLIST_HEAD(&head[i].head);
		}
		ht->hash = head;
	}

	return 0;
}

static struct ctl_table_header *quic_sysctl_header;

static void quic_sysctl_register(void)
{
	unsigned long limit;
	int max_share;

	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_quic_mem[0] = limit / 4 * 3;
	sysctl_quic_mem[1] = limit;
	sysctl_quic_mem[2] = sysctl_quic_mem[0] * 2;

	limit = (sysctl_quic_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL * 1024 * 1024, limit);

	sysctl_quic_rmem[0] = PAGE_SIZE;
	sysctl_quic_rmem[1] = 1500 * SKB_TRUESIZE(1);
	sysctl_quic_rmem[2] = max(sysctl_quic_rmem[1], max_share);

	sysctl_quic_wmem[0] = PAGE_SIZE;
	sysctl_quic_wmem[1] = 16 * 1024;
	sysctl_quic_wmem[2] = max(64 * 1024, max_share);

	quic_sysctl_header = register_net_sysctl(&init_net, "net/quic", quic_table);
}

static void quic_sysctl_unregister(void)
{
	unregister_net_sysctl_table(quic_sysctl_header);
}

static __init int quic_init(void)
{
	int err = -ENOMEM;

	if (quic_hash_tables_init())
		goto err;

	quic_wq = create_workqueue("quic_workqueue");
	if (!quic_wq)
		goto err_wq;

	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		goto err_percpu_counter;

	err = quic_protosw_init();
	if (err)
		goto err_protosw;

	err = register_pernet_subsys(&quic_net_ops);
	if (err)
		goto err_def_ops;

	quic_sysctl_register();

	get_random_bytes(random_data, 16);
	pr_info("[QUIC] init\n");
	return 0;

err_def_ops:
	quic_protosw_exit();
err_protosw:
	percpu_counter_destroy(&quic_sockets_allocated);
err_percpu_counter:
	destroy_workqueue(quic_wq);
err_wq:
	quic_hash_tables_destroy();
err:
	pr_err("[QUIC] init error\n");
	return err;
}

static __exit void quic_exit(void)
{
	quic_sysctl_unregister();
	unregister_pernet_subsys(&quic_net_ops);
	quic_protosw_exit();
	percpu_counter_destroy(&quic_sockets_allocated);
	destroy_workqueue(quic_wq);
	quic_hash_tables_destroy();
	pr_info("[QUIC] exit\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_ALIAS("net-pf-" __stringify(PF_INET) "-proto-261");
MODULE_ALIAS("net-pf-" __stringify(PF_INET6) "-proto-261");
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
