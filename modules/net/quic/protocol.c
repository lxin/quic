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

#include <net/inet_common.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <net/protocol.h>
#include <linux/swap.h>
#include <linux/icmp.h>
#include <net/tls.h>

#include "socket.h"

struct quic_hash_table quic_hash_tables[QUIC_HT_MAX_TABLES] __read_mostly;
static DEFINE_PER_CPU(int, quic_memory_per_cpu_fw_alloc);
struct kmem_cache *quic_frame_cachep __read_mostly;
struct workqueue_struct *quic_wq __read_mostly;
struct percpu_counter quic_sockets_allocated;
u8 quic_random_data[32] __read_mostly;

long sysctl_quic_mem[3];
int sysctl_quic_rmem[3];
int sysctl_quic_wmem[3];

struct quic_addr_family_ops {
	u32	iph_len;
	int	(*is_any_addr)(union quic_addr *addr);

	void	(*udp_conf_init)(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *addr);
	int	(*flow_route)(struct sock *sk, union quic_addr *da, union quic_addr *sa);
	void	(*lower_xmit)(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
			      union quic_addr *sa);

	void	(*get_msg_addr)(union quic_addr *addr, struct sk_buff *skb, bool src);
	void	(*seq_dump_addr)(struct seq_file *seq, union quic_addr *addr);
	int	(*get_mtu_info)(struct sk_buff *skb, u32 *info);
	u8	(*get_msg_ecn)(struct sk_buff *skb);
};

struct quic_proto_family_ops {
	int	(*get_user_addr)(struct sock *sk, union quic_addr *a, struct sockaddr *addr,
				 int addr_len);
	void	(*get_pref_addr)(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen);
	void	(*set_pref_addr)(struct sock *sk, u8 *p, union quic_addr *addr);

	bool	(*cmp_sk_addr)(struct sock *sk, union quic_addr *a, union quic_addr *addr);
	int	(*get_sk_addr)(struct socket *sock, struct sockaddr *addr, int peer);
	void	(*set_sk_addr)(struct sock *sk, union quic_addr *addr, bool src);
	void	(*set_sk_ecn)(struct sock *sk, u8 ecn);

	int	(*getsockopt)(struct sock *sk, int level, int optname, char __user *optval,
			      int __user *optlen);
	int	(*setsockopt)(struct sock *sk, int level, int optname, sockptr_t optval,
			      unsigned int optlen);
};

static int quic_v4_is_any_addr(union quic_addr *addr)
{
	return addr->v4.sin_addr.s_addr == htonl(INADDR_ANY);
}

static int quic_v6_is_any_addr(union quic_addr *addr)
{
	return ipv6_addr_any(&addr->v6.sin6_addr);
}

static void quic_v4_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a)
{
	conf->family = AF_INET;
	conf->local_ip.s_addr = a->v4.sin_addr.s_addr;
	conf->local_udp_port = a->v4.sin_port;
	conf->use_udp6_rx_checksums = true;
}

static void quic_v6_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a)
{
	conf->family = AF_INET6;
	conf->local_ip6 = a->v6.sin6_addr;
	conf->local_udp_port = a->v6.sin6_port;
	conf->use_udp6_rx_checksums = true;
	conf->ipv6_v6only = ipv6_only_sock(sk);
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

static void quic_v4_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
			       union quic_addr *sa)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	u8 tos = (inet_sk(sk)->tos | cb->ecn), ttl;
	struct dst_entry *dst;
	__be16 df = 0;

	pr_debug("%s: skb: %p, len: %d, num: %llu, %pI4:%d -> %pI4:%d\n", __func__,
		 skb, skb->len, cb->number, &sa->v4.sin_addr.s_addr, ntohs(sa->v4.sin_port),
		 &da->v4.sin_addr.s_addr, ntohs(da->v4.sin_port));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}
	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	ttl = (u8)ip4_dst_hoplimit(dst);
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, sa->v4.sin_addr.s_addr,
			    da->v4.sin_addr.s_addr, tos, ttl, df, sa->v4.sin_port,
			    da->v4.sin_port, false, false);
}

static void quic_v6_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
			       union quic_addr *sa)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	u8 tc = (inet6_sk(sk)->tclass | cb->ecn), ttl;
	struct dst_entry *dst;

	pr_debug("%s: skb: %p, len: %d, num: %llu, %pI6c:%d -> %pI6c:%d\n", __func__,
		 skb, skb->len, cb->number, &sa->v6.sin6_addr, ntohs(sa->v6.sin6_port),
		 &da->v6.sin6_addr, ntohs(da->v6.sin6_port));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}

	ttl = (u8)ip6_dst_hoplimit(dst);
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &sa->v6.sin6_addr, &da->v6.sin6_addr, tc,
			     ttl, 0, sa->v6.sin6_port, da->v6.sin6_port, false);
}

static void quic_v4_seq_dump_addr(struct seq_file *seq, union quic_addr *addr)
{
	seq_printf(seq, "%pI4:%d\t", &addr->v4.sin_addr.s_addr, ntohs(addr->v4.sin_port));
}

static void quic_v6_seq_dump_addr(struct seq_file *seq, union quic_addr *addr)
{
	seq_printf(seq, "%pI6c:%d\t", &addr->v6.sin6_addr, ntohs(addr->v4.sin_port));
}

static void quic_v4_get_msg_addr(union quic_addr *a, struct sk_buff *skb, bool src)
{
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_CRYPTO_CB(skb)->udph_offset);
	struct sockaddr_in *sa = &a->v4;

	a->v4.sin_family = AF_INET;
	if (src) {
		sa->sin_port = uh->source;
		sa->sin_addr.s_addr = ip_hdr(skb)->saddr;
		return;
	}

	sa->sin_port = uh->dest;
	sa->sin_addr.s_addr = ip_hdr(skb)->daddr;
}

static void quic_v6_get_msg_addr(union quic_addr *a, struct sk_buff *skb, bool src)
{
	struct udphdr *uh = (struct udphdr *)(skb->head + QUIC_CRYPTO_CB(skb)->udph_offset);
	struct sockaddr_in6 *sa = &a->v6;

	a->v6.sin6_family = AF_INET6;
	if (src) {
		sa->sin6_port = uh->source;
		sa->sin6_addr = ipv6_hdr(skb)->saddr;
		return;
	}

	sa->sin6_port = uh->dest;
	sa->sin6_addr = ipv6_hdr(skb)->daddr;
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

static u8 quic_v4_get_msg_ecn(struct sk_buff *skb)
{
	return (ip_hdr(skb)->tos & INET_ECN_MASK);
}

static u8 quic_v6_get_msg_ecn(struct sk_buff *skb)
{
	return (ipv6_get_dsfield(ipv6_hdr(skb)) & INET_ECN_MASK);
}

static struct quic_addr_family_ops quic_af_inet = {
	.iph_len		= sizeof(struct iphdr),
	.is_any_addr		= quic_v4_is_any_addr,
	.udp_conf_init		= quic_v4_udp_conf_init,
	.flow_route		= quic_v4_flow_route,
	.lower_xmit		= quic_v4_lower_xmit,
	.seq_dump_addr		= quic_v4_seq_dump_addr,
	.get_msg_addr		= quic_v4_get_msg_addr,
	.get_mtu_info		= quic_v4_get_mtu_info,
	.get_msg_ecn		= quic_v4_get_msg_ecn,
};

static struct quic_addr_family_ops quic_af_inet6 = {
	.iph_len		= sizeof(struct ipv6hdr),
	.is_any_addr		= quic_v6_is_any_addr,
	.udp_conf_init		= quic_v6_udp_conf_init,
	.flow_route		= quic_v6_flow_route,
	.lower_xmit		= quic_v6_lower_xmit,
	.seq_dump_addr		= quic_v6_seq_dump_addr,
	.get_msg_addr		= quic_v6_get_msg_addr,
	.get_mtu_info		= quic_v6_get_mtu_info,
	.get_msg_ecn		= quic_v6_get_msg_ecn,
};

static struct quic_addr_family_ops *quic_afs[] = {
	&quic_af_inet,
	&quic_af_inet6
};

#define quic_af(a)		quic_afs[(a)->sa.sa_family == AF_INET6]
#define quic_af_skb(skb)	quic_afs[ip_hdr(skb)->version == 6]

static int quic_v4_get_user_addr(struct sock *sk, union quic_addr *a, struct sockaddr *addr,
				 int addr_len)
{
	u32 len = sizeof(struct sockaddr_in);

	if (addr->sa_family != sk->sk_family || addr_len < len)
		return 1;
	memcpy(a, addr, len);
	return 0;
}

static int quic_v6_get_user_addr(struct sock *sk, union quic_addr *a, struct sockaddr *addr,
				 int addr_len)
{
	u32 len = sizeof(struct sockaddr_in);

	if (addr->sa_family != sk->sk_family) {
		if (ipv6_only_sock(sk) || addr_len < len)
			return 1;
		memcpy(a, addr, len);
		return 0;
	}

	len = sizeof(struct sockaddr_in6);
	if (addr_len < len)
		return 1;
	memcpy(a, addr, len);
	return 0;
}

static void quic_v4_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen)
{
	struct quic_path_addr *path = quic_dst(sk);
	u8 *p = *pp;

	memcpy(&addr->v4.sin_addr, p, 4);
	p += 4;
	memcpy(&addr->v4.sin_port, p, 2);
	p += 2;
	p += 16; /* skip ipv6 address */
	p += 2;

	addr->v4.sin_family = AF_INET;
	if (!quic_path_cmp(path, 0, addr))
		memset(addr, 0, sizeof(*addr));
	*plen -= (p - *pp);
	*pp = p;
}

static void quic_v6_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen)
{
	struct quic_path_addr *path = quic_dst(sk);
	u8 *p = *pp;

	p += 4; /* try ipv6 address first */
	p += 2;
	memcpy(&addr->v6.sin6_addr, p, 16);
	p += 16;
	memcpy(&addr->v6.sin6_port, p, 2);
	p += 2;

	if (ipv6_only_sock(sk) ||
	    addr->v6.sin6_port || !ipv6_addr_any(&addr->v6.sin6_addr)) {
		addr->v4.sin_family = AF_INET6;
		if (!quic_path_cmp(path, 0, addr))
			memset(addr, 0, sizeof(*addr));
		*plen -= (p - *pp);
		*pp = p;
		return;
	}

	quic_v4_get_pref_addr(sk, addr, pp, plen);
}

static void quic_v4_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr)
{
	memcpy(p, &addr->v4.sin_addr, 4);
	p += 4;
	memcpy(p, &addr->v4.sin_port, 2);
	p += 2;
	memset(p, 0, 16);
	p += 16;
	memset(p, 0, 2);
}

static void quic_v6_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr)
{
	if (addr->sa.sa_family == AF_INET)
		return quic_v4_set_pref_addr(sk, p, addr);

	memset(p, 0, 4);
	p += 4;
	memset(p, 0, 2);
	p += 2;
	memcpy(p, &addr->v6.sin6_addr, 16);
	p += 16;
	memcpy(p, &addr->v6.sin6_port, 2);
}

static bool quic_v4_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr)
{
	if (a->v4.sin_port != addr->v4.sin_port)
		return false;
	if (a->v4.sin_family != addr->v4.sin_family)
		return false;
	if (a->v4.sin_addr.s_addr == htonl(INADDR_ANY) ||
	    addr->v4.sin_addr.s_addr == htonl(INADDR_ANY))
		return true;
	return a->v4.sin_addr.s_addr == addr->v4.sin_addr.s_addr;
}

static bool quic_v6_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr)
{
	if (a->v4.sin_port != addr->v4.sin_port)
		return false;

	if (a->sa.sa_family == AF_INET && addr->sa.sa_family == AF_INET) {
		if (a->v4.sin_addr.s_addr == htonl(INADDR_ANY) ||
		    addr->v4.sin_addr.s_addr == htonl(INADDR_ANY))
			return true;
		return a->v4.sin_addr.s_addr == addr->v4.sin_addr.s_addr;
	}

	if (a->sa.sa_family != addr->sa.sa_family) {
		if (ipv6_only_sock(sk))
			return false;
		if (a->sa.sa_family == AF_INET6 && ipv6_addr_any(&a->v6.sin6_addr))
			return true;
		if (a->sa.sa_family == AF_INET && addr->sa.sa_family == AF_INET6 &&
		    ipv6_addr_v4mapped(&addr->v6.sin6_addr) &&
		    addr->v6.sin6_addr.s6_addr32[3] == a->v4.sin_addr.s_addr)
			return true;
		if (addr->sa.sa_family == AF_INET && a->sa.sa_family == AF_INET6 &&
		    ipv6_addr_v4mapped(&a->v6.sin6_addr) &&
		    a->v6.sin6_addr.s6_addr32[3] == addr->v4.sin_addr.s_addr)
			return true;
		return false;
	}

	if (ipv6_addr_any(&a->v6.sin6_addr) || ipv6_addr_any(&addr->v6.sin6_addr))
		return true;
	return ipv6_addr_equal(&a->v6.sin6_addr, &addr->v6.sin6_addr);
}

static int quic_v4_get_sk_addr(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return inet_getname(sock, uaddr, peer);
}

static int quic_v6_get_sk_addr(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	union quic_addr *a = quic_addr(uaddr);
	int ret;

	ret = inet6_getname(sock, uaddr, peer);
	if (ret < 0)
		return ret;

	if (a->sa.sa_family == AF_INET6 && ipv6_addr_v4mapped(&a->v6.sin6_addr)) {
		a->v4.sin_family = AF_INET;
		a->v4.sin_port = a->v6.sin6_port;
		a->v4.sin_addr.s_addr = a->v6.sin6_addr.s6_addr32[3];
	}

	if (a->sa.sa_family == AF_INET) {
		memset(a->v4.sin_zero, 0, sizeof(a->v4.sin_zero));
		return sizeof(struct sockaddr_in);
	}
	return sizeof(struct sockaddr_in6);
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
		inet_sk(sk)->inet_sport = a->v4.sin_port;
		if (a->sa.sa_family == AF_INET) {
			sk->sk_v6_rcv_saddr.s6_addr32[0] = 0;
			sk->sk_v6_rcv_saddr.s6_addr32[1] = 0;
			sk->sk_v6_rcv_saddr.s6_addr32[2] = htonl(0x0000ffff);
			sk->sk_v6_rcv_saddr.s6_addr32[3] = a->v4.sin_addr.s_addr;
		} else {
			sk->sk_v6_rcv_saddr = a->v6.sin6_addr;
		}
	} else {
		inet_sk(sk)->inet_dport = a->v4.sin_port;
		if (a->sa.sa_family == AF_INET) {
			sk->sk_v6_daddr.s6_addr32[0] = 0;
			sk->sk_v6_daddr.s6_addr32[1] = 0;
			sk->sk_v6_daddr.s6_addr32[2] = htonl(0x0000ffff);
			sk->sk_v6_daddr.s6_addr32[3] = a->v4.sin_addr.s_addr;
		} else {
			sk->sk_v6_daddr = a->v6.sin6_addr;
		}
	}
}

static void quic_v4_set_sk_ecn(struct sock *sk, u8 ecn)
{
	inet_sk(sk)->tos = ((inet_sk(sk)->tos & ~INET_ECN_MASK) | ecn);
}

static void quic_v6_set_sk_ecn(struct sock *sk, u8 ecn)
{
	quic_v4_set_sk_ecn(sk, ecn);
	inet6_sk(sk)->tclass = ((inet6_sk(sk)->tclass & ~INET_ECN_MASK) | ecn);
}

static struct quic_proto_family_ops quic_pf_inet = {
	.get_user_addr		= quic_v4_get_user_addr,
	.get_pref_addr		= quic_v4_get_pref_addr,
	.set_pref_addr		= quic_v4_set_pref_addr,
	.cmp_sk_addr		= quic_v4_cmp_sk_addr,
	.get_sk_addr		= quic_v4_get_sk_addr,
	.set_sk_addr		= quic_v4_set_sk_addr,
	.set_sk_ecn		= quic_v4_set_sk_ecn,
	.setsockopt		= ip_setsockopt,
	.getsockopt		= ip_getsockopt,
};

static struct quic_proto_family_ops quic_pf_inet6 = {
	.get_user_addr		= quic_v6_get_user_addr,
	.get_pref_addr		= quic_v6_get_pref_addr,
	.set_pref_addr		= quic_v6_set_pref_addr,
	.cmp_sk_addr		= quic_v6_cmp_sk_addr,
	.get_sk_addr		= quic_v6_get_sk_addr,
	.set_sk_addr		= quic_v6_set_sk_addr,
	.set_sk_ecn		= quic_v6_set_sk_ecn,
	.setsockopt		= ipv6_setsockopt,
	.getsockopt		= ipv6_getsockopt,
};

static struct quic_proto_family_ops *quic_pfs[] = {
	&quic_pf_inet,
	&quic_pf_inet6
};

#define quic_pf(sk)		quic_pfs[(sk)->sk_family == AF_INET6]

int quic_common_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
			   unsigned int optlen)
{
	return quic_pf(sk)->setsockopt(sk, level, optname, optval, optlen);
}

int quic_common_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
			   int __user *optlen)
{
	return quic_pf(sk)->getsockopt(sk, level, optname, optval, optlen);
}

static int quic_inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot;

	if (addr_len < (int)sizeof(addr->sa_family))
		return -EINVAL;

	prot = READ_ONCE(sk->sk_prot);

	return prot->connect(sk, addr, addr_len);
}

static int quic_inet_listen(struct socket *sock, int backlog)
{
	struct quic_conn_id_set *source, *dest;
	struct quic_conn_id conn_id, *active;
	struct quic_path_addr *path;
	struct quic_crypto *crypto;
	struct quic_packet *packet;
	struct sock *sk = sock->sk;
	union quic_addr *sa;
	int err = 0;

	lock_sock(sk);

	crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	packet = quic_packet(sk);
	source = quic_source(sk);
	dest = quic_dest(sk);

	if (!backlog)
		goto free;

	if (!sk_unhashed(sk))
		goto out;

	path = quic_src(sk);
	sa = quic_path_addr(path, 0);
	if (!sa->v4.sin_port) { /* auto bind */
		err = quic_path_set_bind_port(sk, path, 0);
		if (err) {
			quic_path_addr_free(sk, path, 0);
			goto free;
		}
		err = quic_path_set_udp_sock(sk, path, 0);
		if (err) {
			quic_path_addr_free(sk, path, 0);
			goto free;
		}
		quic_set_sk_addr(sk, sa, true);
	}
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(dest, &conn_id, 0, NULL);
	if (err)
		goto free;
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(source, &conn_id, 0, sk);
	if (err)
		goto free;
	active = quic_conn_id_active(dest);
	quic_outq_set_serv(quic_outq(sk));

	err = quic_crypto_initial_keys_install(crypto, active, packet->version, 1);
	if (err)
		goto free;
	quic_set_state(sk, QUIC_SS_LISTENING);
	sk->sk_max_ack_backlog = backlog;
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
out:
	release_sock(sk);
	return err;
free:
	sk->sk_prot->unhash(sk);
	sk->sk_max_ack_backlog = 0;
	quic_crypto_destroy(crypto);
	quic_conn_id_set_free(dest);
	quic_conn_id_set_free(source);
	quic_set_state(sk, QUIC_SS_CLOSED);
	goto out;
}

static int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return quic_get_sk_addr(sock, uaddr, peer);
}

static __poll_t quic_inet_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct list_head *head;
	__poll_t mask;

	poll_wait(file, sk_sleep(sk), wait);

	/* comment it out for compiling on the old kernel version for now */
	/* sock_rps_record_flow(sk); */

	if (quic_is_listen(sk))
		return !list_empty(quic_reqs(sk)) ? (EPOLLIN | EPOLLRDNORM) : 0;

	mask = 0;
	if (sk->sk_err || !skb_queue_empty_lockless(&sk->sk_error_queue))
		mask |= EPOLLERR | (sock_flag(sk, SOCK_SELECT_ERR_QUEUE) ? EPOLLPRI : 0);

	head = quic_inq_recv_list(quic_inq(sk));
	if (!list_empty(head))
		mask |= EPOLLIN | EPOLLRDNORM;

	if (quic_is_closed(sk))
		return mask;

	if (sk_stream_wspace(sk) > 0) {
		mask |= EPOLLOUT | EPOLLWRNORM;
	} else {
		sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
		if (sk_stream_wspace(sk) > 0)
			mask |= EPOLLOUT | EPOLLWRNORM;
	}
	return mask;
}

u32 quic_encap_len(union quic_addr *a)
{
	return sizeof(struct udphdr) + quic_af(a)->iph_len;
}

int quic_is_any_addr(union quic_addr *a)
{
	return quic_af(a)->is_any_addr(a);
}

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a)
{
	quic_af(a)->udp_conf_init(sk, conf, a);
}

int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa)
{
	return quic_af(da)->flow_route(sk, da, sa);
}

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
		     union quic_addr *sa)
{
	quic_af(da)->lower_xmit(sk, skb, da, sa);
}

void quic_seq_dump_addr(struct seq_file *seq, union quic_addr *addr)
{
	quic_af(addr)->seq_dump_addr(seq, addr);
}

void quic_get_msg_addr(union quic_addr *addr, struct sk_buff *skb, bool src)
{
	memset(addr, 0, sizeof(*addr));
	quic_af_skb(skb)->get_msg_addr(addr, skb, src);
}

int quic_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	return quic_af_skb(skb)->get_mtu_info(skb, info);
}

u8 quic_get_msg_ecn(struct sk_buff *skb)
{
	return quic_af_skb(skb)->get_msg_ecn(skb);
}

int quic_get_user_addr(struct sock *sk, union quic_addr *a, struct sockaddr *addr, int addr_len)
{
	memset(a, 0, sizeof(*a));
	return quic_pf(sk)->get_user_addr(sk, a, addr, addr_len);
}

void quic_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen)
{
	memset(addr, 0, sizeof(*addr));
	quic_pf(sk)->get_pref_addr(sk, addr, pp, plen);
}

void quic_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr)
{
	quic_pf(sk)->set_pref_addr(sk, p, addr);
}

bool quic_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr)
{
	return quic_pf(sk)->cmp_sk_addr(sk, a, addr);
}

int quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer)
{
	return quic_pf(sock->sk)->get_sk_addr(sock, a, peer);
}

void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	return quic_pf(sk)->set_sk_addr(sk, a, src);
}

void quic_set_sk_ecn(struct sock *sk, u8 ecn)
{
	quic_pf(sk)->set_sk_ecn(sk, ecn);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
	{ /* sentinel */ }
#endif
};

static unsigned int quic_net_id __read_mostly;

struct quic_net *quic_net(struct net *net)
{
	return net_generic(net, quic_net_id);
}

#ifdef CONFIG_PROC_FS
static int quic_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq_file_net(seq);
	u32 hash = (u32)(*(loff_t *)v);
	struct quic_hash_head *head;
	struct quic_outqueue *outq;
	struct sock *sk;

	if (hash >= 64)
		return -ENOMEM;

	head = &quic_hash_tables[QUIC_HT_SOCK].hash[hash];
	spin_lock(&head->lock);
	sk_for_each(sk, &head->head) {
		if (net != sock_net(sk))
			continue;

		quic_seq_dump_addr(seq, quic_path_addr(quic_src(sk), 0));
		quic_seq_dump_addr(seq, quic_path_addr(quic_dst(sk), 0));
		quic_seq_dump_addr(seq, quic_path_udp(quic_src(sk), 0));

		outq = quic_outq(sk);
		seq_printf(seq, "%d\t%lld\t%d\t%d\t%d\t%d\t%d\t%d\n", sk->sk_state,
			   quic_outq_window(outq), quic_packet_mss(quic_packet(sk)),
			   quic_outq_inflight(outq), READ_ONCE(sk->sk_wmem_queued),
			   sk_rmem_alloc_get(sk), sk->sk_sndbuf, sk->sk_rcvbuf);
	}
	spin_unlock(&head->lock);
	return 0;
}

static void *quic_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos >= 64)
		return NULL;

	if (*pos < 0)
		*pos = 0;

	if (*pos == 0)
		seq_printf(seq, "LOCAL_ADDRESS\tREMOTE_ADDRESS\tUDP_ADDRESS\tSTATE\t"
				"WINDOW\tMSS\tIN_FLIGHT\tTX_QUEUE\tRX_QUEUE\tSNDBUF\tRCVBUF\n");

	return (void *)pos;
}

static void *quic_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (++*pos >= 64)
		return NULL;

	return pos;
}

static void quic_seq_stop(struct seq_file *seq, void *v)
{
}

static const struct snmp_mib quic_snmp_list[] = {
	SNMP_MIB_ITEM("QuicConnCurrentEstabs", QUIC_MIB_CONN_CURRENTESTABS),
	SNMP_MIB_ITEM("QuicConnPassiveEstabs", QUIC_MIB_CONN_PASSIVEESTABS),
	SNMP_MIB_ITEM("QuicConnActiveEstabs", QUIC_MIB_CONN_ACTIVEESTABS),
	SNMP_MIB_ITEM("QuicPktRcvFastpaths", QUIC_MIB_PKT_RCVFASTPATHS),
	SNMP_MIB_ITEM("QuicPktDecFastpaths", QUIC_MIB_PKT_DECFASTPATHS),
	SNMP_MIB_ITEM("QuicPktEncFastpaths", QUIC_MIB_PKT_ENCFASTPATHS),
	SNMP_MIB_ITEM("QuicPktRcvBacklogs", QUIC_MIB_PKT_RCVBACKLOGS),
	SNMP_MIB_ITEM("QuicPktDecBacklogs", QUIC_MIB_PKT_DECBACKLOGS),
	SNMP_MIB_ITEM("QuicPktEncBacklogs", QUIC_MIB_PKT_ENCBACKLOGS),
	SNMP_MIB_ITEM("QuicPktInvHdrDrop", QUIC_MIB_PKT_INVHDRDROP),
	SNMP_MIB_ITEM("QuicPktInvNumDrop", QUIC_MIB_PKT_INVNUMDROP),
	SNMP_MIB_ITEM("QuicPktInvFrmDrop", QUIC_MIB_PKT_INVFRMDROP),
	SNMP_MIB_ITEM("QuicPktRcvDrop", QUIC_MIB_PKT_RCVDROP),
	SNMP_MIB_ITEM("QuicPktDecDrop", QUIC_MIB_PKT_DECDROP),
	SNMP_MIB_ITEM("QuicPktEncDrop", QUIC_MIB_PKT_ENCDROP),
	SNMP_MIB_ITEM("QuicFrmRcvBufDrop", QUIC_MIB_FRM_RCVBUFDROP),
	SNMP_MIB_ITEM("QuicFrmRetrans", QUIC_MIB_FRM_RETRANS),
	SNMP_MIB_ITEM("QuicFrmCloses", QUIC_MIB_FRM_CLOSES),
	SNMP_MIB_SENTINEL
};

static int quic_snmp_seq_show(struct seq_file *seq, void *v)
{
	unsigned long buff[QUIC_MIB_MAX];
	struct net *net = seq->private;
	u32 idx;

	memset(buff, 0, sizeof(unsigned long) * QUIC_MIB_MAX);

	snmp_get_cpu_field_batch(buff, quic_snmp_list, quic_net(net)->stat);
	for (idx = 0; quic_snmp_list[idx].name; idx++)
		seq_printf(seq, "%-32s\t%ld\n", quic_snmp_list[idx].name, buff[idx]);

	return 0;
}

static const struct seq_operations quic_seq_ops = {
	.show		= quic_seq_show,
	.start		= quic_seq_start,
	.next		= quic_seq_next,
	.stop		= quic_seq_stop,
};

static int quic_net_proc_init(struct net *net)
{
	quic_net(net)->proc_net = proc_net_mkdir(net, "quic", net->proc_net);
	if (!quic_net(net)->proc_net)
		return -ENOMEM;

	if (!proc_create_net_single("snmp", 0444, quic_net(net)->proc_net,
				    quic_snmp_seq_show, NULL))
		goto free;
	if (!proc_create_net("sks", 0444, quic_net(net)->proc_net,
			     &quic_seq_ops, sizeof(struct seq_net_private)))
		goto free;
	return 0;
free:
	remove_proc_subtree("quic", net->proc_net);
	quic_net(net)->proc_net = NULL;
	return -ENOMEM;
}

static void quic_net_proc_exit(struct net *net)
{
	remove_proc_subtree("quic", net->proc_net);
	quic_net(net)->proc_net = NULL;
}
#endif

static const struct proto_ops quic_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = quic_inet_poll,
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
	.poll		   = quic_inet_poll,
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
	struct proto *proto;
	void *offset;
	int err;

	proto = &quic_prot;
	offset = (void *)(&proto->memory_allocated) + sizeof(proto->memory_allocated);
	if (offset != (void *)&proto->sockets_allocated) /* per_cpu_fw_alloc */
		*(int  __percpu **)offset = &quic_memory_per_cpu_fw_alloc;

	err = proto_register(proto, 1);
	if (err)
		return err;

	proto = &quicv6_prot;
	offset = (void *)(&proto->memory_allocated) + sizeof(proto->memory_allocated);
	if (offset != (void *)&proto->sockets_allocated) /* per_cpu_fw_alloc */
		*(int  __percpu **)offset = &quic_memory_per_cpu_fw_alloc;

	offset = (void *)(&proto->obj_size) + sizeof(proto->obj_size);
	if (offset != &proto->slab_flags) /* ipv6_pinfo_offset */
		*(unsigned int *)offset = offsetof(struct quic6_sock, inet6);

	err = proto_register(proto, 1);
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
	int err = 0;

	quic_net(net)->stat = alloc_percpu(struct quic_mib);
	if (!quic_net(net)->stat)
		return -ENOMEM;

#ifdef CONFIG_PROC_FS
	err = quic_net_proc_init(net);
	if (err) {
		free_percpu(quic_net(net)->stat);
		quic_net(net)->stat = NULL;
	}
#endif
	return err;
}

static void __net_exit quic_net_exit(struct net *net)
{
#ifdef CONFIG_PROC_FS
	quic_net_proc_exit(net);
#endif
	free_percpu(quic_net(net)->stat);
	quic_net(net)->stat = NULL;
}

static struct pernet_operations quic_net_ops = {
	.init = quic_net_init,
	.exit = quic_net_exit,
	.id   = &quic_net_id,
	.size = sizeof(struct quic_net),
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

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *quic_sysctl_header;

static void quic_sysctl_register(void)
{
	unsigned long limit;
	int max_share;

	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_quic_mem[0] = (long)limit / 4 * 3;
	sysctl_quic_mem[1] = (long)limit;
	sysctl_quic_mem[2] = sysctl_quic_mem[0] * 2;

	limit = (sysctl_quic_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL * 1024 * 1024, limit);

	sysctl_quic_rmem[0] = PAGE_SIZE;
	sysctl_quic_rmem[1] = 1024 * 1024;
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
#endif

static __init int quic_init(void)
{
	int err = -ENOMEM;

	if (quic_hash_tables_init())
		goto err;

	quic_frame_cachep = kmem_cache_create("quic_frame", sizeof(struct quic_frame),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_frame_cachep)
		goto err_cachep;

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

#ifdef CONFIG_SYSCTL
	quic_sysctl_register();
#endif

	get_random_bytes(quic_random_data, 32);
	pr_info("quic: init\n");
	return 0;

err_def_ops:
	quic_protosw_exit();
err_protosw:
	percpu_counter_destroy(&quic_sockets_allocated);
err_percpu_counter:
	destroy_workqueue(quic_wq);
err_wq:
	kmem_cache_destroy(quic_frame_cachep);
err_cachep:
	quic_hash_tables_destroy();
err:
	return err;
}

static __exit void quic_exit(void)
{
#ifdef CONFIG_SYSCTL
	quic_sysctl_unregister();
#endif
	unregister_pernet_subsys(&quic_net_ops);
	quic_protosw_exit();
	percpu_counter_destroy(&quic_sockets_allocated);
	destroy_workqueue(quic_wq);
	quic_hash_tables_destroy();
	pr_info("quic: exit\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_ALIAS("net-pf-" __stringify(PF_INET) "-proto-261");
MODULE_ALIAS("net-pf-" __stringify(PF_INET6) "-proto-261");
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
