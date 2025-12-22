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
#include <net/udp_tunnel.h>
#include <linux/icmp.h>

#include "common.h"
#include "family.h"

static int quic_v4_is_any_addr(union quic_addr *addr)
{
	return addr->v4.sin_addr.s_addr == htonl(INADDR_ANY);
}

static int quic_v6_is_any_addr(union quic_addr *addr)
{
	return ipv6_addr_any(&addr->v6.sin6_addr);
}

static void quic_v4_seq_dump_addr(struct seq_file *seq, union quic_addr *addr)
{
	seq_printf(seq, "%pI4:%d\t", &addr->v4.sin_addr.s_addr, ntohs(addr->v4.sin_port));
}

static void quic_v6_seq_dump_addr(struct seq_file *seq, union quic_addr *addr)
{
	seq_printf(seq, "%pI6c:%d\t", &addr->v6.sin6_addr, ntohs(addr->v4.sin_port));
}

static void quic_v4_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a)
{
	conf->family = AF_INET;
	conf->local_ip.s_addr = a->v4.sin_addr.s_addr;
	conf->local_udp_port = a->v4.sin_port;
	conf->use_udp6_rx_checksums = true;
	conf->bind_ifindex = sk->sk_bound_dev_if;
}

static void quic_v6_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a)
{
	conf->family = AF_INET6;
	conf->local_ip6 = a->v6.sin6_addr;
	conf->local_udp_port = a->v6.sin6_port;
	conf->use_udp6_rx_checksums = true;
	conf->ipv6_v6only = ipv6_only_sock(sk);
	conf->bind_ifindex = sk->sk_bound_dev_if;
}

static int quic_v4_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa,
			      struct flowi *fl)
{
	struct flowi4 *fl4;
	struct rtable *rt;

	if (__sk_dst_check(sk, 0))
		return 1;

	memset(fl, 0x00, sizeof(*fl));
	fl4 = &fl->u.ip4;
	fl4->saddr = sa->v4.sin_addr.s_addr;
	fl4->fl4_sport = sa->v4.sin_port;
	fl4->daddr = da->v4.sin_addr.s_addr;
	fl4->fl4_dport = da->v4.sin_port;
	fl4->flowi4_proto = IPPROTO_UDP;
	fl4->flowi4_oif = sk->sk_bound_dev_if;

	fl4->flowi4_scope = ip_sock_rt_scope(sk);
#ifdef flowi4_dscp
	fl4->flowi4_dscp = inet_sk_dscp(inet_sk(sk));
#else
	fl4->flowi4_tos = ip_sock_rt_tos(sk);
#endif

	rt = ip_route_output_key(sock_net(sk), fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	if (quic_v4_is_any_addr(sa)) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_addr.s_addr = fl4->saddr;
	}
	sk_setup_caps(sk, &rt->dst);
	return 0;
}

static int quic_v6_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa,
			      struct flowi *fl)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct ip6_flowlabel *flowlabel;
	struct dst_entry *dst;
	struct flowi6 *fl6;

	if (__sk_dst_check(sk, np->dst_cookie))
		return 1;

	memset(fl, 0x00, sizeof(*fl));
	fl6 = &fl->u.ip6;
	fl6->saddr = sa->v6.sin6_addr;
	fl6->fl6_sport = sa->v6.sin6_port;
	fl6->daddr = da->v6.sin6_addr;
	fl6->fl6_dport = da->v6.sin6_port;
	fl6->flowi6_proto = IPPROTO_UDP;
	fl6->flowi6_oif = sk->sk_bound_dev_if;

#ifdef inet6_test_bit
	if (inet6_test_bit(SNDFLOW, sk)) {
#else
	if (np->sndflow) {
#endif
		fl6->flowlabel = (da->v6.sin6_flowinfo & IPV6_FLOWINFO_MASK);
		if (fl6->flowlabel & IPV6_FLOWLABEL_MASK) {
			flowlabel = fl6_sock_lookup(sk, fl6->flowlabel);
			if (IS_ERR(flowlabel))
				return -EINVAL;
			fl6_sock_release(flowlabel);
		}
	}

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, fl6, NULL);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	if (quic_v6_is_any_addr(sa)) {
		sa->v6.sin6_family = AF_INET6;
		sa->v6.sin6_addr = fl6->saddr;
	}
	ip6_dst_store(sk, dst, NULL, NULL);
	return 0;
}

static void quic_v4_lower_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 tos = (inet_sk(sk)->tos | cb->ecn), ttl;
	struct flowi4 *fl4 = &fl->u.ip4;
	struct dst_entry *dst;
	__be16 df = 0;

	pr_debug("%s: skb: %p, len: %d, num: %llu, %pI4:%d -> %pI4:%d\n", __func__,
		 skb, skb->len, cb->number, &fl4->saddr, ntohs(fl4->fl4_sport),
		 &fl4->daddr, ntohs(fl4->fl4_dport));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}
	if (ip_dont_fragment(sk, dst) && !skb->ignore_df)
		df = htons(IP_DF);

	ttl = (u8)ip4_dst_hoplimit(dst);
#ifdef IPSKB_MCROUTE
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, fl4->saddr, fl4->daddr,
			    tos, ttl, df, fl4->fl4_sport, fl4->fl4_dport, false, false, 0);
#else
	udp_tunnel_xmit_skb((struct rtable *)dst, sk, skb, fl4->saddr, fl4->daddr,
			    tos, ttl, df, fl4->fl4_sport, fl4->fl4_dport, false, false);
#endif
}

static void quic_v6_lower_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 tc = (inet6_sk(sk)->tclass | cb->ecn), ttl;
	struct flowi6 *fl6 = &fl->u.ip6;
	struct dst_entry *dst;
	__be32 label;

	pr_debug("%s: skb: %p, len: %d, num: %llu, %pI6c:%d -> %pI6c:%d\n", __func__,
		 skb, skb->len, cb->number, &fl6->saddr, ntohs(fl6->fl6_sport),
		 &fl6->daddr, ntohs(fl6->fl6_dport));

	dst = sk_dst_get(sk);
	if (!dst) {
		kfree_skb(skb);
		return;
	}

	ttl = (u8)ip6_dst_hoplimit(dst);
	label = ip6_make_flowlabel(sock_net(sk), skb, fl6->flowlabel, true, fl6);
#ifdef IPSKB_MCROUTE
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &fl6->saddr, &fl6->daddr, tc,
			     ttl, label, fl6->fl6_sport, fl6->fl6_dport, false, 0);
#else
	udp_tunnel6_xmit_skb(dst, sk, skb, NULL, &fl6->saddr, &fl6->daddr, tc,
			     ttl, label, fl6->fl6_sport, fl6->fl6_dport, false);
#endif
}

static void quic_v4_get_msg_addrs(struct sk_buff *skb, union quic_addr *da, union quic_addr *sa)
{
	struct udphdr *uh = udp_hdr(skb);

	sa->v4.sin_family = AF_INET;
	sa->v4.sin_port = uh->source;
	sa->v4.sin_addr.s_addr = ip_hdr(skb)->saddr;

	da->v4.sin_family = AF_INET;
	da->v4.sin_port = uh->dest;
	da->v4.sin_addr.s_addr = ip_hdr(skb)->daddr;
}

static void quic_v6_get_msg_addrs(struct sk_buff *skb, union quic_addr *da, union quic_addr *sa)
{
	struct udphdr *uh = udp_hdr(skb);

	sa->v6.sin6_family = AF_INET6;
	sa->v6.sin6_port = uh->source;
	sa->v6.sin6_addr = ipv6_hdr(skb)->saddr;

	da->v6.sin6_family = AF_INET6;
	da->v6.sin6_port = uh->dest;
	da->v6.sin6_addr = ipv6_hdr(skb)->daddr;
}

static int quic_v4_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	struct icmphdr *hdr;

	hdr = (struct icmphdr *)(skb_network_header(skb) - sizeof(struct icmphdr));
	if (hdr->type == ICMP_DEST_UNREACH && hdr->code == ICMP_FRAG_NEEDED) {
		*info = ntohs(hdr->un.frag.mtu);
		return 0;
	}

	/* Defer other types' processing to UDP error handler. */
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

	/* Defer other types' processing to UDP error handler. */
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

static int quic_v4_get_addr_from_user(struct sock *sk, union quic_addr *a, struct sockaddr *addr,
				      int addr_len)
{
	u32 len = sizeof(struct sockaddr_in);

	if (addr_len < len || addr->sa_family != AF_INET)
		return -EINVAL;
	if (ipv4_is_multicast(quic_addr(addr)->v4.sin_addr.s_addr))
		return -EINVAL;
	memcpy(a, addr, len);
	return 0;
}

static int quic_v6_get_addr_from_user(struct sock *sk, union quic_addr *a, struct sockaddr *addr,
				      int addr_len)
{
	u32 len = sizeof(struct sockaddr_in);
	int type;

	if (addr_len < len)
		return -EINVAL;

	if (addr->sa_family != AF_INET6) {
		if (ipv6_only_sock(sk))
			return -EINVAL;
		return quic_v4_get_addr_from_user(sk, a, addr, addr_len);
	}

	len = sizeof(struct sockaddr_in6);
	if (addr_len < len)
		return -EINVAL;
	type = ipv6_addr_type(&quic_addr(addr)->v6.sin6_addr);
	if (type != IPV6_ADDR_ANY && !(type & IPV6_ADDR_UNICAST))
		return -EINVAL;
	memcpy(a, addr, len);
	return 0;
}

static void quic_v4_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen)
{
	u8 *p = *pp;

	memcpy(&addr->v4.sin_addr, p, QUIC_ADDR4_LEN);
	p += QUIC_ADDR4_LEN;
	memcpy(&addr->v4.sin_port, p, QUIC_PORT_LEN);
	p += QUIC_PORT_LEN;
	addr->v4.sin_family = AF_INET;
	/* Skip over IPv6 address and port, not used for AF_INET sockets. */
	p += QUIC_ADDR6_LEN;
	p += QUIC_PORT_LEN;

	if (!addr->v4.sin_port || quic_v4_is_any_addr(addr) ||
	    ipv4_is_multicast(addr->v4.sin_addr.s_addr))
		memset(addr, 0, sizeof(*addr));
	*plen -= (p - *pp);
	*pp = p;
}

static void quic_v6_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen)
{
	u8 *p = *pp;
	int type;

	/* Skip over IPv4 address and port. */
	p += QUIC_ADDR4_LEN;
	p += QUIC_PORT_LEN;
	/* Try to use IPv6 address and port first. */
	memcpy(&addr->v6.sin6_addr, p, QUIC_ADDR6_LEN);
	p += QUIC_ADDR6_LEN;
	memcpy(&addr->v6.sin6_port, p, QUIC_PORT_LEN);
	p += QUIC_PORT_LEN;
	addr->v6.sin6_family = AF_INET6;

	type = ipv6_addr_type(&addr->v6.sin6_addr);
	if (!addr->v6.sin6_port || !(type & IPV6_ADDR_UNICAST)) {
		memset(addr, 0, sizeof(*addr));
		if (ipv6_only_sock(sk))
			goto out;
		/* Fallback to IPv4 if IPv6 address is not usable. */
		return quic_v4_get_pref_addr(sk, addr, pp, plen);
	}
out:
	*plen -= (p - *pp);
	*pp = p;
}

static void quic_v4_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr)
{
	memcpy(p, &addr->v4.sin_addr, QUIC_ADDR4_LEN);
	p += QUIC_ADDR4_LEN;
	memcpy(p, &addr->v4.sin_port, QUIC_PORT_LEN);
	p += QUIC_PORT_LEN;
	memset(p, 0, QUIC_ADDR6_LEN);
	p += QUIC_ADDR6_LEN;
	memset(p, 0, QUIC_PORT_LEN);
}

static void quic_v6_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr)
{
	if (addr->sa.sa_family == AF_INET)
		return quic_v4_set_pref_addr(sk, p, addr);

	memset(p, 0, QUIC_ADDR4_LEN);
	p += QUIC_ADDR4_LEN;
	memset(p, 0, QUIC_PORT_LEN);
	p += QUIC_PORT_LEN;
	memcpy(p, &addr->v6.sin6_addr, QUIC_ADDR6_LEN);
	p += QUIC_ADDR6_LEN;
	memcpy(p, &addr->v6.sin6_port, QUIC_PORT_LEN);
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

static bool quic_v4_match_v6_addr(union quic_addr *a4, union quic_addr *a6)
{
	if (ipv6_addr_any(&a6->v6.sin6_addr))
		return true;
	if (ipv6_addr_v4mapped(&a6->v6.sin6_addr) &&
	    a6->v6.sin6_addr.s6_addr32[3] == a4->v4.sin_addr.s_addr)
		return true;
	return false;
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
		if (a->sa.sa_family == AF_INET)
			return quic_v4_match_v6_addr(a, addr);
		return quic_v4_match_v6_addr(addr, a);
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

static void quic_v6_copy_sk_addr(struct in6_addr *skaddr, union quic_addr *a)
{
	if (a->sa.sa_family == AF_INET) {
		skaddr->s6_addr32[0] = 0;
		skaddr->s6_addr32[1] = 0;
		skaddr->s6_addr32[2] = htonl(0x0000ffff);
		skaddr->s6_addr32[3] = a->v4.sin_addr.s_addr;
	} else {
		*skaddr = a->v6.sin6_addr;
	}
}

static void quic_v6_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	if (src) {
		inet_sk(sk)->inet_sport = a->v4.sin_port;
		quic_v6_copy_sk_addr(&sk->sk_v6_rcv_saddr, a);
	} else {
		inet_sk(sk)->inet_dport = a->v4.sin_port;
		quic_v6_copy_sk_addr(&sk->sk_v6_daddr, a);
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

#define quic_af_ipv4(a)		((a)->sa.sa_family == AF_INET)

u32 quic_encap_len(union quic_addr *a)
{
	return (quic_af_ipv4(a) ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) +
	       sizeof(struct udphdr);
}

int quic_is_any_addr(union quic_addr *a)
{
	return quic_af_ipv4(a) ? quic_v4_is_any_addr(a) : quic_v6_is_any_addr(a);
}

void quic_seq_dump_addr(struct seq_file *seq, union quic_addr *addr)
{
	quic_af_ipv4(addr) ? quic_v4_seq_dump_addr(seq, addr) : quic_v6_seq_dump_addr(seq, addr);
}

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a)
{
	quic_af_ipv4(a) ? quic_v4_udp_conf_init(sk, conf, a) : quic_v6_udp_conf_init(sk, conf, a);
}

int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa, struct flowi *fl)
{
	return quic_af_ipv4(da) ? quic_v4_flow_route(sk, da, sa, fl) :
				  quic_v6_flow_route(sk, da, sa, fl);
}

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da, struct flowi *fl)
{
	quic_af_ipv4(da) ? quic_v4_lower_xmit(sk, skb, fl) : quic_v6_lower_xmit(sk, skb, fl);
}

#define quic_skb_ipv4(skb)	(ip_hdr(skb)->version == 4)

void quic_get_msg_addrs(struct sk_buff *skb, union quic_addr *da, union quic_addr *sa)
{
	memset(sa, 0, sizeof(*sa));
	memset(da, 0, sizeof(*da));
	quic_skb_ipv4(skb) ? quic_v4_get_msg_addrs(skb, da, sa) :
			     quic_v6_get_msg_addrs(skb, da, sa);
}

int quic_get_mtu_info(struct sk_buff *skb, u32 *info)
{
	return quic_skb_ipv4(skb) ? quic_v4_get_mtu_info(skb, info) :
				    quic_v6_get_mtu_info(skb, info);
}

u8 quic_get_msg_ecn(struct sk_buff *skb)
{
	return quic_skb_ipv4(skb) ? quic_v4_get_msg_ecn(skb) : quic_v6_get_msg_ecn(skb);
}

#define quic_pf_ipv4(sk)	((sk)->sk_family == PF_INET)

int quic_get_addr_from_user(struct sock *sk, union quic_addr *a, struct sockaddr *addr,
			    int addr_len)
{
	memset(a, 0, sizeof(*a));
	return quic_pf_ipv4(sk) ? quic_v4_get_addr_from_user(sk, a, addr, addr_len) :
				  quic_v6_get_addr_from_user(sk, a, addr, addr_len);
}

void quic_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen)
{
	memset(addr, 0, sizeof(*addr));
	quic_pf_ipv4(sk) ? quic_v4_get_pref_addr(sk, addr, pp, plen) :
			   quic_v6_get_pref_addr(sk, addr, pp, plen);
}

void quic_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr)
{
	quic_pf_ipv4(sk) ? quic_v4_set_pref_addr(sk, p, addr) : quic_v6_set_pref_addr(sk, p, addr);
}

bool quic_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr)
{
	return quic_pf_ipv4(sk) ? quic_v4_cmp_sk_addr(sk, a, addr) :
				  quic_v6_cmp_sk_addr(sk, a, addr);
}

int quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer)
{
	return quic_pf_ipv4(sock->sk) ? quic_v4_get_sk_addr(sock, a, peer) :
					quic_v6_get_sk_addr(sock, a, peer);
}

void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src)
{
	quic_pf_ipv4(sk) ? quic_v4_set_sk_addr(sk, a, src) : quic_v6_set_sk_addr(sk, a, src);
}

void quic_set_sk_ecn(struct sock *sk, u8 ecn)
{
	quic_pf_ipv4(sk) ? quic_v4_set_sk_ecn(sk, ecn) : quic_v6_set_sk_ecn(sk, ecn);
}

int quic_common_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
			   unsigned int optlen)
{
	return quic_pf_ipv4(sk) ? ip_setsockopt(sk, level, optname, optval, optlen) :
				  ipv6_setsockopt(sk, level, optname, optval, optlen);
}

int quic_common_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
			   int __user *optlen)
{
	return quic_pf_ipv4(sk) ? ip_getsockopt(sk, level, optname, optval, optlen) :
				  ipv6_getsockopt(sk, level, optname, optval, optlen);
}
