/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quichdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 pnl:2,
	     key:1,
	     reserved:2,
	     spin:1,
	     fixed:1,
	     form:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 form:1,
	     fixed:1,
	     spin:1,
	     reserved:2,
	     key:1,
	     pnl:2;
#endif
};

static inline struct quichdr *quic_hdr(struct sk_buff *skb)
{
	return (struct quichdr *)skb_transport_header(skb);
}

struct quichshdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 pnl:2,
	     reserved:2,
	     type:2,
	     fixed:1,
	     form:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 form:1,
	     fixed:1,
	     type:2,
	     reserved:2,
	     pnl:2;
#endif
};

static inline struct quichshdr *quic_hshdr(struct sk_buff *skb)
{
	return (struct quichshdr *)skb_transport_header(skb);
}

union quic_addr {
	struct sockaddr_in6 v6;
	struct sockaddr_in v4;
	struct sockaddr sa;
};

static inline union quic_addr *quic_addr(const void *addr)
{
	return (union quic_addr *)addr;
}

struct quic_hash_head {
	spinlock_t		lock; /* protect the 'head' member access */
	struct hlist_head	head;
};

struct quic_hash_table {
	struct quic_hash_head *hash;
	int size;
};

enum  {
	QUIC_HT_SOCK,
	QUIC_HT_UDP_SOCK,
	QUIC_HT_CONNECTION_ID,
	QUIC_HT_BIND_PORT,
	QUIC_HT_MAX_TABLES,
};

static inline __u32 quic_shash(const struct net *net, const union quic_addr *a)
{
	__u32 addr = (a->sa.sa_family == AF_INET6) ? jhash(&a->v6.sin6_addr, 16, 0)
						   : (__force __u32)a->v4.sin_addr.s_addr;

	return  jhash_3words(addr, (__force __u32)a->v4.sin_port, net_hash_mix(net), 0);
}

static inline __u32 quic_ahash(const struct net *net, const union quic_addr *s,
			       const union quic_addr *d)
{
	__u32 ports = ((__force __u32)s->v4.sin_port) << 16 | (__force __u32)d->v4.sin_port;
	__u32 saddr = (s->sa.sa_family == AF_INET6) ? jhash(&s->v6.sin6_addr, 16, 0)
						    : (__force __u32)s->v4.sin_addr.s_addr;
	__u32 daddr = (d->sa.sa_family == AF_INET6) ? jhash(&d->v6.sin6_addr, 16, 0)
						    : (__force __u32)d->v4.sin_addr.s_addr;

	return  jhash_3words(saddr, ports, net_hash_mix(net), daddr);
}

extern struct quic_hash_table quic_hash_tables[QUIC_HT_MAX_TABLES];

static inline struct quic_hash_head *quic_sock_head(struct net *net, union quic_addr *s,
						    union quic_addr *d)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_SOCK];

	return &ht->hash[quic_ahash(net, s, d) & (ht->size - 1)];
}

static inline struct quic_hash_head *quic_listen_sock_head(struct net *net, u16 port)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_SOCK];

	return &ht->hash[port & (ht->size - 1)];
}

static inline struct quic_hash_head *quic_bind_port_head(struct net *net, u16 port)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_BIND_PORT];

	return &ht->hash[port & (ht->size - 1)];
}

static inline struct quic_hash_head *quic_source_conn_id_head(struct net *net, u8 *scid)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_CONNECTION_ID];

	return &ht->hash[jhash(scid, 4, 0) & (ht->size - 1)];
}

static inline struct quic_hash_head *quic_udp_sock_head(struct net *net, u16 port)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_UDP_SOCK];

	return &ht->hash[port & (ht->size - 1)];
}

static inline struct quic_hash_head *quic_stream_head(struct quic_hash_table *ht, u64 stream_id)
{
	return &ht->hash[stream_id & (ht->size - 1)];
}
