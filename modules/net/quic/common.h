/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/netns/hash.h>
#include <linux/jhash.h>

#define QUIC_MAX_ACK_DELAY	(16384 * 1000)
#define QUIC_DEF_ACK_DELAY	25000

#define QUIC_STREAM_BIT_FIN	0x01
#define QUIC_STREAM_BIT_LEN	0x02
#define QUIC_STREAM_BIT_OFF	0x04
#define QUIC_STREAM_BIT_MASK	0x08

#define QUIC_CONN_ID_MAX_LEN	20
#define QUIC_CONN_ID_DEF_LEN	8

struct quic_conn_id {
	u8 data[QUIC_CONN_ID_MAX_LEN];
	u8 len;
};

static inline void quic_conn_id_update(struct quic_conn_id *conn_id, u8 *data, u32 len)
{
	memcpy(conn_id->data, data, len);
	conn_id->len = (u8)len;
}

struct quic_crypto_cb {
	void (*crypto_done)(struct sk_buff *skb, int err);
	union {
		struct quic_conn_id *conn_id;
		struct sk_buff *last;
	};
	s64 number_max;
	s64 number;
	u16 errcode;
	u16 length;
	u32 time;

	u16 number_offset;
	u16 udph_offset;
	u8 number_len;
	u8 level;

	u8 key_update:1;
	u8 key_phase:1;
	u8 resume:1;
	u8 path:1;
	u8 ecn:2;
};

#define QUIC_CRYPTO_CB(skb)	((struct quic_crypto_cb *)&((skb)->cb[0]))

static inline struct udphdr *quic_udphdr(const struct sk_buff *skb)
{
	return (struct udphdr *)(skb->head + QUIC_CRYPTO_CB(skb)->udph_offset);
}

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

static inline u32 quic_shash(const struct net *net, const union quic_addr *a)
{
	u32 addr = (a->sa.sa_family == AF_INET6) ? jhash(&a->v6.sin6_addr, 16, 0)
						 : (__force u32)a->v4.sin_addr.s_addr;

	return  jhash_3words(addr, (__force u32)a->v4.sin_port, net_hash_mix(net), 0);
}

static inline u32 quic_ahash(const struct net *net, const union quic_addr *s,
			     const union quic_addr *d)
{
	u32 ports = ((__force u32)s->v4.sin_port) << 16 | (__force u32)d->v4.sin_port;
	u32 saddr = (s->sa.sa_family == AF_INET6) ? jhash(&s->v6.sin6_addr, 16, 0)
						  : (__force u32)s->v4.sin_addr.s_addr;
	u32 daddr = (d->sa.sa_family == AF_INET6) ? jhash(&d->v6.sin6_addr, 16, 0)
						  : (__force u32)d->v4.sin_addr.s_addr;

	return  jhash_3words(saddr, ports, net_hash_mix(net), daddr);
}

static inline u32 quic_var_len(u64 n)
{
	if (n < 64)
		return 1;
	if (n < 16384)
		return 2;
	if (n < 1073741824)
		return 4;
	return 8;
}

struct quic_data {
	u8 *data;
	u32 len;
};

static inline struct quic_data *quic_data(struct quic_data *d, u8 *data, u32 len)
{
	d->data = data;
	d->len  = len;
	return d;
}

static inline int quic_data_cmp(struct quic_data *d1, struct quic_data *d2)
{
	return d1->len != d2->len || memcmp(d1->data, d2->data, d1->len);
}

static inline void quic_data_free(struct quic_data *d)
{
	kfree(d->data);
	d->data = NULL;
	d->len = 0;
}

struct quic_hash_head *quic_sock_head(struct net *net, union quic_addr *s, union quic_addr *d);
struct quic_hash_head *quic_listen_sock_head(struct net *net, u16 port);
struct quic_hash_head *quic_bind_port_head(struct net *net, u16 port);

struct quic_hash_head *quic_stream_head(struct quic_hash_table *ht, s64 stream_id);
struct quic_hash_head *quic_source_conn_id_head(struct net *net, u8 *scid);
struct quic_hash_head *quic_udp_sock_head(struct net *net, u16 port);

struct quic_hash_head *quic_sock_hash(u32 hash);
void quic_hash_tables_destroy(void);
int quic_hash_tables_init(void);

u32 quic_get_int(u8 **pp, u32 *plen, u64 *val, u32 len);
s64 quic_get_num(s64 max_pkt_num, s64 pkt_num, u32 n);
int quic_get_param(u64 *pdest, u8 **pp, u32 *plen);
u8 quic_get_var(u8 **pp, u32 *plen, u64 *val);

u8 *quic_put_param(u8 *p, u16 id, u64 value);
u8 *quic_put_data(u8 *p, u8 *data, u32 len);
u8 *quic_put_int(u8 *p, u64 num, u8 len);
u8 *quic_put_var(u8 *p, u64 num);

void quic_data_from_string(struct quic_data *to, u8 *from, u32 len);
void quic_data_to_string(u8 *to, u32 *plen, struct quic_data *from);

int quic_data_match(struct quic_data *d1, struct quic_data *d2);
int quic_data_append(struct quic_data *to, u8 *data, u32 len);
int quic_data_has(struct quic_data *d1, struct quic_data *d2);
int quic_data_dup(struct quic_data *to, u8 *data, u32 len);
