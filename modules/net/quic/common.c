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

#include "common.h"

#define QUIC_VARINT_1BYTE_MAX		0x3fULL
#define QUIC_VARINT_2BYTE_MAX		0x3fffULL
#define QUIC_VARINT_4BYTE_MAX		0x3fffffffULL

#define QUIC_VARINT_2BYTE_PREFIX	0x40
#define QUIC_VARINT_4BYTE_PREFIX	0x80
#define QUIC_VARINT_8BYTE_PREFIX	0xc0

#define QUIC_VARINT_LENGTH(p)		BIT((*(p)) >> 6)
#define QUIC_VARINT_VALUE_MASK		0x3f

struct quic_hashinfo {
	struct quic_shash_table		shash; /* Source connection ID hashtable */
	struct quic_shash_table		lhash; /* Listening sock hashtable */
	struct quic_shash_table		chash; /* Connection sock hashtable */
	struct quic_uhash_table		uhash; /* UDP sock hashtable */
};

static struct quic_hashinfo quic_hashinfo;

u32 quic_sock_hash_size(void)
{
	return quic_hashinfo.chash.size;
}

struct quic_shash_head *quic_sock_hash(u32 hash)
{
	return &quic_hashinfo.chash.hash[hash];
}

struct quic_shash_head *quic_sock_head(struct net *net, union quic_addr *s, union quic_addr *d)
{
	struct quic_shash_table *ht = &quic_hashinfo.chash;

	return &ht->hash[quic_ahash(net, s, d) & (ht->size - 1)];
}

u32 quic_listen_sock_hash_size(void)
{
	return quic_hashinfo.lhash.size;
}

struct quic_shash_head *quic_listen_sock_hash(u32 hash)
{
	return &quic_hashinfo.lhash.hash[hash];
}

struct quic_shash_head *quic_listen_sock_head(struct net *net, u16 port)
{
	struct quic_shash_table *ht = &quic_hashinfo.lhash;

	return &ht->hash[port & (ht->size - 1)];
}

struct quic_shash_head *quic_source_conn_id_head(struct net *net, u8 *scid)
{
	struct quic_shash_table *ht = &quic_hashinfo.shash;

	return &ht->hash[jhash(scid, 4, 0) & (ht->size - 1)];
}

struct quic_uhash_head *quic_udp_sock_head(struct net *net, u16 port)
{
	struct quic_uhash_table *ht = &quic_hashinfo.uhash;

	return &ht->hash[port & (ht->size - 1)];
}

struct quic_shash_head *quic_stream_head(struct quic_shash_table *ht, s64 stream_id)
{
	return &ht->hash[stream_id & (ht->size - 1)];
}

static void quic_shash_table_free(struct quic_shash_table *ht)
{
	free_pages((unsigned long)ht->hash, get_order(ht->size * sizeof(struct quic_shash_head)));
	ht->hash = NULL;
}

static void quic_uhash_table_free(struct quic_uhash_table *ht)
{
	free_pages((unsigned long)ht->hash, get_order(ht->size * sizeof(struct quic_uhash_head)));
	ht->hash = NULL;
}

void quic_hash_tables_destroy(void)
{
	quic_shash_table_free(&quic_hashinfo.shash);
	quic_shash_table_free(&quic_hashinfo.lhash);
	quic_shash_table_free(&quic_hashinfo.chash);
	quic_uhash_table_free(&quic_hashinfo.uhash);
}

static int quic_shash_table_init(struct quic_shash_table *ht, u32 max_size, int order)
{
	int i, max_order, size;

	max_order = get_order(max_size * sizeof(struct quic_shash_head));
	order = min(order, max_order);
	/* Try to allocate hash buckets; if fails, retry with smaller order. */
	do {
		ht->hash = (struct quic_shash_head *)
			__get_free_pages(GFP_KERNEL | __GFP_NOWARN, order);
	} while (!ht->hash && --order > 0);

	if (!ht->hash)
		return -ENOMEM;

	/* Calculate actual number of buckets from allocated memory. */
	size = (1UL << order) * PAGE_SIZE / sizeof(struct quic_shash_head);
	/* Round down to power of two (simplifies masking in hash functions). */
	ht->size = rounddown_pow_of_two(size);
	for (i = 0; i < ht->size; i++) {
		rwlock_init(&ht->hash[i].lock);
		INIT_HLIST_HEAD(&ht->hash[i].head);
	}
	return 0;
}

static int quic_uhash_table_init(struct quic_uhash_table *ht, u32 max_size, int order)
{
	int i, max_order, size;

	/* Same sizing logic as in quic_shash_table_init(). */
	max_order = get_order(max_size * sizeof(struct quic_uhash_head));
	order = min(order, max_order);
	do {
		ht->hash = (struct quic_uhash_head *)
			__get_free_pages(GFP_KERNEL | __GFP_NOWARN, order);
	} while (!ht->hash && --order > 0);

	if (!ht->hash)
		return -ENOMEM;

	size = (1UL << order) * PAGE_SIZE / sizeof(struct quic_uhash_head);
	ht->size = rounddown_pow_of_two(size);
	for (i = 0; i < ht->size; i++) {
		mutex_init(&ht->hash[i].lock);
		INIT_HLIST_HEAD(&ht->hash[i].head);
	}
	return 0;
}

int quic_hash_tables_init(void)
{
	unsigned long nr_pages = totalram_pages();
	unsigned long goal;
	int err, order;

	/* Calculate the hashtable size similar to SCTP in sctp_init(). */
	if (nr_pages >= (128 * 1024))
		goal = nr_pages >> (22 - PAGE_SHIFT);
	else
		goal = nr_pages >> (24 - PAGE_SHIFT);
	order = get_order(goal);

	/* Source connection ID table (fast lookup, larger size) */
	err = quic_shash_table_init(&quic_hashinfo.shash, 64 * 1024, order);
	if (err)
		goto err;
	err = quic_shash_table_init(&quic_hashinfo.lhash, 16 * 1024, order);
	if (err)
		goto err;
	err = quic_shash_table_init(&quic_hashinfo.chash, 16 * 1024, order);
	if (err)
		goto err;
	err = quic_uhash_table_init(&quic_hashinfo.uhash, 16 * 1024, order);
	if (err)
		goto err;
	return 0;
err:
	quic_hash_tables_destroy();
	return err;
}

union quic_var {
	u8	u8;
	__be16	be16;
	__be32	be32;
	__be64	be64;
};

/* Returns the number of bytes required to encode a QUIC variable-length integer. */
u8 quic_var_len(u64 n)
{
	if (n <= QUIC_VARINT_1BYTE_MAX)
		return 1;
	if (n <= QUIC_VARINT_2BYTE_MAX)
		return 2;
	if (n <= QUIC_VARINT_4BYTE_MAX)
		return 4;
	return 8;
}

/* Decodes a QUIC variable-length integer from a buffer. */
u8 quic_get_var(u8 **pp, u32 *plen, u64 *val)
{
	union quic_var n = {};
	u8 *p = *pp, len;
	u64 v = 0;

	if (!*plen)
		return 0;

	len = QUIC_VARINT_LENGTH(p);
	if (*plen < len)
		return 0;

	switch (len) {
	case 1:
		v = *p;
		break;
	case 2:
		memcpy(&n.be16, p, 2);
		n.u8 &= QUIC_VARINT_VALUE_MASK;
		v = be16_to_cpu(n.be16);
		break;
	case 4:
		memcpy(&n.be32, p, 4);
		n.u8 &= QUIC_VARINT_VALUE_MASK;
		v = be32_to_cpu(n.be32);
		break;
	case 8:
		memcpy(&n.be64, p, 8);
		n.u8 &= QUIC_VARINT_VALUE_MASK;
		v = be64_to_cpu(n.be64);
		break;
	default:
		return 0;
	}

	*plen -= len;
	*pp = p + len;
	*val = v;
	return len;
}

/* Reads a fixed-length integer from the buffer. */
u32 quic_get_int(u8 **pp, u32 *plen, u64 *val, u32 len)
{
	union quic_var n;
	u8 *p = *pp;
	u64 v = 0;

	if (*plen < len)
		return 0;
	*plen -= len;

	switch (len) {
	case 1:
		v = *p;
		break;
	case 2:
		memcpy(&n.be16, p, 2);
		v = be16_to_cpu(n.be16);
		break;
	case 3:
		n.be32 = 0;
		memcpy(((u8 *)&n.be32) + 1, p, 3);
		v = be32_to_cpu(n.be32);
		break;
	case 4:
		memcpy(&n.be32, p, 4);
		v = be32_to_cpu(n.be32);
		break;
	case 8:
		memcpy(&n.be64, p, 8);
		v = be64_to_cpu(n.be64);
		break;
	default:
		return 0;
	}
	*pp = p + len;
	*val = v;
	return len;
}

u32 quic_get_data(u8 **pp, u32 *plen, u8 *data, u32 len)
{
	if (*plen < len)
		return 0;

	memcpy(data, *pp, len);
	*pp += len;
	*plen -= len;

	return len;
}

/* Encodes a value into the QUIC variable-length integer format. */
u8 *quic_put_var(u8 *p, u64 num)
{
	union quic_var n;

	if (num <= QUIC_VARINT_1BYTE_MAX) {
		*p++ = (u8)(num & 0xff);
		return p;
	}
	if (num <= QUIC_VARINT_2BYTE_MAX) {
		n.be16 = cpu_to_be16((u16)num);
		*((__be16 *)p) = n.be16;
		*p |= QUIC_VARINT_2BYTE_PREFIX;
		return p + 2;
	}
	if (num <= QUIC_VARINT_4BYTE_MAX) {
		n.be32 = cpu_to_be32((u32)num);
		*((__be32 *)p) = n.be32;
		*p |= QUIC_VARINT_4BYTE_PREFIX;
		return p + 4;
	}
	n.be64 = cpu_to_be64(num);
	*((__be64 *)p) = n.be64;
	*p |= QUIC_VARINT_8BYTE_PREFIX;
	return p + 8;
}

/* Writes a fixed-length integer to the buffer in network byte order. */
u8 *quic_put_int(u8 *p, u64 num, u8 len)
{
	union quic_var n;

	switch (len) {
	case 1:
		*p++ = (u8)(num & 0xff);
		return p;
	case 2:
		n.be16 = cpu_to_be16((u16)(num & 0xffff));
		*((__be16 *)p) = n.be16;
		return p + 2;
	case 4:
		n.be32 = cpu_to_be32((u32)num);
		*((__be32 *)p) = n.be32;
		return p + 4;
	default:
		return NULL;
	}
}

/* Encodes a value as a variable-length integer with explicit length. */
u8 *quic_put_varint(u8 *p, u64 num, u8 len)
{
	union quic_var n;

	switch (len) {
	case 1:
		*p++ = (u8)(num & 0xff);
		return p;
	case 2:
		n.be16 = cpu_to_be16((u16)(num & 0xffff));
		*((__be16 *)p) = n.be16;
		*p |= QUIC_VARINT_2BYTE_PREFIX;
		return p + 2;
	case 4:
		n.be32 = cpu_to_be32((u32)num);
		*((__be32 *)p) = n.be32;
		*p |= QUIC_VARINT_4BYTE_PREFIX;
		return p + 4;
	default:
		return NULL;
	}
}

u8 *quic_put_data(u8 *p, u8 *data, u32 len)
{
	if (!len)
		return p;

	memcpy(p, data, len);
	return p + len;
}

/* Writes a transport parameter as two varints: ID and value length, followed by value. */
u8 *quic_put_param(u8 *p, u16 id, u64 value)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, quic_var_len(value));
	return quic_put_var(p, value);
}

/* Reads a QUIC transport parameter value. */
u8 quic_get_param(u64 *pdest, u8 **pp, u32 *plen)
{
	u64 valuelen;

	if (!quic_get_var(pp, plen, &valuelen))
		return 0;

	if (*plen < valuelen)
		return 0;

	if (!quic_get_var(pp, plen, pdest))
		return 0;

	return (u8)valuelen;
}

/* rfc9000#section-a.3: DecodePacketNumber()
 *
 * Reconstructs the full packet number from a truncated one.
 */
s64 quic_get_num(s64 max_pkt_num, s64 pkt_num, u32 n)
{
	s64 expected = max_pkt_num + 1;
	s64 win = BIT_ULL(n * 8);
	s64 hwin = win / 2;
	s64 mask = win - 1;
	s64 cand;

	cand = (expected & ~mask) | pkt_num;
	if (cand <= expected - hwin && cand < (1ULL << 62) - win)
		return cand + win;
	if (cand > expected + hwin && cand >= win)
		return cand - win;
	return cand;
}

int quic_data_dup(struct quic_data *to, u8 *data, u32 len)
{
	if (!len)
		return 0;

	data = kmemdup(data, len, GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	kfree(to->data);
	to->data = data;
	to->len = len;
	return 0;
}

int quic_data_append(struct quic_data *to, u8 *data, u32 len)
{
	u8 *p;

	if (!len)
		return 0;

	p = kzalloc(to->len + len, GFP_ATOMIC);
	if (!p)
		return -ENOMEM;
	p = quic_put_data(p, to->data, to->len);
	p = quic_put_data(p, data, len);

	kfree(to->data);
	to->len = to->len + len;
	to->data = p - to->len;
	return 0;
}

/* Check whether 'd2' is equal to any element inside the list 'd1'.
 *
 * 'd1' is assumed to be a sequence of length-prefixed elements. Each element
 * is compared to 'd2' using 'quic_data_cmp()'.
 *
 * Returns 1 if a match is found, 0 otherwise.
 */
int quic_data_has(struct quic_data *d1, struct quic_data *d2)
{
	struct quic_data d;
	u64 length;
	u32 len;
	u8 *p;

	for (p = d1->data, len = d1->len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&d, p, length);
		if (!quic_data_cmp(&d, d2))
			return 1;
	}
	return 0;
}

/* Check if any element of 'd1' is present in the list 'd2'.
 *
 * Iterates through each element in 'd1', and uses 'quic_data_has()' to check
 * for its presence in 'd2'.
 *
 * Returns 1 if any match is found, 0 otherwise.
 */
int quic_data_match(struct quic_data *d1, struct quic_data *d2)
{
	struct quic_data d;
	u64 length;
	u32 len;
	u8 *p;

	for (p = d1->data, len = d1->len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&d, p, length);
		if (quic_data_has(d2, &d))
			return 1;
	}
	return 0;
}

/* Serialize a list of 'quic_data' elements into a comma-separated string.
 *
 * Each element in 'from' is length-prefixed. This function copies their raw
 * content into the output buffer 'to', inserting commas in between. The
 * resulting string length is written to '*plen'.
 */
int quic_data_to_string(u8 *to, u32 *plen, struct quic_data *from)
{
	u32 remlen = *plen;
	struct quic_data d;
	u8 *data = to, *p;
	u64 length;
	u32 len;

	p = from->data;
	len = from->len;
	while (len) {
		if (!quic_get_int(&p, &len, &length, 1) || len < length)
			return -EINVAL;

		quic_data(&d, p, length);
		if (d.len > remlen)
			return -EOVERFLOW;

		data = quic_put_data(data, d.data, d.len);
		remlen -= d.len;
		p += d.len;
		len -= d.len;
		if (len) {
			if (!remlen)
				return -EOVERFLOW;
			data = quic_put_int(data, ',', 1);
			remlen--;
		}
	}
	*plen = data - to;
	return 0;
}

/* Parse a comma-separated string into a 'quic_data' list format.
 *
 * Each comma-separated token is turned into a length-prefixed element. The
 * first byte of each element stores the length. Elements are stored in
 * 'to->data', and 'to->len' is updated.
 */
int quic_data_from_string(struct quic_data *to, u8 *from, u32 len)
{
	u32 remlen = to->len;
	struct quic_data d;
	u8 *p = to->data;

	to->len = 0;
	while (len) {
		while (len && *from == ' ') {
			from++;
			len--;
		}
		if (!len)
			break;
		if (!remlen)
			return -EOVERFLOW;
		d.data = p++;
		d.len  = 0;
		remlen--;
		while (len) {
			if (*from == ',') {
				from++;
				len--;
				break;
			}
			if (!remlen)
				return -EOVERFLOW;
			*p++ = *from++;
			len--;
			d.len++;
			remlen--;
		}
		if (d.len > U8_MAX)
			return -EINVAL;
		*d.data = (u8)(d.len);
		to->len += d.len + 1;
	}
	return 0;
}
