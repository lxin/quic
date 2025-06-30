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

static struct quic_hash_table quic_hash_tables[QUIC_HT_MAX_TABLES];

struct quic_hash_head *quic_sock_hash(u32 hash)
{
	return &quic_hash_tables[QUIC_HT_SOCK].hash[hash];
}

struct quic_hash_head *quic_sock_head(struct net *net, union quic_addr *s, union quic_addr *d)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_SOCK];

	return &ht->hash[quic_ahash(net, s, d) & (ht->size - 1)];
}

struct quic_hash_head *quic_listen_sock_head(struct net *net, u16 port)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_LISTEN_SOCK];

	return &ht->hash[port & (ht->size - 1)];
}

struct quic_hash_head *quic_source_conn_id_head(struct net *net, u8 *scid)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_CONNECTION_ID];

	return &ht->hash[jhash(scid, 4, 0) & (ht->size - 1)];
}

struct quic_hash_head *quic_udp_sock_head(struct net *net, u16 port)
{
	struct quic_hash_table *ht = &quic_hash_tables[QUIC_HT_UDP_SOCK];

	return &ht->hash[port & (ht->size - 1)];
}

struct quic_hash_head *quic_stream_head(struct quic_hash_table *ht, s64 stream_id)
{
	return &ht->hash[stream_id & (ht->size - 1)];
}

void quic_hash_tables_destroy(void)
{
	struct quic_hash_table *ht;
	int table;

	for (table = 0; table < QUIC_HT_MAX_TABLES; table++) {
		ht = &quic_hash_tables[table];
		ht->size = QUIC_HT_SIZE;
		kfree(ht->hash);
	}
}

int quic_hash_tables_init(void)
{
	struct quic_hash_head *head;
	struct quic_hash_table *ht;
	int table, i;

	for (table = 0; table < QUIC_HT_MAX_TABLES; table++) {
		ht = &quic_hash_tables[table];
		ht->size = QUIC_HT_SIZE;
		head = kmalloc_array(ht->size, sizeof(*head), GFP_KERNEL);
		if (!head) {
			quic_hash_tables_destroy();
			return -ENOMEM;
		}
		for (i = 0; i < ht->size; i++) {
			INIT_HLIST_HEAD(&head[i].head);
			if (table == QUIC_HT_UDP_SOCK) {
				mutex_init(&head[i].m_lock);
				continue;
			}
			spin_lock_init(&head[i].s_lock);
		}
		ht->hash = head;
	}

	return 0;
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
void quic_data_to_string(u8 *to, u32 *plen, struct quic_data *from)
{
	struct quic_data d;
	u8 *data = to, *p;
	u64 length;
	u32 len;

	for (p = from->data, len = from->len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&d, p, length);
		data = quic_put_data(data, d.data, d.len);
		if (len - length)
			data = quic_put_int(data, ',', 1);
	}
	*plen = data - to;
}

/* Parse a comma-separated string into a 'quic_data' list format.
 *
 * Each comma-separated token is turned into a length-prefixed element. The
 * first byte of each element stores the length (minus one). Elements are
 * stored in 'to->data', and 'to->len' is updated.
 */
void quic_data_from_string(struct quic_data *to, u8 *from, u32 len)
{
	struct quic_data d;
	u8 *p = to->data;

	to->len = 0;
	while (len) {
		d.data = p++;
		d.len  = 1;
		while (len && *from == ' ') {
			from++;
			len--;
		}
		while (len) {
			if (*from == ',') {
				from++;
				len--;
				break;
			}
			*p++ = *from++;
			len--;
			d.len++;
		}
		*d.data = (u8)(d.len - 1);
		to->len += d.len;
	}
}
