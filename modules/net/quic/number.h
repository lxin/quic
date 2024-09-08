/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

union quic_num {
	u8	u8;
	__be16	be16;
	__be32	be32;
	__be64	be64;
};

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

static inline u8 quic_get_var(u8 **pp, u32 *plen, u64 *val)
{
	union quic_num n;
	u8 *p = *pp, len;
	u64 v = 0;

	if (!*plen)
		return 0;

	len = (u8)(1u << (*p >> 6));
	if (*plen < len)
		return 0;

	switch (len) {
	case 1:
		v = *p;
		break;
	case 2:
		memcpy(&n.be16, p, 2);
		n.u8 &= 0x3f;
		v = ntohs(n.be16);
		break;
	case 4:
		memcpy(&n.be32, p, 4);
		n.u8 &= 0x3f;
		v = ntohl(n.be32);
		break;
	case 8:
		memcpy(&n.be64, p, 8);
		n.u8 &= 0x3f;
		v = be64_to_cpu(n.be64);
		break;
	}

	*plen -= len;
	*pp = p + len;
	*val = v;
	return len;
}

static inline u8 quic_get_int(u8 **pp, u32 *plen, u64 *val, u32 len)
{
	union quic_num n;
	u8 *p = *pp;
	u64 v = 0;

	if (*plen < len)
		return 0;
	*plen -= len;

	n.be32 = 0;
	switch (len) {
	case 1:
		v = *p;
		break;
	case 2:
		memcpy(&n.be16, p, 2);
		v = ntohs(n.be16);
		break;
	case 3:
		memcpy(((u8 *)&n.be32) + 1, p, 3);
		v = ntohl(n.be32);
		break;
	case 4:
		memcpy(&n.be32, p, 4);
		v = ntohl(n.be32);
		break;
	case 8:
		memcpy(&n.be64, p, 8);
		v = be64_to_cpu(n.be64);
		break;
	}
	*pp = p + len;
	*val = v;
	return len;
}

static inline u8 *quic_put_var(u8 *p, u64 num)
{
	union quic_num n;

	if (num < 64) {
		*p++ = (u8)num;
		return p;
	}
	if (num < 16384) {
		n.be16 = htons((u16)num);
		*((__be16 *)p) = n.be16;
		*p |= 0x40;
		return p + 2;
	}
	if (num < 1073741824) {
		n.be32 = htonl((u32)num);
		*((__be32 *)p) = n.be32;
		*p |= 0x80;
		return p + 4;
	}
	n.be64 = cpu_to_be64(num);
	*((__be64 *)p) = n.be64;
	*p |= 0xc0;
	return p + 8;
}

static inline u8 *quic_put_int(u8 *p, u64 num, u8 len)
{
	union quic_num n;

	switch (len) {
	case 1:
		*p++ = (u8)num;
		return p;
	case 2:
		n.be16 = htons((u16)num);
		*((__be16 *)p) = n.be16;
		return p + 2;
	case 4:
		n.be32 = htonl((u32)num);
		*((__be32 *)p) = n.be32;
		return p + 4;
	default:
		return NULL;
	}
}

static inline u8 *quic_put_data(u8 *p, u8 *data, u32 len)
{
	if (!len)
		return p;

	memcpy(p, data, len);
	return p + len;
}

static inline u8 *quic_put_param(u8 *p, u16 id, u64 value)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, quic_var_len(value));
	return quic_put_var(p, value);
}

static inline int quic_get_param(u64 *pdest, u8 **pp, u32 *plen)
{
	u64 valuelen;

	if (!quic_get_var(pp, plen, &valuelen))
		return -1;

	if (*plen < valuelen)
		return -1;

	if (!quic_get_var(pp, plen, pdest))
		return -1;
	return 0;
}

static inline s64 quic_get_num(s64 max_pkt_num, s64 pkt_num, u32 n)
{
	s64 expected = max_pkt_num + 1;
	s64 win = (s64)1 << (n * 8);
	s64 hwin = win / 2;
	s64 mask = win - 1;
	s64 cand;

	cand = (expected & ~mask) | pkt_num;
	if (cand <= expected - hwin)
		return cand + win;
	if (cand > expected + hwin && cand >= win)
		return cand - win;
	return cand;
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

static inline void quic_data_free(struct quic_data *d)
{
	kfree(d->data);
	d->data = NULL;
	d->len = 0;
}

static inline int quic_data_dup(struct quic_data *to, u8 *data, u32 len)
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

static inline int quic_data_cmp(struct quic_data *d1, struct quic_data *d2)
{
	return d1->len != d2->len || memcmp(d1->data, d2->data, d1->len);
}

static inline int quic_data_has(struct quic_data *d1, struct quic_data *d2)
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

static inline int quic_data_match(struct quic_data *d1, struct quic_data *d2)
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

static inline void quic_data_to_string(u8 *to, u32 *plen, struct quic_data *from)
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

static inline void quic_data_from_string(struct quic_data *to, u8 *from, u32 len)
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
		*d.data = d.len - 1;
		to->len += d.len;
	}
}
