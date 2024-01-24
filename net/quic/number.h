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
	u16	u16;
	u32	u32;
	u64	u64;
	u8	n[8];
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
		n.n[0] &= 0x3f;
		v = ntohs(n.be16);
		break;
	case 4:
		memcpy(&n.be32, p, 4);
		n.n[0] &= 0x3f;
		v = ntohl(n.be32);
		break;
	case 8:
		memcpy(&n.be64, p, 8);
		n.n[0] &= 0x3f;
		v = be64_to_cpu(n.be64);
		break;
	}

	*plen -= len;
	*pp = p + len;
	*val = v;
	return len;
}

static inline u32 quic_get_int(u8 **pp, u32 len)
{
	union quic_num n;
	u8 *p = *pp;
	u32 v = 0;

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
	}
	*pp = p + len;
	return v;
}

static inline u8 *quic_put_var(u8 *p, u64 num)
{
	union quic_num n;

	n.u64 = num;
	if (num < 64) {
		*p++ = n.u8;
		return p;
	}
	if (num < 16384) {
		n.be16 = htons(n.u16);
		memcpy(p, &n.be16, 2);
		*p |= 0x40;
		return p + 2;
	}
	if (num < 1073741824) {
		n.be32 = htonl(n.u32);
		memcpy(p, &n.be32, 4);
		*p |= 0x80;
		return p + 4;
	}
	n.be64 = cpu_to_be64(n.u64);
	memcpy(p, &n.be64, 8);
	*p |= 0xc0;
	return p + 8;
}

static inline u8 *quic_put_int(u8 *p, u64 num, u8 len)
{
	union quic_num n;

	n.u64 = num;

	switch (len) {
	case 1:
		*p++ = n.u8;
		return p;
	case 2:
		n.be16 = htons(n.u16);
		memcpy(p, &n.be16, 2);
		return p + 2;
	case 4:
		n.be32 = htonl(n.u32);
		memcpy(p, &n.be32, 4);
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
