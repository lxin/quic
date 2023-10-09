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
	u8	n8;
	u16	n16;
	u32	n32;
	u64	n64;
	u8	n[8];
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
		memcpy(&n.n16, p, 2);
		n.n[0] &= 0x3f;
		v = ntohs(n.n16);
		break;
	case 4:
		memcpy(&n.n32, p, 4);
		n.n[0] &= 0x3f;
		v = ntohl(n.n32);
		break;
	case 8:
		memcpy(&n.n64, p, 8);
		n.n[0] &= 0x3f;
		v = be64_to_cpu(n.n64);
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
	u32 v;

	n.n32 = 0;
	switch (len) {
	case 1:
		v = *p;
		break;
	case 2:
		memcpy(&n.n16, p, 2);
		v = ntohs(n.n16);
		break;
	case 3:
		memcpy(((u8 *)&n.n32) + 1, p, 3);
		v = ntohl(n.n32);
		break;
	case 4:
		memcpy(&n.n32, p, 4);
		v = ntohl(n.n32);
		break;
	}
	*pp = p + len;
	return v;
}

static inline u8 *quic_put_var(u8 *p, u64 num)
{
	union quic_num n;

	n.n64 = num;
	if (num < 64) {
		*p++ = n.n8;
		return p;
	}
	if (num < 16384) {
		n.n16 = htons(n.n16);
		memcpy(p, &n.n16, 2);
		*p |= 0x40;
		return p + 2;
	}
	if (num < 1073741824) {
		n.n32 = htonl(n.n32);
		memcpy(p, &n.n32, 4);
		*p |= 0x80;
		return p + 4;
	}
	n.n64 = cpu_to_be64(n.n64);
	memcpy(p, &n.n64, 8);
	*p |= 0xc0;
	return p + 8;
}

static inline u8 *quic_put_int(u8 *p, u64 num, u8 len)
{
	union quic_num n;

	n.n64 = num;

	switch (len) {
	case 1:
		*p++ = n.n8;
		return p;
	case 2:
		n.n16 = htons(n.n16);
		memcpy(p, &n.n16, 2);
		return p + 2;
	case 3:
		n.n32 = htonl(n.n32);
		memcpy(p, ((u8 *)&n.n32) + 1, 3);
		return p + 3;
	case 4:
		n.n32 = htonl(n.n32);
		memcpy(p, &n.n32, 4);
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
