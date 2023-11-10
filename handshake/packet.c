// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is the userspace handshake part for the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "connection.h"

#define QUIC_MIN_LONG_HEADERLEN (1 + 4 + 1 + 1 + 1 + 1)
#define QUIC_PKT_LENGTHLEN 4
#define QUIC_HEADER_FORM_BIT 0x80
#define QUIC_FIXED_BIT_MASK 0x40
#define QUIC_LONG_TYPE_MASK 0x30

#define QUIC_PROTO_VER_V1 ((uint32_t)0x00000001u)

#define QUIC_MAX_STREAMS (1LL << 60)

#define QUIC_FRAME_CRYPTO	0x06
#define QUIC_FRAME_ACK		0x02
#define QUIC_FRAME_PING		0x01
#define QUIC_FRAME_PADDING	0x00
#define QUIC_MAX_CIDLEN		20

#define test_bit(_n,_p)		(_n & (1u << _p))
#define set_bit(_n, _p)		(_n |= (1u << _p))

enum quic_transport_param_id {
	QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID = 0x0000,
	QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT = 0x0001,
	QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 0x0002,
	QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE = 0x0003,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA = 0x0004,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x0005,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x0007,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI = 0x0008,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI = 0x0009,
	QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT = 0x000a,
	QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY = 0x000b,
	QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION = 0x000c,
	QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS = 0x000d,
	QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x000e,
	QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x000f,
	QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID = 0x0010,
	QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE = 0x0020,
	QUIC_TRANSPORT_PARAM_GREASE_QUIC_BIT = 0x2ab2,
	QUIC_TRANSPORT_PARAM_VERSION_INFORMATION = 0x11,
};

enum {
	QUIC_PKT_TYPE_INITIAL,
	QUIC_PKT_TYPE_0RTT,
	QUIC_PKT_TYPE_HANDSHAKE,
	QUIC_PKT_TYPE_RETRY,
	QUIC_PKT_TYPE_VERSION,
	QUIC_PKT_TYPE_1RTT,
};

static uint8_t *put_uint64be(uint8_t *p, uint64_t n)
{
	n = htobe64(n);
	memcpy(p, &n, sizeof(n));
	return p + sizeof(n);
}

static uint8_t *put_uint32be(uint8_t *p, uint32_t n)
{
	n = htonl(n);
	memcpy(p, &n, sizeof(n));
	return p + sizeof(n);
}

static uint8_t *put_uint16be(uint8_t *p, uint16_t n)
{
	n = htons(n);
	memcpy(p, &n, sizeof(n));
	return p + sizeof(n);
}

static uint8_t *put_uvarint30(uint8_t *p, uint32_t n)
{
	uint8_t *rv;

	rv = put_uint32be(p, n);
	*p |= 0x80;

	return rv;
}

static uint8_t *put_uvarint(uint8_t *p, uint64_t n) {
	uint8_t *rv;
	if (n < 64) {
		*p++ = (uint8_t)n;
		return p;
	}
	if (n < 16384) {
		rv = put_uint16be(p, (uint16_t)n);
		*p |= 0x40;
		return rv;
	}
	if (n < 1073741824) {
		rv = put_uint32be(p, (uint32_t)n);
		*p |= 0x80;
		return rv;
	}
	rv = put_uint64be(p, n);
	*p |= 0xc0;
	return rv;
}

static uint32_t put_uvarintlen(uint64_t n)
{
	if (n < 64)
		return 1;
	if (n < 16384)
		return 2;
	if (n < 1073741824)
		return 4;
	return 8;
}

static uint8_t *put_data(void *dest, const void *src, uint32_t n)
{
	memcpy(dest, src, n);
	return (uint8_t *)dest + n;
}

static uint32_t varint_paramlen(enum quic_transport_param_id id, uint64_t param)
{
	uint32_t valuelen = put_uvarintlen(param);
	return put_uvarintlen(id) + put_uvarintlen(valuelen) + valuelen;
}

static uint32_t cid_paramlen(enum quic_transport_param_id id, const struct quic_connection_id *conn_id)
{
	return put_uvarintlen(id) + put_uvarintlen(conn_id->len) + conn_id->len;
}

static uint8_t *write_cid_param(uint8_t *p, enum quic_transport_param_id id,
				const struct quic_connection_id *conn_id)
{
	p = put_uvarint(p, id);
	p = put_uvarint(p, conn_id->len);
	memcpy(p, conn_id->data, conn_id->len);
	p += conn_id->len;
	return p;
}

static uint8_t *write_varint_param(uint8_t *p, enum quic_transport_param_id id,
				   uint64_t value)
{
	p = put_uvarint(p, id);
	p = put_uvarint(p, put_uvarintlen(value));
	return put_uvarint(p, value);
}

static uint32_t get_uvarintlen(const uint8_t *p)
{
	return (uint32_t)(1u << (*p >> 6));
}

const uint8_t *get_uvarint(uint64_t *dest, const uint8_t *p)
{
	uint32_t len = (uint32_t)(1u << (*p >> 6));
	union {
		uint8_t n8;
		uint16_t n16;
		uint32_t n32;
		uint64_t n64;
	} n;

	switch (len) {
	case 1:
		*dest = *p;
		break;
	case 2:
		memcpy(&n, p, 2);
		n.n8 &= 0x3f;
		*dest = ntohs(n.n16);
		break;
	case 4:
		memcpy(&n, p, 4);
		n.n8 &= 0x3f;
		*dest = ntohl(n.n32);
		break;
	case 8:
		memcpy(&n, p, 8);
		n.n8 &= 0x3f;
		*dest = be64toh(n.n64);
		break;
	}
	return p + len;
}

static const uint8_t *get_uint16(uint16_t *dest, const uint8_t *p)
{
	uint16_t n;
	memcpy(&n, p, sizeof(n));
	*dest = ntohs(n);
	return p + sizeof(n);
}

static const uint8_t *get_uint24(uint32_t *dest, const uint8_t *p)
{
	uint32_t n = 0;
	memcpy(((uint8_t *)&n) + 1, p, 3);
	*dest = ntohl(n);
	return p + 3;
}

static const uint8_t *get_uint32(uint32_t *dest, const uint8_t *p)
{
	uint32_t n;
	memcpy(&n, p, sizeof(n));
	*dest = ntohl(n);
	return p + sizeof(n);
}

int64_t quic_packet_get_num(const uint8_t *p, size_t pkt_numlen)
{
	uint32_t l;
	uint16_t s;

	switch (pkt_numlen) {
	case 1:
		return *p;
	case 2:
		get_uint16(&s, p);
		return (int64_t)s;
	case 3:
		get_uint24(&l, p);
		return (int64_t)l;
	case 4:
		get_uint32(&l, p);
		return (int64_t)l;
	default:
		return 0;
	}
}

static int decode_varint(uint64_t *pdest, const uint8_t **pp, const uint8_t *end)
{
	const uint8_t *p = *pp;
	uint32_t len;

	if (p == end)
		return -1;

	len = get_uvarintlen(p);
	if ((uint64_t)(end - p) < len)
		return -1;

	*pp = get_uvarint(pdest, p);
	return 0;
}

static int decode_varint_param(uint64_t *pdest, const uint8_t **pp, const uint8_t *end)
{
	const uint8_t *p = *pp;
	uint64_t valuelen;

	if (decode_varint(&valuelen, &p, end) != 0)
		return -1;

	if (p == end)
		return -1;

	if ((uint64_t)(end - p) < valuelen)
		return -1;

	if (get_uvarintlen(p) != valuelen)
		return -1;

	*pp = get_uvarint(pdest, p);
	return 0;
}

int quic_packet_decode_transport_params(struct quic_conn *conn, const uint8_t *data, uint32_t datalen)
{
	struct quic_transport_param *params = &conn->context.remote;
	const uint8_t *p, *end, *lend;
	uint64_t param_type, valuelen;

	params->max_udp_payload_size = 65527;
	params->ack_delay_exponent = 3;
	params->max_ack_delay = 25000;
	params->active_connection_id_limit = 2;

	p = data;
	end = data + datalen;
	for (; (uint32_t)(end - p) >= 2;) {
		if (decode_varint(&param_type, &p, end) != 0)
			return -1;

		switch (param_type) {
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			if (decode_varint_param(&params->initial_max_stream_data_bidi_local, &p, end))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			if (decode_varint_param(&params->initial_max_stream_data_bidi_remote, &p, end))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
			if (decode_varint_param(&params->initial_max_stream_data_uni, &p, end))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
			if (decode_varint_param(&params->initial_max_data, &p, end))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
			if (decode_varint_param(&params->initial_max_streams_bidi, &p, end))
				return -1;
			if (params->initial_max_streams_bidi > QUIC_MAX_STREAMS)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
			if (decode_varint_param(&params->initial_max_streams_uni, &p, end))
				return -1;
			if (params->initial_max_streams_uni > QUIC_MAX_STREAMS)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT:
			if (decode_varint_param(&params->max_idle_timeout, &p, end))
				return -1;
			params->max_idle_timeout *= 1000;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE:
			if (decode_varint_param(&params->max_udp_payload_size, &p, end))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
			if (decode_varint_param(&params->ack_delay_exponent, &p, end))
				return -1;
			if (params->ack_delay_exponent > 20)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION:
			if (decode_varint(&valuelen, &p, end))
				return -1;
			if (valuelen)
				return -1;
			params->disable_active_migration = 1;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY:
			if (decode_varint_param(&params->max_ack_delay, &p, end))
				return -1;
			if (params->max_ack_delay >= 16384)
				return -1;
			params->max_ack_delay *= 1000;
			break;
		case QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT:
			if (decode_varint_param(&params->active_connection_id_limit, &p, end))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE:
			if (decode_varint_param(&params->max_datagram_frame_size, &p, end))
				return -1;
			break;
		default:
			/* Ignore unknown parameter */
			if (decode_varint(&valuelen, &p, end))
				return -1;
			if ((uint32_t)(end - p) < valuelen)
				return -1;
			p += valuelen;
			break;
		}
	}

	if (end - p != 0)
		return -1;
	return 0;
}

int quic_packet_encode_transport_params(struct quic_conn *conn, uint8_t *dest, uint32_t destlen)
{
	struct quic_transport_param *params = &conn->context.local;
	uint8_t *p = dest;
	uint32_t len = 0;

	if (params->initial_max_stream_data_bidi_local) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
				       params->initial_max_stream_data_bidi_local);
	}
	if (params->initial_max_stream_data_bidi_remote) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
				       params->initial_max_stream_data_bidi_remote);
	}
	if (params->initial_max_stream_data_uni) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
				       params->initial_max_stream_data_uni);
	}
	if (params->initial_max_data) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA,
				       params->initial_max_data);
	}
	if (params->initial_max_streams_bidi) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
				       params->initial_max_streams_bidi);
	}
	if (params->initial_max_streams_uni) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
				       params->initial_max_streams_uni);
	}
	if (params->max_udp_payload_size != 65527) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE,
				       params->max_udp_payload_size);
	}
	if (params->ack_delay_exponent != 3) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
				       params->ack_delay_exponent);
	}
	if (params->disable_active_migration) {
		len += put_uvarintlen(QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) +
		       put_uvarintlen(0);
	}
	if (params->max_ack_delay != 25000) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY,
				       params->max_ack_delay / 1000);
	}
	if (params->max_idle_timeout) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
				       params->max_idle_timeout / 1000);
	}
	if (params->active_connection_id_limit && params->active_connection_id_limit != 2) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
				       params->active_connection_id_limit);
	}
	if (params->max_datagram_frame_size) {
		len += varint_paramlen(QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE,
				       params->max_datagram_frame_size);
	}
	len += cid_paramlen(QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID, &conn->context.source);
	if (conn->context.is_serv) {
		len += cid_paramlen(QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID, &conn->orig);
		p = write_cid_param(p, QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID, &conn->orig);
	}
	p = write_cid_param(p, QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID, &conn->context.source);
	if (params->initial_max_stream_data_bidi_local) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
				       params->initial_max_stream_data_bidi_local);
	}
	if (params->initial_max_stream_data_bidi_remote) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
				       params->initial_max_stream_data_bidi_remote);
	}
	if (params->initial_max_stream_data_uni) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
				       params->initial_max_stream_data_uni);
	}
	if (params->initial_max_data) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA,
				       params->initial_max_data);
	}
	if (params->initial_max_streams_bidi) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
				       params->initial_max_streams_bidi);
	}
	if (params->initial_max_streams_uni) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
				       params->initial_max_streams_uni);
	}
	if (params->max_udp_payload_size != 65527) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE,
				       params->max_udp_payload_size);
	}
	if (params->ack_delay_exponent != 3) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
				       params->ack_delay_exponent);
	}
	if (params->disable_active_migration) {
		p = put_uvarint(p, QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION);
		p = put_uvarint(p, 0);
	}
	if (params->max_ack_delay != 25000) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY,
				       params->max_ack_delay / 1000);
	}
	if (params->max_idle_timeout) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
				       params->max_idle_timeout / 1000);
	}
	if (params->active_connection_id_limit && params->active_connection_id_limit != 2) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
				       params->active_connection_id_limit);
	}
	if (params->max_datagram_frame_size) {
		p = write_varint_param(p, QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE,
				       params->max_datagram_frame_size);
	}

	if (p - dest != len)
		return -1;
	return len;
}

static void encode_header(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	uint32_t len = QUIC_MIN_LONG_HEADERLEN + conn->context.dest.len + conn->context.source.len - 2;
	uint32_t pkt_numlen = 1, version = QUIC_PROTO_VER_V1;
	uint8_t *p, *pkt;

	if (hd->type == QUIC_PKT_TYPE_INITIAL) {
		len += put_uvarintlen(conn->token.datalen) + conn->token.datalen;
		hd->pktns = &conn->in_pktns;
		hd->key = &conn->in_key[1];
		len += QUIC_PKT_LENGTHLEN +  pkt_numlen;
	} else if (hd->type == QUIC_PKT_TYPE_HANDSHAKE) {
		hd->pktns = &conn->hs_pktns;
		hd->key = &conn->hs_key[1];
		len += QUIC_PKT_LENGTHLEN +  pkt_numlen;
	} else if (hd->type == QUIC_PKT_TYPE_VERSION) {
		version = 0;
	}

	hd->offset = packet->buflen;
	pkt = &packet->buf[hd->offset];
	p = pkt;
	*p = (uint8_t)(QUIC_HEADER_FORM_BIT | (hd->type << 4) | (uint8_t)(pkt_numlen - 1));
	*p |= QUIC_FIXED_BIT_MASK;
	++p;

	p = put_uint32be(p, version);

	*p++ = (uint8_t)conn->context.dest.len;
	if (conn->context.dest.len)
		p = put_data(p, conn->context.dest.data, conn->context.dest.len);
	*p++ = (uint8_t)conn->context.source.len;
	if (conn->context.source.len)
		p = put_data(p, conn->context.source.data, conn->context.source.len);
	if (hd->type == QUIC_PKT_TYPE_INITIAL) {
		p = put_uvarint(p, conn->token.datalen);
		if (conn->token.datalen)
			p = put_data(p, conn->token.data, conn->token.datalen);
	}
	if (hd->type == QUIC_PKT_TYPE_VERSION) {
		packet->buflen += len;
		hd->hdlen = len;
		return;
	}

	hd->number = hd->pktns->send_number++;
	hd->len_offset = p - pkt;
	p = put_uvarint30(p, hd->length);
	hd->num_offset = p - pkt;
	*p++ = (uint8_t)hd->number;
	hd->numlen = 1;
	hd->length = 1;

	hd->hdlen = hd->num_offset + hd->numlen;
	packet->buflen += len;
	print_debug("[ %s: %d %d %d\n", __func__, hd->type, hd->number, len);
}

struct quic_ack_gap {
	uint32_t end;
	uint32_t start;
};

static void encode_frame_ack(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	uint32_t largest_ack, range = 0, n, m = 0;
	uint8_t *p, *pkt, i = 0, num_gabs, flag;
	struct quic_ack_gap gabs[8] = {};

	if (!hd->pktns->ack_needed)
		return;

	largest_ack = hd->pktns->recv_number;
	for (n = 0; n <= largest_ack - hd->pktns->number_base; n++) {
		flag = test_bit(hd->pktns->number_map, n);
		if (!m) {
			if (flag)
				m = n + 1; /* start from the 1st set one */
			continue;
		}
		if (!flag) {
			if (!gabs[i].start)
				gabs[i].start = n + 1;
			continue;
		}
		if (gabs[i].start)
			gabs[i++].end = n;
	}
	num_gabs = i;
	range = largest_ack - hd->pktns->number_base;
	if (num_gabs)
		range -= gabs[num_gabs - 1].end;

	pkt = &packet->buf[packet->buflen];
	p = pkt;

	p = put_uvarint(p, QUIC_FRAME_ACK);
	p = put_uvarint(p, largest_ack);
	p = put_uvarint(p, 0); /* ACK Delay */
	p = put_uvarint(p, num_gabs); /* ACK Range Count */
	p = put_uvarint(p, range); /* First ACK Range */

	if (num_gabs) {
		for (i = num_gabs - 1; i > 0; i--) {
			p = put_uvarint(p, gabs[i].end - gabs[i].start); /* Gap */
			p = put_uvarint(p, gabs[i].start - gabs[i - 1].end - 2); /* ACK Range Length */
		}
		p = put_uvarint(p, gabs[0].end - gabs[0].start); /* Gap */
		p = put_uvarint(p, gabs[0].start - 2); /* ACK Range Length */
	}
	hd->pktns->ack_needed = 0;

	n = (p - pkt);
	hd->length += n;
	packet->buflen += n;
	print_debug("  %s: %d %d %d largest %d range %d base %d ngrabs %d map %x\n", __func__,
		    hd->type, hd->number, n, largest_ack, range, hd->pktns->number_base, num_gabs,
		    hd->pktns->number_map);
}

static uint32_t crypto_frame_len(struct quic_frame *frame)
{
	uint32_t datalen = frame->data.buflen;

	return 1 + put_uvarintlen(frame->offset) + put_uvarintlen(datalen) + datalen;
}

static void encode_frame_crypto(struct quic_conn *conn, struct quic_buf *packet,
				    struct quic_pkthd *hd, struct quic_frame *frame)
{
	uint32_t datalen = frame->data.buflen;
	size_t len = crypto_frame_len(frame);
	uint8_t *p;

	p = &packet->buf[packet->buflen];
	*p++ = QUIC_FRAME_CRYPTO;

	p = put_uvarint(p, frame->offset);
	p = put_uvarint(p, datalen);
	p = put_data(p, frame->data.buf, datalen);

	frame->number = hd->number;
	hd->length += len;
	packet->buflen += len;
	print_debug("  %s: %d %d %d\n", __func__, hd->type, hd->number, len);
}

static void encode_final(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	uint32_t pktlen = hd->length + hd->num_offset;
	uint8_t *pkt = &packet->buf[hd->offset];
	uint32_t paddinglen;

	if (hd->type == QUIC_PKT_TYPE_VERSION) {
		put_uint32be(pkt + hd->hdlen, QUIC_PROTO_VER_V1);
		packet->buflen += 4;
		conn->version = 0;
		return;
	}
	if (hd->type == QUIC_PKT_TYPE_INITIAL && !conn->context.is_serv && pktlen < 1184) {
		paddinglen = 1184 - pktlen;
		memset(pkt + pktlen, 0, paddinglen);

		hd->length += paddinglen;
		packet->buflen += paddinglen;
	}

	put_uvarint30(pkt + hd->len_offset, (uint16_t)(hd->length + 16));
	if (quic_crypto_encrypt(conn, packet, hd))
		return;
	print_debug("] %s: %d %d %d hdlen %d numlen %d\n", __func__,
		    hd->type, hd->number, hd->length, hd->hdlen, hd->numlen);
}

static int decode_header(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	const uint8_t *pkt = &packet->buf[hd->offset], *p, *token;
	uint32_t version, ntokenlen = 0, tokenlen = 0;
	uint32_t buflen, len, dcil, scil, n, type;
	uint64_t vi;
	int ret;

	hd->pktns = NULL;
	if (!(pkt[0] & QUIC_HEADER_FORM_BIT)) {
		hd->type = QUIC_PKT_TYPE_1RTT;
		return 0;
	}
	buflen = packet->buflen - hd->offset;
	if (buflen < 5)
		return -EINVAL;
	get_uint32(&version, &pkt[1]);
	if (!version)
		return -EINVAL;
	hd->type = ((pkt[0] & QUIC_LONG_TYPE_MASK) >> 4);
	if (hd->type == QUIC_PKT_TYPE_INITIAL) {
		len = QUIC_MIN_LONG_HEADERLEN + 1 - 1;
		hd->pktns = &conn->in_pktns;
		hd->key = &conn->in_key[0];
	} else if (hd->type == QUIC_PKT_TYPE_HANDSHAKE) {
		len = QUIC_MIN_LONG_HEADERLEN - 1;
		hd->pktns = &conn->hs_pktns;
		hd->key = &conn->hs_key[0];
	} else if (hd->type == QUIC_PKT_TYPE_RETRY){
		len = 5 + 2;
	} else if (version != QUIC_PROTO_VER_V1) {
		hd->type = QUIC_PKT_TYPE_VERSION;
		return 0;
	} else {
		return -EINVAL;
	}
	if (buflen < len)
		return -EINVAL;

	p = &pkt[5];
	dcil = *p;
	if (dcil > QUIC_MAX_CIDLEN)
		return -EINVAL;
	len += dcil;
	if (buflen < len)
		return -EINVAL;

	p += 1 + dcil;
	scil = *p;
	if (scil > QUIC_MAX_CIDLEN)
		return -EINVAL;
	len += scil;
	if (buflen < len)
		return -EINVAL;
	p += 1 + scil;

	if (hd->type == QUIC_PKT_TYPE_INITIAL) {
		ntokenlen = get_uvarintlen(p);
		len += ntokenlen - 1;
		if (buflen < len)
			return -EINVAL;
		p = get_uvarint(&vi, p);
		if (buflen - len < vi)
			return -EINVAL;
		tokenlen = (uint32_t)vi;
		len += tokenlen;
		if (tokenlen)
			token = p;
		p += tokenlen;
	}

	if (hd->type != QUIC_PKT_TYPE_RETRY) {
		n = get_uvarintlen(p);
		len += n - 1;
		if (buflen < len)
			return -EINVAL;
	}

	p = &pkt[6];
	memcpy(hd->dcid.data, p, dcil);
	hd->dcid.datalen = dcil;
	p += dcil + 1;
	memcpy(hd->scid.data, p, scil);
	hd->scid.datalen = scil;
	p += scil;

	memcpy(hd->token.data, token, tokenlen);
	hd->token.datalen = tokenlen;
	p += ntokenlen + tokenlen;
	if (hd->type == QUIC_PKT_TYPE_RETRY)
		return 0;

	hd->len_offset = p - pkt;
	p = get_uvarint(&vi, p);
	hd->length = (uint32_t)vi;
	hd->num_offset = p - pkt;
	if (buflen < len + hd->length)
		return -EINVAL;

	conn->context.dest.len = hd->scid.datalen;
	memcpy(conn->context.dest.data, hd->scid.data, hd->scid.datalen);
	if (conn->context.is_serv && !conn->orig.len) {
		conn->orig.len = hd->dcid.datalen;
		memcpy(conn->orig.data, hd->dcid.data, hd->dcid.datalen);
		quic_crypto_derive_initial_keys(conn, hd->dcid.data, hd->dcid.datalen);
	}

	ret = quic_crypto_decrypt(conn, packet, hd);
	if (ret)
		return ret;
	if (hd->number < hd->pktns->number_base ||
	    hd->number > hd->pktns->number_base + 31)
		return -EINVAL;
	hd->fr_offset = 0;
	print_debug("{ %s: %d %d %d hdlen %d numlen %d\n", __func__,
		    hd->type, hd->number, hd->length, hd->hdlen, hd->numlen);
	return 0;
}

static uint8_t decode_frame_type(struct quic_conn *conn, struct quic_buf *packet,
				 struct quic_pkthd *hd)
{
	return packet->buf[hd->offset + hd->hdlen + hd->fr_offset];
}

static void check_sent_list(struct quic_conn *conn, struct quic_pkthd *hd,
			    uint64_t smallest_ack, uint64_t largest_ack)
{
	struct quic_frame *frame = hd->pktns->sent_list, *last = NULL;

	while (frame) {
		if (frame->number < smallest_ack ||
		    frame->number > largest_ack) {
			last = frame;
			frame = frame->next;
			continue;
		}
		if (!last) {
			hd->pktns->sent_list = frame->next;
			free(frame);
			frame = hd->pktns->sent_list;
			continue;
		}
		last->next = frame->next;
		free(frame);
		frame = last->next;
	}
}

static int decode_frame_ack(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	uint64_t vi, smallest_ack, largest_ack, ack_delay, first_ack_range, gap, range;
	const uint8_t *p, *pkt = &packet->buf[hd->offset + hd->hdlen + hd->fr_offset];
	uint32_t payloadlen = hd->length - hd->numlen - hd->fr_offset;
	uint32_t len = 5, n, nrangecnt, rangecnt, max_rangecnt, i, j;
	uint8_t type = *pkt;

	if (payloadlen < len)
		return -EINVAL;
	/* Largest Acknowledged */
	p = pkt + 1;
	n = get_uvarintlen(p);
	len += n - 1;
	if (payloadlen < len)
		return -EINVAL;
	/* ACK Delay */
	p += n;
	n = get_uvarintlen(p);
	len += n - 1;
	if (payloadlen < len)
		return -EINVAL;
	/* ACK Range Count */
	p += n;
	nrangecnt = get_uvarintlen(p);
	len += nrangecnt - 1;
	if (payloadlen < len)
		return -EINVAL;

	p = get_uvarint(&vi, p);
	if (vi > SIZE_MAX / (1 + 1) || payloadlen - len < vi * (1 + 1))
		return -EINVAL;
	rangecnt = (size_t)vi;
	len += rangecnt * (1 + 1);

	/* First ACK Range */
	n = get_uvarintlen(p);
	len += n - 1;
	if (payloadlen < len)
		return -EINVAL;
	p += n;
	for (i = 0; i < rangecnt; ++i) {
		/* Gap, and Additional ACK Range */
		for (j = 0; j < 2; ++j) {
			n = get_uvarintlen(p);
			len += n - 1;
			if (payloadlen < len)
				return -EINVAL;
			p += n;
		}
	}
	max_rangecnt = rangecnt;
	if (rangecnt > 32)
		max_rangecnt = 32;

	p = pkt + 1;
	p = get_uvarint(&largest_ack, p);
	p = get_uvarint(&ack_delay, p);
	p += nrangecnt;
	p = get_uvarint(&first_ack_range, p);
	smallest_ack = largest_ack - first_ack_range;
	print_debug("  %s: %d %d %d smallest %d largest %d\n", __func__,
		    hd->type, hd->number, hd->length, smallest_ack, largest_ack);
	check_sent_list(conn, hd, smallest_ack, largest_ack);

	for (i = 0; i < max_rangecnt; ++i) {
		p = get_uvarint(&gap, p);
		p = get_uvarint(&range, p);
		largest_ack = smallest_ack - gap - 2;
		smallest_ack = largest_ack - range;
		print_debug("  %s: %d %d %d smallest %d largest %d\n", __func__,
			    hd->type, hd->number, hd->length, smallest_ack, largest_ack);
		check_sent_list(conn, hd, smallest_ack, largest_ack);
	}

	for (i = max_rangecnt; i < rangecnt; ++i) {
		p += get_uvarintlen(p);
		p += get_uvarintlen(p);
	}
	hd->fr_offset += (p - pkt);
	return 0;
}

static int check_recv_list(struct quic_conn *conn, struct quic_pkthd *hd, const uint8_t *p,
			   uint32_t datalen, uint64_t offset)
{
	uint8_t level = GNUTLS_ENCRYPTION_LEVEL_INITIAL;
	struct quic_frame *new, *frame, *last = NULL;
	int ret;

	if (hd->type == QUIC_PKT_TYPE_HANDSHAKE)
		level = GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE;

	if (hd->pktns->recv_offset == offset) {
		ret = quic_crypto_read_write_crypto_data(conn, level, p, datalen);
		if (ret)
			return ret;
		hd->pktns->recv_offset += datalen;

		for (frame = hd->pktns->recv_list; frame; frame = frame->next) {
			if (frame->offset != hd->pktns->recv_offset)
				break;
			ret = quic_crypto_read_write_crypto_data(conn, level, frame->data.buf,
								 frame->data.buflen);
			if (ret)
				return ret;
			hd->pktns->recv_offset += frame->data.buflen;
			if (!last) {
				hd->pktns->recv_list = frame->next;
				free(frame);
				continue;
			}
			last->next = frame->next;
			free(frame);
		}
		return 0;
	}

	new = malloc(sizeof(*new));
	if (!new)
		return -ENOMEM;
	new->offset = offset;
	new->data.buflen = datalen;
	memcpy(new->data.buf, p, datalen);
	for (frame = hd->pktns->recv_list; frame; frame = frame->next) {
		if (new->offset < frame->offset) {
			new->next = frame;
			if (!last) {
				hd->pktns->recv_list = new;
				break;
			}
			last->next = new;
			break;
		}
		last = frame;
	}
	return 0;
}

static int decode_frame_crypto(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	const uint8_t *p, *pkt = &packet->buf[hd->offset + hd->hdlen + hd->fr_offset];
	uint32_t payloadlen = hd->length - hd->numlen - hd->fr_offset;
	uint32_t n, datalen, ndatalen, len = 3;
	uint64_t vi, offset;
	int ret;

	if (payloadlen < len)
		return -EINVAL;

	p = pkt + 1;
	n = get_uvarintlen(p);
	len += n - 1;
	if (payloadlen < len)
		return -EINVAL;

	p += n;
	ndatalen = get_uvarintlen(p);
	len += ndatalen - 1;
	if (payloadlen < len)
		return -EINVAL;
	p = get_uvarint(&vi, p);
	if (payloadlen - len < vi)
		return -EINVAL;
	datalen = (size_t)vi;
	len += datalen;

	p = pkt + 1;
	p = get_uvarint(&offset, p);
	p += ndatalen;

	ret = check_recv_list(conn, hd, p, datalen, offset);
	if (ret)
		return ret;
	print_debug("  %s: %d %d %d datalen %d offset %d\n", __func__,
		    hd->type, hd->number, hd->length, datalen, offset);

	p += datalen;
	hd->fr_offset += (p - pkt);
	hd->pktns->ack_needed = 1;
	return 0;
}

static int decode_final(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	if (hd->type == QUIC_PKT_TYPE_VERSION) {
		conn->version = 1;
		hd->offset = packet->buflen;
		return 0;
	}
	if (hd->type == QUIC_PKT_TYPE_RETRY) {
		conn->token = hd->token;
		hd->offset = packet->buflen;
		return 0;
	}
	if (hd->type == QUIC_PKT_TYPE_1RTT) {
		if (conn->state == QUIC_CONN_HANDSHAKE_STATE_COMPLETED &&
		    !conn->hs_pktns.send_list) {
			conn->state = QUIC_CONN_HANDSHAKE_STATE_CONFIRMED;
			conn->ctxdata.buflen = packet->buflen - hd->offset;
			memcpy(conn->ctxdata.buf, packet->buf + hd->offset, conn->ctxdata.buflen);
			print_debug("* %s: confirmed %d\n", __func__, conn->ctxdata.buflen);
		}
		hd->offset = packet->buflen;
		return 0; /* skip 1RTT pkt */
	}
	hd->offset += hd->length + hd->num_offset + 16;
	set_bit(hd->pktns->number_map, hd->number - hd->pktns->number_base);
	if (hd->number > hd->pktns->recv_number) {
		hd->pktns->recv_number = hd->number;
		if (hd->number > hd->pktns->number_base + 23) {
			hd->pktns->number_map >> 16;
			hd->pktns->number_base -= 16;
		}
	}
	print_debug("} %s: %d %d %d map %x\n", __func__,
		    hd->type, hd->number, hd->length, hd->pktns->number_map);
	return 0;
}

static int encode_packet(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd, uint8_t type)
{
	struct quic_frame *frame;
	int ret = 0;

	hd->type = type;
	encode_header(conn, packet, hd);
	if (type == QUIC_PKT_TYPE_VERSION) {
		ret = 1;
		goto out;
	}
	encode_frame_ack(conn, packet, hd);
	frame = hd->pktns->send_list;
	while (frame) {
		if (packet->buflen + crypto_frame_len(frame) > MAX_BUFLEN - 16) {
			ret = 1;
			break;
		}
		encode_frame_crypto(conn, packet, hd, frame);

		hd->pktns->send_list = frame->next;
		if (!hd->pktns->sent_list)
			hd->pktns->sent_list = frame;
		else
			hd->pktns->sent_last->next = frame;
		hd->pktns->sent_last = frame;
		frame->next = NULL;
		frame = hd->pktns->send_list;
	}
out:
	encode_final(conn, packet, hd);
	return ret;
}

static int decode_packet(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	int type, ret = 0;

	ret = decode_header(conn, packet, hd);
	if (ret)
		return ret;
	if (!hd->pktns)
		return decode_final(conn, packet, hd);
	do {
		type = decode_frame_type(conn, packet, hd);
		switch (type) {
		case QUIC_FRAME_ACK:
			ret = decode_frame_ack(conn, packet, hd);
			break;
		case QUIC_FRAME_CRYPTO:
			ret = decode_frame_crypto(conn, packet, hd);
			break;
		case QUIC_FRAME_PING:
			hd->fr_offset += 1;
			hd->pktns->ack_needed = 1;
			break;
		case QUIC_FRAME_PADDING:
			hd->fr_offset = hd->length - hd->numlen;
			break;
		default:
			ret = -EINVAL;
			break;
		}
		print_debug("  %s: %d %d %d\n", __func__, hd->type, type, ret);
		if (ret < 0)
			return ret;
	} while (hd->fr_offset < hd->length - hd->numlen);
	return decode_final(conn, packet, hd);
}

static void quic_packet_purge_list(struct quic_frame *list)
{
	struct quic_frame *frame = list;

	while (frame) {
		list = frame->next;
		free(frame);
		frame = list;
	}
}

void quic_packet_purge_lists(struct quic_conn *conn)
{
	quic_packet_purge_list(conn->in_pktns.send_list);
	quic_packet_purge_list(conn->in_pktns.sent_list);
	quic_packet_purge_list(conn->in_pktns.recv_list);

	quic_packet_purge_list(conn->hs_pktns.send_list);
	quic_packet_purge_list(conn->hs_pktns.sent_list);
	quic_packet_purge_list(conn->hs_pktns.recv_list);
}

void quic_packet_sent_timeout(struct quic_conn *conn)
{
	if (conn->in_pktns.sent_list) {
		conn->in_pktns.sent_last->next = conn->in_pktns.send_list;
		conn->in_pktns.send_list = conn->in_pktns.sent_list;
		conn->in_pktns.sent_list = NULL;
	}
	if (conn->hs_pktns.sent_list) {
		conn->hs_pktns.sent_last->next = conn->hs_pktns.send_list;
		conn->hs_pktns.send_list = conn->hs_pktns.sent_list;
		conn->hs_pktns.sent_list = NULL;
	}
}

int quic_packet_create(struct quic_conn *conn, struct quic_buf *packet)
{
	struct quic_pkthd *hd = &conn->hd;

	memset(hd, 0, sizeof(*hd));
	packet->buflen = 0;

	if (conn->version) {
		if (encode_packet(conn, packet, hd, QUIC_PKT_TYPE_VERSION))
			goto out;
	}
	if (conn->in_pktns.send_list || conn->in_pktns.ack_needed) {
		if (encode_packet(conn, packet, hd, QUIC_PKT_TYPE_INITIAL))
			goto out;
	}
	if (conn->hs_pktns.send_list || conn->hs_pktns.ack_needed) {
		if (encode_packet(conn, packet, hd, QUIC_PKT_TYPE_HANDSHAKE))
			goto out;
	}
out:
	return packet->buflen;
}

int quic_packet_process(struct quic_conn *conn, struct quic_buf *packet)
{
	struct quic_pkthd *hd = &conn->hd;
	int ret = 0;

	memset(hd, 0, sizeof(*hd));

	do {
		ret = decode_packet(conn, packet, hd);
		if (ret)
			break;
	} while (hd->offset < packet->buflen);

	return ret;
}
