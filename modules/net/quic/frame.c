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

#include <linux/version.h>
#include "socket.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#include <net/proto_memory.h>
#endif

/* rfc9000#section-19.3:
 *
 * ACK or ACK_ECN Frame {
 *  Type (i) = 0x02..0x03,
 *  Largest Acknowledged (i),
 *  ACK Delay (i),
 *  ACK Range Count (i),
 *  First ACK Range (i),
 *  ACK Range (..) ...,
 *  [ECN Counts (..)],
 * }
 *
 * ACK Range {
 *   Gap (i),
 *   ACK Range Length (i),
 * }
 *
 * ECN Counts {
 *   ECT0 Count (i),
 *   ECT1 Count (i),
 *   ECN-CE Count (i),
 * }
 *
 * Receivers send ACK or ACK_ECN frames to inform senders of packets they have received and
 * processed. The ACK frame contains one or more ACK Ranges. ACK Ranges identify acknowledged
 * packets. If ACK_ECN frames also contain the cumulative count of QUIC packets with associated
 * ECN marks received on the connection up until this point.
 */
static struct quic_frame *quic_frame_ack_create(struct sock *sk, void *data, u8 type)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAP_MAX_GABS];
	u64 largest, smallest, range, delay, *ecn_count;
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p, level = *((u8 *)data);
	struct quic_pnspace *space;
	u32 frame_len, num_gabs, i;
	struct quic_frame *frame;

	space = quic_pnspace(sk, level);
	/* If ECN counts are present, use ACK_ECN frame type. */
	type += quic_pnspace_has_ecn_count(space);
	/* Collect gap-based ACK blocks from the PN space. */
	num_gabs = quic_pnspace_num_gabs(space, gabs);

	/* Determine the Largest Acknowledged and First ACK Range. */
	largest = space->max_pn_seen;
	smallest = space->min_pn_seen;
	if (num_gabs)
		smallest = space->base_pn + gabs[num_gabs - 1].end;
	range = largest - smallest; /* rfc9000#section-19.3.1: smallest = largest - ack_range. */
	/* Calculate ACK Delay, adjusted by the ACK delay exponent. */
	delay = quic_ktime_get_us() - space->max_pn_time;
	delay >>= outq->ack_delay_exponent;

	/* Estimate the maximum frame length: type + 4 * varints + ranges + ECN Counts. */
	frame_len = 1 + quic_var_len(largest) + quic_var_len(delay) + quic_var_len(num_gabs) +
		    quic_var_len(range) + sizeof(struct quic_gap_ack_block) * num_gabs +
		    sizeof(*ecn_count) * QUIC_ECN_MAX;
	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, largest); /* Largest Acknowledged. */
	p = quic_put_var(p, delay); /* ACK Delay. */
	p = quic_put_var(p, num_gabs); /* ACK Count. */
	p = quic_put_var(p, range); /* First ACK Range. */

	if (num_gabs) { /* Encode additional ACK Ranges and Gaps if present. */
		for (i = num_gabs - 1; i > 0; i--) {
			p = quic_put_var(p, gabs[i].end - gabs[i].start); /* Gap. */
			/* ACK Range Length. */
			p = quic_put_var(p, gabs[i].start - gabs[i - 1].end - 2);
		}
		/* Final gap and range. */
		p = quic_put_var(p, gabs[0].end - gabs[0].start); /* Gap. */
		largest = gabs[0].start - 1 + space->base_pn - 1;
		range = largest - space->min_pn_seen;
		p = quic_put_var(p, range); /* ACK Range Length. */
	}
	if (type == QUIC_FRAME_ACK_ECN) {
		ecn_count = space->ecn_count[QUIC_ECN_LOCAL];
		p = quic_put_var(p, ecn_count[QUIC_ECN_ECT0]); /* ECT0 Count. */
		p = quic_put_var(p, ecn_count[QUIC_ECN_ECT1]); /* ECT1 Count. */
		p = quic_put_var(p, ecn_count[QUIC_ECN_CE]); /* ECN-CE Count. */
	}
	/* Finalize frame metadata. */
	frame->type = type;
	frame->len = (u16)(p - frame->data);
	frame->size = frame->len;
	frame->level = level;

	return frame;
}

/* rfc9000#section-19.2:
 *
 * PING Frame {
 *   Type (i) = 0x01,
 * }
 *
 * Endpoints can use PING frames to verify that their peers are still alive or to check
 * reachability to the peer.
 *
 * It is also used for PMTUD probing. When probe size is provided, it fills the rest of the
 * frame with zeros and sets the padding flag.
 */
static struct quic_frame *quic_frame_ping_create(struct sock *sk, void *data, u8 type)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_probeinfo *info = data;
	struct quic_frame *frame;
	u32 frame_len = 1;

	/* If a probe size is specified and larger than the overhead, request padding to reach
	 * that total size.
	 */
	if (info->size > packet->overhead)
		frame_len = info->size - packet->overhead;

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;

	frame->level = info->level;
	quic_put_var(frame->data, type);
	if (frame_len > 1) {
		memset(frame->data + 1, 0, frame_len - 1);
		frame->padding = 1;
	}

	return frame;
}

/* rfc9000#section-19.1:
 *
 * PADDING Frame {
 *   Type (i) = 0x00,
 * }
 *
 * A PADDING frame (type=0x00) has no semantic value. PADDING frames can be used to increase
 * the size of a packet.
 */
static struct quic_frame *quic_frame_padding_create(struct sock *sk, void *data, u8 type)
{
	struct quic_frame *frame;
	u32 *frame_len = data;

	frame = quic_frame_alloc(*frame_len + 1, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_var(frame->data, type);
	memset(frame->data + 1, 0, *frame_len);

	return frame;
}

/* rfc9000#section-19.7:
 *
 *
 * NEW_TOKEN Frame {
 *   Type (i) = 0x07,
 *   Token Length (i),
 *   Token (..),
 * }
 *
 * The NEW_TOKEN frame is used by servers to provide address validation tokens to clients.
 * These tokens can be used by clients to skip address validation in future connections.
 */
static struct quic_frame *quic_frame_new_token_create(struct sock *sk, void *data, u8 type)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p, buf[QUIC_FRAME_BUF_LARGE];
	struct quic_frame *frame;
	u32 tlen;

	/* Write token flags into buffer: QUIC_TOKEN_FLAG_REGULAR means regular token. */
	quic_put_int(buf, QUIC_TOKEN_FLAG_REGULAR, 1);
	/* Generate the token into buf; includes client's address and connection ID. */
	if (quic_crypto_generate_token(crypto, quic_path_daddr(paths, 0), sizeof(union quic_addr),
				       quic_conn_id_active(id_set), buf, &tlen))
		return NULL;

	frame = quic_frame_alloc(tlen + 1 + quic_var_len(tlen), NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, tlen);
	p = quic_put_data(p, buf, tlen);
	frame->len = (u16)(p - frame->data);
	frame->size = frame->len;
	outq->token_pending = 1; /* Mark token pending until it gets ACKed. */

	return frame;
}

static struct quic_frame_frag *quic_frame_frag_alloc(u16 size)
{
	struct quic_frame_frag *frag;

	frag = kzalloc(sizeof(*frag) + size, GFP_KERNEL);
	if (frag)
		frag->size = size;

	return frag;
}

/* rfc9000#section-19.8:
 *
 * STREAM Frame {
 *  Type (i) = 0x08..0x0f,
 *  Stream ID (i),
 *  [Offset (i)],
 *  [Length (i)],
 *  Stream Data (..),
 * }
 *
 * STREAM frames implicitly create a stream and carry stream data. The Type field in the STREAM
 * frame takes the form 0b00001XXX (or the set of values from 0x08 to 0x0f). The three low-order
 * bits of the frame type determine the fields that are present in the frame: The OFF bit
 * (0x04); The LEN bit (0x02); The FIN bit (0x01).
 */
static struct quic_frame *quic_frame_stream_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_msginfo *info = data;
	struct quic_frame_frag *frag;
	struct quic_stream *stream;
	struct quic_frame *frame;
	u8 *p, nodelay = 0;
	u64 wspace;

	stream = info->stream;
	/* Estimate header length: type (1 byte) + varint stream ID. */
	hlen += quic_var_len(stream->id);
	/* If there is a non-zero offset, include it and set OFF bit. */
	if (stream->send.bytes) {
		type |= QUIC_STREAM_BIT_OFF;
		hlen += quic_var_len(stream->send.bytes); /* varint Offset. */
	}
	/* To make things simple, always include length field, so set LEN bit. */
	type |= QUIC_STREAM_BIT_LEN;
	/* Reserve max varint length in case more data is appended later. */
	hlen += quic_var_len(QUIC_MAX_UDP_PAYLOAD);

	max_frame_len = quic_packet_max_payload(quic_packet(sk)); /* MSS. */
	msg_len = iov_iter_count(info->msg); /* Total message length from user space. */
	wspace = quic_outq_wspace(sk, stream); /* Flow control limit. */

	/* Trim msg_len to respect flow control and MSS constraints. */
	if ((u64)msg_len <= wspace) { /* All data fits in flow control limit. */
		if (msg_len <= max_frame_len - hlen) { /* Fits in MSS. */
			/* If message fits fully, include FIN bit if requested. */
			if (info->flags & MSG_QUIC_STREAM_FIN)
				type |= QUIC_STREAM_BIT_FIN;
		} else { /* Limit to MSS and mark as nodelay. */
			nodelay = 1;
			msg_len = max_frame_len - hlen;
		}
	} else { /* Limit to flow control limit. */
		msg_len = wspace;
		if (msg_len > max_frame_len - hlen) { /* Limit to MSS and mark as nodelay. */
			nodelay = 1;
			msg_len = max_frame_len - hlen;
		}
	}

	frame = quic_frame_alloc(hlen, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	frame->stream = stream;

	if (msg_len) { /* Allocate and attach frame fragment for the payload. */
		frag = quic_frame_frag_alloc(msg_len);
		if (!frag) {
			quic_frame_put(frame);
			return NULL;
		}
		/* Copy user data into the frame fragment. */
		if (!copy_from_iter_full(frag->data, msg_len, info->msg)) {
			quic_frame_put(frame);
			kfree(frag);
			return NULL;
		}
		frame->flist = frag;
	}

	/* Encode STREAM frame header. */
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, stream->id);
	if (type & QUIC_STREAM_BIT_OFF)
		p = quic_put_var(p, stream->send.bytes);
	p = quic_put_var(p, msg_len);

	/* Finalize frame metadata. */
	frame->type = type;
	frame->size = (u16)(p - frame->data);
	frame->bytes = (u16)msg_len;
	frame->len = frame->size + frame->bytes;
	frame->nodelay = nodelay;

	return frame;
}

/* rfc9000#section-19.20:
 *
 * HANDSHAKE_DONE Frame {
 *   Type (i) = 0x1e,
 * }
 *
 * The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal confirmation of the handshake to
 * the client.
 */
static struct quic_frame *quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.6:
 *
 * CRYPTO Frame {
 *   Type (i) = 0x06,
 *   Offset (i),
 *   Length (i),
 *   Crypto Data (..),
 * }
 *
 * A CRYPTO frame (type=0x06) is used to transmit cryptographic handshake messages. It can be
 * sent in all packet types except 0-RTT. The CRYPTO frame offers the cryptographic protocol an
 * in-order stream of bytes. CRYPTO frames are functionally identical to STREAM frames, except
 * that they do not bear a stream identifier.
 */
static struct quic_frame *quic_frame_crypto_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, max_frame_len, wspace, hlen = 1;
	struct quic_msginfo *info = data;
	struct quic_crypto *crypto;
	struct quic_frame *frame;
	u64 offset;
	u8 *p;

	max_frame_len = quic_packet_max_payload(quic_packet(sk)); /* MSS. */
	crypto = quic_crypto(sk, info->level);
	msg_len = iov_iter_count(info->msg);
	wspace = sk_stream_wspace(sk);

	offset = crypto->send_offset;
	hlen += quic_var_len(offset);
	hlen += quic_var_len(max_frame_len);
	/* Trim msg_len to respect socket sndbuf and MSS constraints. */
	if (msg_len > wspace)
		msg_len = wspace;
	if (msg_len > max_frame_len - hlen)
		msg_len = max_frame_len - hlen;

	frame = quic_frame_alloc(msg_len + hlen, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, offset);
	p = quic_put_var(p, msg_len);
	if (!copy_from_iter_full(p, msg_len, info->msg)) {
		quic_frame_put(frame);
		return NULL;
	}
	p += msg_len;

	frame->bytes = (u16)msg_len;
	frame->len = (u16)(p - frame->data);
	frame->size = frame->len;
	frame->level = info->level;

	return frame;
}

/* rfc9000#section-19.16:
 *
 * RETIRE_CONNECTION_ID Frame {
 *   Type (i) = 0x19,
 *   Sequence Number (i),
 * }
 *
 * An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to indicate that it will no longer
 * use a connection ID that was issued by its peer.
 */
static struct quic_frame *quic_frame_retire_conn_id_create(struct sock *sk, void *data, u8 type)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_connection_id_info info = {};
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_conn_id *active;
	struct quic_frame *frame;
	u64 *seqno = data; /* Sequence number to retire. */
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *seqno);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	/* Remove the specified connection ID from the destination CID set. */
	quic_conn_id_remove(id_set, *seqno);

	/* Notify the QUIC stack that a CID has been retired. */
	info.dest = 1;
	info.prior_to =  quic_conn_id_first_number(id_set);
	active = quic_conn_id_active(id_set);
	info.active = quic_conn_id_number(active);
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_ID, &info);

	return frame;
}

/* rfc9000#section-19.15:
 *
 * NEW_CONNECTION_ID Frame {
 *   Type (i) = 0x18,
 *   Sequence Number (i),
 *   Retire Prior To (i),
 *   Length (8),
 *   Connection ID (8..160),
 *   Stateless Reset Token (128),
 * }
 *
 * An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide its peer with alternative
 * connection IDs that can be used to break linkability when migrating connections.
 */
static struct quic_frame *quic_frame_new_conn_id_create(struct sock *sk, void *data, u8 type)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	u8 *p, buf[QUIC_FRAME_BUF_LARGE], token[QUIC_CONN_ID_TOKEN_LEN];
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_conn_id scid = {};
	u64 seqno, *prior = data; /* Retire Prior To. */
	struct quic_frame *frame;
	u32 frame_len;
	int err;

	/* Compute the next sequence number for the new connection ID. */
	seqno = quic_conn_id_last_number(id_set) + 1;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, seqno);
	p = quic_put_var(p, *prior);
	/* Generate value for the new source connection ID (SCID). */
	quic_conn_id_generate(&scid);
	p = quic_put_var(p, scid.len);
	p = quic_put_data(p, scid.data, scid.len);
	/* rfc9000#section-10.3:
	 *
	 * A stateless reset token is specific to a connection ID. An endpoint issues a
	 * stateless reset token by including the value in the Stateless Reset Token field
	 * of a NEW_CONNECTION_ID frame.
	 */
	if (quic_crypto_generate_stateless_reset_token(crypto, scid.data, scid.len,
						       token, QUIC_CONN_ID_TOKEN_LEN))
		return NULL;
	p = quic_put_data(p, token, QUIC_CONN_ID_TOKEN_LEN);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	/* Register the new SCID in the connection ID set with the new sequence number. */
	err = quic_conn_id_add(id_set, &scid, seqno, sk);
	if (err) {
		quic_frame_put(frame);
		return NULL;
	}

	return frame;
}

/* rfc9000#section-19.18:
 *
 * PATH_RESPONSE Frame {
 *   Type (i) = 0x1b,
 *   Data (64),
 * }
 *
 * A PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE frame.
 */
static struct quic_frame *quic_frame_path_response_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL], *entropy = data;
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_data(p, entropy, QUIC_PATH_ENTROPY_LEN);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.17:
 *
 * PATH_CHALLENGE Frame {
 *   Type (i) = 0x1a,
 *   Data (64),
 * }
 *
 * Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check reachability to the peer and for
 * path validation during connection migration.
 */
static struct quic_frame *quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, *entropy, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	entropy = quic_paths(sk)->entropy;
	get_random_bytes(entropy, QUIC_PATH_ENTROPY_LEN); /* Generate new entropy each time. */

	p = quic_put_var(buf, type);
	p = quic_put_data(p, entropy, QUIC_PATH_ENTROPY_LEN);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.4:
 *
 * RESET_STREAM Frame {
 *   Type (i) = 0x04,
 *   Stream ID (i),
 *   Application Protocol Error Code (i),
 *   Final Size (i),
 * }
 *
 * An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly terminate the sending part of a
 * stream.
 */
static struct quic_frame *quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_errinfo *info = data; /* Error info. */
	u8 *p, buf[QUIC_FRAME_BUF_LARGE];
	struct quic_stream *stream;
	struct quic_frame *frame;
	u32 frame_len;

	stream = quic_stream_find(streams, info->stream_id);
	WARN_ON(!stream);

	p = quic_put_var(buf, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	p = quic_put_var(p, stream->send.bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	stream->send.errcode = info->errcode; /* Update stream send error code. */
	frame->stream = stream;

	/* Clear active stream ID if this stream was active. */
	if (streams->send.active_stream_id == stream->id)
		streams->send.active_stream_id = -1;

	return frame;
}

/* rfc9000#section-19.5:
 *
 * STOP_SENDING Frame {
 *   Type (i) = 0x05,
 *   Stream ID (i),
 *   Application Protocol Error Code (i),
 * }
 *
 * An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that incoming data is being
 * discarded on receipt per application request. STOP_SENDING requests that a peer cease
 * transmission on a stream.
 */
static struct quic_frame *quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_errinfo *info = data; /* Error info. */
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_stream *stream;
	struct quic_frame *frame;
	u32 frame_len;

	stream = quic_stream_find(streams, info->stream_id);
	WARN_ON(!stream);

	p = quic_put_var(buf, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	stream->recv.stop_sent = 1; /* Mark stop sending request sent. */
	frame->stream = stream;

	return frame;
}

/* rfc9000#section-19.9:
 *
 * MAX_DATA Frame {
 *   Type (i) = 0x10,
 *   Maximum Data (i),
 * }
 *
 * A MAX_DATA frame (type=0x10) is used in flow control to inform the peer of the maximum amount
 * of data that can be sent on the connection as a whole.
 */
static struct quic_frame *quic_frame_max_data_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_inqueue *inq = data;
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, inq->max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.10:
 *
 * MAX_STREAM_DATA Frame {
 *   Type (i) = 0x11,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * A MAX_STREAM_DATA frame (type=0x11) is used in flow control to inform a peer of the maximum
 * amount of data that can be sent on a stream.
 */
static struct quic_frame *quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream *stream = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->recv.max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.11:
 *
 * MAX_STREAMS (_UNI or _BIDI) Frame {
 *   Type (i) = 0x12..0x13,
 *   Maximum Streams (i),
 * }
 *
 * A MAX_STREAMS frame (type=0x12 or 0x13) informs the peer of the cumulative number of streams
 * of a given type it is permitted to open. A MAX_STREAMS_BIDI frame applies to bidirectional
 * streams, and a MAX_STREAMS_UNI frame applies to unidirectional streams.
 */
static struct quic_frame *quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* Similar to quic_frame_max_streams_uni_create(). */
static struct quic_frame *quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.19:
 *
 * CONNECTION_CLOSE or CONNECTION_CLOSE_APP Frame {
 *   Type (i) = 0x1c..0x1d,
 *   Error Code (i),
 *   [Frame Type (i)],
 *   Reason Phrase Length (i),
 *   Reason Phrase (..),
 * }
 *
 * An endpoint sends a CONNECTION_CLOSE or CONNECTION_CLOSE_APP frame to notify its peer that
 * the connection is being closed. The CONNECTION_CLOSE frame is used to signal errors at only
 * the QUIC layer, or the absence of errors (with the NO_ERROR code). The CONNECTION_CLOSE_APP
 * is used to signal an error with the application that uses QUIC.
 */
static struct quic_frame *quic_frame_connection_close_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[QUIC_FRAME_BUF_LARGE], *phrase, *level = data;
	struct quic_outqueue *outq = quic_outq(sk);
	u32 frame_len, phrase_len = 0;
	struct quic_frame *frame;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, outq->close_errcode);

	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		p = quic_put_var(p, outq->close_frame);

	phrase = outq->close_phrase;
	if (phrase)
		phrase_len = strlen(phrase);
	p = quic_put_var(p, phrase_len);
	p = quic_put_data(p, phrase, phrase_len);

	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_OUTCLOSES);
	frame->level = *level;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.12:
 *
 * DATA_BLOCKED Frame {
 *   Type (i) = 0x14,
 *   Maximum Data (i),
 * }
 *
 * A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes to send data but is
 * unable to do so due to connection-level flow control.
 */
static struct quic_frame *quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	struct quic_outqueue *outq = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, outq->max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.13:
 *
 * STREAM_DATA_BLOCKED Frame {
 *   Type (i) = 0x15,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to send data but
 * is unable to do so due to stream-level flow control. This frame is analogous to DATA_BLOCKED.
 */
static struct quic_frame *quic_frame_stream_data_blocked_create(struct sock *sk,
								void *data, u8 type)
{
	struct quic_stream *stream = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->send.max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	frame->stream = stream;

	return frame;
}

/* rfc9000#section-19.14:
 *
 * STREAMS_BLOCKED (_UNI or _BIDI) Frame {
 *   Type (i) = 0x16..0x17,
 *   Maximum Streams (i),
 * }
 *
 * A sender SHOULD send a STREAMS_BLOCKED frame when it wishes to open a stream but is unable to
 * do so due to the maximum stream limit set by its peer. A STREAMS_BLOCKED_BIDI frame is used
 * to indicate reaching the bidirectional stream limit, and a STREAMS_BLOCKED_UNI frame is used
 * to indicate reaching the unidirectional stream limit.
 */
static struct quic_frame *quic_frame_streams_blocked_uni_create(struct sock *sk,
								void *data, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	s64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_stream_id_to_streams(*max));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	streams->send.uni_blocked = 1;

	return frame;
}

/* Similar to quic_frame_streams_blocked_uni_create(). */
static struct quic_frame *quic_frame_streams_blocked_bidi_create(struct sock *sk,
								 void *data, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	s64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_stream_id_to_streams(*max));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_KERNEL);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	streams->send.bidi_blocked = 1;

	return frame;
}

static int quic_frame_crypto_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 offset, length;
	int err;

	if (!quic_get_var(&p, &len, &offset))
		return -EINVAL;
	if (!quic_get_var(&p, &len, &length) || length > len)
		return -EINVAL;

	/* Allocate a new frame for the crypto payload. Avoid copying: reuse the existing
	 * buffer by pointing to 'p' and holding the skb.
	 */
	nframe = quic_frame_alloc(length, p, GFP_ATOMIC);
	if (!nframe)
		return -ENOMEM;
	nframe->skb = skb_get(frame->skb);

	nframe->offset = offset;
	nframe->level = frame->level;

	/* Submit the CRYPTO frame to the inqueue for reassembly and processing. */
	err = quic_inq_handshake_recv(sk, nframe);
	if (err) {
		frame->errcode = nframe->errcode; /* Propagate error reason. */
		quic_frame_put(nframe);
		return err;
	}
	len -= length;
	/* Return number of bytes consumed from the original frame. */
	return (int)(frame->len - len);
}

static int quic_frame_stream_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u64 stream_id, payload_len, offset = 0;
	struct quic_stream *stream;
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id))
		return -EINVAL;
	if (type & QUIC_STREAM_BIT_OFF) {
		if (!quic_get_var(&p, &len, &offset))
			return -EINVAL;
	}

	payload_len = len;
	if (type & QUIC_STREAM_BIT_LEN) {
		if (!quic_get_var(&p, &len, &payload_len) || payload_len > len)
			return -EINVAL;
	}

	/* Look up the stream for receiving data (may create it if valid). */
	stream = quic_stream_get(streams, (s64)stream_id, 0, quic_is_serv(sk), false);
	if (IS_ERR(stream)) {
		/* rfc9000#section-4.6:
		 *
		 * An endpoint that receives a frame with a stream ID exceeding the limit it
		 * has sent MUST treat this as a connection error of type STREAM_LIMIT_ERROR.
		 *
		 * rfc9000#section-19.8:
		 *
		 * An endpoint MUST terminate the connection with error STREAM_STATE_ERROR if
		 * it receives a STREAM frame for a locally initiated stream that has not yet
		 * been created, or for a send-only stream.
		 */
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOSTR)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		goto out; /* If stream is already released, skip processing. */
	}

	/* Skip if stream already finished receiving, was reset, or stop-sending requested. */
	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD || stream->recv.stop_sent)
		goto out;

	/* Follows the same processing logic as quic_frame_crypto_process(). */
	nframe = quic_frame_alloc(payload_len, p, GFP_ATOMIC);
	if (!nframe)
		return -ENOMEM;
	nframe->skb = skb_get(frame->skb);

	nframe->offset = offset;
	nframe->stream = stream;
	nframe->stream_fin = (type & QUIC_STREAM_BIT_FIN);
	nframe->level = frame->level;

	err = quic_inq_stream_recv(sk, nframe);
	if (err) {
		frame->errcode = nframe->errcode;
		quic_frame_put(nframe);
		return err;
	}

out:
	len -= payload_len;
	return (int)(frame->len - len);
}

static int quic_frame_ack_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	u64 largest, smallest, range, delay, count, gap, i, ecn_count[QUIC_ECN_MAX];
	u8 *p = frame->data, level = frame->level;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_pnspace *space;
	u32 len = frame->len;

	if (!quic_get_var(&p, &len, &largest) ||
	    !quic_get_var(&p, &len, &delay) ||
	    !quic_get_var(&p, &len, &count) || count > QUIC_PN_MAP_MAX_GABS ||
	    !quic_get_var(&p, &len, &range) || range > largest)
		return -EINVAL;

	space = quic_pnspace(sk, level);
	if ((s64)largest >= space->next_pn) {
		/* rfc9000#section-13.1:
		 *
		 * An endpoint SHOULD treat receipt of an acknowledgment for a packet it did
		 * not send as a connection error of type PROTOCOL_VIOLATION, if it is able to
		 * detect the condition.
		 */
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	smallest = largest - range; /* rfc9000#section-19.3.1: smallest = largest - ack_range. */
	/* Calculate ACK Delay, adjusted by the ACK delay exponent. */
	delay <<= inq->ack_delay_exponent;
	/* ACK transmitted packets within [smallest, largest] range. */
	quic_outq_transmitted_sack(sk, level, (s64)largest, (s64)smallest, (s64)largest, delay);

	for (i = 0; i < count; i++) {
		if (!quic_get_var(&p, &len, &gap) || gap + 2 > smallest ||
		    !quic_get_var(&p, &len, &range) || range > smallest - gap - 2)
			return -EINVAL;
		/* rfc9000#section-19.3.1:
		 *
		 * smallest = largest - ack_range;
		 * largest = previous_smallest - gap - 2.
		 */
		largest = smallest - gap - 2;
		smallest = largest - range;
		quic_outq_transmitted_sack(sk, level, (s64)largest, (s64)smallest, -1, 0);
	}

	if (type == QUIC_FRAME_ACK_ECN) {
		if (!quic_get_var(&p, &len, &ecn_count[QUIC_ECN_ECT0]) ||
		    !quic_get_var(&p, &len, &ecn_count[QUIC_ECN_ECT1]) ||
		    !quic_get_var(&p, &len, &ecn_count[QUIC_ECN_CE]))
			return -EINVAL;
		/* If the ECN-CE counter reported by the peer has increased, this could be a
		 * new congestion event.
		 */
		if (quic_pnspace_set_ecn_count(space, ecn_count)) {
			quic_cong_on_process_ecn(cong);
			quic_outq_sync_window(sk, cong->window);
		}
	}

	return (int)(frame->len - len);
}

static int quic_frame_new_conn_id_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	u64 seqno, prior, length, first;
	u8 *p = frame->data, *token;
	struct quic_conn_id dcid;
	u32 len = frame->len;
	int err;

	if (!quic_get_var(&p, &len, &seqno) ||
	    !quic_get_var(&p, &len, &prior) ||
	    !quic_get_var(&p, &len, &length) ||
	    !length || length > QUIC_CONN_ID_MAX_LEN || length + QUIC_CONN_ID_TOKEN_LEN > len)
		return -EINVAL;

	memcpy(dcid.data, p, length);
	dcid.len = (u8)length;
	token = p + length;

	if (prior > seqno) {
		/* rfc9000#section-19.15:
		 *
		 * The value in the Retire Prior To field MUST be less than or equal to the value in
		 * the Sequence Number field. Receiving a value in the Retire Prior To field that is
		 * greater than that in the Sequence Number field MUST be treated as a connection
		 * error of type FRAME_ENCODING_ERROR.
		 */
		frame->errcode = QUIC_TRANSPORT_ERROR_FRAME_ENCODING;
		return -EINVAL;
	}

	first = quic_conn_id_first_number(id_set);
	if (seqno < first) /* This seqno was already used, skip processing. */
		goto out;
	if (prior < first)
		prior = first;
	if (seqno - prior + 1 > id_set->max_count) {
		/* rfc9000#section-5.1.1:
		 *
		 * After processing a NEW_CONNECTION_ID frame and adding and retiring active
		 * connection IDs, if the number of active connection IDs exceeds the value
		 * advertised in its active_connection_id_limit transport parameter, an endpoint
		 * MUST close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
		 */
		frame->errcode = QUIC_TRANSPORT_ERROR_CONNECTION_ID_LIMIT;
		return -EINVAL;
	}

	err = quic_conn_id_add(id_set, &dcid, seqno, token);
	if (err)
		return err;

	if (prior > first) {
		/* rfc9000#section-19.15:
		 *
		 * An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number
		 * smaller than the Retire Prior To field of a previously received NEW_CONNECTION_ID
		 * frame MUST send a corresponding RETIRE_CONNECTION_ID frame that retires the newly
		 * received connection ID, unless it has already done so for that sequence number.
		 */
		if (quic_outq_transmit_retire_conn_id(sk, prior, frame->path, true))
			return -ENOMEM;
	}

	/* If path migration is pending due to missing connection IDs, trigger probing on the
	 * alternate path to continue the migration.
	 */
	if (quic_path_alt_state(quic_paths(sk), QUIC_PATH_ALT_PENDING))
		quic_outq_probe_path_alt(sk, true);

out:
	len -= (length + QUIC_CONN_ID_TOKEN_LEN);
	return (int)(frame->len - len);
}

static int quic_frame_retire_conn_id_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_connection_id_info info = {};
	struct quic_conn_id *active;
	u64 seqno, last, first;
	u32 len = frame->len;
	u8 *p = frame->data;

	if (!quic_get_var(&p, &len, &seqno))
		return -EINVAL;

	first = quic_conn_id_first_number(id_set);
	last  = quic_conn_id_last_number(id_set);
	if (seqno >= first) {
		if (seqno >= last) {
			/* rfc9000#section-19.16:
			 *
			 * Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
			 * greater than any previously sent to the peer MUST be treated as a
			 * connection error of type PROTOCOL_VIOLATION.
			 */
			frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			return -EINVAL;
		}

		/* Notify application of connection IDs change. */
		quic_conn_id_remove(id_set, seqno);
		first = quic_conn_id_first_number(id_set);
		info.prior_to = first;
		active = quic_conn_id_active(id_set);
		info.active = quic_conn_id_number(active);
		quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_ID, &info);
	}

	/* rfc9000#section-5.1.2:
	 *
	 * Sending a RETIRE_CONNECTION_ID frame indicates that the connection ID will not be
	 * used again and requests that the peer replace it with a new connection ID using a
	 * NEW_CONNECTION_ID frame.
	 */
	if (quic_outq_transmit_new_conn_id(sk, first, frame->path, true))
		return -ENOMEM;
	return (int)(frame->len - len);
}

static int quic_frame_new_token_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_data *token = quic_token(sk);
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 length;

	if (quic_is_serv(sk)) {
		/* rfc9000#section-19.7:
		 *
		 * A server MUST treat receipt of a NEW_TOKEN frame as a connection error of
		 * type PROTOCOL_VIOLATION.
		 */
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	if (!quic_get_var(&p, &len, &length) || length > len || length > QUIC_TOKEN_MAX_LEN)
		return -EINVAL;

	/* Store the token internally so user space can retrieve it via getsockopt(). */
	if (quic_data_dup(token, p, length))
		return -ENOMEM;
	/* Notify upper layers that a valid NEW_TOKEN was received. */
	quic_inq_event_recv(sk, QUIC_EVENT_NEW_TOKEN, token);

	len -= length;
	return (int)(frame->len - len);
}

static int quic_frame_handshake_done_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_path_group *paths = quic_paths(sk);

	if (quic_is_serv(sk)) {
		/* rfc9000#section-19.20:
		 *
		 * A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection error
		 * of type PROTOCOL_VIOLATION.
		 */
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	/* Handshake is complete and clean up transmitted handshake packets. */
	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAX, 0, -1, 0);

	if (paths->pref_addr) {
		/* Initiate probing on the new path to validate it (e.g., send PATH_CHALLENGE).
		 * This starts the connection migration procedure.
		 */
		quic_outq_probe_path_alt(sk, true);
		paths->pref_addr = 0;
	}
	return 0;
}

static int quic_frame_padding_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	u8 *p = frame->data;

	/* Some implementations put the PADDING frame ahead of other frames.  We need to skip over
	 * zero bytes and find the first non-zero byte, which marks the start of the next frame.
	 */
	for (; !(*p) && p != frame->data + frame->len; p++)
		;
	return (int)(p - frame->data);
}

static int quic_frame_ping_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return 0; /* No content. */
}

static int quic_frame_path_challenge_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	u8 entropy[QUIC_PATH_ENTROPY_LEN];
	u32 len = frame->len;

	if (len < QUIC_PATH_ENTROPY_LEN)
		return -EINVAL;
	/* rfc9000#section-19.17:
	 *
	 * The recipient of this frame MUST generate a PATH_RESPONSE frame containing the same
	 * Data value.
	 */
	memcpy(entropy, frame->data, QUIC_PATH_ENTROPY_LEN);
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_PATH_RESPONSE, entropy, frame->path, true))
		return -ENOMEM;

	len -= QUIC_PATH_ENTROPY_LEN;
	return (int)(frame->len - len);
}

static int quic_frame_reset_stream_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_stream_update update = {};
	u64 stream_id, errcode, finalsz;
	struct quic_stream *stream;
	u32 len = frame->len;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &errcode) ||
	    !quic_get_var(&p, &len, &finalsz))
		return -EINVAL;

	stream = quic_stream_get(streams, (s64)stream_id, 0, quic_is_serv(sk), false);
	if (IS_ERR(stream)) {
		/* rfc9000#section-19.4:
		 *
		 * An endpoint that receives a RESET_STREAM frame for a send-only stream MUST
		 * terminate the connection with error STREAM_STATE_ERROR.
		 */
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOSTR)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		goto out;
	}

	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		goto out; /* Skip if stream has already received all data or a reset. */

	if (finalsz < stream->recv.highest ||
	    (stream->recv.finalsz && stream->recv.finalsz != finalsz)) {
		/* rfc9000#section-4.5:
		 *
		 * Once a final size for a stream is known, it cannot change. If a RESET_STREAM or
		 * STREAM frame is received indicating a change in the final size for the stream, an
		 * endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR.
		 */
		frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
		return -EINVAL;
	}

	/* Notify that stream has received a reset. */
	update.id = (s64)stream_id;
	update.state = QUIC_STREAM_RECV_STATE_RESET_RECVD;
	update.errcode = errcode;
	update.finalsz = finalsz;
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

	/* rfc9000#section-3.2:
	 *
	 * Receiving a RESET_STREAM frame in the "Recv" or "Size Known" state causes the stream to
	 * enter the "Reset Recvd" state.
	 */
	stream->recv.state = update.state;
	stream->recv.finalsz = update.finalsz;

	/* rfc9000#section-19.4:
	 *
	 * A receiver of RESET_STREAM can discard any data that it already received on that stream.
	 */
	quic_inq_list_purge(sk, &inq->stream_list, stream);
	quic_inq_list_purge(sk, &inq->recv_list, stream);
	quic_stream_put(streams, stream, quic_is_serv(sk), false); /* Release the receive stream. */
out:
	return (int)(frame->len - len);
}

static int quic_frame_stop_sending_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_stream_update update = {};
	struct quic_stream *stream;
	struct quic_errinfo info;
	u64 stream_id, errcode;
	u32 len = frame->len;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &errcode))
		return -EINVAL;

	stream = quic_stream_get(streams, (s64)stream_id, 0, quic_is_serv(sk), true);
	if (IS_ERR(stream)) {
		/* rfc9000#section-19.5:
		 *
		 * Receiving a STOP_SENDING frame for a locally initiated stream that has not yet
		 * been created MUST be treated as a connection error of type STREAM_STATE_ERROR.
		 * An endpoint that receives a STOP_SENDING frame for a receive-only stream MUST
		 * terminate the connection with error STREAM_STATE_ERROR.
		 */
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOSTR)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		return err;
	}

	/* rfc9000#section-3.1:
	 *
	 * Alternatively, an endpoint might receive a STOP_SENDING frame from its peer. In either
	 * case, the endpoint sends a RESET_STREAM frame, which causes the stream to enter the
	 * "Reset Sent" state.
	 */
	info.stream_id = (s64)stream_id;
	info.errcode = errcode;
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_RESET_STREAM, &info, 0, true))
		return -ENOMEM;

	/* Notify that stream has received a stop_sending and sent a reset. */
	update.id = (s64)stream_id;
	update.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	update.errcode = errcode;
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

	stream->send.state = update.state;
	quic_outq_list_purge(sk, &outq->transmitted_list, stream);
	quic_outq_list_purge(sk, &outq->stream_list, stream);
	return (int)(frame->len - len);
}

static int quic_frame_max_data_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 max_bytes;

	if (!quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	if (max_bytes > outq->max_bytes) {
		/* Update only if the peer increases the allowed send data. Wake up processes
		 * blocked while attempting to send more data.
		 */
		outq->max_bytes = max_bytes;
		sk->sk_write_space(sk);
	}

	return (int)(frame->len - len);
}

static int quic_frame_max_stream_data_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream_max_data data;
	struct quic_stream *stream;
	u64 max_bytes, stream_id;
	u32 len = frame->len;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	stream = quic_stream_get(streams, (s64)stream_id, 0, quic_is_serv(sk), true);
	if (IS_ERR(stream)) {
		/* rfc9000#section-19.10:
		 *
		 * Receiving a MAX_STREAM_DATA frame for a locally initiated stream that has not yet
		 * been created MUST be treated as a connection error of type STREAM_STATE_ERROR. An
		 * endpoint that receives a MAX_STREAM_DATA frame for a receive-only stream MUST
		 * terminate the connection with error STREAM_STATE_ERROR.
		 */
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOSTR)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		return err;
	}

	if (max_bytes > stream->send.max_bytes) {
		/* Update only if the peer increases the allowed send data. Wake up processes
		 * blocked while attempting to send more data.
		 */
		stream->send.max_bytes = max_bytes;
		sk->sk_write_space(sk);
		/* Notify the application of updated per-stream flow control.  This is useful for
		 * userspace to prioritize or schedule data transmission across multiple streams.
		 */
		data.id = stream->id;
		data.max_data = max_bytes;
		quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_DATA, &data);
	}

	return (int)(frame->len - len);
}

static int quic_frame_max_streams_uni_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = streams->send.max_uni_stream_id;
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;

	/* rfc9000#section-19.11:
	 *
	 * Loss or reordering can cause an endpoint to receive a MAX_STREAMS frame with a lower
	 * stream limit than was previously received. MAX_STREAMS frames that do not increase the
	 * stream limit MUST be ignored.
	 */
	if (max <= quic_stream_id_to_streams(stream_id))
		goto out;

	type = QUIC_STREAM_TYPE_CLIENT_UNI;
	if (quic_is_serv(sk))
		type = QUIC_STREAM_TYPE_SERVER_UNI;
	/* Notify the application of updated maximum uni-directional stream ID allowed to open. */
	stream_id = quic_stream_streams_to_id(max, type);
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_STREAM, &stream_id);

	streams->send.max_uni_stream_id = stream_id;
	sk->sk_write_space(sk); /* Wake up processes blocked while attempting to open a stream. */
out:
	return (int)(frame->len - len);
}

static int quic_frame_max_streams_bidi_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u32 len = frame->len;
	u8 *p = frame->data;
	s64 stream_id;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;

	/* Similar to quic_frame_max_streams_uni_process(), but applies to bidirectional streams. */
	stream_id = streams->send.max_bidi_stream_id;
	if (max <= quic_stream_id_to_streams(stream_id))
		goto out;

	type = QUIC_STREAM_TYPE_CLIENT_BIDI;
	if (quic_is_serv(sk))
		type = QUIC_STREAM_TYPE_SERVER_BIDI;
	stream_id = quic_stream_streams_to_id(max, type);
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_STREAM, &stream_id);

	streams->send.max_bidi_stream_id = stream_id;
	sk->sk_write_space(sk);
out:
	return (int)(frame->len - len);
}

static int quic_frame_connection_close_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	u8 *p = frame->data, buf[QUIC_FRAME_BUF_LARGE] = {}, *data;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close *close;
	u64 err_code, phrase_len, ftype = 0;
	u32 len = frame->len;

	if (!quic_get_var(&p, &len, &err_code))
		return -EINVAL;
	if (type == QUIC_FRAME_CONNECTION_CLOSE && !quic_get_var(&p, &len, &ftype))
		return -EINVAL;
	if (type == QUIC_FRAME_CONNECTION_CLOSE_APP && frame->level != QUIC_CRYPTO_APP)
		return -EINVAL;

	if (!quic_get_var(&p, &len, &phrase_len) || phrase_len > len)
		return -EINVAL;

	/* Notify that the peer closed the connection and provided error information. */
	close = (void *)buf;
	if (phrase_len) {
		if (phrase_len > QUIC_CLOSE_PHRASE_MAX_LEN)
			return -EINVAL;
		memcpy(close->phrase, p, phrase_len);
	}
	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_INCLOSES);
	close->errcode = err_code;
	close->frame = (u8)ftype;
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close);

	/* Save close frame info so that user space can retrieve it via getsockopt(). */
	data = kzalloc(phrase_len + 1, GFP_ATOMIC);
	if (data) {
		outq->close_errcode = err_code;
		outq->close_frame = (u8)ftype;
		kfree(outq->close_phrase);
		outq->close_phrase = memcpy(data, p, phrase_len);
	}

	quic_set_state(sk, QUIC_SS_CLOSED);
	pr_debug("%s: errcode: %d, frame: %d\n", __func__, close->errcode, close->frame);

	len -= phrase_len;
	return (int)(frame->len - len);
}

static int quic_frame_data_blocked_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_inqueue *inq = quic_inq(sk);
	u64 window, max_bytes, recv_max_bytes;
	u32 len = frame->len;
	u8 *p = frame->data;

	if (!quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;
	recv_max_bytes = inq->max_bytes;

	/* rfc9000#section-19.12:
	 *
	 * DATA_BLOCKED frames can be used as input to tuning of flow control algorithms.
	 *
	 * Similar to quic_inq_flow_control(), but MAX_DATA is sent unconditionally.
	 */
	window = inq->max_data;
	if (sk_under_memory_pressure(sk))
		window >>= 1;

	inq->max_bytes = inq->bytes + window;
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_DATA, inq, 0, true)) {
		/* If sending fails, restore previous max_bytes value. */
		inq->max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
	return (int)(frame->len - len);
}

static int quic_frame_stream_data_blocked_process(struct sock *sk, struct quic_frame *frame,
						  u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u64 stream_id, max_bytes, recv_max_bytes;
	u32 window, len = frame->len;
	struct quic_stream *stream;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	stream = quic_stream_get(streams, (s64)stream_id, 0, quic_is_serv(sk), false);
	if (IS_ERR(stream)) {
		/* rfc9000#section-19.13:
		 *
		 * An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream
		 * MUST terminate the connection with error STREAM_STATE_ERROR.
		 */
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOSTR)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		goto out;
	}

	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		goto out; /* Skip if stream has already received all data or a reset. */

	/* Follows the same processing logic as quic_frame_data_blocked_process(). */
	window = stream->recv.window;
	if (sk_under_memory_pressure(sk))
		window >>= 1;

	recv_max_bytes = stream->recv.max_bytes;
	stream->recv.max_bytes = stream->recv.bytes + window;
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_STREAM_DATA, stream, 0, true)) {
		stream->recv.max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
out:
	return (int)(frame->len - len);
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk, struct quic_frame *frame,
						  u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = streams->send.max_uni_stream_id;
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;
	if (max > quic_stream_id_to_streams(stream_id))
		goto out; /* Ignore if peer requests more streams than currently allowed. */
	/* Respond with a MAX_STREAMS_UNI frame to inform the peer of the current limit. */
	max = quic_stream_id_to_streams(stream_id);
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_STREAMS_UNI, &max, 0, true))
		return -ENOMEM;
out:
	return (int)(frame->len - len);
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk, struct quic_frame *frame,
						   u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u32 len = frame->len;
	u8 *p = frame->data;
	s64 stream_id;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;
	/* Follows the same processing logic as quic_frame_streams_blocked_uni_process(). */
	stream_id = streams->recv.max_bidi_stream_id;
	if (max > quic_stream_id_to_streams(stream_id))
		goto out;
	max = quic_stream_id_to_streams(stream_id);
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_MAX_STREAMS_BIDI, &max, 0, true))
		return -ENOMEM;
out:
	return (int)(frame->len - len);
}

static int quic_frame_path_response_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_path_group *paths = quic_paths(sk);
	u8 local, entropy[QUIC_PATH_ENTROPY_LEN];
	u32 len = frame->len;

	if (len < 8)
		return -EINVAL;

	/* Verify path challenge entropy. */
	memcpy(entropy, frame->data, QUIC_PATH_ENTROPY_LEN);
	if (memcmp(paths->entropy, entropy, QUIC_PATH_ENTROPY_LEN))
		goto out;

	/* Peer's application key is ready and clean up transmitted handshake packets. */
	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAX, 0, -1, 0);

	if (!quic_path_alt_state(paths, QUIC_PATH_ALT_PROBING))
		goto out;

	/* If this was a probe for connection migration, Promotes the alternate path (path[1])
	 * to become the new active path.
	 */
	sk->sk_prot->unhash(sk);
	quic_path_swap(paths);
	sk->sk_prot->hash(sk);
	quic_set_sk_addr(sk, quic_path_saddr(paths, 0), 1);
	quic_set_sk_addr(sk, quic_path_daddr(paths, 0), 0);
	/* Notify application of updated path; indicate whether it is a local address change. */
	local = !quic_cmp_sk_addr(sk, quic_path_saddr(paths, 1), quic_path_saddr(paths, 0));
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_MIGRATION, &local);

	/* Update path ID for all control and transmitted frames, reset route, and use the
	 * active connection ID for the new path.
	 */
	frame->path = 0;
	__sk_dst_reset(sk);
	quic_outq_update_path(sk);
	quic_conn_id_swap_active(quic_dest(sk));

out:
	len -= 8;
	return (int)(frame->len - len);
}

static struct quic_frame *quic_frame_invalid_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

/* rfc9221#section-4:
 *
 * DATAGRAM or DATAGRAM_LEN Frame {
 *   Type (i) = 0x30..0x31,
 *   [Length (i)],
 *   Datagram Data (..),
 * }
 *
 * DATAGRAM frames are used to transmit application data in an unreliable manner. There is a
 * Length field present in DATAGRAM_LEN Frame.
 */
static struct quic_frame *quic_frame_datagram_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, hlen = 1, frame_len, max_frame_len;
	struct iov_iter *msg = data;
	struct quic_frame *frame;
	u8 *p;

	max_frame_len = quic_packet_max_payload_dgram(quic_packet(sk)); /* MSS for dgram. */
	hlen += quic_var_len(max_frame_len);

	/* rfc9221#section-5:
	 *
	 * DATAGRAM frames cannot be fragmented; therefore, application protocols need to handle
	 * cases where the maximum datagram size is limited by other factors.
	 */
	msg_len = iov_iter_count(msg);
	if (msg_len > max_frame_len - hlen)
		return NULL;

	frame = quic_frame_alloc(msg_len + hlen, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;

	p = quic_put_var(frame->data, type);
	/* To make things simple, only create DATAGRAM_LEN frame with Length encoded. */
	p = quic_put_var(p, msg_len);

	if (!copy_from_iter_full(p, msg_len, msg)) {
		quic_frame_put(frame);
		return NULL;
	}
	p += msg_len;
	frame_len = (u32)(p - frame->data);

	frame->bytes = (u16)msg_len;
	frame->len = (u16)frame_len;
	frame->size = frame->len;
	frame->dgram = 1;

	return frame;
}

static int quic_frame_invalid_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	/* rfc9000#section-12.4:
	 *
	 * An endpoint MUST treat the receipt of a frame of unknown type as a connection error of
	 * type FRAME_ENCODING_ERROR.
	 */
	frame->errcode = QUIC_TRANSPORT_ERROR_FRAME_ENCODING;
	return -EPROTONOSUPPORT;
}

static int quic_frame_datagram_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 payload_len;
	int err;

	payload_len = frame->len;
	if (type == QUIC_FRAME_DATAGRAM_LEN) {
		if (!quic_get_var(&p, &len, &payload_len) || payload_len > len)
			return -EINVAL;
	}

	/* rfc9221#section-3:
	 *
	 * An endpoint that receives a DATAGRAM frame that is larger than the value it sent in
	 * its max_datagram_frame_size transport parameter MUST terminate the connection with
	 * an error of type PROTOCOL_VIOLATION.
	 */
	if (payload_len + (p - frame->data) + 1 > inq->max_datagram_frame_size) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	/* Follows the same processing logic as quic_frame_crypto_process(). */
	nframe = quic_frame_alloc(payload_len, p, GFP_ATOMIC);
	if (!nframe)
		return -ENOMEM;
	nframe->skb = skb_get(frame->skb);

	err = quic_inq_dgram_recv(sk, nframe);
	if (err) {
		quic_frame_put(nframe);
		return err;
	}

	len -= payload_len;
	return (int)(frame->len - len);
}

static void quic_frame_padding_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_ping_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_ack_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_reset_stream_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream = frame->stream;
	struct quic_stream_update update;

	/* Notify that stream has been reset. */
	update.id = stream->id;
	update.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
	update.errcode = stream->send.errcode;
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

	/* rfc9000#section-3.1:
	 *
	 * Once a packet containing a RESET_STREAM has been acknowledged, the sending part of
	 * the stream enters the "Reset Recvd" state, which is a terminal state.
	 */
	stream->send.state = update.state;
	quic_stream_put(streams, stream, quic_is_serv(sk), true); /* Release the send stream. */
	sk->sk_write_space(sk); /* Wake up processes blocked while attempting to open a stream. */
}

static void quic_frame_stop_sending_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_crypto_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_new_token_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_outqueue *outq = quic_outq(sk);

	outq->token_pending = 0; /* Clear flag so a new NEW_TOKEN frame can be sent if needed. */
}

static void quic_frame_stream_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream = frame->stream;
	struct quic_stream_update update;

	stream->send.frags--;
	if (stream->send.frags || stream->send.state != QUIC_STREAM_SEND_STATE_SENT)
		return; /* Skip if there are data in flight, or stream isn't in "Sent" state. */

	/* Notify that stream received all data by peer. */
	update.id = stream->id;
	update.state = QUIC_STREAM_SEND_STATE_RECVD;
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

	/* rfc9000#section-3.1:
	 *
	 * Once all stream data has been successfully acknowledged, the sending part of the
	 * stream enters the "Data Recvd" state, which is a terminal state.
	 */
	stream->send.state = update.state;
	quic_stream_put(streams, stream, quic_is_serv(sk), true); /* Release the send stream. */
	sk->sk_write_space(sk); /* Wake up processes blocked while attempting to open a stream. */
}

static void quic_frame_max_data_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_stream_data_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_streams_bidi_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_streams_uni_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_data_blocked_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_outqueue *outq = quic_outq(sk);

	/* Clear flag so a new DATA_BLOCKED frame can be sent if needed. */
	outq->data_blocked = 0;
}

static void quic_frame_stream_data_blocked_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_stream *stream = frame->stream;

	/* Clear flag so a new STREAM_DATA_BLOCKED frame can be sent if needed. */
	stream->send.data_blocked = 0;
}

static void quic_frame_streams_blocked_bidi_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_stream_table *streams = quic_streams(sk);

	/* Clear flag so a new STREAMS_BLOCKED_BIDI frame can be sent if needed. */
	streams->send.bidi_blocked = 0;
}

static void quic_frame_streams_blocked_uni_ack(struct sock *sk, struct quic_frame *frame)
{
	struct quic_stream_table *streams = quic_streams(sk);

	/* Clear flag so a new STREAMS_BLOCKED_UNI frame can be sent if needed. */
	streams->send.uni_blocked = 0;
}

static void quic_frame_new_conn_id_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_retire_conn_id_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_path_challenge_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_path_response_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_connection_close_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_handshake_done_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_invalid_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_datagram_ack(struct sock *sk, struct quic_frame *frame)
{
}

#define quic_frame_create_and_process_and_ack(type, eliciting) \
	{ \
		.frame_create	= quic_frame_##type##_create, \
		.frame_process	= quic_frame_##type##_process, \
		.frame_ack	= quic_frame_##type##_ack, \
		.ack_eliciting	= eliciting \
	}

static struct quic_frame_ops quic_frame_ops[QUIC_FRAME_MAX + 1] = {
	quic_frame_create_and_process_and_ack(padding, 0), /* 0x00 */
	quic_frame_create_and_process_and_ack(ping, 1),
	quic_frame_create_and_process_and_ack(ack, 0),
	quic_frame_create_and_process_and_ack(ack, 0), /* ack_ecn */
	quic_frame_create_and_process_and_ack(reset_stream, 1),
	quic_frame_create_and_process_and_ack(stop_sending, 1),
	quic_frame_create_and_process_and_ack(crypto, 1),
	quic_frame_create_and_process_and_ack(new_token, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(max_data, 1), /* 0x10 */
	quic_frame_create_and_process_and_ack(max_stream_data, 1),
	quic_frame_create_and_process_and_ack(max_streams_bidi, 1),
	quic_frame_create_and_process_and_ack(max_streams_uni, 1),
	quic_frame_create_and_process_and_ack(data_blocked, 1),
	quic_frame_create_and_process_and_ack(stream_data_blocked, 1),
	quic_frame_create_and_process_and_ack(streams_blocked_bidi, 1),
	quic_frame_create_and_process_and_ack(streams_blocked_uni, 1),
	quic_frame_create_and_process_and_ack(new_conn_id, 1),
	quic_frame_create_and_process_and_ack(retire_conn_id, 1),
	quic_frame_create_and_process_and_ack(path_challenge, 0),
	quic_frame_create_and_process_and_ack(path_response, 0),
	quic_frame_create_and_process_and_ack(connection_close, 0),
	quic_frame_create_and_process_and_ack(connection_close, 0),
	quic_frame_create_and_process_and_ack(handshake_done, 1),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0), /* 0x20 */
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(datagram, 1), /* 0x30 */
	quic_frame_create_and_process_and_ack(datagram, 1),
};

void quic_frame_ack(struct sock *sk, struct quic_frame *frame)
{
	quic_frame_ops[frame->type].frame_ack(sk, frame);

	list_del_init(&frame->list);
	frame->transmitted = 0;
	quic_frame_put(frame);
}

int quic_frame_process(struct sock *sk, struct quic_frame *frame)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 type, level = frame->level;
	int ret;

	if (!frame->len) {
		/* rfc9000#section-12.4:
		 *
		 * An endpoint MUST treat receipt of a packet containing no frames as a
		 * connection error of type PROTOCOL_VIOLATION.
		 */
		packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	while (frame->len > 0) {
		type = *frame->data++;
		frame->len--;

		if (type > QUIC_FRAME_MAX) {
			pr_debug("%s: unsupported frame, type: %x, level: %d\n",
				 __func__, type, level);
			/* rfc9000#section-12.4:
			 *
			 * An endpoint MUST treat the receipt of a frame of unknown type
			 * as a connection error of type FRAME_ENCODING_ERROR.
			 */
			packet->errcode = QUIC_TRANSPORT_ERROR_FRAME_ENCODING;
			return -EPROTONOSUPPORT;
		} else if (quic_frame_level_check(level, type)) {
			pr_debug("%s: invalid frame, type: %x, level: %d\n",
				 __func__, type, level);
			return -EINVAL;
		}
		ret = quic_frame_ops[type].frame_process(sk, frame, type);
		if (ret < 0) {
			pr_debug("%s: failed, type: %x, level: %d, err: %d\n",
				 __func__, type, level, ret);
			packet->errframe = type;
			packet->errcode = frame->errcode;
			return ret;
		}
		pr_debug("%s: done, type: %x, level: %d\n", __func__, type, level);
		if (quic_frame_ops[type].ack_eliciting) {
			packet->ack_requested = 1;
			/* Require immediate ACKs for non-stream or stream-FIN frames. */
			if (!quic_frame_stream(type) || (type & QUIC_STREAM_BIT_FIN))
				packet->ack_immediate = 1;
			/* rfc9000#section-9.1:
			 *
			 * PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames
			 * are "probing frames", and all other frames are "non-probing frames".
			 * (PATH_CHALLENGE, PATH_RESPONSE and PADDING are not ack_eliciting.)
			 */
			if (!quic_frame_new_conn_id(type))
				packet->non_probing = 1;
		}
		if (quic_frame_sack(type))
			packet->has_sack = 1;

		frame->data += ret;
		frame->len -= ret;
	}
	return 0;
}

struct quic_frame *quic_frame_create(struct sock *sk, u8 type, void *data)
{
	struct quic_frame *frame;

	if (type > QUIC_FRAME_MAX)
		return NULL;
	frame = quic_frame_ops[type].frame_create(sk, data, type);
	if (!frame) {
		pr_debug("%s: failed, type: %x\n", __func__, type);
		return NULL;
	}
	INIT_LIST_HEAD(&frame->list);
	if (!frame->type)
		frame->type = type;
	frame->ack_eliciting = quic_frame_ops[type].ack_eliciting;
	pr_debug("%s: done, type: %x, len: %u\n", __func__, type, frame->len);
	return frame;
}

struct quic_frame *quic_frame_alloc(u32 size, u8 *data, gfp_t gfp)
{
	struct quic_frame *frame;

	frame = kmem_cache_zalloc(quic_frame_cachep, gfp);
	if (!frame)
		return NULL;
	if (data) {
		frame->data = data;
		goto out;
	}
	frame->data = kmalloc(size, gfp);
	if (!frame->data) {
		kmem_cache_free(quic_frame_cachep, frame);
		return NULL;
	}
out:
	refcount_set(&frame->refcnt, 1);
	frame->offset = -1;
	frame->len = (u16)size;
	frame->size = frame->len;
	return frame;
}

static void quic_frame_free(struct quic_frame *frame)
{
	struct quic_frame_frag *frag, *next;

	/* Handle RX stream/crypto/dgram frames. Use !frame->type to detect RX,
	 * since frame->skb shares a union with frame->flist, used only on TX.
	 */
	if (!frame->type && frame->skb) {
		kfree_skb(frame->skb);
		goto out;
	}

	for (frag = frame->flist; frag; frag = next) {
		next = frag->next;
		kfree(frag);
	}
	kfree(frame->data);
out:
	kmem_cache_free(quic_frame_cachep, frame);
}

struct quic_frame *quic_frame_get(struct quic_frame *frame)
{
	refcount_inc(&frame->refcnt);
	return frame;
}

void quic_frame_put(struct quic_frame *frame)
{
	if (refcount_dec_and_test(&frame->refcnt))
		quic_frame_free(frame);
}

/* Appends stream data to a QUIC frame. */
int quic_frame_stream_append(struct sock *sk, struct quic_frame *frame,
			     struct quic_msginfo *info, u8 pack)
{
	struct quic_stream *stream = info->stream;
	u8 *p, type = frame->type, nodelay = 0;
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_frame_frag *frag, *pos;
	u64 wspace, offset = 0;

	/* Calculate header length: frame type + stream ID + (optional) offset + length. */
	hlen += quic_var_len(stream->id);
	offset = stream->send.bytes - frame->bytes;
	if (offset)
		hlen += quic_var_len(offset);
	max_frame_len = quic_packet_max_payload(quic_packet(sk)); /* MSS. */
	hlen += quic_var_len(max_frame_len);
	if (max_frame_len - hlen <= frame->bytes)
		return -1; /* Not enough space for any additional payload. */

	/* Trim msg_len to respect flow control and MSS constraints, similar to
	 * quic_frame_stream_create().
	 */
	msg_len = iov_iter_count(info->msg);
	wspace = quic_outq_wspace(sk, stream);
	if ((u64)msg_len <= wspace) {
		if (msg_len <= max_frame_len - hlen - frame->bytes) {
			if (info->flags & MSG_QUIC_STREAM_FIN)
				type |= QUIC_STREAM_BIT_FIN;
		} else {
			nodelay = 1;
			msg_len = max_frame_len - hlen - frame->bytes;
		}
	} else {
		msg_len = wspace;
		if (msg_len > max_frame_len - hlen - frame->bytes) {
			nodelay = 1;
			msg_len = max_frame_len - hlen - frame->bytes;
		}
	}
	if (!pack) /* Only calculating how much to append. */
		return msg_len;

	if (msg_len) { /* Attach data to frame as fragment. */
		frag = quic_frame_frag_alloc(msg_len);
		if (!frag)
			return -1;
		if (!copy_from_iter_full(frag->data, msg_len, info->msg)) {
			kfree(frag);
			return -1;
		}
		if (frame->flist) {
			pos = frame->flist;
			while (pos->next)
				pos = pos->next;
			pos->next = frag;
		} else {
			frame->flist = frag;
		}
	}

	/* Update stream data header and frame fields. */
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, stream->id);
	if (offset)
		p = quic_put_var(p, offset);
	p = quic_put_var(p, frame->bytes + msg_len);

	frame->type = type;
	frame->size = (u16)(p - frame->data);
	frame->bytes += msg_len;
	frame->len = frame->size + frame->bytes;
	frame->nodelay = nodelay;

	return msg_len;
}

/* rfc9000#section-18:
 *
 * Transport Parameter {
 *   Transport Parameter ID (i),
 *   Transport Parameter Length (i),
 *   Transport Parameter Value (..),
 * }
 */
static u8 *quic_frame_put_conn_id(u8 *p, u16 id, struct quic_conn_id *conn_id)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, conn_id->len);
	p = quic_put_data(p, conn_id->data, conn_id->len);
	return p;
}

/* rfc9368#section-3:
 *
 * Version Information {
 *   Chosen Version (32),
 *   Available Versions (32) ...,
 * }
 */
static u8 *quic_frame_put_version_info(u8 *p, u16 id, u32 version)
{
	u32 *versions, i, len = QUIC_VERSION_LEN;

	versions = quic_packet_compatible_versions(version);
	if (!versions)
		return p;

	for (i = 1; versions[i]; i++)
		len += QUIC_VERSION_LEN;
	p = quic_put_var(p, id);
	p = quic_put_var(p, len);
	p = quic_put_int(p, version, QUIC_VERSION_LEN);

	for (i = 1; versions[i]; i++)
		p = quic_put_int(p, versions[i], QUIC_VERSION_LEN);

	return p;
}

/* rfc9000#section-18.2:
 *
 * Preferred Address {
 *   IPv4 Address (32),
 *   IPv4 Port (16),
 *   IPv6 Address (128),
 *   IPv6 Port (16),
 *   Connection ID Length (8),
 *   Connection ID (..),
 *   Stateless Reset Token (128),
 * }
 */
static u8 *quic_frame_put_address(u8 *p, u16 id, union quic_addr *addr,
				  struct quic_conn_id *conn_id, u8 *token, struct sock *sk)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, QUIC_PREF_ADDR_LEN + 1 + conn_id->len + QUIC_CONN_ID_TOKEN_LEN);
	quic_set_pref_addr(sk, p, addr);
	p += QUIC_PREF_ADDR_LEN;

	p = quic_put_int(p, conn_id->len, 1);
	p = quic_put_data(p, conn_id->data, conn_id->len);
	p = quic_put_data(p, token, QUIC_CONN_ID_TOKEN_LEN);
	return p;
}

#define USEC_TO_MSEC(usec)	DIV_ROUND_UP((usec), 1000)
#define MSEC_TO_USEC(msec)	((msec) > U32_MAX / 1000 ? U32_MAX : (msec) * 1000)

/* Construct the full encoded transport parameters extension for a QUIC connection. */
int quic_frame_build_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					  u8 *data, u32 *len)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_path_group *paths = quic_paths(sk);
	u8 *p = data, token[QUIC_CONN_ID_TOKEN_LEN];
	struct quic_conn_id *scid, conn_id;
	struct quic_crypto *crypto;
	u16 param_id;

	scid = quic_conn_id_active(id_set);
	if (quic_is_serv(sk)) {
		crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
		/* rfc9000#section-10.3:
		 *
		 * A server includes the Destination Connection ID field from the first Initial
		 * packet it received from the client in the original_destination_connection_id
		 * transport parameter; if the server sent a Retry packet, this refers to the
		 * first Initial packet received before sending the Retry packet.
		 */
		param_id = QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID;
		p = quic_frame_put_conn_id(p, param_id, &paths->orig_dcid);
		if (params->stateless_reset) {
			/* rfc9000#section-10.3:
			 *
			 * Servers can also issue a stateless_reset_token transport parameter
			 * during the handshake that applies to the connection ID that it
			 * selected during the handshake.
			 */
			p = quic_put_var(p, QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
			p = quic_put_var(p, QUIC_CONN_ID_TOKEN_LEN);
			if (quic_crypto_generate_stateless_reset_token(crypto, scid->data,
								       scid->len, token,
								       QUIC_CONN_ID_TOKEN_LEN))
				return -1;
			p = quic_put_data(p, token, QUIC_CONN_ID_TOKEN_LEN);
		}
		if (paths->retry) {
			/* rfc9000#section-10.3:
			 *
			 * If it sends a Retry packet, a server also includes the Source
			 * Connection ID field from the Retry packet in the
			 * retry_source_connection_id transport parameter.
			 */
			param_id = QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID;
			p = quic_frame_put_conn_id(p, param_id, &paths->retry_dcid);
		}
		if (paths->pref_addr) {
			/* Write preferred address parameter with an associated conn ID and
			 * stateless reset token.
			 */
			quic_conn_id_generate(&conn_id);
			if (quic_crypto_generate_stateless_reset_token(crypto, conn_id.data,
								       conn_id.len, token,
								       QUIC_CONN_ID_TOKEN_LEN))
				return -1;
			if (quic_conn_id_add(id_set, &conn_id, 1, sk))
				return -1;
			param_id = QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS;
			p = quic_frame_put_address(p, param_id, quic_path_saddr(paths, 1),
						   &conn_id, token, sk);
		}
	}
	/* rfc9000#section-10.3:
	 *
	 * Each endpoint includes the value of the Source Connection ID field from the first
	 * Initial packet it sent in the initial_source_connection_id transport parameter.
	 */
	p = quic_frame_put_conn_id(p, QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID, scid);
	if (params->max_stream_data_bidi_local) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
				   params->max_stream_data_bidi_local);
	}
	if (params->max_stream_data_bidi_remote) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
				   params->max_stream_data_bidi_remote);
	}
	if (params->max_stream_data_uni) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
				   params->max_stream_data_uni);
	}
	if (params->max_data) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA,
				   params->max_data);
	}
	if (params->max_streams_bidi) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
				   params->max_streams_bidi);
	}
	if (params->max_streams_uni) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
				   params->max_streams_uni);
	}
	if (params->max_udp_payload_size != QUIC_MAX_UDP_PAYLOAD) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE,
				   params->max_udp_payload_size);
	}
	if (params->ack_delay_exponent != QUIC_DEF_ACK_DELAY_EXPONENT) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
				   params->ack_delay_exponent);
	}
	if (params->disable_active_migration) {
		p = quic_put_var(p, QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION);
		p = quic_put_var(p, 0);
	}
	if (params->disable_1rtt_encryption) {
		p = quic_put_var(p, QUIC_TRANSPORT_PARAM_DISABLE_1RTT_ENCRYPTION);
		p = quic_put_var(p, 0);
	}
	if (!params->disable_compatible_version) {
		p = quic_frame_put_version_info(p, QUIC_TRANSPORT_PARAM_VERSION_INFORMATION,
						quic_packet(sk)->version);
	}
	if (params->grease_quic_bit) {
		p = quic_put_var(p, QUIC_TRANSPORT_PARAM_GREASE_QUIC_BIT);
		p = quic_put_var(p, 0);
	}
	if (params->max_ack_delay != QUIC_DEF_ACK_DELAY) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY,
				   USEC_TO_MSEC(params->max_ack_delay));
	}
	if (params->max_idle_timeout) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
				   USEC_TO_MSEC(params->max_idle_timeout));
	}
	if (params->active_connection_id_limit &&
	    params->active_connection_id_limit != QUIC_CONN_ID_LEAST) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
				   params->active_connection_id_limit);
	}
	if (params->max_datagram_frame_size) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE,
				   params->max_datagram_frame_size);
	}
	*len = p - data;
	return 0;
}

/* Parse a QUIC Connection ID transport parameter. */
static int quic_frame_get_conn_id(struct quic_conn_id *conn_id, u8 **pp, u32 *plen)
{
	u64 valuelen;

	if (!quic_get_var(pp, plen, &valuelen))
		return -1;

	if ((u64)*plen < valuelen || valuelen > QUIC_CONN_ID_MAX_LEN)
		return -1;

	memcpy(conn_id->data, *pp, valuelen);
	conn_id->len = (u8)valuelen;

	*pp += valuelen;
	*plen -= valuelen;
	return 0;
}

#define QUIC_MAX_VERSIONS	16

/* Parse QUIC version information transport parameter. */
static int quic_frame_get_version_info(u32 *versions, u8 *count, u8 **pp, u32 *plen)
{
	u64 valuelen, v = 0;
	u8 i;

	if (!quic_get_var(pp, plen, &valuelen))
		return -1;

	if ((u64)*plen < valuelen || valuelen > QUIC_VERSION_LEN * QUIC_MAX_VERSIONS)
		return -1;

	*count = (u8)(valuelen / QUIC_VERSION_LEN);
	for (i = 0; i < *count; i++) {
		quic_get_int(pp, plen, &v, QUIC_VERSION_LEN);
		versions[i] = v;
	}
	return 0;
}

/* Parse Preferred Address transport parameter. */
static int quic_frame_get_address(union quic_addr *addr, struct quic_conn_id *conn_id,
				  u8 *token, u8 **pp, u32 *plen, struct sock *sk)
{
	u64 valuelen, len;

	if (!quic_get_var(pp, plen, &valuelen))
		return -1;

	if ((u64)*plen < valuelen || valuelen < QUIC_PREF_ADDR_LEN + 1)
		return -1;

	quic_get_pref_addr(sk, addr, pp, plen);

	if (!quic_get_int(pp, plen, &len, 1) || len > QUIC_CONN_ID_MAX_LEN)
		return -1;
	if (valuelen != QUIC_PREF_ADDR_LEN + 1 + len + QUIC_CONN_ID_TOKEN_LEN)
		return -1;

	conn_id->len = len;
	if (!quic_get_data(pp, plen, conn_id->data, conn_id->len))
		return -1;
	if (!quic_get_data(pp, plen, token, QUIC_CONN_ID_TOKEN_LEN))
		return -1;
	return 0;
}

/* Parse the full encoded transport parameters extension for a QUIC connection. */
int quic_frame_parse_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					  u8 *data, u32 len)
{
	u8 *p = data, count = 1, token[QUIC_CONN_ID_TOKEN_LEN];
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_conn_id *active, conn_id;
	u32 versions[QUIC_MAX_VERSIONS] = {};
	u64 type, value, valuelen;
	union quic_addr addr;

	/* Apply default values if the peer omits these transport parameters. */
	params->max_udp_payload_size = QUIC_MAX_UDP_PAYLOAD;
	params->ack_delay_exponent = QUIC_DEF_ACK_DELAY_EXPONENT;
	params->max_ack_delay = QUIC_DEF_ACK_DELAY;
	params->active_connection_id_limit = QUIC_CONN_ID_LEAST;

	active = quic_conn_id_active(id_set);
	versions[0] = packet->version;
	while (len > 0) {
		if (!quic_get_var(&p, &len, &type))
			return -1;

		switch (type) {
		case QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID:
			if (quic_is_serv(sk))
				return -1;
			if (quic_frame_get_conn_id(&conn_id, &p, &len))
				return -1;
			/* Validate original_destination_connection_id sent by the server. */
			if (quic_conn_id_cmp(&paths->orig_dcid, &conn_id))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID:
			if (quic_is_serv(sk) || !paths->retry)
				return -1;
			if (quic_frame_get_conn_id(&conn_id, &p, &len))
				return -1;
			/* Validate retry_source_connection_id sent by the server. */
			if (quic_conn_id_cmp(&paths->retry_dcid, &conn_id))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID:
			if (quic_frame_get_conn_id(&conn_id, &p, &len))
				return -1;
			/* Validate initial_source_connection_id sent by the peer. */
			if (quic_conn_id_cmp(active, &conn_id))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			if (!quic_get_param(&params->max_stream_data_bidi_local, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			if (!quic_get_param(&params->max_stream_data_bidi_remote, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
			if (!quic_get_param(&params->max_stream_data_uni, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
			if (!quic_get_param(&params->max_data, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			/* Limit the number of bidirectional streams to avoid exhausting system
			 * memory.
			 */
			if (value > QUIC_MAX_STREAMS)
				value = QUIC_MAX_STREAMS;
			params->max_streams_bidi = value;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			/* Limit the number of unidirectional streams to avoid exhausting system
			 * memory.
			 */
			if (value > QUIC_MAX_STREAMS)
				value = QUIC_MAX_STREAMS;
			params->max_streams_uni = value;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			value = MSEC_TO_USEC(value);
			if (value < QUIC_MIN_IDLE_TIMEOUT)
				return -1;
			params->max_idle_timeout = value;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			if (value < QUIC_MIN_UDP_PAYLOAD || value > QUIC_MAX_UDP_PAYLOAD)
				return -1;
			params->max_udp_payload_size = value;
			break;
		case QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			if (value > QUIC_MAX_ACK_DELAY_EXPONENT)
				return -1;
			params->ack_delay_exponent = value;
			break;
		case QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION:
			if (!quic_get_var(&p, &len, &valuelen))
				return -1;
			if (valuelen)
				return -1;
			params->disable_active_migration = 1;
			break;
		case QUIC_TRANSPORT_PARAM_DISABLE_1RTT_ENCRYPTION:
			if (!quic_get_var(&p, &len, &valuelen) || (u64)len < valuelen)
				return -1;
			if (!quic_is_serv(sk) && valuelen)
				return -1;
			params->disable_1rtt_encryption = 1;
			len -= valuelen;
			p += valuelen;
			break;
		case QUIC_TRANSPORT_PARAM_GREASE_QUIC_BIT:
			if (!quic_get_var(&p, &len, &valuelen))
				return -1;
			if (valuelen)
				return -1;
			params->grease_quic_bit = 1;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			value = MSEC_TO_USEC(value);
			if (value >= QUIC_MAX_ACK_DELAY)
				return -1;
			params->max_ack_delay = value;
			break;
		case QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			if (value < QUIC_CONN_ID_LEAST || value > QUIC_CONN_ID_LIMIT)
				return -1;
			params->active_connection_id_limit = value;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE:
			if (!quic_get_param(&value, &p, &len))
				return -1;
			if (value && value < QUIC_PATH_MIN_PMTU)
				return -1;
			params->max_datagram_frame_size = value;
			break;
		case QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
			if (quic_is_serv(sk))
				return -1;
			if (!quic_get_var(&p, &len, &valuelen) || (u64)len < valuelen ||
			    valuelen != QUIC_CONN_ID_TOKEN_LEN)
				return -1;
			quic_conn_id_set_token(active, p);
			params->stateless_reset = 1;
			len -= valuelen;
			p += valuelen;
			break;
		case QUIC_TRANSPORT_PARAM_VERSION_INFORMATION:
			if (quic_frame_get_version_info(versions, &count, &p, &len))
				return -1;
			/* rfc9368#section-3:
			 *
			 * The version that the sender has chosen to use for this connection.
			 * In most cases, this field will be equal to the value of the Version
			 * field in the long header that carries this data.
			 */
			if (!count || versions[0] != packet->version)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS:
			if (quic_is_serv(sk))
				return -1;
			if (quic_frame_get_address(&addr, &conn_id, token, &p, &len, sk))
				return -1;
			if (quic_conn_id_add(id_set, &conn_id, 1, token))
				return -1;
			/* Mark and set preferred address if it's valid and differs from the
			 * original.
			 */
			if (addr.v4.sin_port &&
			    !quic_cmp_sk_addr(sk, quic_path_daddr(paths, 0), &addr)) {
				paths->pref_addr = 1;
				quic_path_set_daddr(paths, 1, &addr);
			}
			break;
		default:
			/* Ignore unknown parameter. */
			if (!quic_get_var(&p, &len, &valuelen) || (u64)len < valuelen)
				return -1;
			len -= valuelen;
			p += valuelen;
			break;
		}
	}

	return quic_packet_select_version(sk, versions, count);
}
