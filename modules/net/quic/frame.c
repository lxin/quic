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

#include <linux/nospec.h>

#include "socket.h"

/* ACK Frame {
 *  Type (i) = 0x02..0x03,
 *  Largest Acknowledged (i),
 *  ACK Delay (i),
 *  ACK Range Count (i),
 *  First ACK Range (i),
 *  ACK Range (..) ...,
 *  [ECN Counts (..)],
 * }
 */

static bool quic_frame_copy_from_iter_full(void *addr, size_t bytes, struct iov_iter *i)
{
	size_t copied = _copy_from_iter(addr, bytes, i);

	if (likely(copied == bytes))
		return true;
	iov_iter_revert(i, copied);
	return false;
}

static struct quic_frame *quic_frame_ack_create(struct sock *sk, void *data, u8 type)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	u64 largest, smallest, range, delay, *ecn_count;
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p, level = *((u8 *)data);
	struct quic_pnspace *space;
	u32 frame_len, num_gabs, i;
	struct quic_frame *frame;

	space = quic_pnspace(sk, level);
	type += quic_pnspace_has_ecn_count(space);
	num_gabs = quic_pnspace_num_gabs(space, gabs);
	frame_len = sizeof(type) + sizeof(u32) * 7;
	frame_len += sizeof(struct quic_gap_ack_block) * num_gabs;

	largest = quic_pnspace_max_pn_seen(space);
	smallest = quic_pnspace_min_pn_seen(space);
	if (num_gabs)
		smallest = quic_pnspace_base_pn(space) + gabs[num_gabs - 1].end;
	range = largest - smallest;
	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	delay = jiffies_to_usecs(jiffies) - quic_pnspace_max_pn_time(space);
	delay >>= quic_outq_ack_delay_exponent(outq);
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, largest); /* Largest Acknowledged */
	p = quic_put_var(p, delay); /* ACK Delay */
	p = quic_put_var(p, num_gabs); /* ACK Count */
	p = quic_put_var(p, range); /* First ACK Range */

	if (num_gabs) {
		for (i = num_gabs - 1; i > 0; i--) {
			p = quic_put_var(p, gabs[i].end - gabs[i].start); /* Gap */
			/* ACK Range Length */
			p = quic_put_var(p, gabs[i].start - gabs[i - 1].end - 2);
		}
		p = quic_put_var(p, gabs[0].end - gabs[0].start); /* Gap */
		range = gabs[0].start - 1 + quic_pnspace_base_pn(space);
		range -= (quic_pnspace_min_pn_seen(space) + 1);
		p = quic_put_var(p, range); /* ACK Range Length */
	}
	if (type == QUIC_FRAME_ACK_ECN) {
		ecn_count = quic_pnspace_ecn_count(space);
		p = quic_put_var(p, ecn_count[1]); /* ECT0 Count */
		p = quic_put_var(p, ecn_count[0]); /* ECT1 Count */
		p = quic_put_var(p, ecn_count[2]); /* ECN-CE Count */
	}
	frame->type = type;
	frame->len = (u16)(p - frame->data);
	frame->size = frame->len;
	frame->level = (level % QUIC_CRYPTO_EARLY);

	return frame;
}

static struct quic_frame *quic_frame_ping_create(struct sock *sk, void *data, u8 type)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_frame *frame;
	u32 *probe_size = data;
	u32 frame_len = 1;

	if (*probe_size > packet->overhead)
		frame_len = *probe_size - packet->overhead;

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;

	quic_put_var(frame->data, type);
	if (frame_len > 1) {
		memset(frame->data + 1, 0, frame_len - 1);
		frame->padding = 1;
	}

	return frame;
}

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

static struct quic_frame *quic_frame_new_token_create(struct sock *sk, void *data, u8 type)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_conn_id_set *id_set = quic_source(sk);
	union quic_addr *da = quic_path_addr(quic_dst(sk), 0);
	struct quic_frame *frame;
	u8 token[72], *p;
	u32 tokenlen;

	quic_put_int(token, 0, 1); /* regular token */
	if (quic_crypto_generate_token(crypto, da, quic_addr_len(sk),
				       quic_conn_id_active(id_set), token, &tokenlen))
		return NULL;

	frame = quic_frame_alloc(tokenlen + 4, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, tokenlen);
	p = quic_put_data(p, token, tokenlen);
	frame->len = (u16)(p - frame->data);
	frame->size = frame->len;

	return frame;
}

static struct quic_frame_frag *quic_frame_frag_alloc(u16 size)
{
	struct quic_frame_frag *frag;

	frag = kzalloc(sizeof(*frag) + size, GFP_ATOMIC);
	if (frag)
		frag->size = size;

	return frag;
}

/* STREAM Frame {
 *  Type (i) = 0x08..0x0f,
 *  Stream ID (i),
 *  [Offset (i)],
 *  [Length (i)],
 *  Stream Data (..),
 * }
 */

static struct quic_frame *quic_frame_stream_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_msginfo *info = data;
	struct quic_frame_frag *frag;
	struct quic_stream *stream;
	struct quic_frame *frame;
	u8 *p, nodelay = 0;

	stream = info->stream;
	hlen += quic_var_len(stream->id);
	if (stream->send.offset) {
		type |= QUIC_STREAM_BIT_OFF;
		hlen += quic_var_len(stream->send.offset);
	}
	type |= QUIC_STREAM_BIT_LEN;
	max_frame_len = quic_packet_max_payload(quic_packet(sk));
	hlen += quic_var_len(max_frame_len);

	msg_len = iov_iter_count(info->msg);
	if (msg_len <= sk_stream_wspace(sk)) {
		if (msg_len <= max_frame_len - hlen) {
			if (info->flags & MSG_STREAM_FIN)
				type |= QUIC_STREAM_BIT_FIN;
		} else {
			nodelay = 1;
			msg_len = max_frame_len - hlen;
		}
	} else {
		msg_len = sk_stream_wspace(sk);
		if (msg_len > max_frame_len - hlen) {
			nodelay = 1;
			msg_len = max_frame_len - hlen;
		}
	}

	frame = quic_frame_alloc(hlen, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	frame->stream = stream;

	/* attach the data into frag list */
	if (msg_len) {
		frag = quic_frame_frag_alloc(msg_len);
		if (!frag) {
			quic_frame_put(frame);
			return NULL;
		}
		if (!quic_frame_copy_from_iter_full(frag->data, msg_len, info->msg)) {
			quic_frame_put(frame);
			kfree(frag);
			return NULL;
		}
		frame->flist = frag;
	}

	/* set up stream data header and frame fields */
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, stream->id);
	if (type & QUIC_STREAM_BIT_OFF)
		p = quic_put_var(p, stream->send.offset);
	p = quic_put_var(p, msg_len);

	frame->type = type;
	frame->size = (u16)(p - frame->data);
	frame->bytes = (u16)msg_len;
	frame->len = frame->size + frame->bytes;
	frame->nodelay = nodelay;

	stream->send.offset += msg_len;
	return frame;
}

int quic_frame_stream_append(struct sock *sk, struct quic_frame *frame,
			     struct quic_msginfo *info, u8 pack)
{
	struct quic_stream *stream = info->stream;
	u8 *p, type = frame->type, nodelay = 0;
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_frame_frag *frag, *pos;
	u64 offset = 0;

	hlen += quic_var_len(stream->id);
	offset = stream->send.offset - frame->bytes;
	if (offset)
		hlen += quic_var_len(offset);
	max_frame_len = quic_packet_max_payload(quic_packet(sk));
	hlen += quic_var_len(max_frame_len);
	if (max_frame_len - hlen <= frame->bytes)
		return -1;

	msg_len = iov_iter_count(info->msg);
	if (msg_len <= sk_stream_wspace(sk)) {
		if (msg_len <= max_frame_len - hlen - frame->bytes) {
			if (info->flags & MSG_STREAM_FIN)
				type |= QUIC_STREAM_BIT_FIN;
		} else {
			nodelay = 1;
			msg_len = max_frame_len - hlen - frame->bytes;
		}
	} else {
		msg_len = sk_stream_wspace(sk);
		if (msg_len > max_frame_len - hlen - frame->bytes) {
			nodelay = 1;
			msg_len = max_frame_len - hlen - frame->bytes;
		}
	}
	if (!pack)
		return msg_len;

	/* attach the data into frag list */
	if (msg_len) {
		frag = quic_frame_frag_alloc(msg_len);
		if (!frag)
			return -1;
		if (!quic_frame_copy_from_iter_full(frag->data, msg_len, info->msg)) {
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

	/* update stream data header and frame fields */
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

	stream->send.offset += msg_len;
	return msg_len;
}

static struct quic_frame *quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type)
{
	struct quic_frame *frame;
	u8 *p, buf[4];
	u32 frame_len;

	p = quic_put_var(buf, type);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_crypto_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_msginfo *info = data;
	struct quic_crypto *crypto;
	struct quic_frame *frame;
	u64 offset;
	u8 *p;

	max_frame_len = quic_packet_max_payload(quic_packet(sk));
	crypto = quic_crypto(sk, info->level);
	msg_len = iov_iter_count(info->msg);

	if (!info->level) {
		offset = 0;
		hlen += quic_var_len(offset);
		hlen += quic_var_len(max_frame_len);
		if (msg_len > max_frame_len - hlen)
			return NULL;

		frame = quic_frame_alloc(msg_len + hlen, NULL, GFP_ATOMIC);
		if (!frame)
			return NULL;
		p = quic_put_var(frame->data, type);
		p = quic_put_var(p, offset);
		p = quic_put_var(p, msg_len);
		if (!quic_frame_copy_from_iter_full(p, msg_len, info->msg)) {
			quic_frame_put(frame);
			return NULL;
		}
		p += msg_len;
		frame->bytes = (u16)msg_len;
		frame->len = (u16)(p - frame->data);
		frame->size = frame->len;

		return frame;
	}

	offset = quic_crypto_send_offset(crypto);
	hlen += quic_var_len(offset);
	hlen += quic_var_len(max_frame_len);
	if (msg_len > max_frame_len - hlen)
		msg_len = max_frame_len - hlen;

	frame = quic_frame_alloc(msg_len + hlen, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, offset);
	p = quic_put_var(p, msg_len);
	if (!quic_frame_copy_from_iter_full(p, msg_len, info->msg)) {
		quic_frame_put(frame);
		return NULL;
	}
	p += msg_len;
	frame->bytes = (u16)msg_len;
	frame->len = (u16)(p - frame->data);
	frame->size = frame->len;

	frame->level = info->level;
	quic_crypto_inc_send_offset(crypto, msg_len);
	return frame;
}

static struct quic_frame *quic_frame_retire_conn_id_create(struct sock *sk, void *data, u8 type)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_connection_id_info info = {};
	struct quic_conn_id *active;
	struct quic_frame *frame;
	u64 *seqno = data;
	u8 *p, buf[12];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *seqno);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	quic_conn_id_remove(id_set, *seqno);

	info.dest = 1;
	info.prior_to =  quic_conn_id_first_number(id_set);
	active = quic_conn_id_active(id_set);
	info.active = quic_conn_id_number(active);
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_ID, &info);
	return frame;
}

static struct quic_frame *quic_frame_new_conn_id_create(struct sock *sk, void *data, u8 type)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_conn_id scid = {};
	u8 *p, buf[100], token[16];
	u64 *prior = data, seqno;
	struct quic_frame *frame;
	u32 frame_len;
	int err;

	seqno = quic_conn_id_last_number(quic_source(sk)) + 1;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, seqno);
	p = quic_put_var(p, *prior);
	quic_conn_id_generate(&scid);
	p = quic_put_var(p, scid.len);
	p = quic_put_data(p, scid.data, scid.len);
	if (quic_crypto_generate_stateless_reset_token(crypto, scid.data, scid.len, token, 16))
		return NULL;
	p = quic_put_data(p, token, 16);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	err = quic_conn_id_add(quic_source(sk), &scid, seqno, sk);
	if (err) {
		quic_frame_put(frame);
		return NULL;
	}

	return frame;
}

static struct quic_frame *quic_frame_path_response_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, buf[12], *entropy = data;
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_data(p, entropy, 8);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_path_addr *path = data;
	struct quic_frame *frame;
	u32 frame_len;
	u8 *p;

	if (quic_packet_config(sk, QUIC_CRYPTO_APP, 0))
		return NULL;

	frame_len = QUIC_MIN_UDP_PAYLOAD - packet->overhead;
	get_random_bytes(quic_path_entropy(path), 8);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	p = quic_put_var(frame->data, type);
	p = quic_put_data(p, quic_path_entropy(path), 8);
	memset(p, 0, frame_len - 1 - 8);
	frame->padding = 1;

	return frame;
}

static struct quic_frame *quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_errinfo *info = data;
	struct quic_stream *stream;
	struct quic_frame *frame;
	u8 *p, buf[28];
	u32 frame_len;

	stream = quic_stream_find(streams, info->stream_id);
	WARN_ON(!stream);

	p = quic_put_var(buf, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	p = quic_put_var(p, stream->send.offset);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	stream->send.errcode = info->errcode;
	frame->stream = stream;

	if (quic_stream_send_active_id(streams) == stream->id)
		quic_stream_set_send_active_id(streams, -1);

	return frame;
}

static struct quic_frame *quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type)
{
	struct quic_errinfo *info = data;
	struct quic_frame *frame;
	u8 *p, buf[20];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_max_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_inqueue *inq = data;
	struct quic_frame *frame;
	u8 *p, buf[12];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_inq_max_bytes(inq));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream *stream = data;
	struct quic_frame *frame;
	u8 *p, buf[20];
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

static struct quic_frame *quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type)
{
	struct quic_frame *frame;
	u64 *max = data;
	u8 *p, buf[12];
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

static struct quic_frame *quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type)
{
	struct quic_frame *frame;
	u64 *max = data;
	u8 *p, buf[12];
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

static struct quic_frame *quic_frame_connection_close_create(struct sock *sk, void *data, u8 type)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 frame_len, phrase_len = 0;
	u8 *p, buf[100], *phrase;
	struct quic_frame *frame;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_outq_close_errcode(outq));

	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		p = quic_put_var(p, quic_outq_close_frame(outq));

	phrase = quic_outq_close_phrase(outq);
	if (phrase)
		phrase_len = strlen(phrase);
	p = quic_put_var(p, phrase_len);
	p = quic_put_data(p, phrase, phrase_len);

	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	struct quic_outqueue *outq = data;
	struct quic_frame *frame;
	u8 *p, buf[12];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_outq_max_bytes(outq));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_stream_data_blocked_create(struct sock *sk,
								void *data, u8 type)
{
	struct quic_stream *stream = data;
	struct quic_frame *frame;
	u8 *p, buf[20];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->send.max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);
	frame->stream = stream;

	return frame;
}

static struct quic_frame *quic_frame_streams_blocked_uni_create(struct sock *sk,
								void *data, u8 type)
{
	struct quic_frame *frame;
	s64 *max = data;
	u8 *p, buf[12];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_stream_id_to_streams(*max));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static struct quic_frame *quic_frame_streams_blocked_bidi_create(struct sock *sk,
								 void *data, u8 type)
{
	struct quic_frame *frame;
	s64 *max = data;
	u8 *p, buf[12];
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_stream_id_to_streams(*max));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

static int quic_frame_crypto_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_data *ticket = quic_ticket(sk);
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 offset, length;
	int err;

	if (!quic_get_var(&p, &len, &offset))
		return -EINVAL;
	if (!quic_get_var(&p, &len, &length) || length > len)
		return -EINVAL;

	if (!frame->level) {
		if (quic_data_dup(ticket, p, length))
			return -ENOMEM;
		quic_inq_event_recv(sk, QUIC_EVENT_NEW_SESSION_TICKET, ticket);
		goto out;
	}

	nframe = quic_frame_alloc(length, p, GFP_ATOMIC);
	if (!nframe)
		return -ENOMEM;
	nframe->skb = skb_get(frame->skb);

	nframe->offset = offset;
	nframe->level = frame->level;

	err = quic_inq_handshake_recv(sk, nframe);
	if (err) {
		frame->errcode = nframe->errcode;
		quic_frame_put(nframe);
		return err;
	}
out:
	len -= length;
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

	stream = quic_stream_recv_get(streams, (s64)stream_id, quic_is_serv(sk));
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOSTR)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		goto out;
	}

	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		goto out;

	nframe = quic_frame_alloc(payload_len, p, GFP_ATOMIC);
	if (!nframe)
		return -ENOMEM;
	nframe->skb = skb_get(frame->skb); /* use the data from skb */

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
	u64 largest, smallest, range, delay, count, gap, i, ecn_count[3];
	u8 *p = frame->data, level = frame->level;
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_pnspace *space;
	u32 len = frame->len;

	if (!quic_get_var(&p, &len, &largest) ||
	    !quic_get_var(&p, &len, &delay) ||
	    !quic_get_var(&p, &len, &count) || count > QUIC_PN_MAX_GABS ||
	    !quic_get_var(&p, &len, &range))
		return -EINVAL;

	space = quic_pnspace(sk, level);
	if ((s64)largest >= quic_pnspace_next_pn(space)) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	smallest = largest - range;
	delay <<= quic_inq_ack_delay_exponent(inq);
	quic_outq_transmitted_sack(sk, level, (s64)largest, (s64)smallest, (s64)largest, delay);

	for (i = 0; i < count; i++) {
		if (!quic_get_var(&p, &len, &gap) ||
		    !quic_get_var(&p, &len, &range))
			return -EINVAL;
		largest = smallest - gap - 2;
		smallest = largest - range;
		quic_outq_transmitted_sack(sk, level, (s64)largest, (s64)smallest, -1, 0);
	}

	if (type == QUIC_FRAME_ACK_ECN) {
		if (!quic_get_var(&p, &len, &ecn_count[1]) ||
		    !quic_get_var(&p, &len, &ecn_count[0]) ||
		    !quic_get_var(&p, &len, &ecn_count[2]))
			return -EINVAL;
		if (quic_pnspace_set_ecn_count(space, ecn_count)) {
			quic_cong_on_process_ecn(cong);
			quic_outq_sync_window(sk, quic_cong_window(cong));
		}
	}

	return (int)(frame->len - len);
}

static int quic_frame_new_conn_id_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	u64 seqno, prior, length, first;
	u8 *p = frame->data, *token;
	struct quic_frame *nframe;
	struct quic_conn_id dcid;
	u32 len = frame->len;
	int err;

	if (!quic_get_var(&p, &len, &seqno) ||
	    !quic_get_var(&p, &len, &prior) ||
	    !quic_get_var(&p, &len, &length) ||
	    !length || length > QUIC_CONN_ID_MAX_LEN || length + 16 > len)
		return -EINVAL;

	memcpy(dcid.data, p, length);
	dcid.len = (u8)length;
	token = p + length;

	if (prior > seqno)
		return -EINVAL;

	first = quic_conn_id_first_number(id_set);
	if (prior < first)
		prior = first;
	if (seqno - prior + 1 > quic_conn_id_max_count(id_set)) {
		frame->errcode = QUIC_TRANSPORT_ERROR_CONNECTION_ID_LIMIT;
		return -EINVAL;
	}

	err = quic_conn_id_add(id_set, &dcid, seqno, token);
	if (err)
		return err;

	for (; first < prior; first++) {
		nframe = quic_frame_create(sk, QUIC_FRAME_RETIRE_CONNECTION_ID, &first);
		if (!nframe)
			return -ENOMEM;
		nframe->path_alt = frame->path_alt;
		quic_outq_ctrl_tail(sk, nframe, true);
	}

	len -= (length + 16);
	return (int)(frame->len - len);
}

static int quic_frame_retire_conn_id_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_connection_id_info info = {};
	struct quic_conn_id *active;
	struct quic_frame *nframe;
	u64 seqno, last, first;
	u32 len = frame->len;
	u8 *p = frame->data;

	if (!quic_get_var(&p, &len, &seqno))
		return -EINVAL;
	first = quic_conn_id_first_number(id_set);
	if (seqno < first) /* dup */
		goto out;
	last  = quic_conn_id_last_number(id_set);
	if (seqno != first || seqno == last) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	quic_conn_id_remove(id_set, seqno);
	info.prior_to =  quic_conn_id_first_number(id_set);
	active = quic_conn_id_active(id_set);
	info.active = quic_conn_id_number(active);
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_ID, &info);

	if (last - seqno >= quic_conn_id_max_count(id_set))
		goto out;
	seqno++;
	nframe = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &seqno);
	if (!nframe)
		return -ENOMEM;
	nframe->path_alt = frame->path_alt;
	quic_outq_ctrl_tail(sk, nframe, true);
out:
	return (int)(frame->len - len);
}

static int quic_frame_new_token_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_data *token = quic_token(sk);
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 length;

	if (quic_is_serv(sk)) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	if (!quic_get_var(&p, &len, &length) || length > len)
		return -EINVAL;

	if (quic_data_dup(token, p, length))
		return -ENOMEM;
	quic_inq_event_recv(sk, QUIC_EVENT_NEW_TOKEN, token);

	len -= length;
	return (int)(frame->len - len);
}

static int quic_frame_handshake_done_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	if (quic_is_serv(sk)) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}
	/* some implementations don't send ACKs to handshake packets, so ACK them manually */
	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_INITIAL, QUIC_PN_MAP_MAX_PN, 0, -1, 0);
	quic_outq_transmitted_sack(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAP_MAX_PN, 0, -1, 0);

	if (quic_outq_pref_addr(quic_outq(sk)))
		quic_sock_change_daddr(sk, NULL, 0);
	return 0; /* no content */
}

static int quic_frame_padding_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	u8 *p = frame->data;

	for (; !(*p) && p != frame->data + frame->len; p++)
		;
	return (int)(p - frame->data);
}

static int quic_frame_ping_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return 0; /* no content */
}

static int quic_frame_path_challenge_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 entropy[8];

	if (len < 8)
		return -EINVAL;
	memcpy(entropy, frame->data, 8);
	nframe = quic_frame_create(sk, QUIC_FRAME_PATH_RESPONSE, entropy);
	if (!nframe)
		return -ENOMEM;
	nframe->path_alt = frame->path_alt;
	quic_outq_ctrl_tail(sk, nframe, true);

	len -= 8;
	return (int)(frame->len - len);
}

static int quic_frame_reset_stream_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
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

	stream = quic_stream_recv_get(streams, (s64)stream_id, quic_is_serv(sk));
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOMEM)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		goto out;
	}

	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		goto out;

	if (finalsz < stream->recv.highest ||
	    (stream->recv.finalsz && stream->recv.finalsz != finalsz)) {
		frame->errcode = QUIC_TRANSPORT_ERROR_FINAL_SIZE;
		return -EINVAL;
	}

	update.id = (s64)stream_id;
	update.state = QUIC_STREAM_RECV_STATE_RESET_RECVD;
	update.errcode = errcode;
	update.finalsz = finalsz;
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

	stream->recv.state = update.state;
	stream->recv.finalsz = update.finalsz;
	quic_inq_stream_list_purge(sk, stream);
	quic_stream_recv_put(streams, stream, quic_is_serv(sk));
out:
	return (int)(frame->len - len);
}

static int quic_frame_stop_sending_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream_update update = {};
	struct quic_stream *stream;
	struct quic_frame *nframe;
	struct quic_errinfo info;
	u64 stream_id, errcode;
	u32 len = frame->len;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &errcode))
		return -EINVAL;

	stream = quic_stream_send_get(streams, (s64)stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOMEM)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		return err;
	}

	info.stream_id = (s64)stream_id;
	info.errcode = errcode;
	nframe = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, &info);
	if (!nframe)
		return -ENOMEM;

	update.id = (s64)stream_id;
	update.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	update.errcode = errcode;
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

	stream->send.state = update.state;
	quic_outq_stream_list_purge(sk, stream);
	quic_outq_ctrl_tail(sk, nframe, true);
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

	if (max_bytes >= quic_outq_max_bytes(outq))
		quic_outq_set_max_bytes(outq, max_bytes);

	return (int)(frame->len - len);
}

static int quic_frame_max_stream_data_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream;
	u64 max_bytes, stream_id;
	u32 len = frame->len;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	stream = quic_stream_send_get(streams, (s64)stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOMEM)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		return err;
	}

	if (max_bytes >= stream->send.max_bytes)
		stream->send.max_bytes = max_bytes;

	return (int)(frame->len - len);
}

static int quic_frame_max_streams_uni_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = quic_stream_send_max_uni_id(streams);
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;

	if (max <= quic_stream_id_to_streams(stream_id))
		goto out;

	type = QUIC_STREAM_TYPE_CLIENT_UNI;
	if (quic_is_serv(sk))
		type = QUIC_STREAM_TYPE_SERVER_UNI;
	stream_id = quic_stream_streams_to_id(max, type);
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_STREAM, &stream_id);

	quic_stream_set_send_max_uni_id(streams, stream_id);
	sk->sk_write_space(sk);
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

	stream_id = quic_stream_send_max_bidi_id(streams);
	if (max <= quic_stream_id_to_streams(stream_id))
		goto out;

	type = QUIC_STREAM_TYPE_CLIENT_BIDI;
	if (quic_is_serv(sk))
		type = QUIC_STREAM_TYPE_SERVER_BIDI;
	stream_id = quic_stream_streams_to_id(max, type);
	quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_STREAM, &stream_id);

	quic_stream_set_send_max_bidi_id(streams, stream_id);
	sk->sk_write_space(sk);
out:
	return (int)(frame->len - len);
}

static int quic_frame_connection_close_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_connection_close *close;
	u64 err_code, phrase_len, ftype = 0;
	u8 *p = frame->data, buf[100] = {};
	u32 len = frame->len;

	if (!quic_get_var(&p, &len, &err_code))
		return -EINVAL;
	if (type == QUIC_FRAME_CONNECTION_CLOSE && !quic_get_var(&p, &len, &ftype))
		return -EINVAL;
	if (type == QUIC_FRAME_CONNECTION_CLOSE_APP && frame->level != QUIC_CRYPTO_APP) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	if (!quic_get_var(&p, &len, &phrase_len) || phrase_len > len)
		return -EINVAL;

	close = (void *)buf;
	if (phrase_len) {
		if (phrase_len > QUIC_CLOSE_PHRASE_MAX_LEN)
			return -EINVAL;
		memcpy(close->phrase, p, phrase_len);
	}
	close->errcode = err_code;
	close->frame = (u8)ftype;
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close);

	quic_set_state(sk, QUIC_SS_CLOSED);
	pr_debug("%s: errcode: %d, frame: %d\n", __func__, close->errcode, close->frame);

	len -= phrase_len;
	return (int)(frame->len - len);
}

static int quic_frame_data_blocked_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_inqueue *inq = quic_inq(sk);
	u64 max_bytes, recv_max_bytes;
	u32 window, len = frame->len;
	struct quic_frame *nframe;
	u8 *p = frame->data;

	if (!quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;
	recv_max_bytes = quic_inq_max_bytes(inq);

	window = quic_inq_window(inq);
	if (quic_under_memory_pressure(sk))
		window >>= 1;

	quic_inq_set_max_bytes(inq, quic_inq_bytes(inq) + window);
	nframe = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
	if (!nframe) {
		quic_inq_set_max_bytes(inq, recv_max_bytes);
		return -ENOMEM;
	}
	quic_outq_ctrl_tail(sk, nframe, true);
	return (int)(frame->len - len);
}

static int quic_frame_stream_data_blocked_process(struct sock *sk, struct quic_frame *frame,
						  u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u64 stream_id, max_bytes, recv_max_bytes;
	u32 window, len = frame->len;
	struct quic_stream *stream;
	struct quic_frame *nframe;
	u8 *p = frame->data;
	int err;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	stream = quic_stream_recv_get(streams, (s64)stream_id, quic_is_serv(sk));
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		if (err == -EAGAIN)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_LIMIT;
		else if (err != -ENOMEM)
			frame->errcode = QUIC_TRANSPORT_ERROR_STREAM_STATE;
		goto out;
	}

	if (stream->recv.state >= QUIC_STREAM_RECV_STATE_RECVD)
		goto out;

	window = stream->recv.window;
	if (quic_under_memory_pressure(sk))
		window >>= 1;

	recv_max_bytes = stream->recv.max_bytes;
	stream->recv.max_bytes = stream->recv.bytes + window;
	nframe = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream);
	if (!nframe) {
		stream->recv.max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
	quic_outq_ctrl_tail(sk, nframe, true);
out:
	return (int)(frame->len - len);
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk, struct quic_frame *frame,
						  u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = quic_stream_recv_max_uni_id(streams);
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 *p = frame->data;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;
	if (max > quic_stream_id_to_streams(stream_id))
		goto out;
	max = quic_stream_id_to_streams(stream_id);
	nframe = quic_frame_create(sk, QUIC_FRAME_MAX_STREAMS_UNI, &max);
	if (!nframe)
		return -ENOMEM;
	quic_outq_ctrl_tail(sk, nframe, true);
out:
	return (int)(frame->len - len);
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk, struct quic_frame *frame,
						   u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_frame *nframe;
	u32 len = frame->len;
	u8 *p = frame->data;
	s64 stream_id;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;
	stream_id = quic_stream_recv_max_bidi_id(streams);
	if (max > quic_stream_id_to_streams(stream_id))
		goto out;
	max = quic_stream_id_to_streams(stream_id);
	nframe = quic_frame_create(sk, QUIC_FRAME_MAX_STREAMS_BIDI, &max);
	if (!nframe)
		return -ENOMEM;
	quic_outq_ctrl_tail(sk, nframe, true);
out:
	return (int)(frame->len - len);
}

static int quic_frame_path_response_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	struct quic_path_addr *path;
	u32 len = frame->len;
	u8 entropy[8];

	if (len < 8)
		return -EINVAL;
	memcpy(entropy, frame->data, 8);

	path = quic_src(sk); /* source address validation */
	if (!memcmp(quic_path_entropy(path), entropy, 8) && quic_path_sent_cnt(path))
		quic_outq_validate_path(sk, frame, path);

	path = quic_dst(sk); /* dest address validation */
	if (!memcmp(quic_path_entropy(path), entropy, 8) && quic_path_sent_cnt(path))
		quic_outq_validate_path(sk, frame, path);

	len -= 8;
	return (int)(frame->len - len);
}

static struct quic_frame *quic_frame_invalid_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_datagram_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, hlen = 1, frame_len, max_frame_len;
	struct iov_iter *msg = data;
	struct quic_frame *frame;
	u8 *p;

	max_frame_len = quic_packet_max_payload_dgram(quic_packet(sk));
	hlen += quic_var_len(max_frame_len);

	msg_len = iov_iter_count(msg);
	if (msg_len > max_frame_len - hlen)
		return NULL;

	frame = quic_frame_alloc(msg_len + hlen, NULL, GFP_ATOMIC);
	if (!frame)
		return NULL;

	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, msg_len);
	frame_len = (u32)(p - frame->data);

	if (!quic_frame_copy_from_iter_full(p, msg_len, msg)) {
		quic_frame_put(frame);
		return NULL;
	}

	frame->bytes = (u16)msg_len;
	frame_len += msg_len;
	frame->len = (u16)frame_len;
	frame->size = frame->len;
	frame->dgram = 1;
	return frame;
}

static int quic_frame_invalid_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
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

	if (payload_len + (p - frame->data) + 1 > quic_inq_max_dgram(inq)) {
		frame->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

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

#define quic_frame_create_and_process(type) \
	{ .frame_create = quic_frame_##type##_create, .frame_process = quic_frame_##type##_process }

static struct quic_frame_ops quic_frame_ops[QUIC_FRAME_MAX + 1] = {
	quic_frame_create_and_process(padding), /* 0x00 */
	quic_frame_create_and_process(ping),
	quic_frame_create_and_process(ack),
	quic_frame_create_and_process(ack), /* ack_ecn */
	quic_frame_create_and_process(reset_stream),
	quic_frame_create_and_process(stop_sending),
	quic_frame_create_and_process(crypto),
	quic_frame_create_and_process(new_token),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(stream),
	quic_frame_create_and_process(max_data), /* 0x10 */
	quic_frame_create_and_process(max_stream_data),
	quic_frame_create_and_process(max_streams_bidi),
	quic_frame_create_and_process(max_streams_uni),
	quic_frame_create_and_process(data_blocked),
	quic_frame_create_and_process(stream_data_blocked),
	quic_frame_create_and_process(streams_blocked_bidi),
	quic_frame_create_and_process(streams_blocked_uni),
	quic_frame_create_and_process(new_conn_id),
	quic_frame_create_and_process(retire_conn_id),
	quic_frame_create_and_process(path_challenge),
	quic_frame_create_and_process(path_response),
	quic_frame_create_and_process(connection_close),
	quic_frame_create_and_process(connection_close),
	quic_frame_create_and_process(handshake_done),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid), /* 0x20 */
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(invalid),
	quic_frame_create_and_process(datagram), /* 0x30 */
	quic_frame_create_and_process(datagram),
};

int quic_frame_process(struct sock *sk, struct quic_frame *frame)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 type, level = frame->level;
	int ret;

	if (!frame->len) {
		packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	while (frame->len > 0) {
		type = *frame->data++;
		frame->len--;

		if (type > QUIC_FRAME_MAX) {
			pr_debug("%s: unsupported frame, type: %x, level: %d\n",
				 __func__, type, level);
			packet->errcode = QUIC_TRANSPORT_ERROR_FRAME_ENCODING;
			return -EPROTONOSUPPORT;
		} else if (quic_frame_level_check(level, type)) {
			pr_debug("%s: invalid frame, type: %x, level: %d\n",
				 __func__, type, level);
			packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			return -EINVAL;
		}
		ret = quic_frame_ops[type].frame_process(sk, frame, type);
		if (ret < 0) {
			pr_debug("%s: failed, type: %x, level: %d, err: %d\n",
				 __func__, type, level, ret);
			frame->type = type;
			packet->errcode = frame->errcode;
			return ret;
		}
		pr_debug("%s: done, type: %x, level: %d\n", __func__, type, level);
		if (quic_frame_ack_eliciting(type)) {
			packet->ack_eliciting = 1;
			if (quic_frame_ack_immediate(type))
				packet->ack_immediate = 1;
		}
		if (quic_frame_non_probing(type))
			packet->non_probing = 1;
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
	pr_debug("%s: done, type: %x, len: %u\n", __func__, type, frame->len);
	if (!frame->type)
		frame->type = type;
	return frame;
}

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

static int quic_frame_get_version_info(u32 *versions, u8 *count, u8 **pp, u32 *plen)
{
	u64 valuelen, v = 0;
	u8 i;

	if (!quic_get_var(pp, plen, &valuelen))
		return -1;

	if ((u64)*plen < valuelen || valuelen > 64)
		return -1;

	*count = (u8)(valuelen >> 2);
	for (i = 0; i < *count; i++) {
		quic_get_int(pp, plen, &v, 4);
		versions[i] = v;
	}
	return 0;
}

static int quic_frame_get_address(union quic_addr *addr, struct quic_conn_id *conn_id,
				  u8 *token, u8 **pp, u32 *plen, struct sock *sk)
{
	u64 valuelen;
	u8 *p, len;

	if (!quic_get_var(pp, plen, &valuelen))
		return -1;

	if ((u64)*plen < valuelen || valuelen < 25)
		return -1;

	quic_get_pref_addr(sk, addr, pp, plen);

	p = *pp;
	len = *p;
	if (!len || len > QUIC_CONN_ID_MAX_LEN || valuelen != 25 + len + 16)
		return -1;
	conn_id->len = len;
	p++;
	memcpy(conn_id->data, p, len);
	p += len;

	memcpy(token, p, 16);
	p += 16;

	*pp = p;
	*plen -= (17 + len);
	return 0;
}

int quic_frame_set_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					u8 *data, u32 len)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_conn_id *active, conn_id;
	u32 versions[16] = {packet->version};
	u8 *p = data, count = 1, token[16];
	union quic_addr addr = {};
	u64 type, valuelen;

	params->max_udp_payload_size = QUIC_MAX_UDP_PAYLOAD;
	params->ack_delay_exponent = QUIC_DEF_ACK_DELAY_EXPONENT;
	params->max_ack_delay = QUIC_DEF_ACK_DELAY;
	params->active_connection_id_limit = QUIC_CONN_ID_LEAST;
	active = quic_conn_id_active(id_set);

	while (len > 0) {
		if (!quic_get_var(&p, &len, &type))
			return -1;

		switch (type) {
		case QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID:
			if (quic_is_serv(sk))
				return -1;
			if (quic_frame_get_conn_id(&conn_id, &p, &len))
				return -1;
			if (quic_conn_id_cmp(quic_outq_orig_dcid(outq), &conn_id))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID:
			if (quic_is_serv(sk))
				return -1;
			if (quic_frame_get_conn_id(&conn_id, &p, &len))
				return -1;
			if (quic_conn_id_cmp(quic_outq_retry_dcid(outq), &conn_id))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID:
			if (quic_frame_get_conn_id(&conn_id, &p, &len))
				return -1;
			if (quic_conn_id_cmp(active, &conn_id))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			if (quic_get_param(&params->max_stream_data_bidi_local, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			if (quic_get_param(&params->max_stream_data_bidi_remote, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
			if (quic_get_param(&params->max_stream_data_uni, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
			if (quic_get_param(&params->max_data, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
			if (quic_get_param(&params->max_streams_bidi, &p, &len))
				return -1;
			if (params->max_streams_bidi > QUIC_MAX_STREAMS)
				params->max_streams_bidi = QUIC_MAX_STREAMS;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
			if (quic_get_param(&params->max_streams_uni, &p, &len))
				return -1;
			if (params->max_streams_uni > QUIC_MAX_STREAMS)
				params->max_streams_uni = QUIC_MAX_STREAMS;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT:
			if (quic_get_param(&params->max_idle_timeout, &p, &len))
				return -1;
			params->max_idle_timeout *= 1000;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE:
			if (quic_get_param(&params->max_udp_payload_size, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
			if (quic_get_param(&params->ack_delay_exponent, &p, &len))
				return -1;
			if (params->ack_delay_exponent > QUIC_MAX_ACK_DELAY_EXPONENT)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION:
			if (!quic_get_var(&p, &len, &valuelen))
				return -1;
			if (valuelen)
				return -1;
			params->disable_active_migration = 1;
			break;
		case QUIC_TRANSPORT_PARAM_DISABLE_1RTT_ENCRYPTION:
			if (!quic_get_var(&p, &len, &valuelen))
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
			if (quic_get_param(&params->max_ack_delay, &p, &len))
				return -1;
			params->max_ack_delay *= 1000;
			if (params->max_ack_delay >= (u64)QUIC_MAX_ACK_DELAY)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT:
			if (quic_get_param(&params->active_connection_id_limit, &p, &len) ||
			    params->active_connection_id_limit < QUIC_CONN_ID_LEAST)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE:
			if (quic_get_param(&params->max_datagram_frame_size, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
			if (quic_is_serv(sk))
				return -1;
			if (!quic_get_var(&p, &len, &valuelen) || (u64)len < valuelen ||
			    valuelen != 16)
				return -1;
			quic_conn_id_set_token(active, p);
			params->stateless_reset = 1;
			len -= valuelen;
			p += valuelen;
			break;
		case QUIC_TRANSPORT_PARAM_VERSION_INFORMATION:
			if (quic_frame_get_version_info(versions, &count, &p, &len))
				return -1;
			if (!count || versions[0] != packet->version)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS:
			if (quic_is_serv(sk))
				return -1;
			if (quic_frame_get_address(&addr, &conn_id, token, &p, &len, sk))
				return -1;
			if (!addr.v4.sin_port)
				break;
			if (quic_conn_id_add(id_set, &conn_id, 1, token))
				return -1;
			quic_outq_set_pref_addr(outq, 1);
			quic_path_addr_set(quic_dst(sk), &addr, 1);
			break;
		default:
			/* Ignore unknown parameter */
			if (!quic_get_var(&p, &len, &valuelen) || (u64)len < valuelen)
				return -1;
			len -= valuelen;
			p += valuelen;
			break;
		}
	}

	return quic_packet_select_version(sk, versions, count);
}

static u8 *quic_frame_put_conn_id(u8 *p, u16 id, struct quic_conn_id *conn_id)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, conn_id->len);
	p = quic_put_data(p, conn_id->data, conn_id->len);
	return p;
}

static u8 *quic_frame_put_version_info(u8 *p, u16 id, u32 version)
{
	u32 *versions, i, len = 4;

	versions = quic_packet_compatible_versions(version);
	if (!versions)
		return p;

	for (i = 0; versions[i]; i++)
		len += 4;
	p = quic_put_var(p, id);
	p = quic_put_var(p, len);
	p = quic_put_int(p, version, 4);

	for (i = 0; versions[i]; i++)
		p = quic_put_int(p, versions[i], 4);

	return p;
}

static u8 *quic_frame_put_address(u8 *p, u16 id, union quic_addr *addr,
				  struct quic_conn_id *conn_id, u8 *token, struct sock *sk)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, (4 + 2 + 16 + 2) + 1 + conn_id->len + 16);
	quic_set_pref_addr(sk, p, addr);
	p += (4 + 2 + 16 + 2);

	p = quic_put_int(p, conn_id->len, 1);
	p = quic_put_data(p, conn_id->data, conn_id->len);
	p = quic_put_data(p, token, 16);
	return p;
}

int quic_frame_get_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					u8 *data, u32 *len)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_conn_id *scid, conn_id;
	struct quic_crypto *crypto;
	u8 *p = data, token[16];
	u16 param_id;

	scid = quic_conn_id_active(id_set);
	if (quic_is_serv(sk)) {
		crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
		param_id = QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID;
		p = quic_frame_put_conn_id(p, param_id, quic_outq_orig_dcid(outq));
		if (params->stateless_reset) {
			p = quic_put_var(p, QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
			p = quic_put_var(p, 16);
			if (quic_crypto_generate_stateless_reset_token(crypto, scid->data,
								       scid->len, token, 16))
				return -1;
			p = quic_put_data(p, token, 16);
		}
		if (quic_outq_retry(outq)) {
			param_id = QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID;
			p = quic_frame_put_conn_id(p, param_id, quic_outq_retry_dcid(outq));
		}
		if (quic_outq_pref_addr(outq)) {
			quic_conn_id_generate(&conn_id);
			if (quic_crypto_generate_stateless_reset_token(crypto, conn_id.data,
								       conn_id.len, token, 16))
				return -1;
			if (quic_conn_id_add(id_set, &conn_id, 1, sk))
				return -1;
			param_id = QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS;
			p = quic_frame_put_address(p, param_id, quic_path_addr(quic_src(sk), 1),
						   &conn_id, token, sk);
		}
	}
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
	if (params->ack_delay_exponent != 3) {
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
				   div64_ul(params->max_ack_delay, 1000));
	}
	if (params->max_idle_timeout) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
				   div64_ul(params->max_idle_timeout, 1000));
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

	if (!frame->type && frame->skb) {/* type is 0 on rx path */
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

void quic_frame_list_purge(struct list_head *head)
{
	struct quic_frame *frame, *next;

	list_for_each_entry_safe(frame, next, head, list) {
		list_del_init(&frame->list);
		quic_frame_put(frame);
	}
}
