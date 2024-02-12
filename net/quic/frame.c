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

#include "socket.h"
#include "number.h"
#include "frame.h"
#include <linux/nospec.h>

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

static struct sk_buff *quic_frame_ack_create(struct sock *sk, void *data, u8 type)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	u32 frame_len, num_gabs, pn_ts;
	u8 *p, level = *((u8 *)data);
	u64 largest, smallest, range;
	struct quic_pnmap *map;
	struct sk_buff *skb;
	int i;

	map = quic_pnmap(sk, level);
	num_gabs = quic_pnmap_num_gabs(map, gabs);
	frame_len = sizeof(type) + sizeof(u32) * 4;
	frame_len += sizeof(struct quic_gap_ack_block) * num_gabs;

	largest = quic_pnmap_max_pn_seen(map);
	pn_ts = quic_pnmap_max_pn_ts(map);
	smallest = quic_pnmap_min_pn_seen(map);
	if (num_gabs)
		smallest = quic_pnmap_base_pn(map) + gabs[num_gabs - 1].end;
	range = largest - smallest;
	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	pn_ts = jiffies_to_usecs(jiffies) - pn_ts;
	pn_ts = pn_ts / BIT(quic_outq_ack_delay_exponent(quic_outq(sk)));
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, largest); /* Largest Acknowledged */
	p = quic_put_var(p, pn_ts); /* ACK Delay */
	p = quic_put_var(p, num_gabs); /* ACK Count */
	p = quic_put_var(p, range); /* First ACK Range */

	if (num_gabs) {
		for (i = num_gabs - 1; i > 0; i--) {
			p = quic_put_var(p, gabs[i].end - gabs[i].start); /* Gap */
			/* ACK Range Length */
			p = quic_put_var(p, gabs[i].start - gabs[i - 1].end - 2);
		}
		p = quic_put_var(p, gabs[0].end - gabs[0].start); /* Gap */
		range = gabs[0].start - 1;
		if (map->cum_ack_point == -1)
			range -= map->min_pn_seen;
		p = quic_put_var(p, range); /* ACK Range Length */
	}
	frame_len = (u32)(p - skb->data);
	skb_put(skb, frame_len);
	QUIC_SND_CB(skb)->level = level;

	return skb;
}

static struct sk_buff *quic_frame_ping_create(struct sock *sk, void *data, u8 type)
{
	u16 *probe_size = data;
	struct sk_buff *skb;
	u32 frame_len = 1;

	quic_packet_config(sk, 0, 0);
	frame_len = *probe_size - quic_packet(sk)->overhead;

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;

	quic_put_var(skb->data, type);
	skb_put(skb, 1);
	skb_put_zero(skb, frame_len - 1);
	QUIC_SND_CB(skb)->padding = 1;

	return skb;
}

static struct sk_buff *quic_frame_padding_create(struct sock *sk, void *data, u8 type)
{
	u32 *frame_len = data;
	struct sk_buff *skb;

	skb = alloc_skb(*frame_len + 1, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_zero(skb, *frame_len + 1);
	quic_put_var(skb->data, type);

	return skb;
}

static struct sk_buff *quic_frame_new_token_create(struct sock *sk, void *data, u8 type)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	union quic_addr *da = quic_path_addr(quic_dst(sk), 0);
	struct sk_buff *skb;
	u8 buf[17], *p;
	u32 len = 17;

	p = buf;
	p = quic_put_int(p, 0, 1); /* regular token */
	if (quic_crypto_generate_token(crypto, (u8 *)da, "path_verification", p, 16))
		return NULL;

	skb = alloc_skb(len + 4, GFP_ATOMIC);
	if (!skb)
		return NULL;
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, len);
	p = quic_put_data(p, buf, len);
	skb_put(skb, (u32)(p - skb->data));

	return skb;
}

/* STREAM Frame {
 *  Type (i) = 0x08..0x0f,
 *  Stream ID (i),
 *  [Offset (i)],
 *  [Length (i)],
 *  Stream Data (..),
 * }
*/

static struct sk_buff *quic_frame_stream_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, hlen = 1, frame_len, max_frame_len;
	struct quic_msginfo *info = data;
	struct quic_snd_cb *snd_cb;
	struct quic_stream *stream;
	struct sk_buff *skb;
	u8 *p;

	max_frame_len = quic_packet_max_payload(quic_packet(sk));
	stream = info->stream;
	hlen += quic_var_len(stream->id);
	if (stream->send.offset) {
		type |= QUIC_STREAM_BIT_OFF;
		hlen += quic_var_len(stream->send.offset);
	}

	type |= QUIC_STREAM_BIT_LEN;
	hlen += quic_var_len(max_frame_len);

	msg_len = iov_iter_count(info->msg);
	if (msg_len <= max_frame_len - hlen) {
		if (info->flag & QUIC_STREAM_FLAG_FIN)
			type |= QUIC_STREAM_BIT_FIN;
	} else {
		msg_len = max_frame_len - hlen;
	}

	skb = alloc_skb(msg_len + hlen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, stream->id);
	if (type & QUIC_STREAM_BIT_OFF)
		p = quic_put_var(p, stream->send.offset);
	p = quic_put_var(p, msg_len);
	frame_len = (u32)(p - skb->data);

	if (!copy_from_iter_full(p, msg_len, info->msg)) {
		kfree_skb(skb);
		return NULL;
	}
	frame_len += msg_len;
	skb_put(skb, frame_len);
	snd_cb = QUIC_SND_CB(skb);
	snd_cb->data_bytes = msg_len;
	snd_cb->stream = stream;
	snd_cb->frame_type = type;

	stream->send.offset += msg_len;
	return skb;
}

static struct sk_buff *quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_crypto_create(struct sock *sk, void *data, u8 type)
{
	struct quic_msginfo *info = data;
	u32 msg_len, hlen, max_frame_len;
	struct quic_crypto *crypto;
	struct sk_buff *skb;
	u8 *p;

	quic_packet_config(sk, info->level, 0);
	max_frame_len = quic_packet_max_payload(quic_packet(sk));
	crypto = quic_crypto(sk, info->level);
	msg_len = iov_iter_count(info->msg);

	if (!info->level) {
		if (msg_len > max_frame_len)
			return NULL;
		skb = alloc_skb(msg_len + 8, GFP_ATOMIC);
		if (!skb)
			return NULL;
		p = quic_put_var(skb->data, type);
		p = quic_put_var(p, 0);
		p = quic_put_var(p, msg_len);
		if (!copy_from_iter_full(p, msg_len, info->msg)) {
			kfree_skb(skb);
			return NULL;
		}
		p += msg_len;
		skb_put(skb, (u32)(p - skb->data));

		return skb;
	}

	if (msg_len > max_frame_len)
		msg_len = max_frame_len;
	hlen = 1 + quic_var_len(msg_len) + quic_var_len(crypto->send_offset);
	skb = alloc_skb(msg_len + hlen, GFP_ATOMIC);
	if (!skb)
		return NULL;
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, crypto->send_offset);
	p = quic_put_var(p, msg_len);
	if (!copy_from_iter_full(p, msg_len, info->msg)) {
		kfree_skb(skb);
		return NULL;
	}
	skb_put(skb, msg_len + hlen);
	crypto->send_offset += msg_len;
	QUIC_SND_CB(skb)->level = info->level;
	return skb;
}

static struct sk_buff *quic_frame_retire_connection_id_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u64 *number = data;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, *number);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	quic_connection_id_remove(quic_dest(sk), *number);
	return skb;
}

static struct sk_buff *quic_frame_new_connection_id_create(struct sock *sk, void *data, u8 type)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_connection_id scid = {};
	u8 *p, frame[100], token[16];
	u64 *prior = data, seqno;
	struct sk_buff *skb;
	u32 frame_len;
	int err;

	seqno = quic_connection_id_last_number(quic_source(sk)) + 1;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, seqno);
	p = quic_put_var(p, *prior);
	p = quic_put_var(p, 16);
	quic_generate_id(&scid, 16);
	p = quic_put_data(p, scid.data, scid.len);
	if (quic_crypto_generate_token(crypto, scid.data, "stateless_reset", token, 16))
		return NULL;
	p = quic_put_data(p, token, 16);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	err = quic_connection_id_add(quic_source(sk), &scid, seqno, sk);
	if (err) {
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

static struct sk_buff *quic_frame_path_response_create(struct sock *sk, void *data, u8 type)
{
	u8 *p, frame[10], *entropy = data;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_data(p, entropy, 8);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type)
{
	struct quic_path_addr *path = data;
	struct sk_buff *skb;
	u32 frame_len;
	u8 *p;

	quic_packet_config(sk, 0, 0);
	frame_len = 1184 - quic_packet(sk)->overhead;
	get_random_bytes(path->entropy, sizeof(path->entropy));

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	p = quic_put_var(skb->data, type);
	p = quic_put_data(p, path->entropy, sizeof(path->entropy));
	skb_put(skb, 1 + sizeof(path->entropy));
	skb_put_zero(skb, frame_len - 1);
	QUIC_SND_CB(skb)->padding = 1;

	return skb;
}

static struct sk_buff *quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_errinfo *info = data;
	struct quic_stream *stream;
	struct sk_buff *skb;
	u8 *p, frame[20];
	u32 frame_len;

	stream = quic_stream_find(streams, info->stream_id);
	if (!stream)
		return NULL;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	p = quic_put_var(p, stream->send.offset);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);
	stream->send.errcode = info->errcode;
	QUIC_SND_CB(skb)->stream = stream;

	if (streams->send.stream_active == stream->id)
		streams->send.stream_active = -1;

	return skb;
}

static struct sk_buff *quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type)
{
	struct quic_errinfo *info = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_inqueue *inq = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, inq->max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream *stream = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->recv.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u8 *p, frame[10];
	u64 *max = data;
	int frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type)
{
	struct sk_buff *skb;
	u8 *p, frame[10];
	u64 *max = data;
	int frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_connection_close_create(struct sock *sk, void *data, u8 type)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 frame_len, phrase_len = 0;
	struct sk_buff *skb;
	u8 *p, frame[100];

	p = quic_put_var(frame, type);
	p = quic_put_var(p, outq->close_errcode);

	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		p = quic_put_var(p, outq->close_frame);

	if (outq->close_phrase)
		phrase_len = strlen(outq->close_phrase) + 1;
	p = quic_put_var(p, phrase_len);
	p = quic_put_data(p, outq->close_phrase, phrase_len);

	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	struct quic_outqueue *outq = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, outq->max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_stream_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	struct quic_stream *stream = data;
	struct sk_buff *skb;
	u8 *p, frame[10];
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->send.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);
	QUIC_SND_CB(skb)->stream = stream;

	return skb;
}

static struct sk_buff *quic_frame_streams_blocked_uni_create(struct sock *sk, void *data, u8 type)
{
	u32 *max = data, frame_len;
	struct sk_buff *skb;
	u8 *p, frame[10];

	p = quic_put_var(frame, type);
	p = quic_put_var(p, (*max >> 2) + 1);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static struct sk_buff *quic_frame_streams_blocked_bidi_create(struct sock *sk, void *data, u8 type)
{
	u32 *max = data, frame_len;
	struct sk_buff *skb;
	u8 *p, frame[10];

	p = quic_put_var(frame, type);
	p = quic_put_var(p, (*max >> 2) + 1);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	return skb;
}

static int quic_frame_crypto_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct sk_buff *nskb;
	u64 offset, length;
	u32 len = skb->len;
	u8 *p = skb->data;
	int err;

	if (!quic_get_var(&p, &len, &offset))
		return -EINVAL;
	if (!quic_get_var(&p, &len, &length) || length > len)
		return -EINVAL;

	if (!QUIC_RCV_CB(skb)->level) {
		if (!quic_local(sk)->receive_session_ticket)
			goto out;
		quic_local(sk)->receive_session_ticket = 0;
	}

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;
	skb_pull(nskb, p - skb->data);
	skb_trim(nskb, length);
	QUIC_RCV_CB(nskb)->offset = offset;

	err = quic_inq_handshake_tail(sk, nskb);
	if (err) {
		kfree_skb(nskb);
		return err;
	}
out:
	len -= length;
	return skb->len - len;
}

static int quic_frame_stream_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u64 stream_id, payload_len, offset = 0;
	struct quic_stream *stream;
	struct quic_rcv_cb *rcv_cb;
	struct sk_buff *nskb;
	u32 len = skb->len;
	u8 *p = skb->data;
	int err;

	if (quic_local(sk)->receive_session_ticket)
		return -EINVAL;
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

	stream = quic_stream_recv_get(quic_streams(sk), stream_id, quic_is_serv(sk));
	if (!stream)
		return -EINVAL;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;
	skb_pull(nskb, skb->len - len);
	skb_trim(nskb, payload_len);

	rcv_cb = QUIC_RCV_CB(nskb);
	rcv_cb->stream = stream;
	rcv_cb->stream_fin = (type & QUIC_STREAM_BIT_FIN);
	rcv_cb->offset = offset;

	err = quic_inq_reasm_tail(sk, nskb);
	if (err) {
		kfree_skb(nskb);
		return err;
	}

	len -= payload_len;
	return skb->len - len;
}

static int quic_frame_ack_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u64 largest, smallest, range, delay, count, gap, i;
	u8 *p = skb->data, level;
	u32 len = skb->len;

	level = QUIC_RCV_CB(skb)->level;
	if (!quic_get_var(&p, &len, &largest) ||
	    !quic_get_var(&p, &len, &delay) ||
	    !quic_get_var(&p, &len, &count) || count > QUIC_PN_MAX_GABS ||
	    !quic_get_var(&p, &len, &range))
		return -EINVAL;

	smallest = largest - range;
	quic_outq_retransmit_check(sk, level, largest, smallest, largest, delay);

	for (i = 0; i < count; i++) {
		if (!quic_get_var(&p, &len, &gap) ||
		    !quic_get_var(&p, &len, &range))
			return -EINVAL;
		largest = smallest - gap - 2;
		smallest = largest - range;
		quic_outq_retransmit_check(sk, level, largest, smallest, 0, 0);
	}

	if (type == QUIC_FRAME_ACK_ECN) { /* TODO */
		if (!quic_get_var(&p, &len, &count) ||
		    !quic_get_var(&p, &len, &count) ||
		    !quic_get_var(&p, &len, &count))
			return -EINVAL;
	}

	return skb->len - len;
}

static int quic_frame_new_connection_id_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_connection_id_set *id_set = quic_dest(sk);
	u64 seqno, prior, length, first, last;
	struct quic_connection_id dcid;
	u8 *p = skb->data, *token;
	struct sk_buff *fskb;
	u32 len = skb->len;
	int err;

	if (!quic_get_var(&p, &len, &seqno) ||
	    !quic_get_var(&p, &len, &prior) ||
	    !quic_get_var(&p, &len, &length) || length + 16 > len)
		return -EINVAL;

	memcpy(dcid.data, p, length);
	dcid.len = length;
	token = p + length;

	last = quic_connection_id_last_number(id_set);
	if (seqno < last + 1) /* already exists */
		goto out;

	if (seqno > last + 1 || prior > seqno)
		return -EINVAL;

	err = quic_connection_id_add(id_set, &dcid, seqno, token);
	if (err)
		return err;

	first = quic_connection_id_first_number(id_set);
	if (prior <= first)
		goto out;

	for (; first < prior; first++) {
		fskb = quic_frame_create(sk, QUIC_FRAME_RETIRE_CONNECTION_ID, &first);
		if (!fskb)
			return -ENOMEM;
		QUIC_SND_CB(fskb)->path_alt = QUIC_RCV_CB(skb)->path_alt;
		quic_outq_ctrl_tail(sk, fskb, true);
	}

out:
	len -= (length + 16);
	return skb->len - len;
}

static int quic_frame_retire_connection_id_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_connection_id_set *id_set = quic_source(sk);
	u32 len = skb->len, last, first;
	struct sk_buff *fskb;
	u8 *p = skb->data;
	u64 seqno;

	if (!quic_get_var(&p, &len, &seqno))
		return -EINVAL;
	first = quic_connection_id_first_number(id_set);
	if (seqno < first) /* dup */
		goto out;
	last  = quic_connection_id_last_number(id_set);
	if (seqno != first || seqno == last)
		return -EINVAL;

	quic_connection_id_remove(id_set, seqno);
	if (last - seqno >= quic_source(sk)->max_count)
		goto out;
	seqno++;
	fskb = quic_frame_create(sk, QUIC_FRAME_NEW_CONNECTION_ID, &seqno);
	if (!fskb)
		return -ENOMEM;
	QUIC_SND_CB(fskb)->path_alt = QUIC_RCV_CB(skb)->path_alt;
	quic_outq_ctrl_tail(sk, fskb, true);
out:
	return skb->len - len;
}

static int quic_frame_new_token_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_data *token = quic_token(sk);
	u32 len = skb->len;
	u8 *p = skb->data;
	u64 length;

	if (!quic_get_var(&p, &len, &length) || length > len)
		return -EINVAL;

	if (quic_data_dup(token, p, length))
		return -ENOMEM;

	if (quic_inq_event_recv(sk, QUIC_EVENT_NEW_TOKEN, token))
		return -ENOMEM;

	len -= length;
	return skb->len - len;
}

static int quic_frame_handshake_done_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	/* some implementations don't send ACKs to handshake packets, so ACK them manually */
	quic_outq_retransmit_check(sk, QUIC_CRYPTO_INITIAL, QUIC_PN_MAP_MAX_PN, 0, 0, 0);
	quic_outq_retransmit_check(sk, QUIC_CRYPTO_HANDSHAKE, QUIC_PN_MAP_MAX_PN, 0, 0, 0);
	return 0; /* no content */
}

static int quic_frame_padding_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return skb->len;
}

static int quic_frame_ping_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return 0; /* no content */
}

static int quic_frame_path_challenge_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct sk_buff *fskb;
	u32 len = skb->len;
	u8 entropy[8];

	if (len < 8)
		return -EINVAL;
	memcpy(entropy, skb->data, 8);
	fskb = quic_frame_create(sk, QUIC_FRAME_PATH_RESPONSE, entropy);
	if (!fskb)
		return -ENOMEM;
	QUIC_SND_CB(fskb)->path_alt = QUIC_RCV_CB(skb)->path_alt;
	quic_outq_ctrl_tail(sk, fskb, true);

	len -= 8;
	return skb->len - len;
}

static int quic_frame_reset_stream_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_stream_update update = {};
	u64 stream_id, errcode, finalsz;
	struct quic_stream *stream;
	u32 len = skb->len;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &errcode) ||
	    !quic_get_var(&p, &len, &finalsz))
		return -EINVAL;

	stream = quic_stream_recv_get(quic_streams(sk), stream_id, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	update.id = stream_id;
	update.state = QUIC_STREAM_RECV_STATE_RESET_RECVD;
	update.errcode = errcode;
	if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
		return -ENOMEM;
	stream->recv.state = update.state;
	quic_inq_stream_purge(sk, stream);
	return skb->len - len;
}

static int quic_frame_stop_sending_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_stream_update update = {};
	struct quic_stream *stream;
	struct quic_errinfo info;
	u64 stream_id, errcode;
	struct sk_buff *fskb;
	u32 len = skb->len;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &errcode))
		return -EINVAL;

	stream = quic_stream_send_get(quic_streams(sk), stream_id, 0, quic_is_serv(sk));
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	info.stream_id = stream_id;
	info.errcode = errcode;
	fskb = quic_frame_create(sk, QUIC_FRAME_RESET_STREAM, &info);
	if (!fskb)
		return -ENOMEM;

	update.id = stream_id;
	update.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
	update.errcode = errcode;
	if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update)) {
		kfree_skb(fskb);
		return -ENOMEM;
	}
	stream->send.state = update.state;
	quic_outq_stream_purge(sk, stream);
	quic_outq_ctrl_tail(sk, fskb, true);
	return skb->len - len;
}

static int quic_frame_max_data_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 len = skb->len;
	u8 *p = skb->data;
	u64 max_bytes;

	if (!quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	if (max_bytes >= outq->max_bytes)
		outq->max_bytes = max_bytes;

	return skb->len - len;
}

static int quic_frame_max_stream_data_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_stream *stream;
	u64 max_bytes, stream_id;
	u32 len = skb->len;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	stream = quic_stream_find(quic_streams(sk), stream_id);
	if (!stream)
		return -EINVAL;

	if (max_bytes >= stream->send.max_bytes)
		stream->send.max_bytes = max_bytes;

	return skb->len - len;
}

static int quic_frame_max_streams_uni_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u32 len = skb->len;
	u64 max, stream_id;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;

	if (max < streams->send.max_streams_uni)
		goto out;

	stream_id = ((max - 1) << 2) | QUIC_STREAM_TYPE_UNI_MASK;
	if (quic_is_serv(sk))
		stream_id |= QUIC_STREAM_TYPE_SERVER_MASK;
	if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_STREAM, &stream_id))
		return -ENOMEM;
	streams->send.max_streams_uni = max;
	streams->send.streams_uni = max;
	sk->sk_write_space(sk);
out:
	return skb->len - len;
}

static int quic_frame_max_streams_bidi_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u32 len = skb->len;
	u64 max, stream_id;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;

	if (max < streams->send.max_streams_bidi)
		goto out;

	stream_id = ((max - 1) << 2);
	if (quic_is_serv(sk))
		stream_id |= QUIC_STREAM_TYPE_SERVER_MASK;
	if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_MAX_STREAM, &stream_id))
		return -ENOMEM;
	streams->send.max_streams_bidi = max;
	streams->send.streams_bidi = max;
	sk->sk_write_space(sk);
out:
	return skb->len - len;
}

static int quic_frame_connection_close_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_connection_close *close;
	u64 err_code, phrase_len, ftype = 0;
	u8 *p = skb->data, frame[100] = {};
	u32 len = skb->len;

	if (!quic_get_var(&p, &len, &err_code))
		return -EINVAL;
	if (type == QUIC_FRAME_CONNECTION_CLOSE &&
	    !quic_get_var(&p, &len, &ftype))
		return -EINVAL;

	if (!quic_get_var(&p, &len, &phrase_len) || phrase_len > len)
		return -EINVAL;

	close = (void *)frame;
	if (phrase_len) {
		if ((phrase_len > 80 || *(p + phrase_len - 1) != 0))
			return -EINVAL;
		strscpy(close->phrase, p, phrase_len);
	}
	close->errcode = err_code;
	close->frame = ftype;
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close))
		return -ENOMEM;
	quic_set_state(sk, QUIC_SS_CLOSED);

	len -= phrase_len;
	return skb->len - len;
}

static int quic_frame_data_blocked_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_inqueue *inq = quic_inq(sk);
	u64 max_bytes, recv_max_bytes;
	u32 window, len = skb->len;
	struct sk_buff *fskb;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;
	recv_max_bytes = inq->max_bytes;

	window = inq->window;
	if (sk_under_memory_pressure(sk))
		window >>= 1;

	inq->max_bytes = inq->bytes + window;
	fskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, inq);
	if (!fskb) {
		inq->max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
	quic_outq_ctrl_tail(sk, fskb, true);
	return skb->len - len;
}

static int quic_frame_stream_data_blocked_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u64 stream_id, max_bytes, recv_max_bytes;
	struct quic_stream *stream;
	u32 window, len = skb->len;
	struct sk_buff *fskb;
	u8 *p = skb->data;

	if (!quic_get_var(&p, &len, &stream_id) ||
	    !quic_get_var(&p, &len, &max_bytes))
		return -EINVAL;

	stream = quic_stream_find(quic_streams(sk), stream_id);
	if (!stream)
		return -EINVAL;

	window = stream->recv.window;
	if (sk_under_memory_pressure(sk))
		window >>= 1;

	recv_max_bytes = stream->recv.max_bytes;
	stream->recv.max_bytes = stream->recv.bytes + window;
	fskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream);
	if (!fskb) {
		stream->recv.max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
	quic_outq_ctrl_tail(sk, fskb, true);
	return skb->len - len;
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct sk_buff *fskb;
	u32 len = skb->len;
	u8 *p = skb->data;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;
	if (max < quic_streams(sk)->recv.max_streams_uni)
		goto out;
	fskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAMS_UNI, &max);
	if (!fskb)
		return -ENOMEM;
	quic_outq_ctrl_tail(sk, fskb, true);
	quic_streams(sk)->recv.max_streams_uni = max;
out:
	return skb->len - len;
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct sk_buff *fskb;
	u32 len = skb->len;
	u8 *p = skb->data;
	u64 max;

	if (!quic_get_var(&p, &len, &max))
		return -EINVAL;
	if (max < quic_streams(sk)->recv.max_streams_bidi)
		goto out;
	fskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAMS_BIDI, &max);
	if (!fskb)
		return -ENOMEM;
	quic_outq_ctrl_tail(sk, fskb, true);
	quic_streams(sk)->recv.max_streams_bidi = max;
out:
	return skb->len - len;
}

static int quic_frame_path_response_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_path_addr *path;
	u32 len = skb->len;
	u8 entropy[8];

	if (len < 8)
		return -EINVAL;
	memcpy(entropy, skb->data, 8);

	path = quic_src(sk); /* source address validation */
	if (!memcmp(path->entropy, entropy, 8) && path->sent_cnt)
		quic_outq_validate_path(sk, skb, path);

	path = quic_dst(sk); /* dest address validation */
	if (!memcmp(path->entropy, entropy, 8) && path->sent_cnt)
		quic_outq_validate_path(sk, skb, path);

	len -= 8;
	return skb->len - len;
}

static struct sk_buff *quic_frame_invalid_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct sk_buff *quic_frame_datagram_create(struct sock *sk, void *data, u8 type)
{
	u32 msg_len, hlen = 1, frame_len, max_frame_len;
	struct iov_iter *msg = data;
	struct sk_buff *skb;
	u8 *p;

	max_frame_len = quic_packet_max_payload_dgram(quic_packet(sk));
	hlen += quic_var_len(max_frame_len);

	msg_len = iov_iter_count(msg);
	if (msg_len > max_frame_len - hlen)
		msg_len = max_frame_len - hlen;

	skb = alloc_skb(msg_len + hlen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, msg_len);
	frame_len = (u32)(p - skb->data);

	if (!copy_from_iter_full(p, msg_len, msg)) {
		kfree_skb(skb);
		return NULL;
	}

	QUIC_SND_CB(skb)->data_bytes = msg_len;
	frame_len += msg_len;
	skb_put(skb, frame_len);
	return skb;
}

static int quic_frame_invalid_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	return -EPROTONOSUPPORT;
}

static int quic_frame_datagram_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct sk_buff *nskb;
	u32 len = skb->len;
	u8 *p = skb->data;
	u64 payload_len;
	int err;

	if (quic_local(sk)->receive_session_ticket)
		return -EINVAL;

	if (!quic_inq_max_dgram(quic_inq(sk)))
		return -EINVAL;

	payload_len = skb->len;
	if (type == QUIC_FRAME_DATAGRAM_LEN) {
		if (!quic_get_var(&p, &len, &payload_len) || payload_len > len)
			return -EINVAL;
	}
	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;
	skb_pull(nskb, skb->len - len);
	skb_trim(nskb, payload_len);

	err = quic_inq_dgram_tail(sk, nskb);
	if (err) {
		kfree_skb(nskb);
		return err;
	}

	len -= payload_len;
	return skb->len - len;
}

#define quic_frame_create_and_process(type) \
	{quic_frame_##type##_create, quic_frame_##type##_process}

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
	quic_frame_create_and_process(new_connection_id),
	quic_frame_create_and_process(retire_connection_id),
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

int quic_frame_process(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki)
{
	int ret, len = pki->length;
	u8 type;

	if (!len)
		return -EINVAL;

	while (len > 0) {
		type = *(u8 *)(skb->data);
		skb_pull(skb, 1);
		len--;

		if (type > QUIC_FRAME_MAX) {
			pr_err_once("[QUIC] %s unsupported frame %x\n", __func__, type);
			return -EPROTONOSUPPORT;
		} else if (!type) { /* skip padding */
			skb_pull(skb, len);
			return 0;
		}
		pr_debug("[QUIC] %s type: %x level: %d\n", __func__, type, QUIC_RCV_CB(skb)->level);
		ret = quic_frame_ops[type].frame_process(sk, skb, type);
		if (ret < 0) {
			pr_warn("[QUIC] %s type: %x level: %d err: %d\n", __func__, type,
				QUIC_RCV_CB(skb)->level, ret);
			return ret;
		}
		if (quic_frame_ack_eliciting(type)) {
			pki->ack_eliciting = 1;
			if (quic_frame_ack_immediate(type))
				pki->ack_immediate = 1;
		}
		if (quic_frame_non_probing(type))
			pki->non_probing = 1;

		skb_pull(skb, ret);
		len -= ret;
	}
	return 0;
}

struct sk_buff *quic_frame_create(struct sock *sk, u8 type, void *data)
{
	struct quic_snd_cb *snd_cb;
	struct sk_buff *skb;

	if (type > QUIC_FRAME_MAX)
		return NULL;
	skb = quic_frame_ops[type].frame_create(sk, data, type);
	if (!skb) {
		pr_err("[QUIC] frame create failed %x\n", type);
		return NULL;
	}
	pr_debug("[QUIC] %s type: %u len: %u\n", __func__, type, skb->len);
	snd_cb = QUIC_SND_CB(skb);
	if (!snd_cb->frame_type)
		snd_cb->frame_type = type;
	return skb;
}

static int quic_get_param(u64 *pdest, u8 **pp, u32 *plen)
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

int quic_frame_set_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					u8 *data, u32 len)
{
	struct quic_dest_connection_id *dcid;
	u64 type, valuelen;
	u8 *p = data;

	params->max_udp_payload_size = 65527;
	params->ack_delay_exponent = 3;
	params->max_ack_delay = 25000;
	params->active_connection_id_limit = 2;

	while (len > 0) {
		if (!quic_get_var(&p, &len, &type))
			return -1;

		switch (type) {
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
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
			if (quic_get_param(&params->max_streams_uni, &p, &len))
				return -1;
			if (params->max_streams_uni > QUIC_MAX_STREAMS)
				return -1;
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
			if (params->ack_delay_exponent > 20)
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION:
			if (!quic_get_var(&p, &len, &valuelen))
				return -1;
			if (valuelen)
				return -1;
			params->disable_active_migration = 1;
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
			if (params->max_ack_delay >= 16384)
				return -1;
			params->max_ack_delay *= 1000;
			break;
		case QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT:
			if (quic_get_param(&params->active_connection_id_limit, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE:
			if (quic_get_param(&params->max_datagram_frame_size, &p, &len))
				return -1;
			break;
		case QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
			if (!quic_get_var(&p, &len, &valuelen) || len < valuelen ||
			    valuelen != 16)
				return -1;
			dcid = (struct quic_dest_connection_id *)quic_dest(sk)->active;
			memcpy(dcid->token, p, 16);
			params->stateless_reset = 1;
			len -= valuelen;
			p += valuelen;
			break;
		default:
			/* Ignore unknown parameter */
			if (!quic_get_var(&p, &len, &valuelen))
				return -1;
			if (len < valuelen)
				return -1;
			len -= valuelen;
			p += valuelen;
			break;
		}
	}
	return 0;
}

static u8 *quic_put_conn_id(u8 *p, enum quic_transport_param_id id,
			    struct quic_connection_id *conn_id)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, conn_id->len);
	p = quic_put_data(p, conn_id->data, conn_id->len);
	return p;
}

static u8 *quic_put_param(u8 *p, enum quic_transport_param_id id, u64 value)
{
	p = quic_put_var(p, id);
	p = quic_put_var(p, quic_var_len(value));
	return quic_put_var(p, value);
}

int quic_frame_get_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					u8 *data, u32 *len)
{
	struct quic_connection_id *scid = &quic_source(sk)->active->id;
	u8 *p = data, token[16];

	if (quic_is_serv(sk)) {
		p = quic_put_conn_id(p, QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID,
				     &quic_outq(sk)->orig_dcid);
		if (params->stateless_reset) {
			p = quic_put_var(p, QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
			p = quic_put_var(p, 16);
			if (quic_crypto_generate_token(quic_crypto(sk, QUIC_CRYPTO_INITIAL),
						       scid->data, "stateless_reset", token, 16))
				return -1;
			p = quic_put_data(p, token, 16);
		}
	}
	if (quic_outq(sk)->retry) {
		p = quic_put_conn_id(p, QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID,
				     &quic_outq(sk)->orig_dcid);
	}
	p = quic_put_conn_id(p, QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID, scid);
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
	if (params->max_udp_payload_size != 65527) {
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
	if (params->grease_quic_bit) {
		p = quic_put_var(p, QUIC_TRANSPORT_PARAM_GREASE_QUIC_BIT);
		p = quic_put_var(p, 0);
	}
	if (params->max_ack_delay != 25000) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY,
				   params->max_ack_delay / 1000);
	}
	if (params->max_idle_timeout) {
		p = quic_put_param(p, QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
				   params->max_idle_timeout / 1000);
	}
	if (params->active_connection_id_limit && params->active_connection_id_limit != 2) {
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
