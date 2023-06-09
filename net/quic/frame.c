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

static struct sk_buff *quic_frame_ack_create(struct sock *sk, void *data, u32 len)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	struct quic_pnmap *map = &quic_sk(sk)->pn_map;
	u32 largest, smallest = 0, base, range;
	u8 *p, type = QUIC_FRAME_ACK;
	u32 frame_len, num_gabs;
	struct sk_buff *skb;
	int i;

	num_gabs = quic_pnmap_num_gabs(map, gabs);
	frame_len = sizeof(type) + sizeof(u32) * 4;
	frame_len += sizeof(struct quic_gap_ack_block) * num_gabs;

	largest = quic_pnmap_get_max_pn_seen(map);
	base = quic_pnmap_get_base_pn(map);
	smallest = base;
	if (num_gabs)
		smallest += gabs[num_gabs - 1].end;
	range = largest - smallest;
	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	p = quic_put_var(skb->data, type);
	p = quic_put_var(p, largest); /* Largest Acknowledged */
	p = quic_put_var(p, 0); /* ACK Delay (TODO) */
	p = quic_put_var(p, num_gabs); /* ACK Count */
	p = quic_put_var(p, range); /* First ACK Range */

	if (num_gabs) {
		for (i = num_gabs - 1; i > 0; i--) {
			p = quic_put_var(p, gabs[i].end - gabs[i].start + 1); /* Gap */
			p = quic_put_var(p, gabs[i].start - gabs[i - 1].end - 1); /* ACK Range Length */
		}
		p = quic_put_var(p, gabs[0].end - gabs[0].start + 1); /* Gap */
		p = quic_put_var(p, gabs[0].start - 1); /* ACK Range Length */
	}
	frame_len = (u32)(p - skb->data);
	skb_put(skb, frame_len);

	pr_debug("[QUIC] %s %d\n", __func__, skb->len);
	return skb;
}

static struct sk_buff *quic_frame_ping_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_padding_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_new_token_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_stream_create(struct sock *sk, void *data, u32 len)
{
	u32 msg_len, hlen = 1, frame_len, mss = quic_sk(sk)->packet.mss;
	struct quic_msginfo *info = data;
	u8 type = QUIC_FRAME_STREAM, *p;
	struct quic_stream *stream;
	struct sk_buff *skb;

	stream = info->stream;
	hlen += quic_var_len(stream->id);
	if (stream->send.offset) {
		type |= QUIC_STREAM_BIT_OFF;
		hlen += quic_var_len(stream->send.offset);
	}

	type |= QUIC_STREAM_BIT_LEN;
	hlen += quic_var_len(mss);

	msg_len = iov_iter_count(info->msg);
	if (msg_len <= mss - hlen) {
		if (info->flag & QUIC_STREAM_FLAG_FIN)
			type |= QUIC_STREAM_BIT_FIN;
	} else {
		msg_len = mss - hlen;
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

	if (!copy_from_iter_full(p, msg_len, info->msg))
		return NULL;
	frame_len += msg_len;
	skb_put(skb, frame_len);
	QUIC_SND_CB(skb)->data_bytes = msg_len;

	stream->send.offset += msg_len;
	quic_stream_send_state_update(stream, type);
	pr_debug("[QUIC] %s %u %u\n", __func__, msg_len, frame_len);
	return skb;
}

static struct sk_buff *quic_frame_handshake_done_create(struct sock *sk, void *data, u32 len)
{
	u8 *p, frame[10], type = QUIC_FRAME_HANDSHAKE_DONE;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	pr_debug("[QUIC] %s\n", __func__);
	return skb;
}

static struct sk_buff *quic_frame_crypto_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_retire_connection_id_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_new_connection_id_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_path_response_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_path_challenge_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_reset_stream_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_stop_sending_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_max_data_create(struct sock *sk, void *data, u32 len)
{
	u8 *p, frame[10], type = QUIC_FRAME_MAX_DATA;
	struct quic_packet *packet = data;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, packet->recv.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	pr_debug("[QUIC] %s %d\n", __func__, skb->len);
	return skb;
}

static struct sk_buff *quic_frame_max_stream_data_create(struct sock *sk, void *data, u32 len)
{
	u8 *p, frame[10], type = QUIC_FRAME_MAX_STREAM_DATA;
	struct quic_stream *stream = data;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->recv.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	pr_debug("[QUIC] %s\n", __func__);
	return skb;
}

static struct sk_buff *quic_frame_max_streams_uni_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_connection_close_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_data_blocked_create(struct sock *sk, void *data, u32 len)
{
	u8 *p, frame[10], type = QUIC_FRAME_DATA_BLOCKED;
	struct quic_packet *packet = data;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, packet->send.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	pr_debug("[QUIC] %s %d\n", __func__, skb->len);
	return skb;
}

static struct sk_buff *quic_frame_stream_data_blocked_create(struct sock *sk, void *data, u32 len)
{
	u8 *p, frame[10], type = QUIC_FRAME_STREAM_DATA_BLOCKED;
	struct quic_stream *stream = data;
	struct sk_buff *skb;
	u32 frame_len;

	p = quic_put_var(frame, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->send.max_bytes);
	frame_len = (u32)(p - frame);

	skb = alloc_skb(frame_len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_put_data(skb, frame, frame_len);

	pr_debug("[QUIC] %s\n", __func__);
	return skb;
}

static struct sk_buff *quic_frame_streams_blocked_uni_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static struct sk_buff *quic_frame_streams_blocked_bidi_create(struct sock *sk, void *data, u32 len)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_crypto_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_stream_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 stream_id, offset = 0, payload_len, len, hlen;
	struct sk_buff *nskb;
	u8 *p = skb->data;
	int err;

	stream_id = quic_get_var(&p, &len);
	if (type & QUIC_STREAM_BIT_OFF)
		offset = quic_get_var(&p, &len);

	hlen = p - skb->data;
	if (type & QUIC_STREAM_BIT_LEN) {
		payload_len = quic_get_var(&p, &len);
		hlen += len;
	} else {
		payload_len = skb->len - hlen;
	}
	p += payload_len;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;
	skb_pull(nskb, hlen);
	skb_trim(nskb, payload_len);

	QUIC_RCV_CB(nskb)->stream_id = stream_id;
	QUIC_RCV_CB(nskb)->stream_fin = (type & QUIC_STREAM_BIT_FIN);
	QUIC_RCV_CB(nskb)->stream_offset = offset;

	err = quic_inq_reasm_tail(sk, nskb);
	if (err) {
		kfree_skb(nskb);
		return err;
	}

	return p - skb->data;
}

static int quic_frame_ack_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 largest, smallest, range, gap, delay, len, count, i;
	u8 *p = skb->data;

	largest = quic_get_var(&p, &len);
	delay = quic_get_var(&p, &len);
	count = quic_get_var(&p, &len);
	range = quic_get_var(&p, &len);

	smallest = largest - range;
	quic_outq_retransmit_check(sk, largest, smallest);

	for (i = 0; i < count; i++) {
		gap = quic_get_var(&p, &len);
		range = quic_get_var(&p, &len);
		largest = smallest - gap - 1;
		smallest = largest - range + 1;
		quic_outq_retransmit_check(sk, largest, smallest);
	}

	if (type == QUIC_FRAME_ACK_ECN) { /* TODO */
		count = quic_get_var(&p, &len);
		count = quic_get_var(&p, &len);
		count = quic_get_var(&p, &len);
	}

	pr_debug("[QUIC] %s %u %u\n", __func__, (u32)(p - skb->data), skb->len);
	return p - skb->data;
}

static int quic_frame_new_connection_id_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_retire_connection_id_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_new_token_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_handshake_done_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_padding_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_ping_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_path_challenge_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_reset_stream_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_stop_sending_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_max_data_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_packet *packet = &quic_sk(sk)->packet;
	u32 max_bytes, len;
	u8 *p = skb->data;

	max_bytes = quic_get_var(&p, &len);
	if (max_bytes < packet->send.max_bytes)
		return -EINVAL;

	packet->send.max_bytes = max_bytes;
	packet->send.data_blocked = 0;

	pr_debug("[QUIC] %s\n", __func__);
	return p - skb->data;
}

static int quic_frame_max_stream_data_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 max_bytes, stream_id, len;
	struct quic_stream *stream;
	u8 *p = skb->data;

	stream_id = quic_get_var(&p, &len);
	max_bytes = quic_get_var(&p, &len);

	stream = quic_stream_find(&quic_sk(sk)->streams, stream_id);
	if (!stream)
		return -EINVAL;
	if (max_bytes < stream->send.max_bytes)
		return -EINVAL;
	stream->send.max_bytes = max_bytes;
	stream->send.data_blocked = 0;

	pr_debug("[QUIC] %s\n", __func__);
	return p - skb->data;
}

static int quic_frame_max_streams_uni_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_max_streams_bidi_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_connection_close_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_data_blocked_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	struct quic_packet *packet = &quic_sk(sk)->packet;
	u32 max_bytes, len, recv_max_bytes;
	struct sk_buff *fskb;
	u8 *p = skb->data;

	max_bytes = quic_get_var(&p, &len);
	recv_max_bytes = packet->recv.max_bytes;

	packet->recv.max_bytes = packet->recv.bytes + packet->recv.window;
	fskb = quic_frame_create(sk, QUIC_FRAME_MAX_DATA, packet, 0);
	if (!fskb) {
		packet->recv.max_bytes = recv_max_bytes;
		return -ENOMEM;
	}
	quic_outq_ctrl_tail(sk, fskb, true);
	pr_debug("[QUIC] %s\n", __func__);
	return p - skb->data;
}

static int quic_frame_stream_data_blocked_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	u32 max_bytes, stream_id, len, recv_max_bytes;
	struct quic_stream *stream;
	struct sk_buff *fskb;
	u8 *p = skb->data;

	stream_id = quic_get_var(&p, &len);
	max_bytes = quic_get_var(&p, &len);

	stream = quic_stream_find(&quic_sk(sk)->streams, stream_id);
	if (!stream)
		return -EINVAL;

	recv_max_bytes = stream->recv.max_bytes;
	stream->recv.max_bytes = stream->recv.bytes + stream->recv.window;
	if (recv_max_bytes != stream->recv.max_bytes) {
		fskb = quic_frame_create(sk, QUIC_FRAME_MAX_STREAM_DATA, stream, 0);
		if (!fskb) {
			stream->recv.max_bytes = recv_max_bytes;
			return -ENOMEM;
		}
		quic_outq_ctrl_tail(sk, fskb, true);
	}
	pr_debug("[QUIC] C %s\n", __func__);
	return p - skb->data;
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

static int quic_frame_path_response_process(struct sock *sk, struct sk_buff *skb, u8 type)
{
	pr_debug("[QUIC] %s\n", __func__);
	return 0;
}

#define quic_frame_create_and_process(type) \
	{quic_frame_##type##_create, quic_frame_##type##_process}

static struct quic_frame_ops quic_frame_ops[QUIC_FRAME_BASE_MAX + 1] = {
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
	quic_frame_create_and_process(connection_close), /* close_app */
	quic_frame_create_and_process(handshake_done),
};

int quic_frame_process(struct sock *sk, struct sk_buff *skb)
{
	int err, len;
	u8 type, *p;

	while (1) {
		p = skb->data;
		type = quic_get_var(&p, &len);
		skb_pull(skb, len);

		if (type > QUIC_FRAME_BASE_MAX) {
			pr_err_once("[QUIC] frame err: unsupported frame %x\n", type);
			return -EPROTONOSUPPORT;
		}
		pr_debug("[QUIC] frame process %u %u\n", type, len);
		err = quic_frame_ops[type].frame_process(sk, skb, type);
		if (err < 0) {
			pr_warn("[QUIC] frame err %x %d\n", type, err);
			return err;
		}
		if (quic_frame_ack_eliciting(type)) {
			quic_sk(sk)->packet.ack_eliciting = 1;
			if (quic_frame_ack_immediate(type))
				quic_sk(sk)->packet.ack_immediate = 1;
		}

		skb_pull(skb, err);
		if (skb->len <= 0)
			break;
	}
	return 0;
}

struct sk_buff *quic_frame_create(struct sock *sk, u8 type, void *data, u32 len)
{
	struct sk_buff *skb;

	if (type > QUIC_FRAME_BASE_MAX)
		return NULL;
	pr_debug("[QUIC] frame create %u\n", type);
	skb = quic_frame_ops[type].frame_create(sk, data, len);
	if (!skb) {
		pr_err("[QUIC] frame create failed %x\n", type);
		return NULL;
	}
	QUIC_SND_CB(skb)->frame_type = type;
	return skb;
}

bool quic_frame_ack_eliciting(u8 type)
{
	return type != QUIC_FRAME_ACK && type != QUIC_FRAME_PADDING;
}

bool quic_frame_ack_immediate(u8 type)
{
	return (type < QUIC_FRAME_STREAM || type >= QUIC_FRAME_MAX_DATA) ||
	       (type & QUIC_STREAM_BIT_FIN);
}
