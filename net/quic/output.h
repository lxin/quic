/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_outqueue {
	struct sk_buff_head control_list;
	struct sk_buff_head retransmit_list;
	struct sk_buff *retransmit_skb;
	u64 max_bytes;
	u64 inflight;
	u64 window;
	u64 bytes;

	u32 ack_delay_exponent;
	u32 max_ack_delay;
	u32 close_errcode;
	u8 *close_phrase;
	u8 close_frame;
	u8 data_blocked;
	u8 rtx_count;
};

struct quic_snd_cb {
	struct quic_stream *stream;
	u8 rtx_count;
	u8 frame_type;
	u32 err_code;
	u32 data_bytes;
	u32 transmit_ts;
	u32 packet_number;
	u64 stream_offset; /* for debug only */
};

#define QUIC_SND_CB(__skb)      ((struct quic_snd_cb *)&((__skb)->cb[0]))

static inline void quic_outq_init(struct quic_outqueue *outq)
{
	skb_queue_head_init(&outq->control_list);
	skb_queue_head_init(&outq->retransmit_list);
}

static inline void quic_outq_purge(struct sock *sk, struct quic_outqueue *outq)
{
	__skb_queue_purge(&sk->sk_write_queue);
	__skb_queue_purge(&outq->retransmit_list);
	__skb_queue_purge(&outq->control_list);
	kfree(outq->close_phrase);
}

static inline void quic_outq_reset(struct quic_outqueue *outq)
{
	outq->rtx_count = 0;
}

static inline u32 quic_outq_inflight(struct quic_outqueue *outq)
{
	return outq->inflight;
}

static inline void quic_outq_set_window(struct quic_outqueue *outq, u32 window)
{
	outq->window = window;
}

static inline u32 quic_outq_max_ack_delay(struct quic_outqueue *outq)
{
	return outq->max_ack_delay;
}

static inline u32 quic_outq_ack_delay_exponent(struct quic_outqueue *outq)
{
	return outq->ack_delay_exponent;
}

void quic_outq_data_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_ctrl_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_rtx_tail(struct sock *sk, struct sk_buff *skb);
void quic_outq_flush(struct sock *sk);
void quic_outq_retransmit(struct sock *sk);
void quic_outq_retransmit_check(struct sock *sk, u32 largest, u32 smallest,
				u32 ack_largest, u32 ack_delay);
void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_outq_get_param(struct sock *sk, struct quic_transport_param *p);
