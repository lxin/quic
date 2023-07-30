/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_outqueue {
	struct sk_buff_head control_list;
	struct sk_buff_head retransmit_list;
};

struct quic_snd_cb {
	u8 rtx_count;
	u8 frame_type;
	u32 stream_id;
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
}

void quic_outq_data_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_ctrl_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_flush(struct sock *sk);
void quic_outq_retransmit(struct sock *sk);
void quic_outq_retransmit_check(struct sock *sk, u32 largest, u32 smallest,
				u32 ack_largest, u32 ack_delay);
