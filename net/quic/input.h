/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_inqueue {
	struct sk_buff_head reassemble_list;
	u64 max_bytes;
	u64 window;
	u64 bytes;
	u64 highest;

	u32 ack_delay_exponent;
	u32 max_ack_delay;
};

struct quic_rcv_cb {
	union {
		struct inet_skb_parm    h4;
#if IS_ENABLED(CONFIG_IPV6)
		struct inet6_skb_parm   h6;
#endif
	} header;
	u8 backlog;
	u8 stream_fin;
	u32 stream_id;
	u64 stream_offset;
};

#define QUIC_RCV_CB(__skb)	((struct quic_rcv_cb *)&((__skb)->cb[0]))

static inline void quic_inq_init(struct quic_inqueue *inq)
{
	skb_queue_head_init(&inq->reassemble_list);
}

static inline void quic_inq_purge(struct sock *sk, struct quic_inqueue *inq)
{
	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&inq->reassemble_list);
}

static inline u32 quic_inq_max_ack_delay(struct quic_inqueue *inq)
{
	return inq->max_ack_delay;
}

static inline u32 quic_inq_ack_delay_exponent(struct quic_inqueue *inq)
{
	return inq->ack_delay_exponent;
}

int quic_do_rcv(struct sock *sk, struct sk_buff *skb);
int quic_handshake_do_rcv(struct sock *sk, struct sk_buff *skb);
int quic_rcv(struct sk_buff *skb);
int quic_inq_reasm_tail(struct sock *sk, struct sk_buff *skb);
int quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, struct sk_buff *skb);
void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_get_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_set_owner_r(struct sk_buff *skb, struct sock *sk);
