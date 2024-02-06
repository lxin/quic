/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_inqueue {
	struct sk_buff_head reassemble_list;
	struct sk_buff_head handshake_list;
	struct sk_buff_head backlog_list;
	struct sk_buff *last_event;
	u64 max_bytes;
	u64 window;
	u64 bytes;
	u64 highest;

	u32 max_datagram_frame_size;
	u32 max_udp_payload_size;
	u32 ack_delay_exponent;
	u32 max_idle_timeout;
	u32 max_ack_delay;
	u32 events;
	u32 probe_timeout;
	u8 grease_quic_bit;
};

struct quic_rcv_cb {
	struct quic_stream *stream;
	u64 offset; /* stream or crypto offset */
	u16 read_offset;
	u16 udph_offset;
	u8 number_offset;
	u8 event;
	u8 level;
	u8 dgram:1;
	u8 backlog:1;
	u8 stream_fin:1;
	u8 path_alt:2;
};

#define QUIC_RCV_CB(__skb)	((struct quic_rcv_cb *)&((__skb)->cb[0]))

static inline void quic_inq_init(struct quic_inqueue *inq)
{
	skb_queue_head_init(&inq->reassemble_list);
	skb_queue_head_init(&inq->handshake_list);
	skb_queue_head_init(&inq->backlog_list);
}

static inline void quic_inq_purge(struct sock *sk, struct quic_inqueue *inq)
{
	__skb_queue_purge(&sk->sk_receive_queue);
	__skb_queue_purge(&inq->reassemble_list);
	__skb_queue_purge(&inq->handshake_list);
	__skb_queue_purge(&inq->backlog_list);
}

static inline u32 quic_inq_max_ack_delay(struct quic_inqueue *inq)
{
	return inq->max_ack_delay;
}

static inline u32 quic_inq_ack_delay_exponent(struct quic_inqueue *inq)
{
	return inq->ack_delay_exponent;
}

static inline u32 quic_inq_max_idle_timeout(struct quic_inqueue *inq)
{
	return inq->max_idle_timeout;
}

static inline u32 quic_inq_max_dgram(struct quic_inqueue *inq)
{
	return inq->max_datagram_frame_size;
}

int quic_do_rcv(struct sock *sk, struct sk_buff *skb);
int quic_rcv(struct sk_buff *skb);
int quic_rcv_err(struct sk_buff *skb);
void quic_rcv_err_icmp(struct sock *sk);
int quic_inq_reasm_tail(struct sock *sk, struct sk_buff *skb);
int quic_inq_dgram_tail(struct sock *sk, struct sk_buff *skb);
int quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, int len);
void quic_inq_stream_purge(struct sock *sk, struct quic_stream *stream);
void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_get_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_set_owner_r(struct sk_buff *skb, struct sock *sk);
int quic_inq_event_recv(struct sock *sk, u8 event, void *args);
int quic_inq_handshake_tail(struct sock *sk, struct sk_buff *skb);
