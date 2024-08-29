/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_MAX_ACK_DELAY_EXPONENT	20
#define QUIC_DEF_ACK_DELAY_EXPONENT	3

#define QUIC_MAX_ACK_DELAY		(16384 * 1000)
#define QUIC_DEF_ACK_DELAY		25000

struct quic_inqueue {
	struct sk_buff_head backlog_list;
	struct list_head handshake_list;
	struct list_head stream_list;
	struct list_head early_list;
	struct list_head recv_list;
	struct work_struct work;
	u64 max_bytes;
	u64 highest;
	u64 window;
	u64 bytes;

	struct quic_frame *last_event;
	u32 max_datagram_frame_size;
	u32 max_udp_payload_size;
	u32 ack_delay_exponent;
	u32 max_idle_timeout;
	u32 max_ack_delay;
	u32 events;

	u8 disable_1rtt_encryption:1;
	u8 grease_quic_bit:1;
	u8 need_sack:2;
};

static inline u32 quic_inq_max_idle_timeout(struct quic_inqueue *inq)
{
	return inq->max_idle_timeout;
}

static inline void quic_inq_set_max_idle_timeout(struct quic_inqueue *inq, u32 timeout)
{
	inq->max_idle_timeout = timeout;
}

static inline u32 quic_inq_max_ack_delay(struct quic_inqueue *inq)
{
	return inq->max_ack_delay;
}

static inline u32 quic_inq_max_dgram(struct quic_inqueue *inq)
{
	return inq->max_datagram_frame_size;
}

static inline u32 quic_inq_window(struct quic_inqueue *inq)
{
	return inq->window;
}

static inline u64 quic_inq_bytes(struct quic_inqueue *inq)
{
	return inq->bytes;
}

static inline u64 quic_inq_max_bytes(struct quic_inqueue *inq)
{
	return inq->max_bytes;
}

static inline void quic_inq_set_max_bytes(struct quic_inqueue *inq, u64 bytes)
{
	inq->max_bytes = bytes;
}

static inline u8 quic_inq_grease_quic_bit(struct quic_inqueue *inq)
{
	return inq->grease_quic_bit;
}

static inline struct quic_frame *quic_inq_last_event(struct quic_inqueue *inq)
{
	return inq->last_event;
}

static inline void quic_inq_set_last_event(struct quic_inqueue *inq, struct quic_frame *frame)
{
	inq->last_event = frame;
}

static inline u32 quic_inq_events(struct quic_inqueue *inq)
{
	return inq->events;
}

static inline void quic_inq_set_events(struct quic_inqueue *inq, u32 events)
{
	inq->events = events;
}

static inline struct sk_buff_head *quic_inq_backlog_list(struct quic_inqueue *inq)
{
	return &inq->backlog_list;
}

static inline struct list_head *quic_inq_early_list(struct quic_inqueue *inq)
{
	return &inq->early_list;
}

static inline struct list_head *quic_inq_recv_list(struct quic_inqueue *inq)
{
	return &inq->recv_list;
}

static inline u8 quic_inq_disable_1rtt_encryption(struct quic_inqueue *inq)
{
	return inq->disable_1rtt_encryption;
}

static inline u8 quic_inq_need_sack(struct quic_inqueue *inq)
{
	return inq->need_sack;
}

static inline void quic_inq_set_need_sack(struct quic_inqueue *inq, u8 need_sack)
{
	inq->need_sack = need_sack;
}

void quic_rcv_err_icmp(struct sock *sk);
int quic_rcv_err(struct sk_buff *skb);
int quic_rcv(struct sk_buff *skb);

int quic_inq_handshake_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_stream_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_dgram_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_event_recv(struct sock *sk, u8 event, void *args);

void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, int len);
void quic_inq_stream_purge(struct sock *sk, struct quic_stream *stream);
void quic_inq_decrypted_tail(struct sock *sk, struct sk_buff *skb);
void quic_inq_backlog_tail(struct sock *sk, struct sk_buff *skb);

void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_set_owner_r(int len, struct sock *sk);
void quic_inq_rfree(int len, struct sock *sk);
void quic_inq_init(struct sock *sk);
void quic_inq_free(struct sock *sk);
