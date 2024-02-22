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
	struct sk_buff_head decrypted_list;
	struct sk_buff_head backlog_list;
	struct sk_buff *last_event;
	struct work_struct work;
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
	u32 version;
	u8 grease_quic_bit:1;
	u8 validate_peer_address:1;
	u8 receive_session_ticket:1;
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

static inline u32 quic_inq_max_idle_timeout(struct quic_inqueue *inq)
{
	return inq->max_idle_timeout;
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

static inline u32 quic_inq_probe_timeout(struct quic_inqueue *inq)
{
	return inq->probe_timeout;
}

static inline u8 quic_inq_grease_quic_bit(struct quic_inqueue *inq)
{
	return inq->grease_quic_bit;
}

static inline struct sk_buff *quic_inq_last_event(struct quic_inqueue *inq)
{
	return inq->last_event;
}

static inline void quic_inq_set_last_event(struct quic_inqueue *inq, struct sk_buff *skb)
{
	inq->last_event = skb;
}

static inline u32 quic_inq_events(struct quic_inqueue *inq)
{
	return inq->events;
}

static inline void quic_inq_set_events(struct quic_inqueue *inq, u32 events)
{
	inq->events = events;
}

static inline u32 quic_inq_version(struct quic_inqueue *inq)
{
	return inq->version;
}

static inline void quic_inq_set_version(struct quic_inqueue *inq, u32 version)
{
	inq->version = version;
}

static inline u8 quic_inq_receive_session_ticket(struct quic_inqueue *inq)
{
	return inq->receive_session_ticket;
}

static inline void quic_inq_set_receive_session_ticket(struct quic_inqueue *inq, u8 rcv)
{
	inq->receive_session_ticket = rcv;
}

static inline u8 quic_inq_validate_peer_address(struct quic_inqueue *inq)
{
	return inq->validate_peer_address;
}

static inline struct sk_buff_head *quic_inq_backlog_list(struct quic_inqueue *inq)
{
	return &inq->backlog_list;
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
void quic_inq_init(struct sock *sk);
void quic_inq_free(struct sock *sk);
void quic_inq_decrypted_tail(struct sock *sk, struct sk_buff *skb);
void quic_inq_backlog_tail(struct sock *sk, struct sk_buff *skb);
