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
	struct quic_connection_id orig_dcid;
	struct sk_buff_head retransmit_list;
	struct sk_buff_head encrypted_list;
	struct sk_buff_head datagram_list;
	struct sk_buff_head control_list;
	struct sk_buff *retransmit_skb;
	struct work_struct work;
	u64 max_bytes;
	u64 inflight;
	u64 window;
	u64 bytes;

	u32 max_datagram_frame_size;
	u32 max_udp_payload_size;
	u32 ack_delay_exponent;
	u32 max_idle_timeout;
	u32 max_ack_delay;
	u8 grease_quic_bit:1;
	u8 disable_1rtt_encryption:1;
	/* Use for 0-RTT/1-RTT DATA (re)transmit,
	 * as QUIC_SND_CB(skb)->level is always QUIC_CRYPTO_APP.
	 * Set this level to QUIC_CRYPTO_EARLY or QUIC_CRYPTO_APP
	 * when the corresponding crypto is ready for send.
	 */
	u8 level;

	u32 close_errcode;
	u8 *close_phrase;
	u8 close_frame;
	u8 rtx_count;
	u8 data_blocked:1;
	u8 serv:1;
	u8 retry:1;
};

struct quic_snd_cb {
	struct quic_stream *stream;
	s64 packet_number;
	u32 transmit_ts;
	u16 data_bytes;
	u8 number_offset;
	u8 level;
	u8 rtx_count;
	u8 frame_type;
	u8 path_alt:2; /* bit 1: src, bit 2: dst */
	u8 padding:1;
};

#define QUIC_SND_CB(__skb)      ((struct quic_snd_cb *)&((__skb)->cb[0]))

static inline void quic_outq_reset(struct quic_outqueue *outq)
{
	outq->rtx_count = 0;
}

static inline void quic_outq_set_window(struct quic_outqueue *outq, u32 window)
{
	outq->window = window;
}

static inline u32 quic_outq_ack_delay_exponent(struct quic_outqueue *outq)
{
	return outq->ack_delay_exponent;
}

static inline u32 quic_outq_max_udp(struct quic_outqueue *outq)
{
	return outq->max_udp_payload_size;
}

static inline u64 quic_outq_max_bytes(struct quic_outqueue *outq)
{
	return outq->max_bytes;
}

static inline void quic_outq_set_max_bytes(struct quic_outqueue *outq, u64 bytes)
{
	outq->max_bytes = bytes;
}

static inline u32 quic_outq_close_errcode(struct quic_outqueue *outq)
{
	return outq->close_errcode;
}

static inline void quic_outq_set_close_errcode(struct quic_outqueue *outq, u32 errcode)
{
	outq->close_errcode = errcode;
}

static inline u8 quic_outq_close_frame(struct quic_outqueue *outq)
{
	return outq->close_frame;
}

static inline void quic_outq_set_close_frame(struct quic_outqueue *outq, u8 type)
{
	outq->close_frame = type;
}

static inline u8 *quic_outq_close_phrase(struct quic_outqueue *outq)
{
	return outq->close_phrase;
}

static inline void quic_outq_set_close_phrase(struct quic_outqueue *outq, u8 *phrase)
{
	outq->close_phrase = phrase;
}

static inline u8 quic_outq_retry(struct quic_outqueue *outq)
{
	return outq->retry;
}

static inline void quic_outq_set_retry(struct quic_outqueue *outq, u8 retry)
{
	outq->retry = retry;
}

static inline u32 quic_outq_max_dgram(struct quic_outqueue *outq)
{
	return outq->max_datagram_frame_size;
}

static inline u8 quic_outq_grease_quic_bit(struct quic_outqueue *outq)
{
	return outq->grease_quic_bit;
}

static inline struct quic_connection_id *quic_outq_orig_dcid(struct quic_outqueue *outq)
{
	return &outq->orig_dcid;
}

static inline void quic_outq_set_orig_dcid(struct quic_outqueue *outq,
					   struct quic_connection_id *dcid)
{
	outq->orig_dcid = *dcid;
}

static inline void quic_outq_set_serv(struct quic_outqueue *outq)
{
	outq->serv = 1;
}

static inline void quic_outq_set_level(struct quic_outqueue *outq, u8 level)
{
	outq->level = level;
}

void quic_outq_dgram_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_data_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_ctrl_tail(struct sock *sk, struct sk_buff *skb, bool cork);
void quic_outq_rtx_tail(struct sock *sk, struct sk_buff *skb);
void quic_outq_flush(struct sock *sk);
void quic_outq_retransmit(struct sock *sk);
void quic_outq_retransmit_check(struct sock *sk, u8 level, s64 largest,
				s64 smallest, s64 ack_largest, u32 ack_delay);
void quic_outq_validate_path(struct sock *sk, struct sk_buff *skb,
			     struct quic_path_addr *path);
void quic_outq_stream_purge(struct sock *sk, struct quic_stream *stream);
void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_outq_transmit_close(struct sock *sk, u8 frame, u32 errcode, u8 level);
void quic_outq_transmit_app_close(struct sock *sk);
void quic_outq_transmit_probe(struct sock *sk);
void quic_outq_init(struct sock *sk);
void quic_outq_free(struct sock *sk);
void quic_outq_encrypted_tail(struct sock *sk, struct sk_buff *skb);
