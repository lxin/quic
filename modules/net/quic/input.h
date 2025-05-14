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

struct quic_inqueue {
	struct sk_buff_head backlog_list;
	struct list_head handshake_list;
	struct list_head stream_list;
	struct list_head early_list;
	struct list_head recv_list;
	struct work_struct work;
	u64 max_bytes;
	u64 max_data;
	u64 highest;
	u64 bytes;

	u16 max_datagram_frame_size;
	u16 max_udp_payload_size;
	u8 ack_delay_exponent;
	u32 max_idle_timeout;
	u32 max_ack_delay;
	u32 timeout;
	u32 events;

	u8 disable_compatible_version:1;
	u8 disable_1rtt_encryption:1;
	u8 grease_quic_bit:1;
	u8 stateless_reset:1;
	u8 need_sack:2;
};

int quic_inq_handshake_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_stream_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_dgram_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_event_recv(struct sock *sk, u8 event, void *args);

void quic_inq_stream_list_purge(struct sock *sk, struct quic_stream *stream);
void quic_inq_decrypted_tail(struct sock *sk, struct sk_buff *skb);
void quic_inq_backlog_tail(struct sock *sk, struct sk_buff *skb);
void quic_inq_data_read(struct sock *sk, u32 bytes);

void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, u32 bytes);
void quic_inq_get_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_init(struct sock *sk);
void quic_inq_free(struct sock *sk);
