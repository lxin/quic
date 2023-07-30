/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_packet {
	struct sk_buff_head frame_list;
	u32 overhead;
	u32 len;
	u8 ack_eliciting:1,
	   ack_immediate:1,
	   non_probing:1,
	   ipfragok:1;
	u8 rtx_count;

	u32 next_number; /* next packet number to send */
	u32 mss;
	struct {
		u64 max_bytes;
		u64 window; /* congestion window, connection level */
		u64 bytes;
		u64 inflight;

		u8 data_blocked;
	} send;
	struct {
		u64 max_bytes;
		u64 window;
		u64 bytes;
		u64 highest;
	} recv;
};

void quic_packet_init(struct sock *sk);
void quic_packet_config(struct sock *sk);
void quic_packet_set_param(struct sock *sk, struct quic_transport_param *p, u8 send);
void quic_packet_get_param(struct sock *sk, struct quic_transport_param *p, u8 send);
int quic_packet_process(struct sock *sk, struct sk_buff *skb);
void quic_packet_transmit(struct sock *sk);
int quic_packet_tail(struct sock *sk, struct sk_buff *skb);
void quic_packet_set_send_window(struct sock *sk, u32 window);
u32 quic_packet_mss(struct sock *sk);
u32 quic_packet_inflight(struct sock *sk);
u32 quic_packet_next_number(struct sock *sk);
