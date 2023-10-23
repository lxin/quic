/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_packet {
	struct sk_buff_head frame_list;
	u32 overhead;
	u32 len;

	u32 next_number; /* next packet number to send */
	u32 mss_dgram;
	u32 mss;

	u8  ipfragok:1;
};

static inline u32 quic_packet_mss(struct quic_packet *packet)
{
	return packet->mss;
}

static inline u32 quic_packet_max_payload(struct quic_packet *packet)
{
	return packet->mss - packet->overhead;
}

static inline u32 quic_packet_max_payload_dgram(struct quic_packet *packet)
{
	return packet->mss_dgram - packet->overhead;
}

static inline u32 quic_packet_next_number(struct quic_packet *packet)
{
	return packet->next_number;
}

static inline bool quic_packet_empty(struct quic_packet *packet)
{
	return skb_queue_empty(&packet->frame_list);
}

static inline void quic_packet_init(struct quic_packet *packet)
{
	skb_queue_head_init(&packet->frame_list);
}

void quic_packet_config(struct sock *sk);
void quic_packet_transmit(struct sock *sk);
int quic_packet_process(struct sock *sk, struct sk_buff *skb);
int quic_packet_tail(struct sock *sk, struct sk_buff *skb);
int quic_packet_tail_dgram(struct sock *sk, struct sk_buff *skb);
