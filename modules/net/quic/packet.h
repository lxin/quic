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
	struct quic_conn_id dcid;	/* Dest Connection ID from received packet */
	struct quic_conn_id scid;	/* Source Connection ID from received packet */
	union quic_addr daddr;		/* Dest address from received packet */
	union quic_addr saddr;		/* Source address from received packet */

	struct list_head frame_list;	/* List of frames to pack into packet for send */
	struct sk_buff *head;		/* Head skb for packet bundling on send */
	u16 frame_len;		/* Length of all ack-eliciting frames excluding PING */
	u8 taglen[2];		/* Tag length for short and long packets */
	u32 version;		/* QUIC version used/selected during handshake */
	u8 errframe;		/* Frame type causing packet processing failure */
	u8 overhead;		/* QUIC header length excluding frames */
	u16 errcode;		/* Error code on packet processing failure */
	u16 frames;		/* Number of ack-eliciting frames excluding PING */
	u16 mss[2];		/* MSS for datagram and non-datagram packets */
	u16 hlen;		/* UDP + IP header length for sending */
	u16 len;		/* QUIC packet length excluding taglen for sending */

	u8 ack_eliciting:1;	/* Packet contains ack-eliciting frames to send */
	u8 ack_requested:1;	/* Packet contains ack-eliciting frames received */
	u8 ack_immediate:1;	/* Send ACK immediately (skip ack_delay timer) */
	u8 non_probing:1;	/* Packet has ack-eliciting frames excluding NEW_CONNECTION_ID */
	u8 has_sack:1;		/* Packet has ACK frames received */
	u8 ipfragok:1;		/* Allow IP fragmentation */
	u8 padding:1;		/* Packet has padding frames */
	u8 path:1;		/* Path identifier used to send this packet */
	u8 level;		/* Encryption level used */
};

struct quic_packet_sent {
	struct list_head list;	/* Link in sent packet list for ACK tracking */
	u32 sent_time;		/* Time when packet was sent */
	u16 frame_len;		/* Combined length of all frames held */
	u16 frames;		/* Number of frames held */

	s64 number;		/* Packet number */
	u8  level;		/* Packet number space */
	u8  ecn:2;		/* ECN bits */

	struct quic_frame *frame_array[];	/* Array of pointers to held frames */
};

#define QUIC_PACKET_INITIAL_V1		0
#define QUIC_PACKET_0RTT_V1		1
#define QUIC_PACKET_HANDSHAKE_V1	2
#define QUIC_PACKET_RETRY_V1		3

#define QUIC_PACKET_INITIAL_V2		1
#define QUIC_PACKET_0RTT_V2		2
#define QUIC_PACKET_HANDSHAKE_V2	3
#define QUIC_PACKET_RETRY_V2		0

#define QUIC_PACKET_INITIAL		QUIC_PACKET_INITIAL_V1
#define QUIC_PACKET_0RTT		QUIC_PACKET_0RTT_V1
#define QUIC_PACKET_HANDSHAKE		QUIC_PACKET_HANDSHAKE_V1
#define QUIC_PACKET_RETRY		QUIC_PACKET_RETRY_V1

#define QUIC_VERSION_LEN		4

static inline u8 quic_packet_taglen(struct quic_packet *packet)
{
	return packet->taglen[!!packet->level];
}

static inline void quic_packet_set_taglen(struct quic_packet *packet, u8 taglen)
{
	packet->taglen[0] = taglen;
}

static inline u32 quic_packet_mss(struct quic_packet *packet)
{
	return packet->mss[0] - packet->taglen[!!packet->level];
}

static inline u32 quic_packet_max_payload(struct quic_packet *packet)
{
	return packet->mss[0] - packet->overhead - packet->taglen[!!packet->level];
}

static inline u32 quic_packet_max_payload_dgram(struct quic_packet *packet)
{
	return packet->mss[1] - packet->overhead - packet->taglen[!!packet->level];
}

static inline int quic_packet_empty(struct quic_packet *packet)
{
	return list_empty(&packet->frame_list);
}

static inline void quic_packet_reset(struct quic_packet *packet)
{
	packet->level = 0;
	packet->errcode = 0;
	packet->errframe = 0;
	packet->has_sack = 0;
	packet->non_probing = 0;
	packet->ack_requested = 0;
	packet->ack_immediate = 0;
}

int quic_packet_tail(struct sock *sk, struct quic_frame *frame);
int quic_packet_process(struct sock *sk, struct sk_buff *skb);
int quic_packet_config(struct sock *sk, u8 level, u8 path);

int quic_packet_xmit(struct sock *sk, struct sk_buff *skb);
int quic_packet_create(struct sock *sk);
int quic_packet_route(struct sock *sk);

void quic_packet_mss_update(struct sock *sk, u32 mss);
void quic_packet_flush(struct sock *sk);
void quic_packet_init(struct sock *sk);

int quic_packet_get_dcid(struct quic_conn_id *dcid, struct sk_buff *skb);
int quic_packet_select_version(struct sock *sk, u32 *versions, u8 count);
u32 *quic_packet_compatible_versions(u32 version);

void quic_packet_rcv_err_pmtu(struct sock *sk);
int quic_packet_rcv(struct sk_buff *skb, u8 err);
