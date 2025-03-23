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
	struct quic_conn_id dcid;
	struct quic_conn_id scid;
	union quic_addr daddr;
	union quic_addr saddr;

	struct list_head frame_list;
	struct sk_buff *head;
	u16 frame_len;
	u8 taglen[2];
	u32 version;
	u8 errframe;
	u8 overhead;
	u16 errcode;
	u16 frames;
	u16 mss[2];
	u16 hlen;
	u16 len;

	u8 ack_eliciting:1;
	u8 ack_immediate:1;
	u8 non_probing:1;
	u8 has_sack:1;
	u8 ipfragok:1;
	u8 padding:1;
	u8 path:1;
	u8 level;
};

struct quic_packet_sent {
	struct list_head list;
	u32 sent_time;
	u16 frame_len;
	u16 frames;

	s64 number;
	u8  level;
	u8  ecn:2;

	struct quic_frame *frame_array[];
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

static inline void quic_packet_set_version(struct quic_packet *packet, u32 version)
{
	packet->version = version;
}

static inline u16 quic_packet_len(struct quic_packet *packet)
{
	return packet->len;
}

static inline u16 quic_packet_frame_len(struct quic_packet *packet)
{
	return packet->frame_len;
}

static inline u8 quic_packet_taglen(struct quic_packet *packet)
{
	return packet->taglen[!!packet->level];
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

static inline void quic_packet_set_taglen(struct quic_packet *packet, u8 taglen)
{
	packet->taglen[0] = taglen;
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
	packet->ack_eliciting = 0;
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
int quic_packet_parse_alpn(struct sk_buff *skb, struct quic_data *alpn);
u32 *quic_packet_compatible_versions(u32 version);

void quic_packet_rcv_err_pmtu(struct sock *sk);
int quic_packet_rcv(struct sk_buff *skb, u8 err);
