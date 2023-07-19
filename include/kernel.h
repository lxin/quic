/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef __uapi_quic_h__
#define __uapi_quic_h__

#include <linux/types.h>

enum {
	IPPROTO_QUIC = 144,	/* A UDP-Based Multiplexed and Secure Transport	*/
#define IPPROTO_QUIC		IPPROTO_QUIC
};

#define SOL_QUIC	144

enum {
	QUIC_STREAM_FLAG_NEW = (1 << 0),
	QUIC_STREAM_FLAG_FIN = (1 << 1),
};

struct quic_sndinfo {
	uint32_t stream_id;
	uint32_t stream_flag;
};

struct quic_rcvinfo {
	uint32_t stream_id;
	uint32_t stream_flag;
};

enum quic_cmsg_type {
	QUIC_SNDINFO,
	QUIC_RCVINFO,
};

struct quic_connection_id {
	uint32_t number;
	uint8_t len;
	uint8_t data[20];
};

struct quic_connection_id_numbers {
	uint32_t start_number;
	uint32_t end_number;
	uint32_t active_number;
};

struct quic_transport_param {
	uint32_t max_udp_payload_size;
	uint32_t ack_delay_exponent;
	uint32_t max_ack_delay;
	uint32_t initial_max_data;
	uint32_t initial_max_stream_data_bidi_local;
	uint32_t initial_max_stream_data_bidi_remote;
	uint32_t initial_max_stream_data_uni;
	uint32_t initial_max_streams_bidi;
	uint32_t initial_max_streams_uni;
	uint32_t initial_smoothed_rtt;
};

enum quic_state {
	QUIC_STATE_USER_CLOSED,
	QUIC_STATE_USER_CONNECTING,
	QUIC_STATE_CLIENT_CONNECTED,
	QUIC_STATE_SERVER_CONNECTED,
};

#define QUIC_SOCKOPT_SOURCE_CONNECTION_ID_NUMBERS	0
#define QUIC_SOCKOPT_DEST_CONNECTION_ID_NUMBERS		1
#define QUIC_SOCKOPT_KEY_UPDATE				2
#define QUIC_SOCKOPT_CONNECTION_MIGRATION		3

#define QUIC_SOCKOPT_LOCAL_TRANSPORT_PARAMS	100
#define QUIC_SOCKOPT_PEER_TRANSPORT_PARAMS	101
#define QUIC_SOCKOPT_SOURCE_ADDRESS		102
#define QUIC_SOCKOPT_DEST_ADDRESS		103
#define QUIC_SOCKOPT_SOURCE_CONNECTION_ID	104
#define QUIC_SOCKOPT_DEST_CONNECTION_ID		105
#define QUIC_SOCKOPT_CRYPTO_SEND_SECRET		106
#define QUIC_SOCKOPT_CRYPTO_RECV_SECRET		107
#define QUIC_SOCKOPT_STATE			108

#endif /* __uapi_quic_h__ */
