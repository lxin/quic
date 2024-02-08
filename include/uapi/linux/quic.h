/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef __uapi_quic_h__
#define __uapi_quic_h__

#include <linux/types.h>
#include <linux/socket.h>

enum {
	IPPROTO_QUIC = 261,		/* A UDP-Based Multiplexed and Secure Transport	*/
#define IPPROTO_QUIC		IPPROTO_QUIC
};

#define SOL_QUIC	288

/* Send or Receive Options APIs */
enum quic_cmsg_type {
	QUIC_STREAM_INFO,
	QUIC_HANDSHAKE_INFO,
};

#define QUIC_STREAM_TYPE_SERVER_MASK	0x01
#define QUIC_STREAM_TYPE_UNI_MASK	0x02
#define QUIC_STREAM_TYPE_MASK		0x03

enum {
	QUIC_STREAM_FLAG_NEW		= (1 << 0),
	QUIC_STREAM_FLAG_FIN		= (1 << 1),
	QUIC_STREAM_FLAG_UNI		= (1 << 2),
	QUIC_STREAM_FLAG_ASYNC		= (1 << 3),
	QUIC_STREAM_FLAG_NOTIFICATION	= (1 << 4),
	QUIC_STREAM_FLAG_DATAGRAM	= (1 << 5),
};

enum quic_crypto_level {
	QUIC_CRYPTO_APP,
	QUIC_CRYPTO_INITIAL,
	QUIC_CRYPTO_HANDSHAKE,
	QUIC_CRYPTO_EARLY,
	QUIC_CRYPTO_MAX,
};

struct quic_handshake_info {
	uint8_t	crypto_level;
};

struct quic_stream_info {
	uint64_t stream_id;
	uint32_t stream_flag;
};

enum quic_msg_flags {
	MSG_NOTIFICATION	= 0x8000,
	MSG_STREAM_UNI		= 0x800,
	MSG_DATAGRAM		= 0x10,
};

/* Socket Options APIs */
#define QUIC_SOCKOPT_EVENT				0
#define QUIC_SOCKOPT_STREAM_OPEN			1
#define QUIC_SOCKOPT_STREAM_RESET			2
#define QUIC_SOCKOPT_STREAM_STOP_SENDING		3
#define QUIC_SOCKOPT_CONNECTION_CLOSE			4
#define QUIC_SOCKOPT_CONNECTION_MIGRATION		5
#define QUIC_SOCKOPT_KEY_UPDATE				6
#define QUIC_SOCKOPT_TRANSPORT_PARAM			7
#define QUIC_SOCKOPT_TOKEN				8
#define QUIC_SOCKOPT_ALPN				9
#define QUIC_SOCKOPT_SESSION_TICKET			10
#define QUIC_SOCKOPT_CRYPTO_SECRET			11
#define QUIC_SOCKOPT_TRANSPORT_PARAM_EXT		12
#define QUIC_SOCKOPT_RETIRE_CONNECTION_ID		13
#define QUIC_SOCKOPT_ACTIVE_CONNECTION_ID		14

#define QUIC_VERSION_V1			0x1
#define QUIC_VERSION_V2			0x6b3343cf

struct quic_transport_param {
	uint8_t		remote;
	uint8_t		disable_active_migration;
	uint8_t		grease_quic_bit;
	uint8_t		stateless_reset;
	uint64_t	max_udp_payload_size;
	uint64_t	ack_delay_exponent;
	uint64_t	max_ack_delay;
	uint64_t	active_connection_id_limit;
	uint64_t	max_idle_timeout;
	uint64_t	max_datagram_frame_size;
	uint64_t	max_data;
	uint64_t	max_stream_data_bidi_local;
	uint64_t	max_stream_data_bidi_remote;
	uint64_t	max_stream_data_uni;
	uint64_t	max_streams_bidi;
	uint64_t	max_streams_uni;
	uint64_t	initial_smoothed_rtt;
	uint32_t	plpmtud_probe_timeout;
	uint8_t		validate_peer_address;
	uint8_t		receive_session_ticket;
	uint8_t		certificate_request;
	uint8_t		congestion_control_alg;
	uint32_t	payload_cipher_type;
	uint32_t	version;
};

struct quic_crypto_secret {
	uint8_t level; /* crypto level */
	uint16_t send; /* send or recv */
	uint32_t type; /* TLS_CIPHER_* */
	uint8_t secret[48];
};

enum {
	QUIC_CONG_ALG_RENO,
	QUIC_CONG_ALG_MAX,
};

struct quic_errinfo {
	uint64_t stream_id;
	uint32_t errcode;
};

struct quic_connection_id_info {
	uint32_t source;
	uint32_t dest;
};

struct quic_event_option {
	uint8_t type;
	uint8_t on;
};

/* Event APIs */
enum quic_event_type {
	QUIC_EVENT_NONE,
	QUIC_EVENT_STREAM_UPDATE,
	QUIC_EVENT_STREAM_MAX_STREAM,
	QUIC_EVENT_CONNECTION_CLOSE,
	QUIC_EVENT_CONNECTION_MIGRATION,
	QUIC_EVENT_KEY_UPDATE,
	QUIC_EVENT_NEW_TOKEN,
	QUIC_EVENT_END,
	QUIC_EVENT_MAX = QUIC_EVENT_END - 1,
};

enum {
	QUIC_STREAM_SEND_STATE_READY,
	QUIC_STREAM_SEND_STATE_SEND,
	QUIC_STREAM_SEND_STATE_SENT,
	QUIC_STREAM_SEND_STATE_RECVD,
	QUIC_STREAM_SEND_STATE_RESET_SENT,
	QUIC_STREAM_SEND_STATE_RESET_RECVD,

	QUIC_STREAM_RECV_STATE_RECV,
	QUIC_STREAM_RECV_STATE_SIZE_KNOWN,
	QUIC_STREAM_RECV_STATE_RECVD,
	QUIC_STREAM_RECV_STATE_READ,
	QUIC_STREAM_RECV_STATE_RESET_RECVD,
	QUIC_STREAM_RECV_STATE_RESET_READ,
};

struct quic_stream_update {
	uint64_t id;
	uint32_t state;
	uint32_t errcode; /* or known_size */
};

struct quic_connection_close {
	uint32_t errcode;
	uint8_t frame;
	uint8_t phrase[];
};

union quic_event {
	struct quic_stream_update update;
	struct quic_connection_close close;
	uint64_t max_stream;
	uint8_t local_migration;
	uint8_t key_update_phase;
};

#endif /* __uapi_quic_h__ */
