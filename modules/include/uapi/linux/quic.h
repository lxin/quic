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

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

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

enum quic_msg_flags {
	/* flags for stream_flags */
	MSG_STREAM_NEW		= 0x400,
	MSG_STREAM_FIN		= 0x200,
	MSG_STREAM_UNI		= 0x800,
	MSG_STREAM_DONTWAIT	= 0x10000,
	MSG_STREAM_SNDBLOCK	= 0x20000,

	/* extented flags for msg_flags */
	MSG_DATAGRAM		= 0x10,
	MSG_NOTIFICATION	= 0x8000,
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
	int64_t  stream_id;
	uint32_t stream_flags;
};

/* Socket Options APIs */
#define QUIC_SOCKOPT_EVENT				0
#define QUIC_SOCKOPT_STREAM_OPEN			1
#define QUIC_SOCKOPT_STREAM_RESET			2
#define QUIC_SOCKOPT_STREAM_STOP_SENDING		3
#define QUIC_SOCKOPT_CONNECTION_ID			4
#define QUIC_SOCKOPT_CONNECTION_CLOSE			5
#define QUIC_SOCKOPT_CONNECTION_MIGRATION		6
#define QUIC_SOCKOPT_KEY_UPDATE				7
#define QUIC_SOCKOPT_TRANSPORT_PARAM			8
#define QUIC_SOCKOPT_CONFIG				9
#define QUIC_SOCKOPT_TOKEN				10
#define QUIC_SOCKOPT_ALPN				11
#define QUIC_SOCKOPT_SESSION_TICKET			12
#define QUIC_SOCKOPT_CRYPTO_SECRET			13
#define QUIC_SOCKOPT_TRANSPORT_PARAM_EXT		14

#define QUIC_VERSION_V1			0x1
#define QUIC_VERSION_V2			0x6b3343cf

struct quic_transport_param {
	uint8_t		remote;
	uint8_t		disable_active_migration;
	uint8_t		grease_quic_bit;
	uint8_t		stateless_reset;
	uint8_t		disable_1rtt_encryption;
	uint8_t		disable_compatible_version;
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
};

struct quic_config {
	uint32_t	version;
	uint32_t	plpmtud_probe_interval;
	uint64_t	initial_smoothed_rtt;
	uint8_t		congestion_control_algo;
	uint8_t		validate_peer_address;
	uint32_t	payload_cipher_type;
	uint8_t		receive_session_ticket;
	uint8_t		certificate_request;
	uint8_t		stream_data_nodelay;
};

struct quic_crypto_secret {
	uint8_t send;  /* send or recv */
	uint8_t level; /* crypto level */
	uint32_t type; /* TLS_CIPHER_* */
	uint8_t secret[48];
};

enum quic_cong_algo {
	QUIC_CONG_ALG_RENO,
	QUIC_CONG_ALG_CUBIC,
	QUIC_CONG_ALG_MAX,
};

struct quic_errinfo {
	int64_t  stream_id;
	uint32_t errcode;
};

struct quic_connection_id_info {
	uint8_t  dest;
	uint32_t active;
	uint32_t prior_to;
};

struct quic_event_option {
	uint8_t type;
	uint8_t on;
};

/* Event APIs */
enum quic_event_type {
	QUIC_EVENT_NONE,
	QUIC_EVENT_STREAM_UPDATE,
	QUIC_EVENT_STREAM_MAX_DATA,
	QUIC_EVENT_STREAM_MAX_STREAM,
	QUIC_EVENT_CONNECTION_ID,
	QUIC_EVENT_CONNECTION_CLOSE,
	QUIC_EVENT_CONNECTION_MIGRATION,
	QUIC_EVENT_KEY_UPDATE,
	QUIC_EVENT_NEW_TOKEN,
	QUIC_EVENT_NEW_SESSION_TICKET,
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
	int64_t  id;
	uint8_t  state;
	uint32_t errcode;
	uint64_t finalsz;
};

struct quic_stream_max_data {
	int64_t  id;
	uint64_t max_data;
};

struct quic_connection_close {
	uint32_t errcode;
	uint8_t frame;
	uint8_t phrase[];
};

union quic_event {
	struct quic_stream_update update;
	struct quic_stream_max_data max_data;
	struct quic_connection_close close;
	struct quic_connection_id_info info;
	uint64_t max_stream;
	uint8_t local_migration;
	uint8_t key_update_phase;
};

#endif /* __uapi_quic_h__ */
