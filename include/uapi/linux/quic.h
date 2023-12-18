/* SPDX-License-Identifier: GPL-2.0-or-later */
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

#define SOL_QUIC	287

/* Send or Receive Options APIs */
enum quic_cmsg_type {
	QUIC_STREAM_INFO,
	QUIC_HANDSHAKE_INFO,
};

#define QUIC_STREAM_TYPE_SERVER_MASK	0x01
#define QUIC_STREAM_TYPE_UNI_MASK	0x02
#define QUIC_STREAM_TYPE_MASK		0x03	/* the 1st 2 bits in stream_id */

enum {	/* used in stream_flag of struct quic_sndinfo or quic_rcvinfo */
	QUIC_STREAM_FLAG_NEW = (1 << 0),	/* sendmsg (like MSG_SYN in msg_flags) */
	QUIC_STREAM_FLAG_FIN = (1 << 1),	/* sendmsg or recvmsg (like MSG_FIN in msg_flags) */
	QUIC_STREAM_FLAG_UNI = (1 << 2),	/* getsockopt to open next uni stream with stream_id == -1 */
	QUIC_STREAM_FLAG_ASYNC = (1 << 3),	/* getsockopt or sendmsg to open stream */
	QUIC_STREAM_FLAG_NOTIFICATION = (1 << 4), /* recvmsg (MSG_NOTIFICATION in msg_flags) */
	QUIC_STREAM_FLAG_DATAGRAM = (1 << 5), /* sendmsg or recvmsg (like MSG_DATAGRAM in msg_flags) */
};

enum quic_crypto_level {
	QUIC_CRYPTO_APP,
	QUIC_CRYPTO_INITIAL,
	QUIC_CRYPTO_HANDSHAKE,
	QUIC_CRYPTO_EARLY,
	QUIC_CRYPTO_MAX,
};

struct quic_handshake_info { /* sendmsg or recvmsg */
	uint8_t	crypto_level;
};

struct quic_stream_info { /* sendmsg or setsockopt(QUIC_SOCKOPT_STREAM_OPEN) */
	uint64_t stream_id;
	uint32_t stream_flag;
};

enum quic_msg_flags {	/* msg_flags in send/recvmsg */
	MSG_NOTIFICATION = 0x8000,
	MSG_STREAM_UNI = 0x800,
	MSG_DATAGRAM = 0x10,
#define MSG_NOTIFICATION MSG_NOTIFICATION
};

/* Socket Options APIs */
#define QUIC_SOCKOPT_EVENT				0  /* set and get */
#define QUIC_SOCKOPT_STREAM_OPEN			1  /* get */
#define QUIC_SOCKOPT_STREAM_RESET			2  /* set */
#define QUIC_SOCKOPT_STREAM_STOP_SENDING		3  /* set */
#define QUIC_SOCKOPT_CONNECTION_CLOSE			4  /* set and get */
#define QUIC_SOCKOPT_CONNECTION_MIGRATION		5  /* set */
#define QUIC_SOCKOPT_CONGESTION_CONTROL			6  /* set and get */
#define QUIC_SOCKOPT_KEY_UPDATE				7  /* set */
#define QUIC_SOCKOPT_TRANSPORT_PARAM			8  /* set and get */
#define QUIC_SOCKOPT_TOKEN				9  /* set and get */

/* used to provide parameters for handshake from kernel, so only valid prior to handshake */
#define QUIC_SOCKOPT_ALPN				100 /* set and get */
#define QUIC_SOCKOPT_CRYPTO_SECRET			101 /* set and get */
#define QUIC_SOCKOPT_TRANSPORT_PARAM_EXT		102 /* set and get */
#define QUIC_SOCKOPT_SESSION_TICKET			103 /* set and get */

/* for testing only */
#define QUIC_SOCKOPT_RETIRE_CONNECTION_ID		1000 /* set */
#define QUIC_SOCKOPT_ACTIVE_CONNECTION_ID		1001 /* get */

#define QUIC_VERSION_V1			0x1
#define QUIC_VERSION_V2			0x6b3343cf

struct quic_transport_param {
	uint8_t remote;
	uint8_t disable_active_migration;
	uint8_t grease_quic_bit;
	uint64_t max_udp_payload_size;
	uint64_t ack_delay_exponent;
	uint64_t max_ack_delay;
	uint64_t active_connection_id_limit;
	uint64_t max_idle_timeout;
	uint64_t max_datagram_frame_size;
	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;
	uint64_t initial_smoothed_rtt;
	uint8_t validate_address;	/* for server only, verify token and send retry packet */
	uint8_t recv_session_ticket;	/* for client only, handshake done until ticket is recvd */
	uint8_t cert_request;		/* for server only, 0: IGNORE, 1: REQUEST, 2: REQUIRE */
	uint32_t cipher_type;		/* TLS_CIPHER_AES_GCM_128/AES_GCM_256/AES_CCM_128/CHACHA20_POLY1305 */
	uint32_t version;		/* QUIC_VERSION_V1 or V2 for now */
};

struct quic_crypto_secret {
	uint8_t level; /* stream or handshake */
	uint16_t send; /* send or recv */
	uint32_t type; /* TLS_CIPHER_* */
	uint8_t secret[48];
};

enum { /* CONGESTION_CONTROL */
	QUIC_CONG_ALG_RENO,
	QUIC_CONG_ALG_MAX,
};

struct quic_errinfo { /* STREAM_RESET and STREAM_STOP_SENDING */
	uint64_t stream_id;
	uint32_t errcode;
};

struct quic_connection_id_info { /* RETIRE/ACTIVE_CONNECTION_ID */
	uint32_t source;
	uint32_t dest;
};

struct quic_event_option { /* EVENT */
	uint8_t type;
	uint8_t on;
};

/* Event APIs:
 *
 * - QUIC_EVENT_STREAM_UPDATE:
 *
 *   Only notifications with these states are sent to userspace:
 *
 *   QUIC_STREAM_SEND_STATE_RECVD
 *   QUIC_STREAM_SEND_STATE_RESET_SENT
 *   QUIC_STREAM_SEND_STATE_RESET_RECVD
 *
 *   QUIC_STREAM_RECV_STATE_RECV
 *   QUIC_STREAM_RECV_STATE_SIZE_KNOWN
 *   QUIC_STREAM_RECV_STATE_RECVD
 *   QUIC_STREAM_RECV_STATE_RESET_RECVD
 *
 *   Note:
 *   1. QUIC_STREAM_SEND_STATE_RESET_SENT update is sent only if STOP_SEDNING is received;
 *   2. QUIC_STREAM_RECV_STATE_SIZE_KNOWN update is sent only if data comes out of order;
 *   3. QUIC_STREAM_RECV_STATE_RECV update is sent only when the last frag hasn't arrived.
 *
 * - QUIC_EVENT_STREAM_MAX_STREAM:
 *
 *   This notification is sent when max_streams frame is received, and this is useful when
 *   using QUIC_STREAM_FLAG_ASYNC to open a stream whose id exceeds the max stream count.
 *   After receiving this notification, try to open this stream again.
 *
 * - QUIC_EVENT_CONNECTION_CLOSE
 *
 *   This notification is sent when receiving a close from peer where it can set the close
 *   info with QUIC_SOCKOPT_CONNECTION_CLOSE socket option
 *
 * - QUIC_EVENT_CONNECTION_MIGRATION
 *
 *   This notification is sent when either side sucessfully changes its source address by
 *   QUIC_SOCKOPT_CONNECTION_MIGRATION or dest address by peer's CONNECTION_MIGRATION.
 *   The parameter tells you if it's a local or peer CONNECTION_MIGRATION, and then you
 *   can get the new address with getsockname() or getpeername().
 *
 * - QUIC_EVENT_KEY_UPDATE
 *
 *   This notification is sent when both sides have used the new key, and the parameter
 *   tells you which the new key phase is.
 *
 * - QUIC_EVENT_NEW_TOKEN
 *
 *   Since the handshake is in userspace, this notifications is sent whenever the
 *   frame of NEW_TOKEN is received from the peer where it can send these frame by
 *   QUIC_SOCKOPT_NEW_TOKEN.
 */
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

struct quic_connection_close { /* also used for CONNECTION_CLOSE socket option */
	uint32_t errcode;
	uint8_t frame;
	uint8_t phrase[];
};

union quic_event {
	struct quic_stream_update update;
	uint64_t max_stream;
	struct quic_connection_close close;
	uint8_t local_migration;
	uint8_t key_update_phase;
	uint8_t new_token[0];
};

#endif /* __uapi_quic_h__ */
