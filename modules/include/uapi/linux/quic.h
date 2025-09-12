/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef _UAPI_LINUX_QUIC_H
#define _UAPI_LINUX_QUIC_H

#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/socket.h>
#else
#include <sys/socket.h>
#endif

enum {
	IPPROTO_QUIC = 261,		/* A UDP-Based Multiplexed and Secure Transport	*/
#define IPPROTO_QUIC		IPPROTO_QUIC
};

#define SOL_QUIC	288

/* NOTE: Structure descriptions are specified in:
 * https://datatracker.ietf.org/doc/html/draft-lxin-quic-socket-apis
 */

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
	MSG_STREAM_NEW		= MSG_SYN,
	MSG_STREAM_FIN		= MSG_FIN,
	MSG_STREAM_UNI		= MSG_CONFIRM,
	MSG_STREAM_DONTWAIT	= MSG_WAITFORONE,
	MSG_STREAM_SNDBLOCK	= MSG_ERRQUEUE,

	/* extented flags for msg_flags */
	MSG_DATAGRAM		= MSG_RST,
	MSG_NOTIFICATION	= MSG_MORE,
};

enum quic_crypto_level {
	QUIC_CRYPTO_APP,
	QUIC_CRYPTO_INITIAL,
	QUIC_CRYPTO_HANDSHAKE,
	QUIC_CRYPTO_EARLY,
	QUIC_CRYPTO_MAX,
};

struct quic_handshake_info {
	__u8	crypto_level;
};

struct quic_stream_info {
	__s64	stream_id;
	__u32	stream_flags;
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

#define QUIC_SOCKOPT_STREAM_PEELOFF			15

#define QUIC_VERSION_V1			0x1
#define QUIC_VERSION_V2			0x6b3343cf

struct quic_transport_param {
	__u8	remote;
	__u8	disable_active_migration;
	__u8	grease_quic_bit;
	__u8	stateless_reset;
	__u8	disable_1rtt_encryption;
	__u8	disable_compatible_version;
	__u8	active_connection_id_limit;
	__u8	ack_delay_exponent;
	__u16	max_datagram_frame_size;
	__u16	max_udp_payload_size;
	__u32	max_idle_timeout;
	__u32	max_ack_delay;
	__u16	max_streams_bidi;
	__u16	max_streams_uni;
	__u64	max_data;
	__u64	max_stream_data_bidi_local;
	__u64	max_stream_data_bidi_remote;
	__u64	max_stream_data_uni;
	__u64	reserved;
};

struct quic_config {
	__u32	version;
	__u32	plpmtud_probe_interval;
	__u32	initial_smoothed_rtt;
	__u32	payload_cipher_type;
	__u8	congestion_control_algo;
	__u8	validate_peer_address;
	__u8	stream_data_nodelay;
	__u8	receive_session_ticket;
	__u8	certificate_request;
	__u8	reserved[3];
};

struct quic_crypto_secret {
	__u8	send;  /* send or recv */
	__u8	level; /* crypto level */
	__u32	type; /* TLS_CIPHER_* */
#define QUIC_CRYPTO_SECRET_BUFFER_SIZE 48
	__u8	secret[QUIC_CRYPTO_SECRET_BUFFER_SIZE];
};

enum quic_cong_algo {
	QUIC_CONG_ALG_RENO,
	QUIC_CONG_ALG_CUBIC,
	QUIC_CONG_ALG_MAX,
};

struct quic_errinfo {
	__s64	stream_id;
	__u32	errcode;
};

struct quic_connection_id_info {
	__u8	dest;
	__u32	active;
	__u32	prior_to;
};

struct quic_event_option {
	__u8	type;
	__u8	on;
};

struct quic_stream_peeloff {
	__s64	stream_id;
	__u32	flags;
	int	sd;
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
	QUIC_EVENT_MAX,
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
	__s64	id;
	__u8	state;
	__u32	errcode;
	__u64	finalsz;
};

struct quic_stream_max_data {
	__s64	id;
	__u64	max_data;
};

struct quic_connection_close {
	__u32	errcode;
	__u8	frame;
	__u8	phrase[];
};

union quic_event {
	struct quic_stream_update	update;
	struct quic_stream_max_data	max_data;
	struct quic_connection_close	close;
	struct quic_connection_id_info	info;
	__u64	max_stream;
	__u8	local_migration;
	__u8	key_update_phase;
};

enum {
	QUIC_TRANSPORT_ERROR_NONE			= 0x00,
	QUIC_TRANSPORT_ERROR_INTERNAL			= 0x01,
	QUIC_TRANSPORT_ERROR_CONNECTION_REFUSED		= 0x02,
	QUIC_TRANSPORT_ERROR_FLOW_CONTROL		= 0x03,
	QUIC_TRANSPORT_ERROR_STREAM_LIMIT		= 0x04,
	QUIC_TRANSPORT_ERROR_STREAM_STATE		= 0x05,
	QUIC_TRANSPORT_ERROR_FINAL_SIZE			= 0x06,
	QUIC_TRANSPORT_ERROR_FRAME_ENCODING		= 0x07,
	QUIC_TRANSPORT_ERROR_TRANSPORT_PARAM		= 0x08,
	QUIC_TRANSPORT_ERROR_CONNECTION_ID_LIMIT	= 0x09,
	QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION		= 0x0a,
	QUIC_TRANSPORT_ERROR_INVALID_TOKEN		= 0x0b,
	QUIC_TRANSPORT_ERROR_APPLICATION		= 0x0c,
	QUIC_TRANSPORT_ERROR_CRYPTO_BUF_EXCEEDED	= 0x0d,
	QUIC_TRANSPORT_ERROR_KEY_UPDATE			= 0x0e,
	QUIC_TRANSPORT_ERROR_AEAD_LIMIT_REACHED		= 0x0f,
	QUIC_TRANSPORT_ERROR_NO_VIABLE_PATH		= 0x10,

	/* The cryptographic handshake failed. A range of 256 values is reserved
	 * for carrying error codes specific to the cryptographic handshake that
	 * is used. Codes for errors occurring when TLS is used for the
	 * cryptographic handshake are described in Section 4.8 of [QUIC-TLS].
	 */
	QUIC_TRANSPORT_ERROR_CRYPTO			= 0x0100,
};

#endif /* _UAPI_LINUX_QUIC_H */
