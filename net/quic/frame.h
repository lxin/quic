/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

enum {
	QUIC_FRAME_PADDING = 0x00,
	QUIC_FRAME_PING = 0x01,
	QUIC_FRAME_ACK = 0x02,
	QUIC_FRAME_ACK_ECN = 0x03,
	QUIC_FRAME_RESET_STREAM = 0x04,
	QUIC_FRAME_STOP_SENDING = 0x05,
	QUIC_FRAME_CRYPTO = 0x06,
	QUIC_FRAME_NEW_TOKEN = 0x07,
	QUIC_FRAME_STREAM = 0x08,
	QUIC_FRAME_MAX_DATA = 0x10,
	QUIC_FRAME_MAX_STREAM_DATA = 0x11,
	QUIC_FRAME_MAX_STREAMS_BIDI = 0x12,
	QUIC_FRAME_MAX_STREAMS_UNI = 0x13,
	QUIC_FRAME_DATA_BLOCKED = 0x14,
	QUIC_FRAME_STREAM_DATA_BLOCKED = 0x15,
	QUIC_FRAME_STREAMS_BLOCKED_BIDI = 0x16,
	QUIC_FRAME_STREAMS_BLOCKED_UNI = 0x17,
	QUIC_FRAME_NEW_CONNECTION_ID = 0x18,
	QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19,
	QUIC_FRAME_PATH_CHALLENGE = 0x1a,
	QUIC_FRAME_PATH_RESPONSE = 0x1b,
	QUIC_FRAME_CONNECTION_CLOSE = 0x1c,
	QUIC_FRAME_CONNECTION_CLOSE_APP = 0x1d,
	QUIC_FRAME_HANDSHAKE_DONE = 0x1e,
	QUIC_FRAME_BASE_MAX = QUIC_FRAME_HANDSHAKE_DONE,
	QUIC_FRAME_DATAGRAM = 0x30, /* RFC 9221 */
	QUIC_FRAME_DATAGRAM_LEN = 0x31,
};

struct quic_msginfo {
	struct quic_stream *stream;
	struct iov_iter *msg;
	u32 flag;
};

struct quic_frame_ops {
	struct sk_buff *(*frame_create)(struct sock *sk, void *data, u8 type);
	int (*frame_process)(struct sock *sk, struct sk_buff *skb, u8 type);
};

static inline bool quic_frame_ack_eliciting(u8 type)
{
	return type != QUIC_FRAME_ACK && type != QUIC_FRAME_PADDING &&
		type != QUIC_FRAME_CONNECTION_CLOSE &&
		type != QUIC_FRAME_CONNECTION_CLOSE_APP;
}

static inline bool quic_frame_ack_immediate(u8 type)
{
	return (type < QUIC_FRAME_STREAM || type >= QUIC_FRAME_MAX_DATA) ||
	       (type & QUIC_STREAM_BIT_FIN);
}

static inline bool quic_frame_non_probing(u8 type)
{
	return type != QUIC_FRAME_NEW_CONNECTION_ID && type != QUIC_FRAME_PADDING &&
	       type != QUIC_FRAME_PATH_RESPONSE && type != QUIC_FRAME_PATH_CHALLENGE;
}

struct sk_buff *quic_frame_create(struct sock *sk, u8 type, void *data);
int quic_frame_process(struct sock *sk, struct sk_buff *skb, struct quic_packet_info *pki);
int quic_frame_new_connection_id_ack(struct sock *sk, struct sk_buff *skb);

// 20.1 Transport Error Codes
enum quic_transport_error {
	QUIC_TRANS_ERR_NONE,
	QUIC_TRANS_ERR_INTERNAL,
	QUIC_TRANS_ERR_CONNECTION_REFUSED,
	QUIC_TRANS_ERR_FLOW_CONTROL,
	QUIC_TRANS_ERR_STREAM_LIMIT,
	QUIC_TRANS_ERR_STREAM_STATE,
	QUIC_TRANS_ERR_FINAL_SIZE,
	QUIC_TRANS_ERR_FRAME_ENCODING,
	QUIC_TRANS_ERR_TRANSPORT_PARAM,
	QUIC_TRANS_ERR_CONNECTION_ID_LIMIT,
	QUIC_TRANS_ERR_PROTOCOL_VIOLATION,
	QUIC_TRANS_ERR_INVALID_TOKEN,
	QUIC_TRANS_ERR_APPLICATION,
	QUIC_TRANS_ERR_CRYPTO_BUF_EXCEEDED,
	QUIC_TRANS_ERR_KEY_UPDATE,
	QUIC_TRANS_ERR_AED_LIMIT_REACHED,
	QUIC_TRANS_ERR_NO_VIABLE_PATH,

	/* The cryptographic handshake failed. A range of 256 values is reserved
	 * for carrying error codes specific to the cryptographic handshake that
	 * is used. Codes for errors occurring when TLS is used for the
	 * cryptographic handshake are described in Section 4.8 of [QUIC-TLS].
	 */
	QUIC_TRANS_ERR_CRYPTO,
};
