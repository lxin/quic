/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_CLOSE_PHRASE_MAX_LEN	80

#define QUIC_TOKEN_MAX_LEN		120

#define QUIC_TICKET_MIN_LEN		64
#define QUIC_TICKET_MAX_LEN		4096

#define QUIC_FRAME_BUF_SMALL		20
#define QUIC_FRAME_BUF_LARGE		100

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
	QUIC_FRAME_DATAGRAM = 0x30, /* RFC 9221 */
	QUIC_FRAME_DATAGRAM_LEN = 0x31,
	QUIC_FRAME_MAX = QUIC_FRAME_DATAGRAM_LEN,
};

enum {
	QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID = 0x0000,
	QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT = 0x0001,
	QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN = 0x0002,
	QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE = 0x0003,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA = 0x0004,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x0005,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI = 0x0007,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI = 0x0008,
	QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI = 0x0009,
	QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT = 0x000a,
	QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY = 0x000b,
	QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION = 0x000c,
	QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS = 0x000d,
	QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT = 0x000e,
	QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID = 0x000f,
	QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID = 0x0010,
	QUIC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE = 0x0020,
	QUIC_TRANSPORT_PARAM_GREASE_QUIC_BIT = 0x2ab2,
	QUIC_TRANSPORT_PARAM_VERSION_INFORMATION = 0x11,
	QUIC_TRANSPORT_PARAM_DISABLE_1RTT_ENCRYPTION = 0xbaad,
};

/* Arguments passed to create a STREAM frame */
struct quic_msginfo {
	struct quic_stream *stream;	/* The QUIC stream associated with this frame */
	struct iov_iter *msg;		/* Iterator over message data to send */
	u32 flags;			/* Flags controlling stream frame creation */
	u8 level;			/* Encryption level for this frame */
};

/* Arguments passed to create a PING frame */
struct quic_probeinfo {
	u16 size;	/* Size of the PING packet */
	u8 level;	/* Encryption level for this frame */
};

/* Operations for creating, processing, and acknowledging QUIC frames */
struct quic_frame_ops {
	struct quic_frame *(*frame_create)(struct sock *sk, void *data, u8 type);
	int (*frame_process)(struct sock *sk, struct quic_frame *frame, u8 type);
	void (*frame_ack)(struct sock *sk, struct quic_frame *frame);
	u8 ack_eliciting;
};

/* Fragment of data appended to a STREAM frame */
struct quic_frame_frag {
	struct quic_frame_frag *next;	/* Next fragment in the linked list */
	u16 size;			/* Size of this data fragment */
	u8 data[];			/* Flexible array member holding fragment data */
};

struct quic_frame {
	union {
		struct quic_frame_frag *flist;	/* For TX: linked list of appended data fragments */
		struct sk_buff *skb;		/* For RX: skb containing the raw frame data */
	};
	struct quic_stream *stream;		/* Stream related to this frame, NULL if none */
	struct list_head list;			/* Linked list node for queuing frames */
	union {
		s64 offset;	/* For RX: stream/crypto data offset or read data offset */
		s64 number;	/* For TX: first packet number used */
	};
	u8  *data;		/* Pointer to the actual frame data buffer */

	refcount_t refcnt;
	u16 errcode;		/* Error code set during frame processing */
	u8  level;		/* Packet number space: Initial, Handshake, or App */
	u8  type;		/* Frame type identifier */
	u16 bytes;		/* Number of user data bytes */
	u16 size;		/* Allocated data buffer size */
	u16 len;		/* Total frame length including appended fragments */

	u8  ack_eliciting:1;	/* Frame requires acknowledgment */
	u8  transmitted:1;	/* Frame is in the transmitted queue */
	u8  stream_fin:1;	/* Frame includes FIN flag for stream */
	u8  nodelay:1;		/* Frame bypasses Nagle's algorithm for sending */
	u8  padding:1;		/* Padding is needed after this frame */
	u8  dgram:1;		/* Frame represents a datagram message (RX only) */
	u8  event:1;		/* Frame represents an event (RX only) */
	u8  path:1;		/* Path index used to send this frame */
};

static inline bool quic_frame_new_conn_id(u8 type)
{
	return type == QUIC_FRAME_NEW_CONNECTION_ID;
}

static inline bool quic_frame_dgram(u8 type)
{
	return type == QUIC_FRAME_DATAGRAM || type == QUIC_FRAME_DATAGRAM_LEN;
}

static inline bool quic_frame_stream(u8 type)
{
	return type >= QUIC_FRAME_STREAM && type < QUIC_FRAME_MAX_DATA;
}

static inline bool quic_frame_sack(u8 type)
{
	return type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN;
}

static inline bool quic_frame_ping(u8 type)
{
	return type == QUIC_FRAME_PING;
}

/* Check if a given frame type is valid for the specified encryption level,
 * based on the Frame Types table from rfc9000#section-12.4.
 *
 * Returns 0 if valid, 1 otherwise.
 */
static inline int quic_frame_level_check(u8 level, u8 type)
{
	if (level == QUIC_CRYPTO_APP)
		return 0;

	if (level == QUIC_CRYPTO_EARLY) {
		if (type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN ||
		    type == QUIC_FRAME_CRYPTO || type == QUIC_FRAME_HANDSHAKE_DONE ||
		    type == QUIC_FRAME_NEW_TOKEN || type == QUIC_FRAME_PATH_RESPONSE ||
		    type == QUIC_FRAME_RETIRE_CONNECTION_ID)
			return 1;
		return 0;
	}

	if (type != QUIC_FRAME_ACK && type != QUIC_FRAME_ACK_ECN &&
	    type != QUIC_FRAME_PADDING && type != QUIC_FRAME_PING &&
	    type != QUIC_FRAME_CRYPTO && type != QUIC_FRAME_CONNECTION_CLOSE)
		return 1;
	return 0;
}

int quic_frame_build_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					  u8 *data, u32 *len);
int quic_frame_parse_transport_params_ext(struct sock *sk, struct quic_transport_param *params,
					  u8 *data, u32 len);
int quic_frame_stream_append(struct sock *sk, struct quic_frame *frame,
			     struct quic_msginfo *info, u8 pack);

struct quic_frame *quic_frame_alloc(u32 size, u8 *data, gfp_t gfp);
struct quic_frame *quic_frame_get(struct quic_frame *frame);
void quic_frame_put(struct quic_frame *frame);

struct quic_frame *quic_frame_create(struct sock *sk, u8 type, void *data);
int quic_frame_process(struct sock *sk, struct quic_frame *frame);
void quic_frame_ack(struct sock *sk, struct quic_frame *frame);
