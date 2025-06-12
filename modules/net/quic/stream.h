/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_DEF_STREAMS	100
#define QUIC_MAX_STREAMS	4096ULL

/*
 * rfc9000#section-2.1:
 *
 *   The least significant bit (0x01) of the stream ID identifies the initiator of the stream.
 *   Client-initiated streams have even-numbered stream IDs (with the bit set to 0), and
 *   server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
 *
 *   The second least significant bit (0x02) of the stream ID distinguishes between bidirectional
 *   streams (with the bit set to 0) and unidirectional streams (with the bit set to 1).
 */
#define QUIC_STREAM_TYPE_BITS	2
#define QUIC_STREAM_ID_STEP	BIT(QUIC_STREAM_TYPE_BITS)

#define QUIC_STREAM_TYPE_CLIENT_BIDI	0x00
#define QUIC_STREAM_TYPE_SERVER_BIDI	0x01
#define QUIC_STREAM_TYPE_CLIENT_UNI	0x02
#define QUIC_STREAM_TYPE_SERVER_UNI	0x03

struct quic_stream {
	struct hlist_node node;
	s64 id;				/* Stream ID as defined in RFC 9000 Section 2.1 */
	struct {
		/* Sending-side stream level flow control */
		u64 last_max_bytes;	/* Maximum send offset advertised by peer at last update */
		u64 max_bytes;		/* Current maximum offset we are allowed to send to */
		u64 bytes;		/* Bytes already sent to peer */

		u32 errcode;		/* Application error code to send in RESET_STREAM */
		u32 frags;		/* Number of sent STREAM frames not yet acknowledged */
		u8 state;		/* Send stream state, per rfc9000#section-3.1 */

		u8 data_blocked:1;	/* True if flow control blocks sending more data */
		u8 stop_sent:1;		/* True if STOP_SENDING has been sent, not acknowledged */
		u8 done:1;		/* True if application indicated end of stream (FIN sent) */
	} send;
	struct {
		/* Receiving-side stream level flow control */
		u64 max_bytes;		/* Maximum offset peer is allowed to send to */
		u64 window;		/* Remaining receive window before advertise a new limit */
		u64 bytes;		/* Bytes consumed by application from the stream */

		u64 highest;		/* Highest received offset */
		u64 offset;		/* Offset up to which data is in buffer or consumed */
		u64 finalsz;		/* Final size of the stream if FIN received */

		u32 frags;		/* Number of received STREAM frames pending reassembly */
		u8 state;		/* Receive stream state, per rfc9000#section-3.2 */
		u8 done:1;		/* True if FIN received and final size validated */
	} recv;
};

struct quic_stream_table {
	struct quic_hash_table ht;	/* Hash table storing all active streams */

	struct {
		/* Parameters received from peer, defined in rfc9000#section-18.2 */
		u64 max_stream_data_bidi_remote;	/* initial_max_stream_data_bidi_remote */
		u64 max_stream_data_bidi_local;		/* initial_max_stream_data_bidi_local */
		u64 max_stream_data_uni;		/* initial_max_stream_data_uni */
		u64 max_streams_bidi;			/* initial_max_streams_bidi */
		u64 max_streams_uni;			/* initial_max_streams_uni */

		s64 next_bidi_stream_id;	/* Next bidi stream ID to be opened */
		s64 next_uni_stream_id;		/* Next uni stream ID to be opened */
		s64 max_bidi_stream_id;		/* Highest allowed bidi stream ID */
		s64 max_uni_stream_id;		/* Highest allowed uni stream ID */
		s64 active_stream_id;		/* Most recently opened stream ID */

		u8 bidi_blocked:1;	/* True if STREAMS_BLOCKED_BIDI was sent and not ACKed */
		u8 uni_blocked:1;	/* True if STREAMS_BLOCKED_UNI was sent and not ACKed */
		u16 streams_bidi;	/* Number of currently active bidi streams */
		u16 streams_uni;	/* Number of currently active uni streams */
	} send;
	struct {
		 /* Our advertised limits to the peer, per rfc9000#section-18.2 */
		u64 max_stream_data_bidi_remote;	/* initial_max_stream_data_bidi_remote */
		u64 max_stream_data_bidi_local;		/* initial_max_stream_data_bidi_local */
		u64 max_stream_data_uni;		/* initial_max_stream_data_uni */
		u64 max_streams_bidi;			/* initial_max_streams_bidi */
		u64 max_streams_uni;			/* initial_max_streams_uni */

		s64 next_bidi_stream_id;	/* Next expected bidi stream ID from peer */
		s64 next_uni_stream_id;		/* Next expected uni stream ID from peer */
		s64 max_bidi_stream_id;		/* Current allowed bidi stream ID range */
		s64 max_uni_stream_id;		/* Current allowed uni stream ID range */

		u8 bidi_pending:1;	/* True if MAX_STREAMS_BIDI needs to be sent */
		u8 uni_pending:1;	/* True if MAX_STREAMS_UNI needs to be sent */
		u16 streams_bidi;	/* Number of currently open bidi streams */
		u16 streams_uni;	/* Number of currently open uni streams */
	} recv;
};

static inline u64 quic_stream_id_to_streams(s64 stream_id)
{
	return (u64)(stream_id >> QUIC_STREAM_TYPE_BITS) + 1;
}

static inline s64 quic_stream_streams_to_id(u64 streams, u8 type)
{
	return (s64)((streams - 1) << QUIC_STREAM_TYPE_BITS) | type;
}

struct quic_stream *quic_stream_send_get(struct quic_stream_table *streams, s64 stream_id,
					 u32 flags, bool is_serv);
struct quic_stream *quic_stream_recv_get(struct quic_stream_table *streams, s64 stream_id,
					 bool is_serv);
void quic_stream_send_put(struct quic_stream_table *streams, struct quic_stream *stream,
			  bool is_serv);
void quic_stream_recv_put(struct quic_stream_table *streams, struct quic_stream *stream,
			  bool is_serv);

bool quic_stream_max_streams_update(struct quic_stream_table *streams, s64 *max_uni, s64 *max_bidi);
struct quic_stream *quic_stream_find(struct quic_stream_table *streams, s64 stream_id);
bool quic_stream_id_send_exceeds(struct quic_stream_table *streams, s64 stream_id);

void quic_stream_get_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv);
void quic_stream_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv);
void quic_stream_free(struct quic_stream_table *streams);
int quic_stream_init(struct quic_stream_table *streams);
