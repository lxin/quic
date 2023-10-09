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
	QUIC_STREAM_SEND_STATE_READY,
	QUIC_STREAM_SEND_STATE_SEND,
	QUIC_STREAM_SEND_STATE_SENT,
	QUIC_STREAM_SEND_STATE_RECVD,
	QUIC_STREAM_SEND_STATE_RESET_SENT,
	QUIC_STREAM_SEND_STATE_RESET_RECVD,
};

enum {
	QUIC_STREAM_RECV_STATE_RECV,
	QUIC_STREAM_RECV_STATE_SIZE_KNOWN,
	QUIC_STREAM_RECV_STATE_RECVD,
	QUIC_STREAM_RECV_STATE_READ,
	QUIC_STREAM_RECV_STATE_RESET_RECVD,
	QUIC_STREAM_RECV_STATE_RESET_READ,
};

#define QUIC_STREAM_BIT_FIN	0x01
#define QUIC_STREAM_BIT_LEN	0x02
#define QUIC_STREAM_BIT_OFF	0x04
#define QUIC_STREAM_BIT_MASK	0x08

struct quic_stream {
	struct hlist_node node;
	u32 id;
	struct {
		u64 max_bytes;
		u64 window; /* congestion control in stream level? not now */
		u64 bytes;
		u64 offset;

		u32 frags;
		u8 state;

		u8 data_blocked;
	} send;
	struct {
		u64 max_bytes;
		u64 window;
		u64 bytes;
		u64 offset;
		u64 highest;

		u32 frags;
		u8 state;
	} recv;
	u32 in_flight;
	u64 known_size;
};

struct quic_stream_table {
	struct quic_hash_table ht;

	struct {
		u32 max_stream_data_bidi_local;
		u32 max_stream_data_bidi_remote;
		u32 max_stream_data_uni;
		u32 max_streams_bidi;
		u32 max_streams_uni;
	} send;
	struct {
		u32 max_stream_data_bidi_local;
		u32 max_stream_data_bidi_remote;
		u32 max_stream_data_uni;
		u32 max_streams_bidi;
		u32 max_streams_uni;
	} recv;
};

int quic_streams_init(struct quic_stream_table *streams);
void quic_streams_free(struct quic_stream_table *streams);
void quic_streams_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			    u8 send);
void quic_streams_get_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			    u8 send);
struct quic_stream *quic_stream_send_get(struct quic_stream_table *streams, u32 stream_id,
					 u32 flag, bool is_serv);
struct quic_stream *quic_stream_recv_get(struct quic_stream_table *streams, u32 stream_id,
					 bool is_serv);
struct quic_stream *quic_stream_find(struct quic_stream_table *streams, u32 stream_id);
void quic_stream_send_state_update(struct quic_stream *stream, u8 type);
