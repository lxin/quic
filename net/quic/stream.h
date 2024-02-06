/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_STREAM_BIT_FIN	0x01
#define QUIC_STREAM_BIT_LEN	0x02
#define QUIC_STREAM_BIT_OFF	0x04
#define QUIC_STREAM_BIT_MASK	0x08

#define QUIC_MAX_STREAMS	BIT_ULL(60)

struct quic_stream {
	struct hlist_node node;
	u64 id;
	struct {
		u64 max_bytes;
		u64 window; /* congestion control in stream level? not now */
		u64 bytes;
		u64 offset;

		u32 errcode;
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
};

struct quic_stream_table {
	struct quic_hash_table ht;

	struct {
		u64 max_stream_data_bidi_local;
		u64 max_stream_data_bidi_remote;
		u64 max_stream_data_uni;
		u64 max_streams_bidi;
		u64 max_streams_uni;
		u64 streams_bidi;
		u64 streams_uni;
		u64 stream_active;
	} send;
	struct {
		u64 max_stream_data_bidi_local;
		u64 max_stream_data_bidi_remote;
		u64 max_stream_data_uni;
		u64 max_streams_bidi;
		u64 max_streams_uni;
	} recv;
};

int quic_streams_init(struct quic_stream_table *streams);
void quic_streams_free(struct quic_stream_table *streams);
void quic_streams_set_param(struct quic_stream_table *streams, struct quic_transport_param *local,
			    struct quic_transport_param *remote);
struct quic_stream *quic_stream_send_get(struct quic_stream_table *streams, u64 stream_id,
					 u32 flag, bool is_serv);
struct quic_stream *quic_stream_recv_get(struct quic_stream_table *streams, u64 stream_id,
					 bool is_serv);
struct quic_stream *quic_stream_find(struct quic_stream_table *streams, u64 stream_id);
bool quic_stream_id_exceeds(struct quic_stream_table *streams, u64 stream_id);
