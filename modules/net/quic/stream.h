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

#define QUIC_STREAM_TYPE_CLIENT_BIDI	0x00
#define QUIC_STREAM_TYPE_SERVER_BIDI	0x01
#define QUIC_STREAM_TYPE_CLIENT_UNI	0x02
#define QUIC_STREAM_TYPE_SERVER_UNI	0x03

struct quic_stream {
	struct hlist_node node;
	s64 id;
	struct {
		u64 last_max_bytes;
		u64 max_bytes;
		u64 window; /* congestion control in stream level? not now */
		u64 offset;
		u64 bytes;

		u32 errcode;
		u32 frags;
		u8 state;

		u8 data_blocked:1;
		u8 stop_sent:1;
		u8 done:1;
	} send;
	struct {
		u64 max_bytes;
		u64 highest;
		u64 finalsz;
		u64 window;
		u64 offset;
		u64 bytes;

		u32 frags;
		u8 state;
		u8 done:1;
	} recv;
};

struct quic_stream_table {
	struct quic_hash_table ht;

	struct {
		u64 max_stream_data_bidi_remote;
		u64 max_stream_data_bidi_local;
		u64 max_stream_data_uni;
		u64 max_streams_bidi;
		u64 max_streams_uni;

		s64 next_bidi_stream_id;
		s64 next_uni_stream_id;
		s64 max_bidi_stream_id;
		s64 max_uni_stream_id;
		s64 active_stream_id;

		u16 streams_bidi;
		u16 streams_uni;
	} send;
	struct {
		u64 max_stream_data_bidi_remote;
		u64 max_stream_data_bidi_local;
		u64 max_stream_data_uni;
		u64 max_streams_bidi;
		u64 max_streams_uni;

		s64 next_bidi_stream_id;
		s64 next_uni_stream_id;
		s64 max_bidi_stream_id;
		s64 max_uni_stream_id;

		u8 bidi_pending:1;
		u8 uni_pending:1;
		u16 streams_bidi;
		u16 streams_uni;
	} recv;
};

static inline s64 quic_stream_send_next_bidi_id(struct quic_stream_table *streams)
{
	return streams->send.next_bidi_stream_id;
}

static inline s64 quic_stream_send_next_uni_id(struct quic_stream_table *streams)
{
	return streams->send.next_uni_stream_id;
}

static inline s64 quic_stream_send_active_id(struct quic_stream_table *streams)
{
	return streams->send.active_stream_id;
}

static inline void quic_stream_set_send_active_id(struct quic_stream_table *streams, s64 active)
{
	streams->send.active_stream_id = active;
}

static inline s64 quic_stream_send_max_bidi_id(struct quic_stream_table *streams)
{
	return streams->send.max_bidi_stream_id;
}

static inline void quic_stream_set_send_max_bidi_id(struct quic_stream_table *streams, s64 max)
{
	streams->send.max_bidi_stream_id = max;
}

static inline s64 quic_stream_send_max_uni_id(struct quic_stream_table *streams)
{
	return streams->send.max_uni_stream_id;
}

static inline void quic_stream_set_send_max_uni_id(struct quic_stream_table *streams, s64 max)
{
	streams->send.max_uni_stream_id = max;
}

static inline s64 quic_stream_recv_max_bidi_id(struct quic_stream_table *streams)
{
	return streams->recv.max_bidi_stream_id;
}

static inline s64 quic_stream_recv_max_uni_id(struct quic_stream_table *streams)
{
	return streams->send.max_uni_stream_id;
}

static inline u64 quic_stream_id_to_streams(s64 stream_id)
{
	return (u64)(stream_id >> 2) + 1;
}

static inline s64 quic_stream_streams_to_id(u64 streams, u8 type)
{
	return (s64)((streams - 1) << 2) | type;
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
bool quic_stream_id_send_overflow(struct quic_stream_table *streams, s64 stream_id);
bool quic_stream_id_send_exceeds(struct quic_stream_table *streams, s64 stream_id);

void quic_stream_get_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv);
void quic_stream_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv);
void quic_stream_free(struct quic_stream_table *streams);
int quic_stream_init(struct quic_stream_table *streams);
