// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <linux/quic.h>

#include "common.h"
#include "stream.h"

/* Check if a stream ID is valid for sending or receiving. */
static bool quic_stream_id_valid(s64 stream_id, bool is_serv, bool send)
{
	u8 type = (stream_id & QUIC_STREAM_TYPE_MASK);

	if (send) {
		if (is_serv)
			return type != QUIC_STREAM_TYPE_CLIENT_UNI;
		return type != QUIC_STREAM_TYPE_SERVER_UNI;
	}
	if (is_serv)
		return type != QUIC_STREAM_TYPE_SERVER_UNI;
	return type != QUIC_STREAM_TYPE_CLIENT_UNI;
}

/* Check if a stream ID was initiated locally. */
static bool quic_stream_id_local(s64 stream_id, u8 is_serv)
{
	return is_serv ^ !(stream_id & QUIC_STREAM_TYPE_SERVER_MASK);
}

/* Check if a stream ID represents a unidirectional stream. */
static bool quic_stream_id_uni(s64 stream_id)
{
	return stream_id & QUIC_STREAM_TYPE_UNI_MASK;
}

#define QUIC_STREAM_HT_SIZE	64

static struct hlist_head *quic_stream_head(struct quic_stream_table *streams, s64 stream_id)
{
	return &streams->head[stream_id & (QUIC_STREAM_HT_SIZE - 1)];
}

struct quic_stream *quic_stream_find(struct quic_stream_table *streams, s64 stream_id)
{
	struct hlist_head *head = quic_stream_head(streams, stream_id);
	struct quic_stream *stream;

	hlist_for_each_entry(stream, head, node) {
		if (stream->id == stream_id)
			break;
	}
	return stream;
}

static void quic_stream_add(struct quic_stream_table *streams, struct quic_stream *stream)
{
	struct hlist_head *head;

	head = quic_stream_head(streams, stream->id);
	hlist_add_head(&stream->node, head);
}

static void quic_stream_delete(struct quic_stream *stream)
{
	hlist_del_init(&stream->node);
	kfree(stream);
}

/* Create and register new streams for sending or receiving. */
static struct quic_stream *quic_stream_create(struct quic_stream_table *streams,
					      s64 max_stream_id, bool send, bool is_serv)
{
	struct quic_stream_limits *limits = &streams->send;
	struct quic_stream *pos, *stream = NULL;
	gfp_t gfp = GFP_KERNEL_ACCOUNT;
	struct hlist_node *tmp;
	HLIST_HEAD(head);
	s64 stream_id;
	u32 count = 0;

	if (!send) {
		limits = &streams->recv;
		gfp = GFP_ATOMIC | __GFP_ACCOUNT;
	}
	stream_id = limits->next_bidi_stream_id;
	if (quic_stream_id_uni(max_stream_id))
		stream_id = limits->next_uni_stream_id;

	/* rfc9000#section-2.1: A stream ID that is used out of order results in all streams
	 * of that type with lower-numbered stream IDs also being opened.
	 */
	while (stream_id <= max_stream_id) {
		stream = kzalloc(sizeof(*stream), gfp);
		if (!stream)
			goto free;

		stream->id = stream_id;
		if (quic_stream_id_uni(stream_id)) {
			if (send) {
				stream->send.max_bytes = limits->max_stream_data_uni;
			} else {
				stream->recv.max_bytes = limits->max_stream_data_uni;
				stream->recv.window = stream->recv.max_bytes;
			}
			hlist_add_head(&stream->node, &head);
			stream_id += QUIC_STREAM_ID_STEP;
			continue;
		}

		if (quic_stream_id_local(stream_id, is_serv)) {
			stream->send.max_bytes = streams->send.max_stream_data_bidi_remote;
			stream->recv.max_bytes = streams->recv.max_stream_data_bidi_local;
		} else {
			stream->send.max_bytes = streams->send.max_stream_data_bidi_local;
			stream->recv.max_bytes = streams->recv.max_stream_data_bidi_remote;
		}
		stream->recv.window = stream->recv.max_bytes;
		hlist_add_head(&stream->node, &head);
		stream_id += QUIC_STREAM_ID_STEP;
	}

	hlist_for_each_entry_safe(pos, tmp, &head, node) {
		hlist_del_init(&pos->node);
		quic_stream_add(streams, pos);
		count++;
	}

	/* Streams must be opened sequentially. Update the next stream ID so the correct
	 * starting point is known if an out-of-order open is requested.  Note overflow
	 * of next_uni/bidi_stream_id is impossible with s64.
	 */
	if (quic_stream_id_uni(stream_id)) {
		limits->next_uni_stream_id = stream_id;
		limits->streams_uni += count;
		return stream;
	}

	limits->next_bidi_stream_id = stream_id;
	limits->streams_bidi += count;
	return stream;

free:
	hlist_for_each_entry_safe(pos, tmp, &head, node) {
		hlist_del_init(&pos->node);
		kfree(pos);
	}
	return NULL;
}

/* Check if a send or receive stream ID is already closed. */
static bool quic_stream_id_closed(struct quic_stream_table *streams, s64 stream_id, bool send)
{
	struct quic_stream_limits *limits = send ? &streams->send : &streams->recv;

	if (quic_stream_id_uni(stream_id))
		return stream_id < limits->next_uni_stream_id;
	return stream_id < limits->next_bidi_stream_id;
}

/* Check if a stream ID would exceed local (recv) or peer (send) limits. */
bool quic_stream_id_exceeds(struct quic_stream_table *streams, s64 stream_id, bool send)
{
	u64 nstreams;

	if (!send) {
		/* recv.max_uni_stream_id is updated in quic_stream_max_streams_update()
		 * already based on next_uni/bidi_stream_id, max_streams_uni/bidi, and
		 * streams_uni/bidi, so only recv.max_uni_stream_id needs to be checked.
		 */
		if (quic_stream_id_uni(stream_id))
			return stream_id > streams->recv.max_uni_stream_id;
		return stream_id > streams->recv.max_bidi_stream_id;
	}

	if (quic_stream_id_uni(stream_id)) {
		if (stream_id > streams->send.max_uni_stream_id)
			return true;
		stream_id -= streams->send.next_uni_stream_id;
		nstreams = quic_stream_id_to_streams(stream_id);
		return nstreams + streams->send.streams_uni > streams->send.max_streams_uni;
	}

	if (stream_id > streams->send.max_bidi_stream_id)
		return true;
	stream_id -= streams->send.next_bidi_stream_id;
	nstreams = quic_stream_id_to_streams(stream_id);
	return nstreams + streams->send.streams_bidi > streams->send.max_streams_bidi;
}

/* Get or create a send or recv stream by ID. Requires sock lock held. */
struct quic_stream *quic_stream_get(struct quic_stream_table *streams, s64 stream_id, u32 flags,
				    bool is_serv, bool send)
{
	struct quic_stream *stream;

	if (!quic_stream_id_valid(stream_id, is_serv, send))
		return ERR_PTR(-EINVAL);

	stream = quic_stream_find(streams, stream_id);
	if (stream) {
		if (send && (flags & MSG_QUIC_STREAM_NEW) &&
		    stream->send.state != QUIC_STREAM_SEND_STATE_READY)
			return ERR_PTR(-EINVAL);
		return stream;
	}

	if (!send && quic_stream_id_local(stream_id, is_serv)) {
		if (quic_stream_id_closed(streams, stream_id, !send))
			return ERR_PTR(-ENOSTR);
		return ERR_PTR(-EINVAL);
	}

	if (quic_stream_id_closed(streams, stream_id, send))
		return ERR_PTR(-ENOSTR);

	if (send && !(flags & MSG_QUIC_STREAM_NEW))
		return ERR_PTR(-EINVAL);

	if (quic_stream_id_exceeds(streams, stream_id, send))
		return ERR_PTR(-EAGAIN);

	stream = quic_stream_create(streams, stream_id, send, is_serv);
	if (!stream)
		return ERR_PTR(-ENOSTR);

	if (send || quic_stream_id_valid(stream_id, is_serv, !send))
		streams->send.active_stream_id = stream_id;

	return stream;
}

/* Release or clean up a send or recv stream. This function updates stream counters and state
 * when a send stream has either successfully sent all data or has been reset, or when a recv
 * stream has either consumed all data or has been reset. Requires sock lock held.
 */
void quic_stream_put(struct quic_stream_table *streams, struct quic_stream *stream, bool is_serv,
		     bool send)
{
	if (quic_stream_id_uni(stream->id)) {
		if (send) {
			/* For uni streams, decrement uni count and delete immediately. */
			streams->send.streams_uni--;
			quic_stream_delete(stream);
			return;
		}
		/* For uni streams, decrement uni count and mark done. */
		if (!stream->recv.done) {
			stream->recv.done = 1;
			streams->recv.streams_uni--;
			streams->recv.uni_pending = 1;
		}
		/* Delete stream if fully read or reset. */
		if (stream->recv.state > QUIC_STREAM_RECV_STATE_RECVD)
			quic_stream_delete(stream);
		return;
	}

	if (send) {
		/* For bidi streams, only proceed if receive side is in a final state. */
		if (stream->recv.state != QUIC_STREAM_RECV_STATE_RECVD &&
		    stream->recv.state != QUIC_STREAM_RECV_STATE_READ &&
		    stream->recv.state != QUIC_STREAM_RECV_STATE_RESET_RECVD)
			return;
	} else {
		/* For bidi streams, only proceed if send side is in a final state. */
		if (stream->send.state != QUIC_STREAM_SEND_STATE_RECVD &&
		    stream->send.state != QUIC_STREAM_SEND_STATE_RESET_RECVD)
			return;
	}

	if (quic_stream_id_local(stream->id, is_serv)) {
		/* Local-initiated stream: mark send done and decrement send.bidi count. */
		if (!stream->send.done) {
			stream->send.done = 1;
			streams->send.streams_bidi--;
		}
	} else {
		/* Remote-initiated stream: mark recv done and decrement recv bidi count. */
		if (!stream->recv.done) {
			stream->recv.done = 1;
			streams->recv.streams_bidi--;
			streams->recv.bidi_pending = 1;
		}
	}

	/* Delete stream if fully read or reset. */
	if (stream->recv.state > QUIC_STREAM_RECV_STATE_RECVD)
		quic_stream_delete(stream);
}

/* Updates the maximum allowed incoming stream IDs if any streams were recently closed.
 * Recalculates the max_uni and max_bidi stream ID limits based on the number of open
 * streams and whether any were marked for deletion.
 *
 * Returns true if either max_uni or max_bidi was updated, indicating that a
 * MAX_STREAMS_UNI or MAX_STREAMS_BIDI frame should be sent to the peer.
 */
bool quic_stream_max_streams_update(struct quic_stream_table *streams, s64 *max_uni, s64 *max_bidi)
{
	*max_uni = 0;
	*max_bidi = 0;
	if (streams->recv.uni_pending) {
		streams->recv.max_uni_stream_id =
			streams->recv.next_uni_stream_id - QUIC_STREAM_ID_STEP +
			((streams->recv.max_streams_uni - streams->recv.streams_uni) <<
			 QUIC_STREAM_TYPE_BITS);
		*max_uni = quic_stream_id_to_streams(streams->recv.max_uni_stream_id);
		streams->recv.uni_pending = 0;
	}
	if (streams->recv.bidi_pending) {
		streams->recv.max_bidi_stream_id =
			streams->recv.next_bidi_stream_id - QUIC_STREAM_ID_STEP +
			((streams->recv.max_streams_bidi - streams->recv.streams_bidi) <<
			 QUIC_STREAM_TYPE_BITS);
		*max_bidi = quic_stream_id_to_streams(streams->recv.max_bidi_stream_id);
		streams->recv.bidi_pending = 0;
	}

	return *max_uni || *max_bidi;
}

int quic_stream_init(struct quic_stream_table *streams)
{
	struct hlist_head *head;
	int i;

	head = kmalloc_array(QUIC_STREAM_HT_SIZE, sizeof(*head), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	for (i = 0; i < QUIC_STREAM_HT_SIZE; i++)
		INIT_HLIST_HEAD(&head[i]);
	streams->head = head;
	return 0;
}

void quic_stream_free(struct quic_stream_table *streams)
{
	struct quic_stream *stream;
	struct hlist_head *head;
	struct hlist_node *tmp;
	int i;

	if (!streams->head)
		return;

	for (i = 0; i < QUIC_STREAM_HT_SIZE; i++) {
		head = &streams->head[i];
		hlist_for_each_entry_safe(stream, tmp, head, node)
			quic_stream_delete(stream);
	}
	kfree(streams->head);
}

/* Populate transport parameters from stream hash table. */
void quic_stream_get_param(struct quic_stream_table *streams, struct quic_transport_param *p)
{
	struct quic_stream_limits *limits = p->remote ? &streams->send : &streams->recv;

	p->max_stream_data_bidi_remote = limits->max_stream_data_bidi_remote;
	p->max_stream_data_bidi_local = limits->max_stream_data_bidi_local;
	p->max_stream_data_uni = limits->max_stream_data_uni;
	p->max_streams_bidi = limits->max_streams_bidi;
	p->max_streams_uni = limits->max_streams_uni;
}

/* Configure stream hashtable from transport parameters. */
void quic_stream_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv)
{
	struct quic_stream_limits *limits = p->remote ? &streams->send : &streams->recv;
	u8 bidi_type, uni_type;

	limits->max_stream_data_bidi_local = p->max_stream_data_bidi_local;
	limits->max_stream_data_bidi_remote = p->max_stream_data_bidi_remote;
	limits->max_stream_data_uni = p->max_stream_data_uni;
	limits->max_streams_bidi = p->max_streams_bidi;
	limits->max_streams_uni = p->max_streams_uni;
	limits->active_stream_id = -1;

	if (p->remote ^ is_serv) {
		bidi_type = QUIC_STREAM_TYPE_CLIENT_BIDI;
		uni_type = QUIC_STREAM_TYPE_CLIENT_UNI;
	} else {
		bidi_type = QUIC_STREAM_TYPE_SERVER_BIDI;
		uni_type = QUIC_STREAM_TYPE_SERVER_UNI;
	}

	limits->max_bidi_stream_id = quic_stream_streams_to_id(p->max_streams_bidi, bidi_type);
	limits->next_bidi_stream_id = bidi_type;

	limits->max_uni_stream_id = quic_stream_streams_to_id(p->max_streams_uni, uni_type);
	limits->next_uni_stream_id = uni_type;
}
