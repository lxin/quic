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

/* Check if a stream ID is valid for sending. */
static bool quic_stream_id_send(s64 stream_id, bool is_serv)
{
	u8 type = (stream_id & QUIC_STREAM_TYPE_MASK);

	if (is_serv) {
		if (type == QUIC_STREAM_TYPE_CLIENT_UNI)
			return false;
	} else if (type == QUIC_STREAM_TYPE_SERVER_UNI) {
		return false;
	}
	return true;
}

/* Check if a stream ID is valid for receiving. */
static bool quic_stream_id_recv(s64 stream_id, bool is_serv)
{
	u8 type = (stream_id & QUIC_STREAM_TYPE_MASK);

	if (is_serv) {
		if (type == QUIC_STREAM_TYPE_SERVER_UNI)
			return false;
	} else if (type == QUIC_STREAM_TYPE_CLIENT_UNI) {
		return false;
	}
	return true;
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

struct quic_stream *quic_stream_find(struct quic_stream_table *streams, s64 stream_id)
{
	struct quic_hash_head *head = quic_stream_head(&streams->ht, stream_id);
	struct quic_stream *stream;

	hlist_for_each_entry(stream, &head->head, node) {
		if (stream->id == stream_id)
			break;
	}
	return stream;
}

static void quic_stream_add(struct quic_stream_table *streams, struct quic_stream *stream)
{
	struct quic_hash_head *head;

	head = quic_stream_head(&streams->ht, stream->id);
	hlist_add_head(&stream->node, &head->head);
}

static void quic_stream_delete(struct quic_stream *stream)
{
	hlist_del_init(&stream->node);
	kfree(stream);
}

/* Create and register new streams for sending. */
static struct quic_stream *quic_stream_send_create(struct quic_stream_table *streams,
						   s64 max_stream_id, u8 is_serv)
{
	struct quic_stream *stream;
	s64 stream_id;

	stream_id = streams->send.next_bidi_stream_id;
	if (quic_stream_id_uni(max_stream_id))
		stream_id = streams->send.next_uni_stream_id;

	/* rfc9000#section-2.1: A stream ID that is used out of order results in all streams
	 * of that type with lower-numbered stream IDs also being opened.
	 */
	while (stream_id <= max_stream_id) {
		stream = kzalloc(sizeof(*stream), GFP_KERNEL);
		if (!stream)
			return NULL;

		stream->id = stream_id;
		if (quic_stream_id_uni(stream_id)) {
			stream->send.max_bytes = streams->send.max_stream_data_uni;

			if (streams->send.next_uni_stream_id < stream_id + QUIC_STREAM_ID_STEP)
				streams->send.next_uni_stream_id = stream_id + QUIC_STREAM_ID_STEP;
			streams->send.streams_uni++;

			quic_stream_add(streams, stream);
			stream_id += QUIC_STREAM_ID_STEP;
			continue;
		}

		if (streams->send.next_bidi_stream_id < stream_id + QUIC_STREAM_ID_STEP)
			streams->send.next_bidi_stream_id = stream_id + QUIC_STREAM_ID_STEP;
		streams->send.streams_bidi++;

		if (quic_stream_id_local(stream_id, is_serv)) {
			stream->send.max_bytes = streams->send.max_stream_data_bidi_remote;
			stream->recv.max_bytes = streams->recv.max_stream_data_bidi_local;
		} else {
			stream->send.max_bytes = streams->send.max_stream_data_bidi_local;
			stream->recv.max_bytes = streams->recv.max_stream_data_bidi_remote;
		}
		stream->recv.window = stream->recv.max_bytes;

		quic_stream_add(streams, stream);
		stream_id += QUIC_STREAM_ID_STEP;
	}
	return stream;
}

/* Create and register new streams for receiving. */
static struct quic_stream *quic_stream_recv_create(struct quic_stream_table *streams,
						   s64 max_stream_id, u8 is_serv)
{
	struct quic_stream *stream;
	s64 stream_id;

	stream_id = streams->recv.next_bidi_stream_id;
	if (quic_stream_id_uni(max_stream_id))
		stream_id = streams->recv.next_uni_stream_id;

	/* rfc9000#section-2.1: A stream ID that is used out of order results in all streams
	 * of that type with lower-numbered stream IDs also being opened.
	 */
	while (stream_id <= max_stream_id) {
		stream = kzalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream)
			return NULL;

		stream->id = stream_id;
		if (quic_stream_id_uni(stream_id)) {
			stream->recv.window = streams->recv.max_stream_data_uni;
			stream->recv.max_bytes = stream->recv.window;

			if (streams->recv.next_uni_stream_id < stream_id + QUIC_STREAM_ID_STEP)
				streams->recv.next_uni_stream_id = stream_id + QUIC_STREAM_ID_STEP;
			streams->recv.streams_uni++;

			quic_stream_add(streams, stream);
			stream_id += QUIC_STREAM_ID_STEP;
			continue;
		}

		if (streams->recv.next_bidi_stream_id < stream_id + QUIC_STREAM_ID_STEP)
			streams->recv.next_bidi_stream_id = stream_id + QUIC_STREAM_ID_STEP;
		streams->recv.streams_bidi++;

		if (quic_stream_id_local(stream_id, is_serv)) {
			stream->send.max_bytes = streams->send.max_stream_data_bidi_remote;
			stream->recv.max_bytes = streams->recv.max_stream_data_bidi_local;
		} else {
			stream->send.max_bytes = streams->send.max_stream_data_bidi_local;
			stream->recv.max_bytes = streams->recv.max_stream_data_bidi_remote;
		}
		stream->recv.window = stream->recv.max_bytes;

		quic_stream_add(streams, stream);
		stream_id += QUIC_STREAM_ID_STEP;
	}
	return stream;
}

/* Check if a send stream ID is already closed. */
static bool quic_stream_id_send_closed(struct quic_stream_table *streams, s64 stream_id)
{
	if (quic_stream_id_uni(stream_id)) {
		if (stream_id < streams->send.next_uni_stream_id)
			return true;
	} else {
		if (stream_id < streams->send.next_bidi_stream_id)
			return true;
	}
	return false;
}

/* Check if a receive stream ID is already closed. */
static bool quic_stream_id_recv_closed(struct quic_stream_table *streams, s64 stream_id)
{
	if (quic_stream_id_uni(stream_id)) {
		if (stream_id < streams->recv.next_uni_stream_id)
			return true;
	} else {
		if (stream_id < streams->recv.next_bidi_stream_id)
			return true;
	}
	return false;
}

/* Check if a receive stream ID exceeds would exceed local's limits. */
static bool quic_stream_id_recv_exceeds(struct quic_stream_table *streams, s64 stream_id)
{
	if (quic_stream_id_uni(stream_id)) {
		if (stream_id > streams->recv.max_uni_stream_id)
			return true;
	} else {
		if (stream_id > streams->recv.max_bidi_stream_id)
			return true;
	}
	return false;
}

/* Check if a send stream ID would exceed peer's limits. */
bool quic_stream_id_send_exceeds(struct quic_stream_table *streams, s64 stream_id)
{
	u64 nstreams;

	if (quic_stream_id_uni(stream_id)) {
		if (stream_id > streams->send.max_uni_stream_id)
			return true;
	} else {
		if (stream_id > streams->send.max_bidi_stream_id)
			return true;
	}

	if (quic_stream_id_uni(stream_id)) {
		stream_id -= streams->send.next_uni_stream_id;
		nstreams = quic_stream_id_to_streams(stream_id);
		if (nstreams + streams->send.streams_uni > streams->send.max_streams_uni)
			return true;
	} else {
		stream_id -= streams->send.next_bidi_stream_id;
		nstreams = quic_stream_id_to_streams(stream_id);
		if (nstreams + streams->send.streams_bidi > streams->send.max_streams_bidi)
			return true;
	}
	return false;
}

/* Get or create a send stream by ID. */
struct quic_stream *quic_stream_send_get(struct quic_stream_table *streams, s64 stream_id,
					 u32 flags, bool is_serv)
{
	struct quic_stream *stream;

	if (!quic_stream_id_send(stream_id, is_serv))
		return ERR_PTR(-EINVAL);

	stream = quic_stream_find(streams, stream_id);
	if (stream) {
		if ((flags & MSG_STREAM_NEW) &&
		    stream->send.state != QUIC_STREAM_SEND_STATE_READY)
			return ERR_PTR(-EINVAL);
		return stream;
	}

	if (quic_stream_id_send_closed(streams, stream_id))
		return ERR_PTR(-ENOSTR);

	if (!(flags & MSG_STREAM_NEW))
		return ERR_PTR(-EINVAL);

	if (quic_stream_id_send_exceeds(streams, stream_id))
		return ERR_PTR(-EAGAIN);

	stream = quic_stream_send_create(streams, stream_id, is_serv);
	if (!stream)
		return ERR_PTR(-ENOSTR);
	streams->send.active_stream_id = stream_id;
	return stream;
}

/* Get or create a receive stream by ID. */
struct quic_stream *quic_stream_recv_get(struct quic_stream_table *streams, s64 stream_id,
					 bool is_serv)
{
	struct quic_stream *stream;

	if (!quic_stream_id_recv(stream_id, is_serv))
		return ERR_PTR(-EINVAL);

	stream = quic_stream_find(streams, stream_id);
	if (stream)
		return stream;

	if (quic_stream_id_local(stream_id, is_serv)) {
		if (quic_stream_id_send_closed(streams, stream_id))
			return ERR_PTR(-ENOSTR);
		return ERR_PTR(-EINVAL);
	}

	if (quic_stream_id_recv_closed(streams, stream_id))
		return ERR_PTR(-ENOSTR);

	if (quic_stream_id_recv_exceeds(streams, stream_id))
		return ERR_PTR(-EAGAIN);

	stream = quic_stream_recv_create(streams, stream_id, is_serv);
	if (!stream)
		return ERR_PTR(-ENOSTR);
	if (quic_stream_id_send(stream_id, is_serv))
		streams->send.active_stream_id = stream_id;
	return stream;
}

/* Release or clean up a send stream. This function updates stream counters and state when
 * a send stream has either successfully sent all data or has been reset.
 */
void quic_stream_send_put(struct quic_stream_table *streams, struct quic_stream *stream,
			  bool is_serv)
{
	if (quic_stream_id_uni(stream->id)) {
		/* For unidirectional streams, decrement uni count and delete immediately. */
		streams->send.streams_uni--;
		quic_stream_delete(stream);
		return;
	}

	/* For bidi streams, only proceed if receive side is in a final state. */
	if (stream->recv.state != QUIC_STREAM_RECV_STATE_RECVD &&
	    stream->recv.state != QUIC_STREAM_RECV_STATE_READ &&
	    stream->recv.state != QUIC_STREAM_RECV_STATE_RESET_RECVD)
		return;

	if (quic_stream_id_local(stream->id, is_serv)) {
		/* Local-initiated stream: mark send done and decrement send.bidi count. */
		if (!stream->send.done) {
			stream->send.done = 1;
			streams->send.streams_bidi--;
		}
		goto out;
	}
	/* Remote-initiated stream: mark recv done and decrement recv bidi count. */
	if (!stream->recv.done) {
		stream->recv.done = 1;
		streams->recv.streams_bidi--;
		streams->recv.bidi_pending = 1;
	}
out:
	/* Delete stream if fully read or no data received. */
	if (stream->recv.state == QUIC_STREAM_RECV_STATE_READ || !stream->recv.offset)
		quic_stream_delete(stream);
}

/* Release or clean up a receive stream. This function updates stream counters and state when
 * the receive side has either consumed all data or has been reset.
 */
void quic_stream_recv_put(struct quic_stream_table *streams, struct quic_stream *stream,
			  bool is_serv)
{
	if (quic_stream_id_uni(stream->id)) {
		/* For uni streams, decrement uni count and mark done. */
		if (!stream->recv.done) {
			stream->recv.done = 1;
			streams->recv.streams_uni--;
			streams->recv.uni_pending = 1;
		}
		goto out;
	}

	/* For bidi streams, only proceed if send side is in a final state. */
	if (stream->send.state != QUIC_STREAM_SEND_STATE_RECVD &&
	    stream->send.state != QUIC_STREAM_SEND_STATE_RESET_RECVD)
		return;

	if (quic_stream_id_local(stream->id, is_serv)) {
		/* Local-initiated stream: mark send done and decrement send.bidi count. */
		if (!stream->send.done) {
			stream->send.done = 1;
			streams->send.streams_bidi--;
		}
		goto out;
	}
	/* Remote-initiated stream: mark recv done and decrement recv bidi count. */
	if (!stream->recv.done) {
		stream->recv.done = 1;
		streams->recv.streams_bidi--;
		streams->recv.bidi_pending = 1;
	}
out:
	/* Delete stream if fully read or no data received. */
	if (stream->recv.state == QUIC_STREAM_RECV_STATE_READ || !stream->recv.offset)
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
	struct quic_hash_table *ht = &streams->ht;
	struct quic_hash_head *head;
	int i, size = QUIC_HT_SIZE;

	head = kmalloc_array(size, sizeof(*head), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	for (i = 0; i < size; i++)
		INIT_HLIST_HEAD(&head[i].head);
	ht->size = size;
	ht->hash = head;
	return 0;
}

void quic_stream_free(struct quic_stream_table *streams)
{
	struct quic_hash_table *ht = &streams->ht;
	struct quic_hash_head *head;
	struct quic_stream *stream;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < ht->size; i++) {
		head = &ht->hash[i];
		hlist_for_each_entry_safe(stream, tmp, &head->head, node) {
			hlist_del_init(&stream->node);
			kfree(stream);
		}
	}
	kfree(ht->hash);
}

/* Populate transport parameters from stream hash table. */
void quic_stream_get_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv)
{
	if (p->remote) {
		p->max_stream_data_bidi_remote = streams->send.max_stream_data_bidi_remote;
		p->max_stream_data_bidi_local = streams->send.max_stream_data_bidi_local;
		p->max_stream_data_uni = streams->send.max_stream_data_uni;
		p->max_streams_bidi = streams->send.max_streams_bidi;
		p->max_streams_uni = streams->send.max_streams_uni;
		return;
	}

	p->max_stream_data_bidi_remote = streams->recv.max_stream_data_bidi_remote;
	p->max_stream_data_bidi_local = streams->recv.max_stream_data_bidi_local;
	p->max_stream_data_uni = streams->recv.max_stream_data_uni;
	p->max_streams_bidi = streams->recv.max_streams_bidi;
	p->max_streams_uni = streams->recv.max_streams_uni;
}

/* Configure stream hashtable from transport parameters. */
void quic_stream_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool is_serv)
{
	u8 type;

	if (p->remote) {
		streams->send.max_stream_data_bidi_local = p->max_stream_data_bidi_local;
		streams->send.max_stream_data_bidi_remote = p->max_stream_data_bidi_remote;
		streams->send.max_stream_data_uni = p->max_stream_data_uni;
		streams->send.max_streams_bidi = p->max_streams_bidi;
		streams->send.max_streams_uni = p->max_streams_uni;
		streams->send.active_stream_id = -1;

		if (is_serv) {
			type = QUIC_STREAM_TYPE_SERVER_BIDI;
			streams->send.max_bidi_stream_id =
				quic_stream_streams_to_id(p->max_streams_bidi, type);
			streams->send.next_bidi_stream_id = type;

			type = QUIC_STREAM_TYPE_SERVER_UNI;
			streams->send.max_uni_stream_id =
				quic_stream_streams_to_id(p->max_streams_uni, type);
			streams->send.next_uni_stream_id = type;
			return;
		}

		type = QUIC_STREAM_TYPE_CLIENT_BIDI;
		streams->send.max_bidi_stream_id =
			quic_stream_streams_to_id(p->max_streams_bidi, type);
		streams->send.next_bidi_stream_id = type;

		type = QUIC_STREAM_TYPE_CLIENT_UNI;
		streams->send.max_uni_stream_id =
			quic_stream_streams_to_id(p->max_streams_uni, type);
		streams->send.next_uni_stream_id = type;
		return;
	}

	streams->recv.max_stream_data_bidi_local = p->max_stream_data_bidi_local;
	streams->recv.max_stream_data_bidi_remote = p->max_stream_data_bidi_remote;
	streams->recv.max_stream_data_uni = p->max_stream_data_uni;
	streams->recv.max_streams_bidi = p->max_streams_bidi;
	streams->recv.max_streams_uni = p->max_streams_uni;

	if (is_serv) {
		type = QUIC_STREAM_TYPE_CLIENT_BIDI;
		streams->recv.max_bidi_stream_id =
			quic_stream_streams_to_id(p->max_streams_bidi, type);
		streams->recv.next_bidi_stream_id = type;

		type = QUIC_STREAM_TYPE_CLIENT_UNI;
		streams->recv.max_uni_stream_id =
			quic_stream_streams_to_id(p->max_streams_uni, type);
		streams->recv.next_uni_stream_id = type;
		return;
	}

	type = QUIC_STREAM_TYPE_SERVER_BIDI;
	streams->recv.max_bidi_stream_id =
		quic_stream_streams_to_id(p->max_streams_bidi, type);
	streams->recv.next_bidi_stream_id = type;

	type = QUIC_STREAM_TYPE_SERVER_UNI;
	streams->recv.max_uni_stream_id =
		quic_stream_streams_to_id(p->max_streams_uni, type);
	streams->recv.next_uni_stream_id = type;
}
