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

#include <uapi/linux/quic.h>
#include <net/netns/hash.h>
#include <linux/jhash.h>
#include <net/sock.h>

#include "hashtable.h"
#include "connid.h"
#include "stream.h"
#include "crypto.h"
#include "frame.h"

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

static bool quic_stream_id_local(s64 stream_id, u8 is_serv)
{
	return is_serv ^ !(stream_id & QUIC_STREAM_TYPE_SERVER_MASK);
}

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

static struct quic_stream *quic_stream_send_create(struct quic_stream_table *streams,
						   s64 max_stream_id, u8 is_serv)
{
	struct quic_stream *stream;
	s64 stream_id;

	stream_id = streams->send.next_bidi_stream_id;
	if (quic_stream_id_uni(max_stream_id))
		stream_id = streams->send.next_uni_stream_id;

	while (stream_id <= max_stream_id) {
		stream = kzalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream)
			return NULL;

		stream->id = stream_id;
		if (quic_stream_id_uni(stream_id)) {
			stream->send.window = streams->send.max_stream_data_uni;
			stream->send.max_bytes = stream->send.window;

			if (streams->send.next_uni_stream_id < stream_id + 4)
				streams->send.next_uni_stream_id = stream_id + 4;
			streams->send.streams_uni++;

			quic_stream_add(streams, stream);
			stream_id += 4;
			continue;
		}

		if (streams->send.next_bidi_stream_id < stream_id + 4)
			streams->send.next_bidi_stream_id = stream_id + 4;
		streams->send.streams_bidi++;

		if (quic_stream_id_local(stream_id, is_serv)) {
			stream->send.window = streams->send.max_stream_data_bidi_remote;
			stream->recv.window = streams->recv.max_stream_data_bidi_local;
		} else {
			stream->send.window = streams->send.max_stream_data_bidi_local;
			stream->recv.window = streams->recv.max_stream_data_bidi_remote;
		}
		stream->send.max_bytes = stream->send.window;
		stream->recv.max_bytes = stream->recv.window;

		quic_stream_add(streams, stream);
		stream_id += 4;
	}
	return stream;
}

static struct quic_stream *quic_stream_recv_create(struct quic_stream_table *streams,
						   s64 max_stream_id, u8 is_serv)
{
	struct quic_stream *stream;
	s64 stream_id;

	stream_id = streams->recv.next_bidi_stream_id;
	if (quic_stream_id_uni(max_stream_id))
		stream_id = streams->recv.next_uni_stream_id;

	while (stream_id <= max_stream_id) {
		stream = kzalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream)
			return NULL;

		stream->id = stream_id;
		if (quic_stream_id_uni(stream_id)) {
			stream->recv.window = streams->recv.max_stream_data_uni;
			stream->recv.max_bytes = stream->recv.window;

			if (streams->recv.next_uni_stream_id < stream_id + 4)
				streams->recv.next_uni_stream_id = stream_id + 4;
			streams->recv.streams_uni++;

			quic_stream_add(streams, stream);
			stream_id += 4;
			continue;
		}

		if (streams->recv.next_bidi_stream_id < stream_id + 4)
			streams->recv.next_bidi_stream_id = stream_id + 4;
		streams->recv.streams_bidi++;

		if (quic_stream_id_local(stream_id, is_serv)) {
			stream->send.window = streams->send.max_stream_data_bidi_remote;
			stream->recv.window = streams->recv.max_stream_data_bidi_local;
		} else {
			stream->send.window = streams->send.max_stream_data_bidi_local;
			stream->recv.window = streams->recv.max_stream_data_bidi_remote;
		}
		stream->send.max_bytes = stream->send.window;
		stream->recv.max_bytes = stream->recv.window;

		quic_stream_add(streams, stream);
		stream_id += 4;
	}
	return stream;
}

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

bool quic_stream_id_send_exceeds(struct quic_stream_table *streams, s64 stream_id)
{
	if (quic_stream_id_uni(stream_id)) {
		if (stream_id > streams->send.max_uni_stream_id)
			return true;
	} else {
		if (stream_id > streams->send.max_bidi_stream_id)
			return true;
	}
	return false;
}

bool quic_stream_id_send_overflow(struct quic_stream_table *streams, s64 stream_id)
{
	u64 nstreams;

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

	if (quic_stream_id_send_exceeds(streams, stream_id) ||
	    quic_stream_id_send_overflow(streams, stream_id))
		return ERR_PTR(-EAGAIN);

	stream = quic_stream_send_create(streams, stream_id, is_serv);
	if (!stream)
		return ERR_PTR(-ENOSTR);
	streams->send.active_stream_id = stream_id;
	return stream;
}

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
	return stream;
}

void quic_stream_send_put(struct quic_stream_table *streams, struct quic_stream *stream,
			  bool is_serv)
{
	if (quic_stream_id_uni(stream->id)) {
		streams->send.streams_uni--;
		quic_stream_delete(stream);
		return;
	}

	if (stream->recv.state != QUIC_STREAM_RECV_STATE_RECVD &&
	    stream->recv.state != QUIC_STREAM_RECV_STATE_READ &&
	    stream->recv.state != QUIC_STREAM_RECV_STATE_RESET_RECVD)
		return;

	if (quic_stream_id_local(stream->id, is_serv)) {
		if (!stream->send.done) {
			stream->send.done = 1;
			streams->send.streams_bidi--;
		}
		goto out;
	}
	if (!stream->recv.done) {
		stream->recv.done = 1;
		streams->recv.streams_bidi--;
		streams->recv.bidi_pending = 1;
	}
out:
	if (stream->recv.state == QUIC_STREAM_RECV_STATE_READ || !stream->recv.offset)
		quic_stream_delete(stream);
}

void quic_stream_recv_put(struct quic_stream_table *streams, struct quic_stream *stream,
			  bool is_serv)
{
	if (quic_stream_id_uni(stream->id)) {
		if (!stream->recv.done) {
			stream->recv.done = 1;
			streams->recv.streams_uni--;
			streams->recv.uni_pending = 1;
		}
		goto out;
	}

	if (stream->send.state != QUIC_STREAM_SEND_STATE_RECVD &&
	    stream->send.state != QUIC_STREAM_SEND_STATE_RESET_RECVD)
		return;

	if (quic_stream_id_local(stream->id, is_serv)) {
		if (!stream->send.done) {
			stream->send.done = 1;
			streams->send.streams_bidi--;
		}
		goto out;
	}
	if (!stream->recv.done) {
		stream->recv.done = 1;
		streams->recv.streams_bidi--;
		streams->recv.bidi_pending = 1;
	}
out:
	if (stream->recv.state == QUIC_STREAM_RECV_STATE_READ || !stream->recv.offset)
		quic_stream_delete(stream);
}

bool quic_stream_max_streams_update(struct quic_stream_table *streams, s64 *max_uni, s64 *max_bidi)
{
	if (streams->recv.uni_pending) {
		streams->recv.max_uni_stream_id = streams->recv.next_uni_stream_id - 4 +
			((streams->recv.max_streams_uni - streams->recv.streams_uni) << 2);
		*max_uni = quic_stream_id_to_streams(streams->recv.max_uni_stream_id);
		streams->recv.uni_pending = 0;
	}
	if (streams->recv.bidi_pending) {
		streams->recv.max_bidi_stream_id = streams->recv.next_bidi_stream_id - 4 +
			((streams->recv.max_streams_bidi - streams->recv.streams_bidi) << 2);
		*max_bidi = quic_stream_id_to_streams(streams->recv.max_bidi_stream_id);
		streams->recv.bidi_pending = 0;
	}

	return *max_uni || *max_bidi;
}

int quic_stream_init(struct quic_stream_table *streams)
{
	struct quic_hash_table *ht = &streams->ht;
	struct quic_hash_head *head;
	int i, size = 16;

	head = kmalloc_array(size, sizeof(*head), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	for (i = 0; i < size; i++) {
		spin_lock_init(&head[i].lock);
		INIT_HLIST_HEAD(&head[i].head);
	}
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

void quic_stream_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			   bool remote, bool is_serv)
{
	u8 type;

	if (remote) {
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
