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

#define QUIC_STREAM_TYPE_CLIENT_BI	0x00
#define QUIC_STREAM_TYPE_SERVER_BI	0x01
#define QUIC_STREAM_TYPE_CLIENT_UNI	0x02
#define QUIC_STREAM_TYPE_SERVER_UNI	0x03

struct quic_stream *quic_stream_find(struct quic_stream_table *streams, u64 stream_id)
{
	struct quic_hash_head *head = quic_stream_head(&streams->ht, stream_id);
	struct quic_stream *stream;

	hlist_for_each_entry(stream, &head->head, node) {
		if (stream->id == stream_id)
			break;
	}
	return stream;
}

static bool quic_stream_id_is_send(u64 stream_id, bool is_serv)
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

static struct quic_stream *quic_stream_add(struct quic_stream_table *streams, u64 stream_id,
					   u8 is_serv)
{
	struct quic_hash_head *head;
	struct quic_stream *stream;

	stream = kzalloc(sizeof(*stream), GFP_ATOMIC);
	if (!stream)
		return NULL;

	stream->id = stream_id;
	if (stream_id & QUIC_STREAM_TYPE_UNI_MASK) {
		stream->send.window = streams->send.max_stream_data_uni;
		stream->recv.window = streams->recv.max_stream_data_uni;
		stream->send.max_bytes = stream->send.window;
		stream->recv.max_bytes = stream->recv.window;

		if (quic_stream_id_is_send(stream_id, is_serv) &&
		    streams->send.streams_uni <= (stream_id >> 2))
			streams->send.streams_uni = (stream_id >> 2) + 1;
		goto out;
	}

	if (streams->send.streams_bidi <= (stream_id >> 2))
		streams->send.streams_bidi = (stream_id >> 2) + 1;
	if (is_serv ^ !(stream_id & QUIC_STREAM_TYPE_SERVER_MASK)) {
		stream->send.window = streams->send.max_stream_data_bidi_remote;
		stream->recv.window = streams->recv.max_stream_data_bidi_local;
	} else {
		stream->send.window = streams->send.max_stream_data_bidi_local;
		stream->recv.window = streams->recv.max_stream_data_bidi_remote;
	}
	stream->send.max_bytes = stream->send.window;
	stream->recv.max_bytes = stream->recv.window;
out:
	head = quic_stream_head(&streams->ht, stream_id);
	hlist_add_head(&stream->node, &head->head);
	return stream;
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

void quic_stream_set_param(struct quic_stream_table *streams, struct quic_transport_param *local,
			   struct quic_transport_param *remote)
{
	if (remote) {
		streams->send.max_stream_data_bidi_local = remote->max_stream_data_bidi_local;
		streams->send.max_stream_data_bidi_remote = remote->max_stream_data_bidi_remote;
		streams->send.max_stream_data_uni = remote->max_stream_data_uni;
		streams->send.max_streams_bidi = remote->max_streams_bidi;
		streams->send.max_streams_uni = remote->max_streams_uni;
		streams->send.stream_active = -1;
	}

	if (local) {
		streams->recv.max_stream_data_bidi_local = local->max_stream_data_bidi_local;
		streams->recv.max_stream_data_bidi_remote = local->max_stream_data_bidi_remote;
		streams->recv.max_stream_data_uni = local->max_stream_data_uni;
		streams->recv.max_streams_bidi = local->max_streams_bidi;
		streams->recv.max_streams_uni = local->max_streams_uni;
	}
}

static bool quic_stream_id_is_recv(u64 stream_id, bool is_serv)
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

bool quic_stream_id_send_exceeds(struct quic_stream_table *streams, u64 stream_id)
{
	if (stream_id & QUIC_STREAM_TYPE_UNI_MASK) {
		if ((stream_id >> 2) >= streams->send.max_streams_uni)
			return true;
	} else {
		if ((stream_id >> 2) >= streams->send.max_streams_bidi)
			return true;
	}
	return false;
}

static bool quic_stream_id_recv_exceeds(struct quic_stream_table *streams, u64 stream_id)
{
	if (stream_id & QUIC_STREAM_TYPE_UNI_MASK) {
		if ((stream_id >> 2) >= streams->recv.max_streams_uni)
			return true;
	} else {
		if ((stream_id >> 2) >= streams->recv.max_streams_bidi)
			return true;
	}
	return false;
}

static bool quic_stream_id_send_allowed(u64 stream_id, bool is_serv)
{
	u8 type = (stream_id & QUIC_STREAM_TYPE_MASK);

	if (is_serv) {
		if (type == QUIC_STREAM_TYPE_CLIENT_BI)
			return false;
	} else {
		if (type == QUIC_STREAM_TYPE_SERVER_BI)
			return false;
	}
	return true;
}

struct quic_stream *quic_stream_send_get(struct quic_stream_table *streams, u64 stream_id,
					 u32 flags, bool is_serv)
{
	struct quic_stream *stream;

	if (!quic_stream_id_is_send(stream_id, is_serv))
		return ERR_PTR(-EINVAL);

	stream = quic_stream_find(streams, stream_id);
	if (stream) {
		if (flags & MSG_STREAM_NEW)
			return ERR_PTR(-EINVAL);
		return stream;
	}

	if (!(flags & MSG_STREAM_NEW))
		return ERR_PTR(-EINVAL);

	if (!quic_stream_id_send_allowed(stream_id, is_serv))
		return ERR_PTR(-EINVAL);

	if (quic_stream_id_send_exceeds(streams, stream_id))
		return ERR_PTR(-EAGAIN);

	stream = quic_stream_add(streams, stream_id, is_serv);
	if (!stream)
		return ERR_PTR(-ENOMEM);
	streams->send.stream_active = stream_id;
	return stream;
}

struct quic_stream *quic_stream_recv_get(struct quic_stream_table *streams, u64 stream_id,
					 bool is_serv)
{
	struct quic_stream *stream;

	if (!quic_stream_id_is_recv(stream_id, is_serv))
		return ERR_PTR(-EINVAL);

	stream = quic_stream_find(streams, stream_id);
	if (stream)
		return stream;

	if (quic_stream_id_recv_exceeds(streams, stream_id))
		return ERR_PTR(-EAGAIN);

	stream = quic_stream_add(streams, stream_id, is_serv);
	if (!stream)
		return ERR_PTR(-ENOMEM);
	return stream;
}
