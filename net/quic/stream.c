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

#include "uapi/linux/quic.h"
#include <linux/jhash.h>
#include <net/netns/hash.h>
#include <net/sock.h>
#include "hashtable.h"
#include "stream.h"
#include "frame.h"

#define QUIC_STREAM_TYPE_CLIENT_BI	0x00
#define QUIC_STREAM_TYPE_SERVER_BI	0x01
#define QUIC_STREAM_TYPE_CLIENT_UNI	0x02
#define QUIC_STREAM_TYPE_SERVER_UNI	0x03

#define QUIC_STREAM_TYPE_SERVER_MASK	0x01
#define QUIC_STREAM_TYPE_UNI_MASK	0x02
#define QUIC_STREAM_TYPE_MASK		0x03

struct quic_stream *quic_stream_find(struct quic_stream_table *streams, u32 stream_id)
{
	struct quic_hash_head *head = quic_stream_head(&streams->ht, stream_id);
	struct quic_stream *stream;

	hlist_for_each_entry(stream, &head->head, node) {
		if (stream->id == stream_id)
			break;
	}
	return stream;
}

static struct quic_stream *quic_stream_add(struct quic_stream_table *streams, u32 stream_id,
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
		goto out;
	}

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

int quic_streams_init(struct quic_stream_table *streams)
{
	struct quic_hash_table *ht = &streams->ht;
	struct quic_hash_head *head;
	int i;

	ht->size = 16;
	head = kmalloc_array(ht->size, sizeof(*head), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	for (i = 0; i < ht->size; i++) {
		spin_lock_init(&head[i].lock);
		INIT_HLIST_HEAD(&head[i].head);
	}
	ht->hash = head;
	return 0;
}

void quic_streams_free(struct quic_stream_table *streams)
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

void quic_streams_set_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			    u8 send)
{
	if (send) {
		streams->send.max_stream_data_bidi_local = p->initial_max_stream_data_bidi_local;
		streams->send.max_stream_data_bidi_remote = p->initial_max_stream_data_bidi_remote;
		streams->send.max_stream_data_uni = p->initial_max_stream_data_uni;
		streams->send.max_streams_bidi = p->initial_max_streams_bidi;
		streams->send.max_streams_uni = p->initial_max_streams_uni;
		return;
	}

	streams->recv.max_stream_data_bidi_local = p->initial_max_stream_data_bidi_local;
	streams->recv.max_stream_data_bidi_remote = p->initial_max_stream_data_bidi_remote;
	streams->recv.max_stream_data_uni = p->initial_max_stream_data_uni;
	streams->recv.max_streams_bidi = p->initial_max_streams_bidi;
	streams->recv.max_streams_uni = p->initial_max_streams_uni;
}

void quic_streams_get_param(struct quic_stream_table *streams, struct quic_transport_param *p,
			    u8 send)
{
	if (send) {
		p->initial_max_stream_data_bidi_local = streams->send.max_stream_data_bidi_local;
		p->initial_max_stream_data_bidi_remote = streams->send.max_stream_data_bidi_remote;
		p->initial_max_stream_data_uni = streams->send.max_stream_data_uni;
		p->initial_max_streams_bidi = streams->send.max_streams_bidi;
		p->initial_max_streams_uni = streams->send.max_streams_uni;
		return;
	}

	p->initial_max_stream_data_bidi_local = streams->recv.max_stream_data_bidi_local;
	p->initial_max_stream_data_bidi_remote = streams->recv.max_stream_data_bidi_remote;
	p->initial_max_stream_data_uni = streams->recv.max_stream_data_uni;
	p->initial_max_streams_bidi = streams->recv.max_streams_bidi;
	p->initial_max_streams_uni = streams->recv.max_streams_uni;
}

struct quic_stream *quic_stream_send_get(struct quic_stream_table *streams, u32 stream_id,
					 u32 flag, bool is_serv)
{
	u8 type = (stream_id & QUIC_STREAM_TYPE_MASK);
	struct quic_stream *stream;

	if (is_serv) {
		if (type == QUIC_STREAM_TYPE_CLIENT_UNI)
			return NULL;
	}
	if (type == QUIC_STREAM_TYPE_SERVER_UNI)
		return NULL;

	stream = quic_stream_find(streams, stream_id);
	if (stream) {
		if (flag & QUIC_STREAM_FLAG_NEW)
			return NULL;
		return stream;
	}

	if (!(flag & QUIC_STREAM_FLAG_NEW))
		return NULL;

	if (is_serv) {
		if (type == QUIC_STREAM_TYPE_CLIENT_BI)
			return NULL;
	} else {
		if (type == QUIC_STREAM_TYPE_SERVER_BI)
			return NULL;
	}
	return quic_stream_add(streams, stream_id, is_serv);
}

struct quic_stream *quic_stream_recv_get(struct quic_stream_table *streams, u32 stream_id,
					 bool is_serv)
{
	u8 type = (stream_id & QUIC_STREAM_TYPE_MASK);
	struct quic_stream *stream;

	if (is_serv) {
		if (type == QUIC_STREAM_TYPE_SERVER_UNI)
			return NULL;
	}
	if (type == QUIC_STREAM_TYPE_CLIENT_UNI)
		return NULL;

	stream = quic_stream_find(streams, stream_id);
	if (stream)
		return stream;

	return quic_stream_add(streams, stream_id, is_serv);
}

void quic_stream_send_state_update(struct quic_stream *stream, u8 type)
{
	if (type == QUIC_FRAME_ACK) {
		if (stream->send.state == QUIC_STREAM_SEND_STATE_RESET_SENT) {
			stream->send.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
			return;
		}
		stream->send.state = QUIC_STREAM_SEND_STATE_RECVD;
		return;
	}
	if (type == QUIC_FRAME_RESET_STREAM) {
		stream->send.state = QUIC_STREAM_SEND_STATE_RESET_SENT;
		return;
	}
	if (type & QUIC_STREAM_BIT_FIN) {
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
		return;
	}
	stream->send.state = QUIC_STREAM_SEND_STATE_SEND;
}
