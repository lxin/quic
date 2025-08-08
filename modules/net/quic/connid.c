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
#include <net/sock.h>

#include "common.h"
#include "connid.h"

/* Lookup a source connection ID (scid) in the global source connection ID hash table. */
struct quic_conn_id *quic_conn_id_lookup(struct net *net, u8 *scid, u32 len)
{
	struct quic_hash_head *head = quic_source_conn_id_head(net, scid);
	struct quic_source_conn_id *s_conn_id;
	struct quic_conn_id *conn_id = NULL;

	spin_lock(&head->s_lock);
	hlist_for_each_entry(s_conn_id, &head->head, node) {
		if (net == sock_net(s_conn_id->sk) && s_conn_id->common.id.len == len &&
		    !memcmp(scid, &s_conn_id->common.id.data, s_conn_id->common.id.len)) {
			sock_hold(s_conn_id->sk);
			conn_id = &s_conn_id->common.id;
			break;
		}
	}

	spin_unlock(&head->s_lock);
	return conn_id;
}

/* Check if a given stateless reset token exists in any connection ID in the connection ID set. */
bool quic_conn_id_token_exists(struct quic_conn_id_set *id_set, u8 *token)
{
	struct quic_common_conn_id *common;
	struct quic_dest_conn_id *dcid;

	dcid = (struct quic_dest_conn_id *)id_set->active;
	if (!memcmp(dcid->token, token, QUIC_CONN_ID_TOKEN_LEN)) /* Fast path. */
		return true;

	list_for_each_entry(common, &id_set->head, list) {
		dcid = (struct quic_dest_conn_id *)common;
		if (common == id_set->active)
			continue;
		if (!memcmp(dcid->token, token, QUIC_CONN_ID_TOKEN_LEN))
			return true;
	}
	return false;
}

static void quic_source_conn_id_free_rcu(struct rcu_head *head)
{
	struct quic_source_conn_id *s_conn_id;

	s_conn_id = container_of(head, struct quic_source_conn_id, rcu);
	kfree(s_conn_id);
}

static void quic_source_conn_id_free(struct quic_source_conn_id *s_conn_id)
{
	u8 *data = s_conn_id->common.id.data;
	struct quic_hash_head *head;

	if (!hlist_unhashed(&s_conn_id->node)) {
		head = quic_source_conn_id_head(sock_net(s_conn_id->sk), data);
		spin_lock_bh(&head->s_lock);
		hlist_del_init(&s_conn_id->node);
		spin_unlock_bh(&head->s_lock);
	}

	/* Freeing is deferred via RCU to avoid use-after-free during concurrent lookups. */
	call_rcu(&s_conn_id->rcu, quic_source_conn_id_free_rcu);
}

static void quic_conn_id_del(struct quic_common_conn_id *common)
{
	list_del(&common->list);
	if (!common->hashed) {
		kfree(common);
		return;
	}
	quic_source_conn_id_free((struct quic_source_conn_id *)common);
}

/* Add a connection ID with sequence number and associated private data to the connection ID set. */
int quic_conn_id_add(struct quic_conn_id_set *id_set,
		     struct quic_conn_id *conn_id, u32 number, void *data)
{
	struct quic_source_conn_id *s_conn_id;
	struct quic_dest_conn_id *d_conn_id;
	struct quic_common_conn_id *common;
	struct quic_hash_head *head;
	struct list_head *list;

	/* Locate insertion point to keep list ordered by number. */
	list = &id_set->head;
	list_for_each_entry(common, list, list) {
		if (number == common->number)
			return 0; /* Ignore if it is already exists on the list. */
		if (number < common->number) {
			list = &common->list;
			break;
		}
	}

	if (conn_id->len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	common = kzalloc(id_set->entry_size, GFP_ATOMIC);
	if (!common)
		return -ENOMEM;
	common->id = *conn_id;
	common->number = number;
	if (id_set->entry_size == sizeof(struct quic_dest_conn_id)) {
		/* For destination connection IDs, copy the stateless reset token if available. */
		if (data) {
			d_conn_id = (struct quic_dest_conn_id *)common;
			memcpy(d_conn_id->token, data, QUIC_CONN_ID_TOKEN_LEN);
		}
	} else {
		/* For source connection IDs, mark as hashed and insert into the global source
		 * connection ID hashtable.
		 */
		common->hashed = 1;
		s_conn_id = (struct quic_source_conn_id *)common;
		s_conn_id->sk = data;

		head = quic_source_conn_id_head(sock_net(s_conn_id->sk), common->id.data);
		spin_lock_bh(&head->s_lock);
		hlist_add_head(&s_conn_id->node, &head->head);
		spin_unlock_bh(&head->s_lock);
	}
	list_add_tail(&common->list, list);

	if (number == quic_conn_id_last_number(id_set) + 1) {
		if (!id_set->active)
			id_set->active = common;
		id_set->count++;

		/* Increment count for consecutive following IDs. */
		list_for_each_entry_continue(common, &id_set->head, list) {
			if (common->number != ++number)
				break;
			id_set->count++;
		}
	}
	return 0;
}

/* Remove connection IDs from the set with sequence numbers less than or equal to a number. */
void quic_conn_id_remove(struct quic_conn_id_set *id_set, u32 number)
{
	struct quic_common_conn_id *common, *tmp;
	struct list_head *list;

	list = &id_set->head;
	list_for_each_entry_safe(common, tmp, list, list) {
		if (common->number <= number) {
			if (id_set->active == common)
				id_set->active = tmp;
			quic_conn_id_del(common);
			id_set->count--;
		}
	}
}

struct quic_conn_id *quic_conn_id_find(struct quic_conn_id_set *id_set, u32 number)
{
	struct quic_common_conn_id *common;

	list_for_each_entry(common, &id_set->head, list)
		if (common->number == number)
			return &common->id;
	return NULL;
}

void quic_conn_id_update_active(struct quic_conn_id_set *id_set, u32 number)
{
	struct quic_conn_id *conn_id;

	if (number == id_set->active->number)
		return;
	conn_id = quic_conn_id_find(id_set, number);
	if (!conn_id)
		return;
	quic_conn_id_set_active(id_set, conn_id);
}

void quic_conn_id_set_init(struct quic_conn_id_set *id_set, bool source)
{
	id_set->entry_size = source ? sizeof(struct quic_source_conn_id)
				    : sizeof(struct quic_dest_conn_id);
	INIT_LIST_HEAD(&id_set->head);
}

void quic_conn_id_set_free(struct quic_conn_id_set *id_set)
{
	struct quic_common_conn_id *common, *tmp;

	list_for_each_entry_safe(common, tmp, &id_set->head, list)
		quic_conn_id_del(common);
	id_set->count = 0;
	id_set->active = NULL;
}

void quic_conn_id_get_param(struct quic_conn_id_set *id_set, struct quic_transport_param *p)
{
	p->active_connection_id_limit = id_set->max_count;
}

void quic_conn_id_set_param(struct quic_conn_id_set *id_set, struct quic_transport_param *p)
{
	id_set->max_count = p->active_connection_id_limit;
}
