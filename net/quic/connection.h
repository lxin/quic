/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_common_connection_id {
	struct list_head list;
	struct quic_connection_id id;
	u8 hashed;
};

struct quic_source_connection_id {
	struct quic_common_connection_id common;
	struct hlist_node node;
	struct rcu_head rcu;
	struct sock *sk;
};

struct quic_dest_connection_id {
	struct quic_common_connection_id common;
};

struct quic_connection_id_set {
	struct quic_common_connection_id *active;
	struct list_head head;
	u32 entry_size;
	u32 max_count;
	u32 count;
	u8 pending;
};

static inline u32 quic_connection_id_last_number(struct quic_connection_id_set *id_set)
{
	struct quic_common_connection_id *common;

	common = list_last_entry(&id_set->head, struct quic_common_connection_id, list);
	return common->id.number;
}

static inline u32 quic_connection_id_first_number(struct quic_connection_id_set *id_set)
{
	struct quic_common_connection_id *common;

	common = list_first_entry(&id_set->head, struct quic_common_connection_id, list);
	return common->id.number;
}

struct quic_source_connection_id *quic_source_connection_id_lookup(struct net *net, u8 *scid, u32 len);
int quic_connection_id_add(struct quic_connection_id_set *id_set,
			   struct quic_connection_id *conn_id, struct sock *sk);
int quic_connection_id_append(struct quic_connection_id_set *id_set, u32 number, struct sock *sk,
			      u8 *conn_id, u8 len);
void quic_connection_id_remove(struct quic_connection_id_set *id_set, u32 number);
int quic_connection_id_get(struct quic_connection_id_set *id_set, struct quic_connection_id *conn_id);
void quic_connection_id_set_init(struct quic_connection_id_set *id_set, bool source);
void quic_connection_id_set_free(struct quic_connection_id_set *id_set);
int quic_connection_id_set_param(struct quic_connection_id_set *id_set, struct quic_transport_param *p);
