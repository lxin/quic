/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_CONN_ID_MAX_LEN	20
#define QUIC_CONN_ID_DEF_LEN	8

#define QUIC_CONN_ID_LIMIT	7
#define QUIC_CONN_ID_LEAST	2

struct quic_conn_id {
	u8 data[QUIC_CONN_ID_MAX_LEN];
	u8 len;
};

struct quic_common_conn_id {
	struct quic_conn_id id;
	struct list_head list;
	u32 number;
	u8 hashed;
};

struct quic_source_conn_id {
	struct quic_common_conn_id common;
	struct hlist_node node;
	struct rcu_head rcu;
	struct sock *sk;
};

struct quic_dest_conn_id {
	struct quic_common_conn_id common;
	u8 token[16];
};

struct quic_conn_id_set {
	struct quic_common_conn_id *active;
	struct list_head head;
	u32 entry_size;
	u32 max_count;
	u32 count;

	u8 disable_active_migration;
	u8 pending;
};

static inline u32 quic_conn_id_first_number(struct quic_conn_id_set *id_set)
{
	struct quic_common_conn_id *common;

	common = list_first_entry(&id_set->head, struct quic_common_conn_id, list);
	return common->number;
}

static inline u32 quic_conn_id_last_number(struct quic_conn_id_set *id_set)
{
	return quic_conn_id_first_number(id_set) + id_set->count - 1;
}

static inline void quic_conn_id_generate(struct quic_conn_id *conn_id)
{
	get_random_bytes(conn_id->data, QUIC_CONN_ID_DEF_LEN);
	conn_id->len = QUIC_CONN_ID_DEF_LEN;
}

static inline void quic_conn_id_update(struct quic_conn_id *conn_id, u8 *data, u32 len)
{
	memcpy(conn_id->data, data, len);
	conn_id->len = len;
}

static inline u8 quic_conn_id_disable_active_migration(struct quic_conn_id_set *id_set)
{
	return id_set->disable_active_migration;
}

static inline u32 quic_conn_id_max_count(struct quic_conn_id_set *id_set)
{
	return id_set->max_count;
}

static inline struct quic_conn_id *quic_conn_id_active(struct quic_conn_id_set *id_set)
{
	return &id_set->active->id;
}

static inline u32 quic_conn_id_number(struct quic_conn_id *conn_id)
{
	return ((struct quic_common_conn_id *)conn_id)->number;
}

static inline struct sock *quic_conn_id_sk(struct quic_conn_id *conn_id)
{
	return ((struct quic_source_conn_id *)conn_id)->sk;
}

static inline void quic_conn_id_set_token(struct quic_conn_id *conn_id, u8 *token)
{
	memcpy(((struct quic_dest_conn_id *)conn_id)->token, token, 16);
}

static inline int quic_conn_id_cmp(struct quic_conn_id *a, struct quic_conn_id *b)
{
	return a->len != b->len || memcmp(a->data, b->data, a->len);
}

int quic_conn_id_add(struct quic_conn_id_set *id_set, struct quic_conn_id *conn_id,
		     u32 number, void *data);
struct quic_conn_id *quic_conn_id_lookup(struct net *net, u8 *scid, u32 len);
bool quic_conn_id_token_exists(struct quic_conn_id_set *id_set, u8 *token);
void quic_conn_id_remove(struct quic_conn_id_set *id_set, u32 number);

void quic_conn_id_set_param(struct quic_conn_id_set *id_set, struct quic_transport_param *p);
void quic_conn_id_set_init(struct quic_conn_id_set *id_set, bool source);
void quic_conn_id_set_free(struct quic_conn_id_set *id_set);
