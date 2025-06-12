/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_CONN_ID_LIMIT	8
#define QUIC_CONN_ID_DEF	7
#define QUIC_CONN_ID_LEAST	2

#define QUIC_CONN_ID_TOKEN_LEN	16

/* Common fields shared by both source and destination Connection IDs */
struct quic_common_conn_id {
	struct quic_conn_id id;	/* The actual Connection ID value and its length */
	struct list_head list;	/* Linked list node for conn_id list management */
	u32 number;		/* Sequence number assigned to this Connection ID */
	u8 hashed;		/* Non-zero if this ID is stored in source_conn_id hashtable */
};

struct quic_source_conn_id {
	struct quic_common_conn_id common;
	struct hlist_node node; /* Hash table node for fast lookup by Connection ID */
	struct rcu_head rcu;	/* RCU header for deferred destruction */
	struct sock *sk;	/* Pointer to sk associated with this Connection ID */
};

struct quic_dest_conn_id {
	struct quic_common_conn_id common;
	u8 token[QUIC_CONN_ID_TOKEN_LEN];	/* Stateless reset token in rfc9000#section-10.3 */
};

struct quic_conn_id_set {
	/* Connection ID in use on the current path */
	struct quic_common_conn_id *active;
	/* Connection ID to use for a new path (e.g., after migration) */
	struct quic_common_conn_id *alt;
	struct list_head head;	/* Head of the linked list of available connection IDs */
	u8 entry_size;		/* Size of each connection ID entry (in bytes) in the list */
	u8 max_count;		/* active_connection_id_limit in rfc9000#section-18.2 */
	u8 count;		/* Current number of connection IDs in the list */
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

/* Select an alternate destination Connection ID for a new path (e.g., after migration). */
static inline bool quic_conn_id_select_alt(struct quic_conn_id_set *id_set, bool active)
{
	if (id_set->alt)
		return true;
	/* NAT rebinding: peer keeps using the current source conn_id.
	 * In this case, continue using the same dest conn_id for the new path.
	 */
	if (active) {
		id_set->alt = id_set->active;
		return true;
	}
	/* Treat the prev conn_ids as used.
	 * Try selecting the next conn_id in the list, unless at the end.
	 */
	if (id_set->active->number != quic_conn_id_last_number(id_set)) {
		id_set->alt = list_next_entry(id_set->active, list);
		return true;
	}
	/* If there's only one conn_id in the list, reuse the active one. */
	if (id_set->active->number == quic_conn_id_first_number(id_set)) {
		id_set->alt = id_set->active;
		return true;
	}
	/* No alternate conn_id could be selected.  Caller should send a
	 * QUIC_FRAME_RETIRE_CONNECTION_ID frame to request new connection IDs from the peer.
	 */
	return false;
}

static inline void quic_conn_id_set_alt(struct quic_conn_id_set *id_set, struct quic_conn_id *alt)
{
	id_set->alt = (struct quic_common_conn_id *)alt;
}

/* Swap the active and alternate destination Connection IDs after path migration completes,
 * since the path has already been switched accordingly.
 */
static inline void quic_conn_id_swap_active(struct quic_conn_id_set *id_set)
{
	void *active = id_set->active;

	id_set->active = id_set->alt;
	id_set->alt = active;
}

/* Choose which destination Connection ID to use for a new path migration if alt is true. */
static inline struct quic_conn_id *quic_conn_id_choose(struct quic_conn_id_set *id_set, u8 alt)
{
	return (alt && id_set->alt) ? &id_set->alt->id : &id_set->active->id;
}

static inline struct quic_conn_id *quic_conn_id_active(struct quic_conn_id_set *id_set)
{
	return &id_set->active->id;
}

static inline void quic_conn_id_set_active(struct quic_conn_id_set *id_set,
					   struct quic_conn_id *active)
{
	id_set->active = (struct quic_common_conn_id *)active;
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
	memcpy(((struct quic_dest_conn_id *)conn_id)->token, token, QUIC_CONN_ID_TOKEN_LEN);
}

static inline int quic_conn_id_cmp(struct quic_conn_id *a, struct quic_conn_id *b)
{
	return a->len != b->len || memcmp(a->data, b->data, a->len);
}

int quic_conn_id_add(struct quic_conn_id_set *id_set, struct quic_conn_id *conn_id,
		     u32 number, void *data);
bool quic_conn_id_token_exists(struct quic_conn_id_set *id_set, u8 *token);
void quic_conn_id_remove(struct quic_conn_id_set *id_set, u32 number);

struct quic_conn_id *quic_conn_id_find(struct quic_conn_id_set *id_set, u32 number);
struct quic_conn_id *quic_conn_id_lookup(struct net *net, u8 *scid, u32 len);
void quic_conn_id_update_active(struct quic_conn_id_set *id_set, u32 number);

void quic_conn_id_get_param(struct quic_conn_id_set *id_set, struct quic_transport_param *p);
void quic_conn_id_set_param(struct quic_conn_id_set *id_set, struct quic_transport_param *p);
void quic_conn_id_set_init(struct quic_conn_id_set *id_set, bool source);
void quic_conn_id_set_free(struct quic_conn_id_set *id_set);
