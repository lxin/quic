/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
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
	u32 count;
};

struct quic_source_connection_id *quic_source_connection_id_lookup(struct net *net, u8 *scid);
int quic_connection_id_add(struct quic_connection_id_set *id_set,
			   struct quic_connection_id *conn_id, u8 len, struct sock *sk);
int quic_connection_id_get(struct quic_connection_id_set *id_set, int len,
			   char __user *optval, int __user *optlen);
int quic_connection_id_get_numbers(struct quic_connection_id_set *id_set, int len,
				   char __user *optval, int __user *optlen);
int quic_connection_id_set_numbers(struct quic_connection_id_set *id_set,
				   struct quic_connection_id_numbers *numbers, u8 len);
void quic_connection_id_set_init(struct quic_connection_id_set *id_set, bool source);
void quic_connection_id_set_free(struct quic_connection_id_set *id_set);
