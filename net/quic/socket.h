/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef __net_quic_h__
#define __net_quic_h__

#include <uapi/linux/quic.h>
#include <net/udp_tunnel.h>
#include "connection.h"
#include "hashtable.h"
#include "protocol.h"
#include "crypto.h"
#include "stream.h"
#include "packet.h"
#include "output.h"
#include "input.h"
#include "pnmap.h"
#include "path.h"
#include "timer.h"
#include "cong.h"

extern struct proto quic_prot;
extern struct proto quicv6_prot;

extern struct proto quic_handshake_prot;
extern struct proto quicv6_handshake_prot;

enum quic_state {
	QUIC_STATE_USER_CLOSED,
	QUIC_STATE_USER_LISTEN,
	QUIC_STATE_USER_CONNECTING,
	QUIC_STATE_CLIENT_CONNECTED,
	QUIC_STATE_SERVER_CONNECTED,
};

struct quic_request_sock {
	struct list_head	list;
	union quic_addr		src;
	union quic_addr		dst;
};

struct quic_token {
	u32 len;
	void *data;
};

struct quic_sock {
	struct inet_sock		inet;
	struct quic_addr_family_ops	*af_ops; /* inet4 or inet6 */

	enum quic_state			state;

	struct quic_connection_id_set	source;
	struct quic_connection_id_set	dest;

	struct quic_bind_port		port;
	struct quic_udp_sock		*udp_sk[2];
	struct quic_path_addr		src;
	struct quic_path_addr		dst;

	struct quic_stream_table	streams;
	struct quic_crypto		crypto;
	struct quic_pnmap		pn_map;
	struct quic_token		token;
	struct quic_token		ticket;
	struct quic_token		alpn;

	struct quic_outqueue		outq;
	struct quic_inqueue		inq;
	struct quic_packet		packet;
	struct quic_cong		cong;
	struct quic_timer		timers[QUIC_TIMER_MAX];

	struct list_head		reqs;
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct quic_addr_family_ops *quic_af_ops(const struct sock *sk)
{
	return quic_sk(sk)->af_ops;
}

static inline enum quic_state quic_state(const struct sock *sk)
{
	return quic_sk(sk)->state;
}

static inline void quic_set_state(struct sock *sk, enum quic_state state)
{
	quic_sk(sk)->state = state;
}

static inline struct quic_path_addr *quic_src(const struct sock *sk)
{
	return &quic_sk(sk)->src;
}

static inline struct quic_path_addr *quic_dst(const struct sock *sk)
{
	return &quic_sk(sk)->dst;
}

static inline struct quic_packet *quic_packet(const struct sock *sk)
{
	return &quic_sk(sk)->packet;
}

static inline struct quic_outqueue *quic_outq(const struct sock *sk)
{
	return &quic_sk(sk)->outq;
}

static inline struct quic_inqueue *quic_inq(const struct sock *sk)
{
	return &quic_sk(sk)->inq;
}

static inline struct quic_cong *quic_cong(const struct sock *sk)
{
	return &quic_sk(sk)->cong;
}

static inline struct quic_crypto *quic_crypto(const struct sock *sk)
{
	return &quic_sk(sk)->crypto;
}

static inline struct quic_pnmap *quic_pnmap(const struct sock *sk)
{
	return &quic_sk(sk)->pn_map;
}

static inline struct quic_stream_table *quic_streams(const struct sock *sk)
{
	return &quic_sk(sk)->streams;
}

static inline struct quic_timer *quic_timer(const struct sock *sk, u8 type)
{
	return &quic_sk(sk)->timers[type];
}

static inline struct list_head *quic_reqs(const struct sock *sk)
{
	return &quic_sk(sk)->reqs;
}

static inline struct quic_token *quic_token(const struct sock *sk)
{
	return &quic_sk(sk)->token;
}

static inline struct quic_token *quic_ticket(const struct sock *sk)
{
	return &quic_sk(sk)->ticket;
}

static inline struct quic_token *quic_alpn(const struct sock *sk)
{
	return &quic_sk(sk)->alpn;
}

static inline bool quic_is_serv(struct sock *sk)
{
	return quic_state(sk) == QUIC_STATE_SERVER_CONNECTED;
}

static inline bool quic_is_connected(struct sock *sk)
{
	return quic_state(sk) == QUIC_STATE_SERVER_CONNECTED ||
	       quic_state(sk) == QUIC_STATE_CLIENT_CONNECTED;
}

static inline bool quic_is_listen(struct sock *sk)
{
	return quic_state(sk) == QUIC_STATE_USER_LISTEN;
}

int quic_sock_change_addr(struct sock *sk, struct quic_path_addr *path, void *data,
			  u32 len, bool udp_bind);
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da);
bool quic_request_sock_exists(struct sock *sk, union quic_addr *sa, union quic_addr *da);
int quic_request_sock_enqueue(struct sock *sk, union quic_addr *sa, union quic_addr *da);
struct quic_request_sock *quic_request_sock_dequeue(struct sock *sk);
int quic_get_mss(struct sock *sk);

#endif /* __net_quic_h__ */
