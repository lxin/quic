/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/udp_tunnel.h>
#include <linux/quic.h>

#include "pnspace.h"
#include "common.h"
#include "family.h"
#include "stream.h"
#include "connid.h"
#include "crypto.h"
#include "path.h"
#include "cong.h"

#include "packet.h"
#include "frame.h"

#include "protocol.h"
#include "outqueue.h"
#include "inqueue.h"
#include "timer.h"

extern struct proto quic_prot;
extern struct proto quicv6_prot;

enum quic_state {
	QUIC_SS_CLOSED		= TCP_CLOSE,
	QUIC_SS_LISTENING	= TCP_LISTEN,
	QUIC_SS_ESTABLISHING	= TCP_SYN_RECV,
	QUIC_SS_ESTABLISHED	= TCP_ESTABLISHED,
};

enum quic_tsq_enum {
	QUIC_MTU_REDUCED_DEFERRED,
	QUIC_LOSS_DEFERRED,
	QUIC_SACK_DEFERRED,
	QUIC_PATH_DEFERRED,
	QUIC_PMTU_DEFERRED,
	QUIC_TSQ_DEFERRED,
};

enum quic_tsq_flags {
	QUIC_F_MTU_REDUCED_DEFERRED	= BIT(QUIC_MTU_REDUCED_DEFERRED),
	QUIC_F_LOSS_DEFERRED		= BIT(QUIC_LOSS_DEFERRED),
	QUIC_F_SACK_DEFERRED		= BIT(QUIC_SACK_DEFERRED),
	QUIC_F_PATH_DEFERRED		= BIT(QUIC_PATH_DEFERRED),
	QUIC_F_PMTU_DEFERRED		= BIT(QUIC_PMTU_DEFERRED),
	QUIC_F_TSQ_DEFERRED		= BIT(QUIC_TSQ_DEFERRED),
};

#define QUIC_DEFERRED_ALL (QUIC_F_MTU_REDUCED_DEFERRED |	\
			   QUIC_F_LOSS_DEFERRED |		\
			   QUIC_F_SACK_DEFERRED |		\
			   QUIC_F_PATH_DEFERRED |		\
			   QUIC_F_PMTU_DEFERRED |		\
			   QUIC_F_TSQ_DEFERRED)

struct quic_request_sock {
	struct list_head	list;

	struct quic_conn_id	dcid;
	struct quic_conn_id	scid;
	union quic_addr		daddr;
	union quic_addr		saddr;

	struct quic_conn_id	orig_dcid;
	u32			version;
	u8			retry;

	struct sk_buff_head	backlog_list;
	u32			blen;
};

struct quic_sock {
	struct inet_sock		inet;
	struct list_head		reqs;

	struct quic_config		config;
	struct quic_data		ticket;
	struct quic_data		token;
	struct quic_data		alpn;

	struct quic_stream_table	streams;
	struct quic_conn_id_set		source;
	struct quic_conn_id_set		dest;
	struct quic_path_group		paths;
	struct quic_cong		cong;
	struct quic_pnspace		space[QUIC_PNSPACE_MAX];
	struct quic_crypto		crypto[QUIC_CRYPTO_MAX];

	struct quic_outqueue		outq;
	struct quic_inqueue		inq;
	struct quic_packet		packet;
	struct quic_timer		timers[QUIC_TIMER_MAX];
};

struct quic6_sock {
	struct quic_sock	quic;
	struct ipv6_pinfo	inet6;
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct list_head *quic_reqs(const struct sock *sk)
{
	return &quic_sk(sk)->reqs;
}

static inline struct quic_config *quic_config(const struct sock *sk)
{
	return &quic_sk(sk)->config;
}

static inline struct quic_data *quic_token(const struct sock *sk)
{
	return &quic_sk(sk)->token;
}

static inline struct quic_data *quic_ticket(const struct sock *sk)
{
	return &quic_sk(sk)->ticket;
}

static inline struct quic_data *quic_alpn(const struct sock *sk)
{
	return &quic_sk(sk)->alpn;
}

static inline struct quic_stream_table *quic_streams(const struct sock *sk)
{
	return &quic_sk(sk)->streams;
}

static inline struct quic_conn_id_set *quic_source(const struct sock *sk)
{
	return &quic_sk(sk)->source;
}

static inline struct quic_conn_id_set *quic_dest(const struct sock *sk)
{
	return &quic_sk(sk)->dest;
}

static inline struct quic_path_group *quic_paths(const struct sock *sk)
{
	return &quic_sk(sk)->paths;
}

static inline bool quic_is_serv(const struct sock *sk)
{
	return quic_paths(sk)->serv;
}

static inline struct quic_cong *quic_cong(const struct sock *sk)
{
	return &quic_sk(sk)->cong;
}

static inline struct quic_pnspace *quic_pnspace(const struct sock *sk, u8 level)
{
	return &quic_sk(sk)->space[level % QUIC_CRYPTO_EARLY];
}

static inline struct quic_crypto *quic_crypto(const struct sock *sk, u8 level)
{
	return &quic_sk(sk)->crypto[level];
}

static inline struct quic_outqueue *quic_outq(const struct sock *sk)
{
	return &quic_sk(sk)->outq;
}

static inline struct quic_inqueue *quic_inq(const struct sock *sk)
{
	return &quic_sk(sk)->inq;
}

static inline struct quic_packet *quic_packet(const struct sock *sk)
{
	return &quic_sk(sk)->packet;
}

static inline void *quic_timer(const struct sock *sk, u8 type)
{
	return (void *)&quic_sk(sk)->timers[type];
}

static inline bool quic_is_establishing(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_ESTABLISHING;
}

static inline bool quic_is_established(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_ESTABLISHED;
}

static inline bool quic_is_listen(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_LISTENING;
}

static inline bool quic_is_closed(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_CLOSED;
}

static inline void quic_set_state(struct sock *sk, int state)
{
	struct net *net = sock_net(sk);
	int mib;

	if (sk->sk_state == state)
		return;

	if (state == QUIC_SS_ESTABLISHED) {
		mib = quic_is_serv(sk) ? QUIC_MIB_CONN_PASSIVEESTABS
				       : QUIC_MIB_CONN_ACTIVEESTABS;
		QUIC_INC_STATS(net, mib);
		QUIC_INC_STATS(net, QUIC_MIB_CONN_CURRENTESTABS);
	} else if (quic_is_established(sk)) {
		QUIC_DEC_STATS(net, QUIC_MIB_CONN_CURRENTESTABS);
	}

	inet_sk_set_state(sk, state);
	sk->sk_state_change(sk);
}

struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
				     struct quic_data *alpns);
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
			      struct quic_conn_id *dcid);
bool quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb);

struct quic_request_sock *quic_request_sock_enqueue(struct sock *sk, struct quic_conn_id *odcid,
						    u8 retry);
int quic_request_sock_backlog_tail(struct sock *sk, struct quic_request_sock *req,
				   struct sk_buff *skb);
struct quic_request_sock *quic_request_sock_lookup(struct sock *sk);
