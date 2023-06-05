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

#include "uapi/linux/quic.h"
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

	struct quic_outqueue		outq;

	struct quic_inqueue		inq;

	struct quic_pnmap		pn_map;

	struct quic_packet		packet;

	struct quic_cong		cong;

	struct hlist_node		node;

	struct quic_timer		timers[QUIC_TIMER_MAX];
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline bool quic_handshake_user(struct sock *sk)
{
	return quic_sk(sk)->state == QUIC_STATE_USER_CONNECTING;
}

static inline bool quic_is_serv(struct sock *sk)
{
	return quic_sk(sk)->state == QUIC_STATE_SERVER_CONNECTED;
}

static inline bool quic_is_connected(struct sock *sk)
{
	return quic_sk(sk)->state == QUIC_STATE_SERVER_CONNECTED ||
	       quic_sk(sk)->state == QUIC_STATE_CLIENT_CONNECTED;
}

struct quic_sock *quic_sock_lookup_byaddr(struct sk_buff *skb, union quic_addr *a);
int quic_get_mss(struct sock *sk);

#endif /* __net_quic_h__ */
