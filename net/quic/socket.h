/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
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
#include "pnmap.h"
#include "packet.h"
#include "output.h"
#include "input.h"
#include "path.h"
#include "timer.h"
#include "cong.h"

extern struct proto quic_prot;
extern struct proto quicv6_prot;

extern struct proto quic_handshake_prot;
extern struct proto quicv6_handshake_prot;

enum quic_state {
	QUIC_SS_CLOSED		= TCP_CLOSE,
	QUIC_SS_LISTENING	= TCP_LISTEN,
	QUIC_SS_ESTABLISHING	= TCP_SYN_RECV,
	QUIC_SS_ESTABLISHED	= TCP_ESTABLISHED,
};

struct quic_token {
	u32 len;
	void *data;
};

struct quic_request_sock {
	struct list_head		list;
	union quic_addr			da;
	union quic_addr			sa;
	struct quic_connection_id	dcid;
	struct quic_connection_id	scid;
	u8				retry;
	u32				version;
};

struct quic_sock {
	struct inet_sock		inet;
	struct quic_addr_family_ops	*af_ops; /* inet4 or inet6 */

	struct quic_connection_id_set	source;
	struct quic_connection_id_set	dest;
	struct quic_stream_table	streams;
	struct quic_crypto		crypto[QUIC_CRYPTO_MAX];
	struct quic_pnmap		pn_map[QUIC_CRYPTO_MAX];

	struct quic_bind_port		port;
	struct quic_udp_sock		*udp_sk[2];
	struct quic_path_addr		src;
	struct quic_path_addr		dst;

	struct quic_transport_param	param;
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

struct quic6_sock {
	struct quic_sock	quic;
	struct ipv6_pinfo	inet6;
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct quic_addr_family_ops *quic_af_ops(const struct sock *sk)
{
	return quic_sk(sk)->af_ops;
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

static inline struct quic_crypto *quic_crypto(const struct sock *sk, u8 level)
{
	return &quic_sk(sk)->crypto[level];
}

static inline struct quic_pnmap *quic_pnmap(const struct sock *sk, u8 level)
{
	return &quic_sk(sk)->pn_map[level];
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

static inline struct quic_connection_id_set *quic_source(const struct sock *sk)
{
	return &quic_sk(sk)->source;
}

static inline struct quic_connection_id_set *quic_dest(const struct sock *sk)
{
	return &quic_sk(sk)->dest;
}

static inline struct quic_transport_param *quic_param(const struct sock *sk)
{
	return &quic_sk(sk)->param;
}

static inline struct quic_bind_port *quic_port(const struct sock *sk)
{
	return &quic_sk(sk)->port;
}

static inline bool quic_is_serv(const struct sock *sk)
{
	return quic_port(sk)->serv;
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

static inline bool quic_version_supported(uint32_t version)
{
	return version == QUIC_VERSION_V1 || version == QUIC_VERSION_V2;
}

static inline u8 quic_version_get_type(uint32_t version, u8 type)
{
	if (!quic_version_supported(version))
		return -1;

	if (version == QUIC_VERSION_V1)
		return type;

	switch (type) {
	case QUIC_PACKET_INITIAL_V2:
		return QUIC_PACKET_INITIAL;
	case QUIC_PACKET_0RTT_V2:
		return QUIC_PACKET_0RTT;
	case QUIC_PACKET_HANDSHAKE_V2:
		return QUIC_PACKET_HANDSHAKE;
	case QUIC_PACKET_RETRY_V2:
		return QUIC_PACKET_RETRY;
	default:
		return -1;
	}
	return -1;
}

static inline u8 quic_version_put_type(uint32_t version, u8 type)
{
	if (!quic_version_supported(version))
		return -1;

	if (version == QUIC_VERSION_V1)
		return type;

	switch (type) {
	case QUIC_PACKET_INITIAL:
		return QUIC_PACKET_INITIAL_V2;
	case QUIC_PACKET_0RTT:
		return QUIC_PACKET_0RTT_V2;
	case QUIC_PACKET_HANDSHAKE:
		return QUIC_PACKET_HANDSHAKE_V2;
	case QUIC_PACKET_RETRY:
		return QUIC_PACKET_RETRY_V2;
	default:
		return -1;
	}
	return -1;
}

int quic_sock_change_addr(struct sock *sk, struct quic_path_addr *path, void *data,
			  u32 len, bool udp_bind);
bool quic_request_sock_exists(struct sock *sk, union quic_addr *sa, union quic_addr *da);
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da);
struct quic_request_sock *quic_request_sock_dequeue(struct sock *sk);
int quic_request_sock_enqueue(struct sock *sk, struct quic_request_sock *req);

#endif /* __net_quic_h__ */
