/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PATH_MIN_PMTU	1200U
#define QUIC_PATH_MAX_PMTU	65536U

#define QUIC_MIN_UDP_PAYLOAD	1200
#define QUIC_MAX_UDP_PAYLOAD	65527

#define QUIC_PATH_ENTROPY_LEN	8

enum {
	QUIC_PATH_ALT_NONE,
	QUIC_PATH_ALT_PENDING,
	QUIC_PATH_ALT_PROBING,
	QUIC_PATH_ALT_SWAPPED,
};

struct quic_bind_port {
	struct hlist_node node;
	unsigned short port;
	struct net *net;
};

struct quic_udp_sock {
	struct work_struct work;
	struct hlist_node node;
	union quic_addr addr;
	refcount_t refcnt;
	struct sock *sk;
};

struct quic_path {
	union quic_addr daddr;
	union quic_addr saddr;
	struct quic_bind_port port;
	struct quic_udp_sock *udp_sk;
};

struct quic_path_group {
	u8 entropy[QUIC_PATH_ENTROPY_LEN];
	struct quic_conn_id retry_dcid;
	struct quic_conn_id orig_dcid;
	struct quic_path path[2];
	struct flowi fl;
	u16 ampl_sndlen; /* amplificationlimit send counting */
	u16 ampl_rcvlen; /* amplificationlimit recv counting */

	u32 mtu_info;
	u32 pathmtu;
	struct {
		s64 number;
		u16 pmtu;

		u16 probe_size;
		u16 probe_high;
		u8 probe_count;
		u8 state;
	} pl; /* plpmtud related */

	u8 disable_saddr_alt:1;
	u8 disable_daddr_alt:1;
	u8 validated:1;
	u8 pref_addr:1;

	u8 ecn_probes;
	u8 alt_probes;
	u8 alt_state;
	u8 blocked:1;
	u8 retry:1;
	u8 serv:1;
};

static inline union quic_addr *quic_path_saddr(struct quic_path_group *paths, u8 path)
{
	return &paths->path[path].saddr;
}

static inline void quic_path_set_saddr(struct quic_path_group *paths, u8 path,
				       union quic_addr *addr)
{
	memcpy(quic_path_saddr(paths, path), addr, sizeof(*addr));
}

static inline union quic_addr *quic_path_daddr(struct quic_path_group *paths, u8 path)
{
	return &paths->path[path].daddr;
}

static inline void quic_path_set_daddr(struct quic_path_group *paths, u8 path,
				       union quic_addr *addr)
{
	memcpy(quic_path_daddr(paths, path), addr, sizeof(*addr));
}

static inline union quic_addr *quic_path_uaddr(struct quic_path_group *paths, u8 path)
{
	return &paths->path[path].udp_sk->addr;
}

static inline struct quic_bind_port *quic_path_bind_port(struct quic_path_group *paths, u8 path)
{
	return &paths->path[path].port;
}

static inline bool quic_path_alt_state(struct quic_path_group *paths, u8 state)
{
	return paths->alt_state == state;
}

static inline void quic_path_set_alt_state(struct quic_path_group *paths, u8 state)
{
	paths->alt_state = state;
}

static inline struct quic_conn_id *quic_path_dcid(struct quic_path_group *paths)
{
	return paths->retry ? &paths->retry_dcid : &paths->orig_dcid;
}

int quic_path_detect_alt(struct quic_path_group *paths, union quic_addr *sa, union quic_addr *da,
			 struct sock *sk);
int quic_path_bind(struct sock *sk, struct quic_path_group *paths, u8 path);
void quic_path_free(struct sock *sk, struct quic_path_group *paths, u8 path);
void quic_path_swap(struct quic_path_group *paths);

u32 quic_path_pl_recv(struct quic_path_group *paths, bool *raise_timer, bool *complete);
u32 quic_path_pl_toobig(struct quic_path_group *paths, u32 pmtu, bool *reset_timer);
u32 quic_path_pl_send(struct quic_path_group *paths, s64 number);

void quic_path_get_param(struct quic_path_group *paths, struct quic_transport_param *p);
void quic_path_set_param(struct quic_path_group *paths, struct quic_transport_param *p);
bool quic_path_pl_confirm(struct quic_path_group *paths, s64 largest, s64 smallest);
void quic_path_pl_reset(struct quic_path_group *paths);

int quic_path_init(int (*rcv)(struct sk_buff *skb, u8 err));
void quic_path_destroy(void);
