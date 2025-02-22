/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PATH_MIN_PMTU	1200
#define QUIC_PATH_MAX_PMTU	65536

#define QUIC_MIN_UDP_PAYLOAD	1200
#define QUIC_MAX_UDP_PAYLOAD	65527

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
	struct quic_conn_id retry_dcid;
	struct quic_conn_id orig_dcid;
	struct quic_path path[2];
	u16 ampl_sndlen; /* amplificationlimit send counting */
	u16 ampl_rcvlen; /* amplificationlimit recv counting */
	u8 entropy[8];

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

static inline int quic_path_cmp_saddr(struct quic_path_group *paths, u8 path,
				      union quic_addr *addr)
{
	return memcmp(addr, quic_path_saddr(paths, path), sizeof(*addr));
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

static inline int quic_path_cmp_daddr(struct quic_path_group *paths, u8 path,
				      union quic_addr *addr)
{
	return memcmp(addr, quic_path_daddr(paths, path), sizeof(*addr));
}

static inline union quic_addr *quic_path_uaddr(struct quic_path_group *paths, u8 path)
{
	return &paths->path[path].udp_sk->addr;
}

static inline struct quic_bind_port *quic_path_bind_port(struct quic_path_group *paths, u8 path)
{
	return &paths->path[path].port;
}

static inline u8 quic_path_pref_addr(struct quic_path_group *paths)
{
	return paths->pref_addr;
}

static inline void quic_path_set_pref_addr(struct quic_path_group *paths, u8 pref_addr)
{
	paths->pref_addr = pref_addr;
}

static inline u16 quic_path_ampl_sndlen(struct quic_path_group *paths)
{
	return paths->ampl_sndlen;
}

static inline void quic_path_inc_ampl_sndlen(struct quic_path_group *paths, u16 len)
{
	paths->ampl_sndlen += len;
}

static inline u16 quic_path_ampl_rcvlen(struct quic_path_group *paths)
{
	return paths->ampl_rcvlen;
}

static inline void quic_path_inc_ampl_rcvlen(struct quic_path_group *paths, u16 len)
{
	paths->ampl_rcvlen += len;
}

static inline u8 *quic_path_entropy(struct quic_path_group *paths)
{
	return paths->entropy;
}

static inline u8 quic_path_inc_alt_probes(struct quic_path_group *paths)
{
	return paths->alt_probes++;
}

static inline bool quic_path_alt_state(struct quic_path_group *paths, u8 state)
{
	return paths->alt_state == state;
}

static inline void quic_path_set_alt_state(struct quic_path_group *paths, u8 state)
{
	paths->alt_state = state;
}

static inline bool quic_path_validated(struct quic_path_group *paths)
{
	return paths->validated;
}

static inline void quic_path_set_validated(struct quic_path_group *paths, u8 validated)
{
	paths->validated = validated;
}

static inline u32 quic_path_mtu_info(struct quic_path_group *paths)
{
	return paths->mtu_info;
}

static inline void quic_path_set_mtu_info(struct quic_path_group *paths, u32 mtu_info)
{
	paths->mtu_info = mtu_info;
}

static inline u8 quic_path_ecn_probes(struct quic_path_group *paths)
{
	return paths->ecn_probes;
}

static inline void quic_path_inc_ecn_probes(struct quic_path_group *paths)
{
	paths->ecn_probes++;
}

static inline u16 quic_path_probe_size(struct quic_path_group *paths)
{
	return paths->pl.probe_size;
}

static inline u8 quic_path_retry(struct quic_path_group *paths)
{
	return paths->retry;
}

static inline void quic_path_set_retry(struct quic_path_group *paths, u8 retry)
{
	paths->retry = retry;
}

static inline struct quic_conn_id *quic_path_retry_dcid(struct quic_path_group *paths)
{
	return &paths->retry_dcid;
}

static inline void quic_path_set_retry_dcid(struct quic_path_group *paths, struct quic_conn_id *cid)
{
	paths->retry_dcid = *cid;
}

static inline struct quic_conn_id *quic_path_orig_dcid(struct quic_path_group *paths)
{
	return &paths->orig_dcid;
}

static inline void quic_path_set_orig_dcid(struct quic_path_group *paths, struct quic_conn_id *cid)
{
	paths->orig_dcid = *cid;
}

static inline void quic_path_set_serv(struct quic_path_group *paths)
{
	paths->serv = 1;
}

static inline u8 quic_path_serv(struct quic_path_group *paths)
{
	return paths->serv;
}

static inline u8 quic_path_disable_saddr_alt(struct quic_path_group *paths)
{
	return paths->disable_saddr_alt;
}

int quic_path_detect_alt(struct quic_path_group *paths, union quic_addr *sa, union quic_addr *da);
int quic_path_bind(struct sock *sk, struct quic_path_group *paths, u8 path);
void quic_path_free(struct sock *sk, struct quic_path_group *paths, u8 path);
void quic_path_swap(struct quic_path_group *paths);

u32 quic_path_pl_recv(struct quic_path_group *paths, bool *raise_timer, bool *complete);
u32 quic_path_pl_toobig(struct quic_path_group *paths, u32 pmtu, bool *reset_timer);
u32 quic_path_pl_send(struct quic_path_group *paths, s64 number);

void quic_path_set_param(struct quic_path_group *paths, struct quic_transport_param *p,
			 bool remote);
bool quic_path_pl_confirm(struct quic_path_group *paths, s64 largest, s64 smallest);
void quic_path_pl_reset(struct quic_path_group *paths);
