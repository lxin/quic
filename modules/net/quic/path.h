/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PATH_ALT_SRC	0x1
#define QUIC_PATH_ALT_DST	0x2

#define QUIC_PATH_MAX_PMTU	65536

#define QUIC_MIN_UDP_PAYLOAD	1200
#define QUIC_MAX_UDP_PAYLOAD	65527

struct quic_bind_port {
	struct hlist_node node;
	unsigned short port;
	struct net *net;
	u8 retry:1;
	u8 serv:1;
};

struct quic_udp_sock {
	struct work_struct work;
	struct hlist_node node;
	union quic_addr addr;
	refcount_t refcnt;
	struct sock *sk;
};

struct quic_path_addr {
	union quic_addr addr[2];
	u8 entropy[8];
	u8 addr_len;
	u8 sent_cnt;

	u8 udp_bind:1;
	u8 active:1;
};

struct quic_path_src {
	struct quic_path_addr a;

	struct quic_udp_sock *udp_sk[2];
	struct quic_bind_port port[2];
};

struct quic_path_dst {
	struct quic_path_addr a;
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
	u8 ecn_probes;
	u8 validated:1;
};

static inline void quic_path_addr_set(struct quic_path_addr *a, union quic_addr *addr, bool alt)
{
	memcpy(&a->addr[a->active ^ alt], addr, sizeof(*addr));
}

static inline union quic_addr *quic_path_addr(struct quic_path_addr *a, bool alt)
{
	return &a->addr[a->active ^ alt];
}

static inline union quic_addr *quic_path_udp(struct quic_path_addr *a, bool alt)
{
	return &((struct quic_path_src *)a)->udp_sk[a->active ^ alt]->addr;
}

static inline struct quic_bind_port *quic_path_port(struct quic_path_addr *a, bool alt)
{
	return &((struct quic_path_src *)a)->port[a->active ^ alt];
}

static inline void quic_path_addr_init(struct quic_path_addr *a, u8 udp_bind)
{
	a->udp_bind = udp_bind;
}

static inline int quic_path_cmp(struct quic_path_addr *a, bool alt, union quic_addr *addr)
{
	return memcmp(addr, quic_path_addr(a, alt), sizeof(*addr));
}

static inline u16 quic_path_probe_size(struct quic_path_addr *a)
{
	return ((struct quic_path_dst *)a)->pl.probe_size;
}

static inline u8 quic_path_ecn_probes(struct quic_path_addr *a)
{
	return ((struct quic_path_dst *)a)->ecn_probes;
}

static inline void quic_path_inc_ecn_probes(struct quic_path_addr *a)
{
	((struct quic_path_dst *)a)->ecn_probes++;
}

static inline u32 quic_path_mtu_info(struct quic_path_addr *a)
{
	return ((struct quic_path_dst *)a)->mtu_info;
}

static inline void quic_path_set_mtu_info(struct quic_path_addr *a, u32 mtu_info)
{
	((struct quic_path_dst *)a)->mtu_info = mtu_info;
}

static inline u16 quic_path_ampl_sndlen(struct quic_path_addr *a)
{
	return ((struct quic_path_dst *)a)->ampl_sndlen;
}

static inline void quic_path_inc_ampl_sndlen(struct quic_path_addr *a, u16 len)
{
	((struct quic_path_dst *)a)->ampl_sndlen += len;
}

static inline u16 quic_path_ampl_rcvlen(struct quic_path_addr *a)
{
	return ((struct quic_path_dst *)a)->ampl_rcvlen;
}

static inline void quic_path_inc_ampl_rcvlen(struct quic_path_addr *a, u16 len)
{
	((struct quic_path_dst *)a)->ampl_rcvlen += len;
}

static inline bool quic_path_validated(struct quic_path_addr *a)
{
	return ((struct quic_path_dst *)a)->validated;
}

static inline void quic_path_set_validated(struct quic_path_addr *a, u8 validated)
{
	((struct quic_path_dst *)a)->validated = validated;
}

static inline u8 quic_path_sent_cnt(struct quic_path_addr *a)
{
	return a->sent_cnt;
}

static inline void quic_path_set_sent_cnt(struct quic_path_addr *a, u8 cnt)
{
	a->sent_cnt = cnt;
}

static inline void quic_path_swap_active(struct quic_path_addr *a)
{
	a->active = !a->active;
}

static inline u8 *quic_path_entropy(struct quic_path_addr *a)
{
	return a->entropy;
}

static inline u8 quic_path_udp_bind(struct quic_path_addr *a)
{
	return a->udp_bind;
}

int quic_path_set_bind_port(struct sock *sk, struct quic_path_addr *a, bool alt);
int quic_path_set_udp_sock(struct sock *sk, struct quic_path_addr *a, bool alt);
void quic_path_addr_free(struct sock *sk, struct quic_path_addr *path, bool alt);
void quic_path_free(struct sock *sk, struct quic_path_addr *a);

u32 quic_path_pl_recv(struct quic_path_addr *a, bool *raise_timer, bool *complete);
u32 quic_path_pl_toobig(struct quic_path_addr *a, u32 pmtu, bool *reset_timer);
bool quic_path_pl_confirm(struct quic_path_addr *a, s64 largest, s64 smallest);
u32 quic_path_pl_send(struct quic_path_addr *a, s64 number);
void quic_path_pl_reset(struct quic_path_addr *a);
