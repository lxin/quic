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

/* Connection Migration State Machine:
 *
 * +--------+      recv non-probing, free old path    +----------+
 * |  NONE  | <-------------------------------------- | SWAPPED  |
 * +--------+                                         +----------+
 *      |   ^ \                                            ^
 *      |    \ \                                           |
 *      |     \ \   new path detected,                     | recv
 *      |      \ \  has another DCID,                      | Path
 *      |       \ \ snd Path Challenge                     | Response
 *      |        \ -------------------------------         |
 *      |         ------------------------------- \        |
 *      | new path detected,            Path     \ \       |
 *      | has no other DCID,            Challenge \ \      |
 *      | request a new DCID            failed     \ \     |
 *      v                                           \ v    |
 * +----------+                                       +----------+
 * | PENDING  | ------------------------------------> | PROBING  |
 * +----------+  recv a new DCID, snd Path Challenge  +----------+
 */
enum {
	QUIC_PATH_ALT_NONE,	/* No alternate path (migration complete or aborted) */
	QUIC_PATH_ALT_PENDING,	/* Waiting for a new destination CID for migration */
	QUIC_PATH_ALT_PROBING,	/* Validating the alternate path (PATH_CHALLENGE) */
	QUIC_PATH_ALT_SWAPPED,	/* Alternate path is now active; roles swapped */
};

struct quic_udp_sock {
	struct work_struct work;	/* Workqueue to destroy UDP tunnel socket */
	struct hlist_node node;		/* Entry in address-based UDP socket hash table */
	union quic_addr addr;
	int bind_ifindex;
	refcount_t refcnt;
	struct sock *sk;		/* Underlying UDP tunnel socket */
};

struct quic_path {
	union quic_addr daddr;		/* Destination address */
	union quic_addr saddr;		/* Source address */
	struct quic_udp_sock *udp_sk;	/* Wrapped UDP socket used to receive QUIC packets */
};

struct quic_path_group {
	/* Connection ID validation during handshake (rfc9000#section-7.3) */
	struct quic_conn_id retry_dcid;		/* Source CID from Retry packet */
	struct quic_conn_id orig_dcid;		/* Destination CID from first Initial */

	/* Path validation (rfc9000#section-8.2) */
	u8 entropy[QUIC_PATH_ENTROPY_LEN];	/* Entropy for PATH_CHALLENGE */
	struct quic_path path[2];		/* Active path (0) and alternate path (1) */
	struct flowi fl;			/* Flow info from routing decisions */

	/* Anti-amplification limit (rfc9000#section-8) */
	u16 ampl_sndlen;	/* Bytes sent before address is validated */
	u16 ampl_rcvlen;	/* Bytes received to lift amplification limit */

	/* MTU discovery handling */
	u32 mtu_info;		/* PMTU value from received ICMP, pending apply */
	struct {		/* PLPMTUD probing (rfc8899) */
		s64 number;	/* Packet number used for current probe */
		u16 pmtu;	/* Confirmed path MTU */

		u16 probe_size;	/* Current probe packet size */
		u16 probe_high;	/* Highest failed probe size */
		u8 probe_count;	/* Retry count for current probe_size */
		u8 state;	/* Probe state machine (rfc8899#section-5.2) */
	} pl;

	/* Connection Migration (rfc9000#section-9) */
	u8 disable_saddr_alt:1;	/* Remote disable_active_migration (rfc9000#section-18.2) */
	u8 disable_daddr_alt:1;	/* Local disable_active_migration (rfc9000#section-18.2) */
	u8 pref_addr:1;		/* Preferred address offered (rfc9000#section-18.2) */
	u8 alt_probes;		/* Number of PATH_CHALLENGE probes sent */
	u8 alt_state;		/* State for alternate path migration logic (see above) */

	u8 ecn_probes;		/* ECN probe counter */
	u8 validated:1;		/* Path validated with PATH_RESPONSE */
	u8 blocked:1;		/* Blocked by anti-amplification limit */
	u8 retry:1;		/* Retry used in initial packet */
	u8 serv:1;		/* Indicates server side */
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

static inline struct sock *quic_path_usock(struct quic_path_group *paths, u8 path)
{
	return paths->path[path].udp_sk->sk;
}

static inline bool quic_path_alt_state(struct quic_path_group *paths, u8 state)
{
	return paths->alt_state == state;
}

static inline void quic_path_set_alt_state(struct quic_path_group *paths, u8 state)
{
	paths->alt_state = state;
}

/* Returns the destination Connection ID (DCID) used for identifying the connection.
 * Per rfc9000#section-7.3, handshake packets are considered part of the same connection
 * if their DCID matches the one returned here.
 */
static inline struct quic_conn_id *quic_path_orig_dcid(struct quic_path_group *paths)
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
