/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PN_MAX_GABS	32
#define QUIC_PN_MAP_MAX_PN	((1LL << 62) - 1)

#define QUIC_PN_MAP_INITIAL	64
#define QUIC_PN_MAP_INCREMENT	QUIC_PN_MAP_INITIAL
#define QUIC_PN_MAP_SIZE	4096
#define QUIC_PN_MAP_LIMIT	(QUIC_PN_MAP_SIZE * 3 / 4)

#define QUIC_PNSPACE_MAX	(QUIC_CRYPTO_MAX - 1)
#define QUIC_PNSPACE_NEXT_PN	0
#define QUIC_PNSPACE_TIME_LIMIT	(333000 * 3)

enum {
	QUIC_ECN_ECT1,
	QUIC_ECN_ECT0,
	QUIC_ECN_CE,
	QUIC_ECN_MAX
};

enum {
	QUIC_ECN_LOCAL,
	QUIC_ECN_PEER,
	QUIC_ECN_DIR_MAX
};

struct quic_gap_ack_block {
	u16 start;
	u16 end;
};

/* pn_map:
 * min_pn_seen -->  |----------------------|---------------------|...
 *        base_pn --^        mid_pn_seen --^       max_pn_seen --^
 *
 * move forward:
 *   min_pn_seen = mid_pn_seen;
 *   base_pn = first_zero_bit from mid_pn_seen + 1;
 *   mid_pn_seen = max_pn_seen;
 *   mid_pn_time = now;
 * when:
 *   'max_pn_time - mid_pn_time >= max_time_limit' or
 *   'max_pn_seen - mid_pn_seen > QUIC_PN_MAP_LIMIT'
 * gaps search:
 *    from base_pn - 1 to max_pn_seen
 */
struct quic_pnspace {
	u64 ecn_count[QUIC_ECN_DIR_MAX][QUIC_ECN_MAX];
	unsigned long *pn_map;
	u16 pn_map_len;
	u8  need_sack:1;
	u8  sack_path:1;

	u32 max_time_limit;
	s64 min_pn_seen;
	s64 mid_pn_seen;
	s64 max_pn_seen;
	u32 mid_pn_time;
	u32 max_pn_time;
	s64 base_pn;
	u32 time;

	s64 max_pn_acked_seen;
	u32 max_pn_acked_time;
	u32 last_sent_time;
	u32 loss_time;
	u32 inflight;
	s64 next_pn; /* next packet number to send */
};

static inline void quic_pnspace_set_max_pn_acked_seen(struct quic_pnspace *space,
						      s64 max_pn_acked_seen)
{
	if (space->max_pn_acked_seen >= max_pn_acked_seen)
		return;
	space->max_pn_acked_seen = max_pn_acked_seen;
	space->max_pn_acked_time = jiffies_to_usecs(jiffies);
}

static inline void quic_pnspace_set_base_pn(struct quic_pnspace *space, s64 pn)
{
	space->base_pn = pn;
	space->max_pn_seen = space->base_pn - 1;
	space->mid_pn_seen = space->max_pn_seen;
	space->min_pn_seen = space->max_pn_seen;

	space->max_pn_time = space->time;
	space->mid_pn_time = space->max_pn_time;
}

static inline bool quic_pnspace_has_gap(const struct quic_pnspace *space)
{
	return space->base_pn != space->max_pn_seen + 1;
}

static inline void quic_pnspace_inc_ecn_count(struct quic_pnspace *space, u8 ecn)
{
	if (!ecn)
		return;
	space->ecn_count[QUIC_ECN_LOCAL][ecn - 1]++;
}

static inline int quic_pnspace_set_ecn_count(struct quic_pnspace *space, u64 *ecn_count)
{
	if (space->ecn_count[QUIC_ECN_PEER][QUIC_ECN_ECT0] < ecn_count[QUIC_ECN_ECT0])
		space->ecn_count[QUIC_ECN_PEER][QUIC_ECN_ECT0] = ecn_count[QUIC_ECN_ECT0];
	if (space->ecn_count[QUIC_ECN_PEER][QUIC_ECN_ECT1] < ecn_count[QUIC_ECN_ECT1])
		space->ecn_count[QUIC_ECN_PEER][QUIC_ECN_ECT1] = ecn_count[QUIC_ECN_ECT1];
	if (space->ecn_count[QUIC_ECN_PEER][QUIC_ECN_CE] < ecn_count[QUIC_ECN_CE]) {
		space->ecn_count[QUIC_ECN_PEER][QUIC_ECN_CE] = ecn_count[QUIC_ECN_CE];
		return 1;
	}
	return 0;
}

static inline bool quic_pnspace_has_ecn_count(struct quic_pnspace *space)
{
	return space->ecn_count[QUIC_ECN_LOCAL][QUIC_ECN_ECT0] ||
	       space->ecn_count[QUIC_ECN_LOCAL][QUIC_ECN_ECT1] ||
	       space->ecn_count[QUIC_ECN_LOCAL][QUIC_ECN_CE];
}

u16 quic_pnspace_num_gabs(struct quic_pnspace *space, struct quic_gap_ack_block *gabs);
int quic_pnspace_check(struct quic_pnspace *space, s64 pn);
int quic_pnspace_mark(struct quic_pnspace *space, s64 pn);

void quic_pnspace_free(struct quic_pnspace *space);
int quic_pnspace_init(struct quic_pnspace *space);
