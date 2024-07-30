/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PN_MAX_GABS	256
#define QUIC_PN_MAP_MAX_PN	((1ULL << 62) - 1)

#define QUIC_PN_MAP_INITIAL	BITS_PER_LONG
#define QUIC_PN_MAP_INCREMENT	QUIC_PN_MAP_INITIAL
#define QUIC_PN_MAP_SIZE	4096
#define QUIC_PN_MAP_LIMIT	(QUIC_PN_MAP_SIZE * 3 / 4)

#define QUIC_PNSPACE_MAX	(QUIC_CRYPTO_MAX - 1)
#define QUIC_PNSPACE_NEXT_PN	0

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
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	unsigned long *pn_map;
	u64 ecn_count[2][3]; /* ECT_1, ECT_0, CE count of local and peer */
	u16 pn_map_len;

	u32 max_time_limit;
	s64 min_pn_seen;
	s64 mid_pn_seen;
	s64 max_pn_seen;
	u32 mid_pn_time;
	u32 max_pn_time;
	s64 base_pn;

	s64 max_pn_acked_seen;
	u32 max_pn_acked_time;
	u32 last_sent_time;
	u32 loss_time;
	u32 inflight;
	s64 next_pn; /* next packet number to send */
};

static inline struct quic_gap_ack_block *quic_pnspace_gabs(struct quic_pnspace *space)
{
	return space->gabs;
}

static inline void quic_pnspace_set_max_time_limit(struct quic_pnspace *space, u32 max_time_limit)
{
	space->max_time_limit = max_time_limit;
}

static inline s64 quic_pnspace_min_pn_seen(const struct quic_pnspace *space)
{
	return space->min_pn_seen;
}

static inline s64 quic_pnspace_max_pn_seen(const struct quic_pnspace *space)
{
	return space->max_pn_seen;
}

static inline void quic_pnspace_set_max_pn_acked_seen(struct quic_pnspace *space,
						      s64 max_pn_acked_seen)
{
	if (space->max_pn_acked_seen >= max_pn_acked_seen)
		return;
	space->max_pn_acked_seen = max_pn_acked_seen;
	space->max_pn_acked_time = jiffies_to_usecs(jiffies);
}

static inline s64 quic_pnspace_max_pn_acked_seen(const struct quic_pnspace *space)
{
	return space->max_pn_acked_seen;
}

static inline s32 quic_pnspace_max_pn_acked_time(const struct quic_pnspace *space)
{
	return space->max_pn_acked_time;
}

static inline void quic_pnspace_set_loss_time(struct quic_pnspace *space, u32 loss_time)
{
	space->loss_time = loss_time;
}

static inline u32 quic_pnspace_loss_time(const struct quic_pnspace *space)
{
	return space->loss_time;
}

static inline void quic_pnspace_set_last_sent_time(struct quic_pnspace *space, u32 last_sent_time)
{
	space->last_sent_time = last_sent_time;
}

static inline u32 quic_pnspace_last_sent_time(const struct quic_pnspace *space)
{
	return space->last_sent_time;
}

static inline s64 quic_pnspace_next_pn(const struct quic_pnspace *space)
{
	return space->next_pn;
}

static inline s64 quic_pnspace_inc_next_pn(struct quic_pnspace *space)
{
	return space->next_pn++;
}

static inline u32 quic_pnspace_inflight(struct quic_pnspace *space)
{
	return space->inflight;
}

static inline void quic_pnspace_inc_inflight(struct quic_pnspace *space, u16 bytes)
{
	space->inflight += bytes;
}

static inline void quic_pnspace_dec_inflight(struct quic_pnspace *space, u16 bytes)
{
	space->inflight -= bytes;
}

static inline s64 quic_pnspace_base_pn(const struct quic_pnspace *space)
{
	return space->base_pn;
}

static inline void quic_pnspace_set_base_pn(struct quic_pnspace *space, s64 pn)
{
	space->base_pn = pn;
	space->max_pn_seen = space->base_pn - 1;
	space->mid_pn_seen = space->max_pn_seen;
	space->min_pn_seen = space->max_pn_seen;

	space->max_pn_time = jiffies_to_usecs(jiffies);
	space->mid_pn_time = space->max_pn_time;
}

static inline u32 quic_pnspace_max_pn_time(const struct quic_pnspace *space)
{
	return space->max_pn_time;
}

static inline bool quic_pnspace_has_gap(const struct quic_pnspace *space)
{
	return space->base_pn != space->max_pn_seen + 1;
}

static inline void quic_pnspace_inc_ecn_count(struct quic_pnspace *space, u8 ecn)
{
	if (!ecn)
		return;
	space->ecn_count[0][ecn - 1]++;
}

static inline int quic_pnspace_set_ecn_count(struct quic_pnspace *space, u64 *ecn_count)
{
	if (space->ecn_count[1][0] < ecn_count[0])
		space->ecn_count[1][0] = ecn_count[0];
	if (space->ecn_count[1][1] < ecn_count[1])
		space->ecn_count[1][1] = ecn_count[1];
	if (space->ecn_count[1][2] < ecn_count[2]) {
		space->ecn_count[1][2] = ecn_count[2];
		return 1;
	}
	return 0;
}

static inline u64 *quic_pnspace_ecn_count(struct quic_pnspace *space)
{
	return space->ecn_count[0];
}

static inline bool quic_pnspace_has_ecn_count(struct quic_pnspace *space)
{
	return space->ecn_count[0][0] || space->ecn_count[0][1] || space->ecn_count[0][2];
}

int quic_pnspace_check(struct quic_pnspace *space, s64 pn);
int quic_pnspace_mark(struct quic_pnspace *space, s64 pn);
u16 quic_pnspace_num_gabs(struct quic_pnspace *space);

void quic_pnspace_free(struct quic_pnspace *space);
int quic_pnspace_init(struct quic_pnspace *space);
