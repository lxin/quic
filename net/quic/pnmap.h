/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PN_MAX_GABS	16

/*
 * pn_map:
 *           |----------------------|---------------------|...
 * base_pn --^   last_max_pn_seen --^       max_pn_seen --^
 *
 * move forward:
 *   base_pn = last_max_pn_seen - 1;
 *   last_max_pn_seen = max_pn_seen;
 * when:
 *   'max_pn_ts - last_max_pn_ts >= max_record_ts' or
 *   'max_pn_seen - last_max_pn_seen > QUIC_PN_MAP_SIZE / 2'
 */
struct quic_pnmap {
	unsigned long *pn_map;
	u16 len;

	u32 base_pn;
	u32 min_pn_seen;

	u32 max_pn_seen;
	u32 max_pn_ts;

	u32 max_record_ts;
	u32 cum_ack_point;

	u32 last_max_pn_ts;
	u32 last_max_pn_seen;
};

struct quic_gap_ack_block {
	u16 start;
	u16 end;
};

static inline void quic_pnmap_set_max_record_ts(struct quic_pnmap *map, u32 max_record_ts)
{
	map->max_record_ts = max_record_ts;
}

static inline u32 quic_pnmap_min_pn_seen(const struct quic_pnmap *map)
{
	return map->min_pn_seen;
}

static inline u32 quic_pnmap_max_pn_seen(const struct quic_pnmap *map)
{
	return map->max_pn_seen;
}

static inline u32 quic_pnmap_base_pn(const struct quic_pnmap *map)
{
	return map->base_pn;
}

static inline u32 quic_pnmap_max_pn_ts(const struct quic_pnmap *map)
{
	return map->max_pn_ts;
}

static inline bool quic_pnmap_has_gap(const struct quic_pnmap *map)
{
	return map->cum_ack_point != map->max_pn_seen;
}

struct quic_pnmap *quic_pnmap_init(struct quic_pnmap *map);
int quic_pnmap_check(const struct quic_pnmap *map, u32 pn);
int quic_pnmap_mark(struct quic_pnmap *map, u32 pn);
void quic_pnmap_free(struct quic_pnmap *map);
u16 quic_pnmap_num_gabs(struct quic_pnmap *map, struct quic_gap_ack_block *gabs);
