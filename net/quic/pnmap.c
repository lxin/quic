// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bitmap.h>
#include "pnmap.h"

#define QUIC_PN_MAP_INITIAL BITS_PER_LONG
#define QUIC_PN_MAP_INCREMENT QUIC_PN_MAP_INITIAL
#define QUIC_PN_MAP_SIZE 32768

#define PN_lt(a, b)		\
	(typecheck(u32, a) &&	\
	 typecheck(u32, b) &&	\
	 ((__s32)((a) - (b)) < 0))

#define PN_lte(a, b)		\
	(typecheck(u32, a) &&	\
	 typecheck(u32, b) &&	\
	 ((s32)((a) - (b)) <= 0))

static inline int quic_pnmap_has_gap(const struct quic_pnmap *map)
{
	return map->cumulative_pn_ack_point != map->max_pn_seen;
}

static void quic_pnmap_find_gap_ack(const struct quic_pnmap *map, u16 off,
				    u16 len, u16 *start, u16 *end);
static int quic_pnmap_grow(struct quic_pnmap *map, u16 size);
static void quic_pnmap_update(struct quic_pnmap *map);

struct quic_pnmap *quic_pnmap_init(struct quic_pnmap *map)
{
	u16 len = QUIC_PN_MAP_INITIAL;

	if (!map->pn_map) {
		map->pn_map = kzalloc(len >> 3, GFP_KERNEL);
		if (!map->pn_map)
			return NULL;

		map->len = len;
	} else {
		bitmap_zero(map->pn_map, map->len);
	}

	map->base_pn = 0;
	map->cumulative_pn_ack_point = 0;
	map->max_pn_seen = 0;
	map->max_pn_ts = jiffies_to_usecs(jiffies);
	map->last_max_pn_ts = map->max_pn_ts;
	map->last_max_pn_seen = 0;

	return map;
}

void quic_pnmap_free(struct quic_pnmap *map)
{
	map->len = 0;
	kfree(map->pn_map);
}

int quic_pnmap_check(const struct quic_pnmap *map, u32 pn)
{
	u32 gap;

	if (PN_lt(pn, map->base_pn))
		return 1;

	if (!PN_lt(pn, map->base_pn + QUIC_PN_MAP_SIZE))
		return -1;

	gap = pn - map->base_pn;

	if (gap < map->len && test_bit(gap, map->pn_map))
		return 1;
	else
		return 0;
}

int quic_pnmap_mark(struct quic_pnmap *map, u32 pn)
{
	u16 gap, zero_bit;

	if (PN_lt(pn, map->base_pn))
		return 0;

	gap = pn - map->base_pn;

	if (gap >= map->len && !quic_pnmap_grow(map, gap + 1))
		return -ENOMEM;

	if (PN_lt(map->max_pn_seen, pn)) {
		map->max_pn_seen = pn;
		map->max_pn_ts = jiffies_to_usecs(jiffies);
	}

	if (pn == map->cumulative_pn_ack_point + 1) {
		map->cumulative_pn_ack_point++;
		if (quic_pnmap_has_gap(map)) {
			zero_bit = find_first_zero_bit(map->pn_map, map->max_pn_seen - map->base_pn);
			map->cumulative_pn_ack_point = map->base_pn + zero_bit - 1;
		}
	}

	set_bit(gap, map->pn_map);
	quic_pnmap_update(map);
	return 0;
}

struct quic_pnmap_iter {
	u32 start;
};

static void quic_pnmap_iter_init(const struct quic_pnmap *map, struct quic_pnmap_iter *iter)
{
	iter->start = map->cumulative_pn_ack_point + 1;
}

static int quic_pnmap_next_gap_ack(const struct quic_pnmap *map, struct quic_pnmap_iter *iter,
				   u16 *start, u16 *end)
{
	u16 start_ = 0, end_ = 0, offset;
	int ended = 0;

	if (PN_lte(map->max_pn_seen, iter->start))
		return 0;

	offset = iter->start - map->base_pn;
	quic_pnmap_find_gap_ack(map, offset, map->len, &start_, &end_);

	if (start_ && !end_)
		end_ = map->len - 1;

	if (end_) {
		*start = start_ + 1;
		*end = end_ + 1;

		iter->start = map->base_pn + *end + 1;
		ended = 1;
	}

	return ended;
}

static void quic_pnmap_update(struct quic_pnmap *map)
{
	u32 current_ts = jiffies_to_usecs(jiffies), zero_bit, len;

	if (current_ts - map->last_max_pn_ts < map->max_record_ts)
		return;

	len = map->last_max_pn_seen - map->base_pn;
	map->base_pn = map->last_max_pn_seen;

	map->last_max_pn_ts = current_ts;
	map->last_max_pn_seen = map->max_pn_seen;

	if (len) {
		bitmap_shift_right(map->pn_map, map->pn_map, len, map->len);
		len = map->last_max_pn_seen - map->base_pn + 1;
		zero_bit = find_first_zero_bit(map->pn_map, len);
		map->cumulative_pn_ack_point = map->base_pn + zero_bit - 1;
	}
}

static int quic_pnmap_grow(struct quic_pnmap *map, u16 size)
{
	unsigned long *new;
	unsigned long inc;
	u16  len;

	if (size > QUIC_PN_MAP_SIZE)
		return 0;

	inc = ALIGN((size - map->len), BITS_PER_LONG) + QUIC_PN_MAP_INCREMENT;
	len = min_t(u16, map->len + inc, QUIC_PN_MAP_SIZE);

	new = kzalloc(len >> 3, GFP_ATOMIC);
	if (!new)
		return 0;

	bitmap_copy(new, map->pn_map, map->max_pn_seen - map->base_pn + 1);
	kfree(map->pn_map);
	map->pn_map = new;
	map->len = len;

	return 1;
}

static void quic_pnmap_find_gap_ack(const struct quic_pnmap *map, u16 off, u16 len, u16 *start, u16 *end)
{
	int i = off;

	i = find_next_zero_bit(map->pn_map, len, off);
	if (i < len)
		*start = i;

	if (!*start)
		return;

	if (PN_lte(map->max_pn_seen, map->base_pn + *start - 1)) {
		*start = 0;
		return;
	}

	i = find_next_bit(map->pn_map, len, i);
	if (i < len)
		*end = i - 1;
}

u16 quic_pnmap_num_gabs(struct quic_pnmap *map, struct quic_gap_ack_block *gabs)
{
	struct quic_pnmap_iter iter;
	int ngaps = 0;

	if (quic_pnmap_has_gap(map)) {
		u16 start = 0, end = 0;

		quic_pnmap_iter_init(map, &iter);
		while (quic_pnmap_next_gap_ack(map, &iter, &start, &end)) {
			gabs[ngaps].start = start;
			gabs[ngaps].end = end;
			ngaps++;
			if (ngaps >= QUIC_PN_MAX_GABS)
				break;
		}
	}
	return ngaps;
}
