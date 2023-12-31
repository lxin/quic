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
#define QUIC_PN_MAP_SIZE 1024

static int quic_pnmap_grow(struct quic_pnmap *map, u16 size);
static void quic_pnmap_update(struct quic_pnmap *map, s64 pn);

int quic_pnmap_init(struct quic_pnmap *map)
{
	u16 len = QUIC_PN_MAP_INITIAL;

	if (!map->pn_map) {
		map->pn_map = kzalloc(len >> 3, GFP_KERNEL);
		if (!map->pn_map)
			return -ENOMEM;

		map->len = len;
	} else {
		bitmap_zero(map->pn_map, map->len);
	}

	map->next_number = QUIC_PN_MAP_BASE_PN;

	map->base_pn = QUIC_PN_MAP_BASE_PN;
	map->cum_ack_point = map->base_pn - 1;
	map->min_pn_seen = map->base_pn + QUIC_PN_MAP_SIZE;
	map->max_pn_seen = map->base_pn - 1;
	map->last_max_pn_seen = map->base_pn - 1;

	map->max_pn_ts = jiffies_to_usecs(jiffies);
	map->last_max_pn_ts = map->max_pn_ts;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnmap_init);

void quic_pnmap_free(struct quic_pnmap *map)
{
	map->len = 0;
	kfree(map->pn_map);
}
EXPORT_SYMBOL_GPL(quic_pnmap_free);

int quic_pnmap_check(const struct quic_pnmap *map, s64 pn)
{
	u16 gap;

	if (pn < map->base_pn)
		return 1;

	if (pn >= map->base_pn + QUIC_PN_MAP_SIZE)
		return -1;

	WARN_ON_ONCE(pn > QUIC_PN_MAP_MAX_PN);
	gap = pn - map->base_pn;

	return gap < map->len && test_bit(gap, map->pn_map);
}
EXPORT_SYMBOL_GPL(quic_pnmap_check);

int quic_pnmap_mark(struct quic_pnmap *map, s64 pn)
{
	u16 gap, zero_bit;

	if (pn < map->base_pn)
		return 0;

	gap = pn - map->base_pn;

	if (gap >= map->len && !quic_pnmap_grow(map, gap + 1))
		return -ENOMEM;

	if (map->max_pn_seen < pn) {
		map->max_pn_seen = pn;
		map->max_pn_ts = jiffies_to_usecs(jiffies);
	}

	if (pn < map->min_pn_seen) { /* only in the 1st period */
		map->min_pn_seen = pn;
		map->last_max_pn_seen = pn;
	}

	if (map->cum_ack_point + 1 != pn) {
		set_bit(gap, map->pn_map);
		goto out;
	}

	map->cum_ack_point++;
	if (!quic_pnmap_has_gap(map) && !gap) {
		map->base_pn++;
		goto out;
	}

	set_bit(gap, map->pn_map);
	zero_bit = find_first_zero_bit(map->pn_map, map->max_pn_seen - map->base_pn + 1);
	map->base_pn += zero_bit;
	map->cum_ack_point = map->base_pn - 1;
	bitmap_shift_right(map->pn_map, map->pn_map, zero_bit, map->len);
out:
	quic_pnmap_update(map, pn);
	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnmap_mark);

struct quic_pnmap_iter {
	s64 start;
};

static int quic_pnmap_next_gap_ack(const struct quic_pnmap *map, struct quic_pnmap_iter *iter,
				   u16 *start, u16 *end)
{
	u16 start_ = 0, end_ = 0, offset;

	offset = iter->start - map->base_pn;

	start_ = find_next_zero_bit(map->pn_map, map->len, offset);
	if (map->max_pn_seen <= map->base_pn + start_)
		return 0;

	end_ = find_next_bit(map->pn_map, map->len, start_);
	if (map->max_pn_seen <= map->base_pn + end_ - 1)
		return 0;

	*start = start_ + 1;
	*end = end_;
	iter->start = map->base_pn + *end;
	return 1;
}

static void quic_pnmap_update(struct quic_pnmap *map, s64 pn)
{
	u32 current_ts = jiffies_to_usecs(jiffies);
	u16 zero_bit, offset;

	if (current_ts - map->last_max_pn_ts < map->max_record_ts &&
	    map->max_pn_seen <= map->last_max_pn_seen + QUIC_PN_MAP_SIZE / 2 &&
	    map->max_pn_seen <= map->base_pn + QUIC_PN_MAP_SIZE * 3 / 4)
		return;

	if (map->last_max_pn_seen + 1 <= map->base_pn)
		goto out;

	offset = map->last_max_pn_seen + 1 - map->base_pn;
	zero_bit = find_next_zero_bit(map->pn_map, map->len, offset);
	map->base_pn += zero_bit;
	map->cum_ack_point = map->base_pn - 1;
	bitmap_shift_right(map->pn_map, map->pn_map, zero_bit, map->len);

out:
	map->min_pn_seen = map->last_max_pn_seen;
	map->last_max_pn_ts = current_ts;
	map->last_max_pn_seen = map->max_pn_seen;
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

u16 quic_pnmap_num_gabs(struct quic_pnmap *map, struct quic_gap_ack_block *gabs)
{
	struct quic_pnmap_iter iter;
	u16 start, end, ngaps = 0;

	if (!quic_pnmap_has_gap(map))
		return 0;

	iter.start = map->cum_ack_point + 1;
	if (!iter.start)
		iter.start = map->min_pn_seen + 1;

	while (quic_pnmap_next_gap_ack(map, &iter, &start, &end)) {
		gabs[ngaps].start = start;
		gabs[ngaps].end = end;
		ngaps++;
		if (ngaps >= QUIC_PN_MAX_GABS)
			break;
	}
	return ngaps;
}
EXPORT_SYMBOL_GPL(quic_pnmap_num_gabs);
