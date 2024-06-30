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

static int quic_pnmap_grow(struct quic_pnmap *map, u16 size)
{
	unsigned long *new;
	unsigned long inc;
	u16 len, offset;

	if (size > QUIC_PN_MAP_SIZE)
		return 0;

	inc = ALIGN((size - map->len), BITS_PER_LONG) + QUIC_PN_MAP_INCREMENT;
	len = min_t(u16, map->len + inc, QUIC_PN_MAP_SIZE);

	new = kzalloc(len >> 3, GFP_ATOMIC);
	if (!new)
		return 0;

	offset = map->max_pn_seen + 1 - map->base_pn;
	bitmap_copy(new, map->pn_map, offset);
	kfree(map->pn_map);
	map->pn_map = new;
	map->len = len;

	return 1;
}

int quic_pnmap_init(struct quic_pnmap *map)
{
	if (!map->pn_map) {
		map->pn_map = kzalloc(QUIC_PN_MAP_INITIAL >> 3, GFP_KERNEL);
		if (!map->pn_map)
			return -ENOMEM;
		map->len = QUIC_PN_MAP_INITIAL;
	} else {
		bitmap_zero(map->pn_map, map->len);
	}

	map->next_pn = QUIC_PN_MAP_BASE_PN;
	map->base_pn = QUIC_PN_MAP_BASE_PN;
	map->max_pn_seen = map->base_pn - 1;
	map->mid_pn_seen = map->max_pn_seen;

	/* set it to a large value so that the 1st packet can update it */
	map->min_pn_seen = QUIC_PN_MAP_MAX_PN;
	map->max_pn_time = jiffies_to_usecs(jiffies);
	map->mid_pn_time = map->max_pn_time;
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

/* move base_pn next to pn */
static void quic_pnmap_move(struct quic_pnmap *map, s64 pn)
{
	u16 offset;

	offset = pn + 1 - map->base_pn;
	offset = find_next_zero_bit(map->pn_map, map->len, offset);
	map->base_pn += offset;
	bitmap_shift_right(map->pn_map, map->pn_map, offset, map->len);
}

int quic_pnmap_mark(struct quic_pnmap *map, s64 pn)
{
	s64 mid_pn_seen;
	u16 gap;

	if (pn < map->base_pn)
		return 0;

	gap = pn - map->base_pn;
	if (gap >= map->len && !quic_pnmap_grow(map, gap + 1))
		return -ENOMEM;

	if (map->max_pn_seen < pn) {
		map->max_pn_seen = pn;
		map->max_pn_time = jiffies_to_usecs(jiffies);
	}

	if (map->min_pn_seen > pn) {
		/* mid_pn_seen should NOT be less than min_pn_seen */
		map->min_pn_seen = pn;
		map->mid_pn_seen = pn;
	}

	if (map->base_pn == pn) {
		if (quic_pnmap_has_gap(map))
			quic_pnmap_move(map, pn);
		else /* fast path */
			map->base_pn++;
	} else {
		set_bit(gap, map->pn_map);
	}

	/* move forward min and mid_pn_seen only when receiving max_pn */
	if (map->max_pn_seen != pn)
		return 0;

	mid_pn_seen = min_t(s64, map->mid_pn_seen, map->base_pn);
	if (map->max_pn_time < map->mid_pn_time + map->max_time_limit &&
	    map->max_pn_seen <= mid_pn_seen + QUIC_PN_MAP_LIMIT)
		return 0;

	if (map->mid_pn_seen + 1 > map->base_pn)
		quic_pnmap_move(map, map->mid_pn_seen);

	map->min_pn_seen = map->mid_pn_seen;
	map->mid_pn_seen = map->max_pn_seen;
	map->mid_pn_time = map->max_pn_time;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnmap_mark);

static int quic_pnmap_next_gap_ack(const struct quic_pnmap *map,
				   s64 *iter, u16 *start, u16 *end)
{
	u16 start_ = 0, end_ = 0, offset = *iter - map->base_pn;

	start_ = find_next_zero_bit(map->pn_map, map->len, offset);
	if (map->max_pn_seen <= map->base_pn + start_)
		return 0;

	end_ = find_next_bit(map->pn_map, map->len, start_);
	if (map->max_pn_seen <= map->base_pn + end_ - 1)
		return 0;

	*start = start_ + 1;
	*end = end_;
	*iter = map->base_pn + *end;
	return 1;
}

u16 quic_pnmap_num_gabs(struct quic_pnmap *map)
{
	struct quic_gap_ack_block *gabs = map->gabs;
	u16 start, end, ngaps = 0;
	s64 iter;

	if (!quic_pnmap_has_gap(map))
		return 0;

	iter = map->base_pn;
	if (!iter) /* use min_pn_seen if base_pn hasn't moved */
		iter = map->min_pn_seen + 1;

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
