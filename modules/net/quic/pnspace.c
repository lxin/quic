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

#include <linux/bitmap.h>
#include <linux/types.h>
#include <linux/slab.h>

#include "pnspace.h"

static int quic_pnspace_grow(struct quic_pnspace *space, u16 size)
{
	unsigned long *new;
	unsigned long inc;
	u16 len, offset;

	if (size > QUIC_PN_MAP_SIZE)
		return 0;

	inc = ALIGN((size - space->pn_map_len), BITS_PER_LONG) + QUIC_PN_MAP_INCREMENT;
	len = min_t(u16, space->pn_map_len + inc, QUIC_PN_MAP_SIZE);

	new = kzalloc(len >> 3, GFP_ATOMIC);
	if (!new)
		return 0;

	offset = space->max_pn_seen + 1 - space->base_pn;
	bitmap_copy(new, space->pn_map, offset);
	kfree(space->pn_map);
	space->pn_map = new;
	space->pn_map_len = len;

	return 1;
}

int quic_pnspace_init(struct quic_pnspace *space)
{
	if (!space->pn_map) {
		space->pn_map = kzalloc(QUIC_PN_MAP_INITIAL >> 3, GFP_KERNEL);
		if (!space->pn_map)
			return -ENOMEM;
		space->pn_map_len = QUIC_PN_MAP_INITIAL;
	} else {
		bitmap_zero(space->pn_map, space->pn_map_len);
	}

	/* set it to a large value so that the 1st packet can update it */
	space->next_pn = QUIC_PNSPACE_NEXT_PN;
	space->base_pn = -1;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnspace_init);

void quic_pnspace_free(struct quic_pnspace *space)
{
	space->pn_map_len = 0;
	kfree(space->pn_map);
}
EXPORT_SYMBOL_GPL(quic_pnspace_free);

int quic_pnspace_check(struct quic_pnspace *space, s64 pn)
{
	if (space->base_pn == -1) {
		quic_pnspace_set_base_pn(space, pn + 1);
		return 0;
	}

	if (pn < space->min_pn_seen || pn >= space->base_pn + QUIC_PN_MAP_SIZE)
		return -1;

	if (pn < space->base_pn || (pn - space->base_pn < space->pn_map_len &&
				    test_bit(pn - space->base_pn, space->pn_map)))
		return 1;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnspace_check);

/* move base_pn next to pn */
static void quic_pnspace_move(struct quic_pnspace *space, s64 pn)
{
	u16 offset;

	offset = pn + 1 - space->base_pn;
	offset = find_next_zero_bit(space->pn_map, space->pn_map_len, offset);
	space->base_pn += offset;
	bitmap_shift_right(space->pn_map, space->pn_map, offset, space->pn_map_len);
}

int quic_pnspace_mark(struct quic_pnspace *space, s64 pn)
{
	s64 mid_pn_seen;
	u16 gap;

	if (pn < space->base_pn)
		return 0;

	gap = pn - space->base_pn;
	if (gap >= space->pn_map_len && !quic_pnspace_grow(space, gap + 1))
		return -ENOMEM;

	if (space->max_pn_seen < pn) {
		space->max_pn_seen = pn;
		space->max_pn_time = jiffies_to_usecs(jiffies);
	}

	if (space->base_pn == pn) {
		if (quic_pnspace_has_gap(space))
			quic_pnspace_move(space, pn);
		else /* fast path */
			space->base_pn++;
	} else {
		set_bit(gap, space->pn_map);
	}

	/* move forward min and mid_pn_seen only when receiving max_pn */
	if (space->max_pn_seen != pn)
		return 0;

	mid_pn_seen = min_t(s64, space->mid_pn_seen, space->base_pn);
	if (space->max_pn_time < space->mid_pn_time + space->max_time_limit &&
	    space->max_pn_seen <= mid_pn_seen + QUIC_PN_MAP_LIMIT)
		return 0;

	if (space->mid_pn_seen + 1 > space->base_pn)
		quic_pnspace_move(space, space->mid_pn_seen);

	space->min_pn_seen = space->mid_pn_seen;
	space->mid_pn_seen = space->max_pn_seen;
	space->mid_pn_time = space->max_pn_time;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnspace_mark);

static int quic_pnspace_next_gap_ack(const struct quic_pnspace *space,
				     s64 *iter, u16 *start, u16 *end)
{
	u16 start_ = 0, end_ = 0, offset = *iter - space->base_pn;

	start_ = find_next_zero_bit(space->pn_map, space->pn_map_len, offset);
	if (space->max_pn_seen <= space->base_pn + start_)
		return 0;

	end_ = find_next_bit(space->pn_map, space->pn_map_len, start_);
	if (space->max_pn_seen <= space->base_pn + end_ - 1)
		return 0;

	*start = start_ + 1;
	*end = end_;
	*iter = space->base_pn + *end;
	return 1;
}

u16 quic_pnspace_num_gabs(struct quic_pnspace *space)
{
	struct quic_gap_ack_block *gabs = space->gabs;
	u16 start, end, ngaps = 0;
	s64 iter;

	if (!quic_pnspace_has_gap(space))
		return 0;

	iter = space->base_pn;
	if (!iter) /* use min_pn_seen if base_pn hasn't moved */
		iter = space->min_pn_seen + 1;

	while (quic_pnspace_next_gap_ack(space, &iter, &start, &end)) {
		gabs[ngaps].start = start;
		gabs[ngaps].end = end;
		ngaps++;
		if (ngaps >= QUIC_PN_MAX_GABS)
			break;
	}
	return ngaps;
}
EXPORT_SYMBOL_GPL(quic_pnspace_num_gabs);
