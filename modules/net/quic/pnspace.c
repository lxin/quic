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

#include "common.h"
#include "pnspace.h"

int quic_pnspace_init(struct quic_pnspace *space)
{
	if (!space->pn_map) {
		space->pn_map = kzalloc(BITS_TO_BYTES(QUIC_PN_MAP_INITIAL), GFP_KERNEL);
		if (!space->pn_map)
			return -ENOMEM;
		space->pn_map_len = QUIC_PN_MAP_INITIAL;
	} else {
		bitmap_zero(space->pn_map, space->pn_map_len);
	}

	space->max_time_limit = QUIC_PNSPACE_TIME_LIMIT;
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

/* Expand the bitmap tracking received packet numbers.  Ensures the pn_map bitmap can
 * cover at least @size packet numbers.  Allocates a larger bitmap, copies existing
 * data, and updates metadata.
 *
 * Returns: 1 if the bitmap was successfully grown, 0 on failure or if the requested
 * size exceeds QUIC_PN_MAP_SIZE.
 */
static int quic_pnspace_grow(struct quic_pnspace *space, u16 size)
{
	u16 len, inc, offset;
	unsigned long *new;

	if (size > QUIC_PN_MAP_SIZE)
		return 0;

	inc = ALIGN((size - space->pn_map_len), BITS_PER_LONG) + QUIC_PN_MAP_INCREMENT;
	len = (u16)min(space->pn_map_len + inc, QUIC_PN_MAP_SIZE);

	new = kzalloc(BITS_TO_BYTES(len), GFP_ATOMIC);
	if (!new)
		return 0;

	offset = (u16)(space->max_pn_seen + 1 - space->base_pn);
	bitmap_copy(new, space->pn_map, offset);
	kfree(space->pn_map);
	space->pn_map = new;
	space->pn_map_len = len;

	return 1;
}

/* Check if a packet number has been received.
 *
 * Returns: 0 if the packet number has not been received.  1 if it has already
 * been received.  -1 if the packet number is too old or too far in the future
 * to track.
 */
int quic_pnspace_check(struct quic_pnspace *space, s64 pn)
{
	if (space->base_pn == -1) /* No packet number received yet. */
		return 0;

	if (pn < space->min_pn_seen || pn >= space->base_pn + QUIC_PN_MAP_SIZE)
		return -1;

	if (pn < space->base_pn || (pn - space->base_pn < space->pn_map_len &&
				    test_bit(pn - space->base_pn, space->pn_map)))
		return 1;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnspace_check);

/* Advance base_pn past contiguous received packet numbers.  Finds the next gap
 * (unreceived packet) beyond @pn, shifts the bitmap, and updates base_pn
 * accordingly.
 */
static void quic_pnspace_move(struct quic_pnspace *space, s64 pn)
{
	u16 offset;

	offset = (u16)(pn + 1 - space->base_pn);
	offset = (u16)find_next_zero_bit(space->pn_map, space->pn_map_len, offset);
	space->base_pn += offset;
	bitmap_shift_right(space->pn_map, space->pn_map, offset, space->pn_map_len);
}

/* Mark a packet number as received. Updates the packet number map to record
 * reception of @pn.  Advances base_pn if possible, and updates max/min/last seen
 * fields as needed.
 *
 * Returns: 0 on success or if the packet was already marked.  -ENOMEM if bitmap
 * allocation failed during growth.
 */
int quic_pnspace_mark(struct quic_pnspace *space, s64 pn)
{
	s64 last_max_pn_seen;
	u16 gap;

	if (space->base_pn == -1) {
		/* Initialize base_pn based on the peer's first packet number since peer's
		 * packet numbers may start at a non-zero value.
		 */
		quic_pnspace_set_base_pn(space, pn + 1);
		return 0;
	}

	/* Ignore packets with number less than current base (already processed). */
	if (pn < space->base_pn)
		return 0;

	/* If gap is beyond current map length, try to grow the bitmap to accommodate. */
	gap = (u16)(pn - space->base_pn);
	if (gap >= space->pn_map_len && !quic_pnspace_grow(space, gap + 1))
		return -ENOMEM;

	if (space->max_pn_seen < pn) {
		space->max_pn_seen = pn;
		space->max_pn_time = space->time;
	}

	if (space->base_pn == pn) { /* If packet is exactly at base_pn (next expected packet). */
		if (quic_pnspace_has_gap(space)) /* Advance base_pn to next unacked packet. */
			quic_pnspace_move(space, pn);
		else /* Fast path: increment base_pn if no gaps. */
			space->base_pn++;
	} else { /* Mark this packet as received in the bitmap. */
		set_bit(gap, space->pn_map);
	}

	/* Only update min and last_max_pn_seen if this packet is the current max_pn. */
	if (space->max_pn_seen != pn)
		return 0;

	/* Check if enough time has elapsed or enough packets have been received to
	 * update tracking.
	 */
	last_max_pn_seen = min_t(s64, space->last_max_pn_seen, space->base_pn);
	if (space->max_pn_time < space->last_max_pn_time + space->max_time_limit &&
	    space->max_pn_seen <= last_max_pn_seen + QUIC_PN_MAP_LIMIT)
		return 0;

	/* Advance base_pn if last_max_pn_seen is ahead of current base_pn. This is
	 * needed because QUIC doesn't retransmit packets; retransmitted frames are
	 * carried in new packets, so we move forward.
	 */
	if (space->last_max_pn_seen + 1 > space->base_pn)
		quic_pnspace_move(space, space->last_max_pn_seen);

	space->min_pn_seen = space->last_max_pn_seen;
	space->last_max_pn_seen = space->max_pn_seen;
	space->last_max_pn_time = space->max_pn_time;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_pnspace_mark);

/* Find the next gap in received packet numbers. Scans pn_map for a gap starting from
 * *@iter. A gap is a contiguous block of unreceived packets between received ones.
 *
 * Returns: 1 if a gap was found, 0 if no more gaps exist or are relevant.
 */
static int quic_pnspace_next_gap_ack(const struct quic_pnspace *space,
				     s64 *iter, u16 *start, u16 *end)
{
	u16 start_ = 0, end_ = 0, offset = (u16)(*iter - space->base_pn);

	start_ = (u16)find_next_zero_bit(space->pn_map, space->pn_map_len, offset);
	if (space->max_pn_seen <= space->base_pn + start_)
		return 0;

	end_ = (u16)find_next_bit(space->pn_map, space->pn_map_len, start_);
	if (space->max_pn_seen <= space->base_pn + end_ - 1)
		return 0;

	*start = start_ + 1;
	*end = end_;
	*iter = space->base_pn + *end;
	return 1;
}

/* Generate gap acknowledgment blocks (GABs).  GABs describe ranges of unacknowledged
 * packets between received ones, and are used in ACK frames.
 *
 * Returns: Number of generated GABs (up to QUIC_PN_MAP_MAX_GABS).
 */
u16 quic_pnspace_num_gabs(struct quic_pnspace *space, struct quic_gap_ack_block *gabs)
{
	u16 start, end, ngaps = 0;
	s64 iter;

	if (!quic_pnspace_has_gap(space))
		return 0;

	iter = space->base_pn;
	/* Loop through all gaps until the end of the window or max allowed gaps. */
	while (quic_pnspace_next_gap_ack(space, &iter, &start, &end)) {
		gabs[ngaps].start = start;
		if (ngaps == QUIC_PN_MAP_MAX_GABS - 1) {
			gabs[ngaps].end = (u16)(space->max_pn_seen - space->base_pn);
			ngaps++;
			break;
		}
		gabs[ngaps].end = end;
		ngaps++;
	}
	return ngaps;
}
EXPORT_SYMBOL_GPL(quic_pnspace_num_gabs);
