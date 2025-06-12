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
#define QUIC_PN_MAP_MAX_PN	(BIT_ULL(62) - 1)

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
	QUIC_ECN_LOCAL,		/* ECN bits from incoming IP headers */
	QUIC_ECN_PEER,		/* ECN bits reported by peer in ACK frames */
	QUIC_ECN_DIR_MAX
};

/* Represents a gap (range of missing packets) in the ACK map.  The values are offsets from
 * base_pn, with both 'start' and 'end' being +1.
 */
struct quic_gap_ack_block {
	u16 start;
	u16 end;
};

/* Packet Number Map (pn_map) Layout:
 *
 *     min_pn_seen -->++-----------------------+---------------------+---
 *         base_pn -----^   last_max_pn_seen --^       max_pn_seen --^
 *
 * Map Advancement Logic:
 *   - min_pn_seen = last_max_pn_seen;
 *   - base_pn = first zero bit after last_max_pn_seen;
 *   - last_max_pn_seen = max_pn_seen;
 *   - last_max_pn_time = current time;
 *
 * Conditions to Advance pn_map:
 *   - (max_pn_time - last_max_pn_time) >= max_time_limit, or
 *   - (max_pn_seen - last_max_pn_seen) > QUIC_PN_MAP_LIMIT
 *
 * Gap Search Range:
 *   - From (base_pn - 1) to max_pn_seen
 */
struct quic_pnspace {
	/* ECN counters indexed by direction (TX/RX) and ECN codepoint (ECT1, ECT0, CE) */
	u64 ecn_count[QUIC_ECN_DIR_MAX][QUIC_ECN_MAX];
	unsigned long *pn_map;	/* Bit map tracking received packet numbers for ACK generation */
	u16 pn_map_len;		/* Length of the packet number bit map (in bits) */
	u8  need_sack:1;	/* Flag indicating a SACK frame should be sent for this space */
	u8  sack_path:1;	/* Path used for sending the SACK frame */

	s64 last_max_pn_seen;	/* Highest packet number seen before pn_map advanced */
	u32 last_max_pn_time;	/* Timestamp when last_max_pn_seen was received */
	u32 max_time_limit;	/* Time threshold to trigger pn_map advancement on packet receipt */
	s64 min_pn_seen;	/* Smallest packet number received in this space */
	s64 max_pn_seen;	/* Largest packet number received in this space */
	u32 max_pn_time;	/* Time at which max_pn_seen was received */
	s64 base_pn;		/* Packet number corresponding to the start of the pn_map */
	u32 time;		/* Cached current time, or time accept a socket (listen socket) */

	s64 max_pn_acked_seen;	/* Largest packet number acknowledged by the peer */
	u32 max_pn_acked_time;	/* Time at which max_pn_acked_seen was acknowledged */
	u32 last_sent_time;	/* Time when the last ack-eliciting packet was sent */
	u32 loss_time;		/* Time after which the next packet can be declared lost */
	u32 inflight;		/* Bytes of all ack-eliciting frames in flight in this space */
	s64 next_pn;		/* Next packet number to send in this space */
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
	space->last_max_pn_seen = space->max_pn_seen;
	space->min_pn_seen = space->max_pn_seen;

	space->max_pn_time = space->time;
	space->last_max_pn_time = space->max_pn_time;
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

/* Check if any ECN-marked packets were received. */
static inline bool quic_pnspace_has_ecn_count(struct quic_pnspace *space)
{
	return space->ecn_count[QUIC_ECN_LOCAL][QUIC_ECN_ECT0] ||
	       space->ecn_count[QUIC_ECN_LOCAL][QUIC_ECN_ECT1] ||
	       space->ecn_count[QUIC_ECN_LOCAL][QUIC_ECN_CE];
}

/* Updates the stored ECN counters based on values received in the peer's ACK
 * frame. Each counter is updated only if the new value is higher.
 *
 * Returns: 1 if CE count was increased (congestion indicated), 0 otherwise.
 */
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

u16 quic_pnspace_num_gabs(struct quic_pnspace *space, struct quic_gap_ack_block *gabs);
int quic_pnspace_check(struct quic_pnspace *space, s64 pn);
int quic_pnspace_mark(struct quic_pnspace *space, s64 pn);

void quic_pnspace_free(struct quic_pnspace *space);
int quic_pnspace_init(struct quic_pnspace *space);
