/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_KPERSISTENT_CONGESTION_THRESHOLD	3
#define QUIC_KPACKET_THRESHOLD			3
#define QUIC_KTIME_THRESHOLD(rtt)		((rtt) * 9 / 8)
#define QUIC_KGRANULARITY			1000U

#define QUIC_RTT_INIT		333000U
#define QUIC_RTT_MAX		2000000U
#define QUIC_RTT_MIN		QUIC_KGRANULARITY

/* rfc9002#section-7.3: Congestion Control States
 *
 *                  New path or      +------------+
 *             persistent congestion |   Slow     |
 *         (O)---------------------->|   Start    |
 *                                   +------------+
 *                                         |
 *                                 Loss or |
 *                         ECN-CE increase |
 *                                         v
 *  +------------+     Loss or       +------------+
 *  | Congestion |  ECN-CE increase  |  Recovery  |
 *  | Avoidance  |------------------>|   Period   |
 *  +------------+                   +------------+
 *            ^                            |
 *            |                            |
 *            +----------------------------+
 *               Acknowledgment of packet
 *                 sent during recovery
 */
enum quic_cong_state {
	QUIC_CONG_SLOW_START,
	QUIC_CONG_RECOVERY_PERIOD,
	QUIC_CONG_CONGESTION_AVOIDANCE,
};

struct quic_cong {
	/* RTT tracking */
	u32 smoothed_rtt;	/* Smoothed RTT */
	u32 latest_rtt;		/* Latest RTT sample */
	u32 min_rtt;		/* Lowest observed RTT */
	u32 rttvar;		/* RTT variation */
	u32 loss_delay;		/* Time before marking loss */
	u32 pto;		/* Probe timeout */

	/* Timing & pacing */
	u32 max_ack_delay;	/* max_ack_delay from rfc9000#section-18.2 */
	u32 recovery_time;	/* Recovery period start */
	u32 pacing_rate;	/* Packet sending speed Bytes/sec */
	u64 pacing_time;	/* Next send time */
	u32 time;		/* Cached time */

	/* Congestion window */
	u32 max_window;		/* Max growth cap */
	u32 min_window;		/* Min window limit */
	u32 ssthresh;		/* Slow start threshold */
	u32 window;		/* Bytes in flight allowed */
	u32 mss;		/* QUIC MSS (excl. UDP) */

	/* Algorithm-specific */
	struct quic_cong_ops *ops;
	u64 priv[8];		/* Algo private data */

	/* Flags & state */
	u8 min_rtt_valid;	/* min_rtt initialized */
	u8 is_rtt_set;		/* RTT samples exist */
	u8 state;		/* State machine in rfc9002#section-7.3 */
};

/* Hooks for congestion control algorithms */
struct quic_cong_ops {
	void (*on_packet_acked)(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
	void (*on_packet_lost)(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
	void (*on_process_ecn)(struct quic_cong *cong);
	void (*on_init)(struct quic_cong *cong);

	/* Optional callbacks */
	void (*on_packet_sent)(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
	void (*on_ack_recv)(struct quic_cong *cong, u32 bytes, u32 max_rate);
	void (*on_rtt_update)(struct quic_cong *cong);
};

static inline void quic_cong_set_mss(struct quic_cong *cong, u32 mss)
{
	if (cong->mss == mss)
		return;

	/* rfc9002#section-7.2: Initial and Minimum Congestion Window */
	cong->mss = mss;
	cong->min_window = max(min(mss * 10, 14720U), mss * 2);

	if (cong->window < cong->min_window)
		cong->window = cong->min_window;
}

static inline void *quic_cong_priv(struct quic_cong *cong)
{
	return (void *)cong->priv;
}

void quic_cong_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
void quic_cong_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
void quic_cong_on_process_ecn(struct quic_cong *cong);

void quic_cong_on_packet_sent(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
void quic_cong_on_ack_recv(struct quic_cong *cong, u32 bytes, u32 max_rate);
void quic_cong_rtt_update(struct quic_cong *cong, u32 time, u32 ack_delay);

void quic_cong_set_srtt(struct quic_cong *cong, u32 srtt);
void quic_cong_set_algo(struct quic_cong *cong, u8 algo);
void quic_cong_init(struct quic_cong *cong);
