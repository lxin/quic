/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_RTT_INIT		333000U
#define QUIC_RTO_MIN		100000U
#define QUIC_RTO_MAX		6000000U

enum quic_cong_state {
	QUIC_CONG_SLOW_START,
	QUIC_CONG_RECOVERY_PERIOD,
	QUIC_CONG_CONGESTION_AVOIDANCE,
};

struct quic_cong {
	u32 smoothed_rtt;
	u32 latest_rtt;
	u32 min_rtt;
	u32 rttvar;
	u32 pto;

	u32 recovery_time;
	u32 max_ack_delay;
	u32 pacing_rate;
	u64 pacing_time; /* planned time to send next packet */
	u32 time; /* current time cache */

	u32 max_window;
	u32 min_window;
	u32 ssthresh;
	u32 window;
	u32 mss;

	struct quic_cong_ops *ops;
	u64 priv[8];

	u8 min_rtt_valid;
	u8 state;
};

struct quic_cong_ops {
	/* required */
	void (*on_packet_acked)(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
	void (*on_packet_lost)(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
	void (*on_process_ecn)(struct quic_cong *cong);
	void (*on_init)(struct quic_cong *cong);

	/* optional */
	void (*on_packet_sent)(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
	void (*on_ack_recv)(struct quic_cong *cong, u32 bytes, u32 max_rate);
	void (*on_rtt_update)(struct quic_cong *cong);
};

static inline void quic_cong_set_time(struct quic_cong *cong, u32 time)
{
	cong->time = time;
}

static inline void quic_cong_set_mss(struct quic_cong *cong, u32 mss)
{
	if (cong->mss == mss)
		return;

	cong->mss = mss;
	cong->min_window = max(min(mss * 10, 14720U), mss * 2);

	if (cong->window < cong->min_window)
		cong->window = cong->min_window;
}

static inline void *quic_cong_priv(struct quic_cong *cong)
{
	return (void *)cong->priv;
}

static inline u32 quic_cong_time(struct quic_cong *cong)
{
	return cong->time;
}

static inline u32 quic_cong_window(struct quic_cong *cong)
{
	return cong->window;
}

static inline u32 quic_cong_pto(struct quic_cong *cong)
{
	return cong->pto;
}

static inline u32 quic_cong_latest_rtt(struct quic_cong *cong)
{
	return cong->latest_rtt;
}

static inline u64 quic_cong_pacing_time(struct quic_cong *cong)
{
	return cong->pacing_time;
}

void quic_cong_set_param(struct quic_cong *cong, struct quic_transport_param *p);
void quic_cong_set_config(struct quic_cong *cong, struct quic_config *c);

void quic_cong_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
void quic_cong_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
void quic_cong_on_process_ecn(struct quic_cong *cong);

void quic_cong_on_packet_sent(struct quic_cong *cong, u32 time, u32 bytes, s64 number);
void quic_cong_on_ack_recv(struct quic_cong *cong, u32 bytes, u32 max_rate);
void quic_cong_rtt_update(struct quic_cong *cong, u32 time, u32 ack_delay);
