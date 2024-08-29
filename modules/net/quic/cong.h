/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_RTT_INIT		333000
#define QUIC_RTO_MIN		100000
#define QUIC_RTO_MAX		6000000

enum quic_cong_state {
	QUIC_CONG_SLOW_START,
	QUIC_CONG_RECOVERY_PERIOD,
	QUIC_CONG_CONGESTION_AVOIDANCE,
};

struct quic_cong {
	u32 smoothed_rtt;
	u32 latest_rtt;
	u32 duration;
	u32 min_rtt;
	u32 rttvar;
	u32 rto;

	u32 ack_delay_exponent;
	u32 recovery_time;
	u32 max_ack_delay;
	u32 pacing_rate;
	u64 pacing_time; /* planned time to send next packet */
	u32 time; /* current time cache */

	u32 max_window;
	u32 ssthresh;
	u32 window;
	u32 mss;

	struct quic_cong_ops *ops;
	u64 priv[8];
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

static inline void quic_cong_set_window(struct quic_cong *cong, u32 window)
{
	cong->window = window;
}

static inline void quic_cong_set_mss(struct quic_cong *cong, u32 mss)
{
	cong->mss = mss;
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

static inline u32 quic_cong_rto(struct quic_cong *cong)
{
	return cong->rto;
}

static inline u32 quic_cong_duration(struct quic_cong *cong)
{
	return cong->duration;
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
