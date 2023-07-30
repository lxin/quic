/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
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

struct quic_cong_ops {
	void (*quic_cwnd_update_after_timeout)(struct sock *sk, u32 packet_number, u32 transmit_ts);
	void (*quic_cwnd_update_after_sack)(struct sock *sk, u32 acked_number, u32 transmit_ts,
					    u32 acked_bytes);
};

struct quic_cong {
	struct {
		u32 ack_delay_exponent;
		u32 max_ack_delay;
	} send;
	struct {
		u32 ack_delay_exponent;
		u32 max_ack_delay;
	} recv;

	u32 rto;
	u32 rttvar;
	u32 min_rtt;
	u32 latest_rtt;
	u32 smoothed_rtt;

	u32 last_sent_number;
	u32 max_acked_number;
	u32 max_acked_transmit_ts;
	u32 window;
	u32 prior_window;
	u32 threshold;
	u32 prior_threshold;

	u8 state;
	struct quic_cong_ops *ops;
};

void quic_cong_set_param(struct sock *sk, struct quic_transport_param *p, u8 send);
void quic_cong_get_param(struct sock *sk, struct quic_transport_param *p, u8 send);
void quic_cong_rtt_update(struct sock *sk, u32 transmit_ts, u32 ack_delay);
int quic_cong_set_cong_alg(struct sock *sk, u8 *alg, unsigned int len);
void quic_cong_cwnd_update(struct sock *sk, u32 window);
void quic_cong_cwnd_update_after_timeout(struct sock *sk, u32 packet_number, u32 transmit_ts);
void quic_cong_cwnd_update_after_sack(struct sock *sk, u32 acked_number, u32 transmit_ts,
				      u32 acked_bytes);
