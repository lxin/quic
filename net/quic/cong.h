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
	u32 smoothed_rtt;
};

void quic_cong_set_param(struct sock *sk, struct quic_transport_param *p, u8 send);
void quic_cong_get_param(struct sock *sk, struct quic_transport_param *p, u8 send);
void quic_cong_rtt_update(struct sock *sk, u32 transmit_ts, u32 ack_delay);
