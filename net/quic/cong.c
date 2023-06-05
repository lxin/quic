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

#include "socket.h"

static void quic_cong_set_rto(struct sock *sk, u32 rto)
{
	struct quic_cong *cong = &quic_sk(sk)->cong;

	if (rto < QUIC_RTO_MIN)
		rto = QUIC_RTO_MIN;
	else if (rto > QUIC_RTO_MAX)
		rto = QUIC_RTO_MAX;
	cong->rto = rto;
	quic_pnmap_set_max_record_ts(&quic_sk(sk)->pn_map, cong->rto * 2);
	quic_timer_setup(sk, QUIC_TIMER_RTX, cong->rto);
}

void quic_cong_get_param(struct sock *sk, struct quic_transport_param *p, u8 send)
{
	struct quic_cong *cong = &quic_sk(sk)->cong;

	if (!send) {
		p->ack_delay_exponent = cong->recv.ack_delay_exponent;
		p->max_ack_delay = cong->recv.max_ack_delay;
		return;
	}

	p->ack_delay_exponent = cong->send.ack_delay_exponent;
	p->max_ack_delay = cong->send.max_ack_delay;
	p->initial_smoothed_rtt = cong->smoothed_rtt;
}

void quic_cong_set_param(struct sock *sk, struct quic_transport_param *p, u8 send)
{
	struct quic_cong *cong = &quic_sk(sk)->cong;

	if (!send) {
		cong->recv.ack_delay_exponent = p->ack_delay_exponent;
		cong->recv.max_ack_delay = p->max_ack_delay;
		return;
	}

	cong->send.ack_delay_exponent = p->ack_delay_exponent;
	cong->send.max_ack_delay = p->max_ack_delay;
	quic_timer_setup(sk, QUIC_TIMER_ACK, cong->send.max_ack_delay);

	cong->smoothed_rtt = p->initial_smoothed_rtt;
	cong->rttvar = cong->smoothed_rtt / 2;
	quic_cong_set_rto(sk, cong->smoothed_rtt + cong->rttvar);
}

/* Estimating the Round-Trip Time */
void quic_cong_rtt_update(struct sock *sk, u32 transmit_ts, u32 ack_delay)
{
	struct quic_cong *cong = &quic_sk(sk)->cong;
	u32 latest_rtt, adjusted_rtt, rttvar_sample;

	ack_delay = ack_delay * BIT(cong->recv.ack_delay_exponent);
	ack_delay = min(ack_delay, cong->recv.max_ack_delay);

	latest_rtt = jiffies_to_usecs(jiffies) - transmit_ts;

	if (!cong->min_rtt)
		cong->min_rtt = latest_rtt;

	if (cong->min_rtt > latest_rtt)
		cong->min_rtt = latest_rtt;

	adjusted_rtt = latest_rtt;
	if (latest_rtt >= cong->min_rtt + ack_delay)
		adjusted_rtt = latest_rtt - ack_delay;

	cong->smoothed_rtt = (cong->smoothed_rtt * 7 + adjusted_rtt) / 8;
	rttvar_sample = abs(cong->smoothed_rtt - adjusted_rtt);
	cong->rttvar = (cong->rttvar * 3 + rttvar_sample) / 4;

	pr_debug("[QUIC] update rto %u\n", cong->smoothed_rtt + cong->rttvar);
	quic_cong_set_rto(sk, cong->smoothed_rtt + cong->rttvar);
}
