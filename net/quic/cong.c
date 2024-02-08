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

static void quic_reno_cwnd_update_after_timeout(struct sock *sk, s64 packet_number, u32 transmit_ts)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_cong *cong = quic_cong(sk);
	u32 time_threshold;

	if (packet_number + 3 <= cong->max_acked_number) { /* packet loss check */
		time_threshold = 9 * max(cong->smoothed_rtt, cong->latest_rtt) / 8;
		time_threshold = max(time_threshold, 1000U);
		if (jiffies_to_usecs(jiffies) - transmit_ts <= time_threshold)
			return;

		/* persistent congestion check */
		time_threshold = cong->smoothed_rtt + max(4 * cong->rttvar, 1000U);
		time_threshold = (time_threshold + quic_inq_max_ack_delay(quic_inq(sk))) * 3;
		if (jiffies_to_usecs(jiffies) - cong->max_acked_transmit_ts > time_threshold) {
			pr_debug("[QUIC] %s permanent congestion, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
			cong->window = quic_packet_mss(packet) * 2;
			cong->state = QUIC_CONG_SLOW_START;
		}
	}

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cong->prior_window = cong->window;
		cong->prior_threshold = cong->threshold;
		pr_debug("[QUIC] %s slow_start -> recovery, cwnd: %u threshold: %u\n",
			 __func__, cong->window, cong->threshold);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("[QUIC] %s cong_avoid -> recovery, cwnd: %u threshold: %u\n",
			 __func__, cong->window, cong->threshold);
		break;
	default:
		pr_warn_once("[QUIC] %s wrong congestion state: %d", __func__, cong->state);
		return;
	}

	cong->last_sent_number = quic_pnmap_next_number(quic_pnmap(sk, QUIC_CRYPTO_APP)) - 1;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->threshold = max(cong->window >> 1U, quic_packet_mss(packet) * 2);
	cong->window = cong->threshold;

	quic_outq_set_window(quic_outq(sk), cong->window);
}

static void quic_reno_cwnd_update_after_sack(struct sock *sk, s64 acked_number, u32 transmit_ts,
					     u32 acked_bytes)
{
	u32 inflight = quic_outq_inflight(quic_outq(sk));
	struct quic_cong *cong = quic_cong(sk);

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cong->window = min_t(u32, cong->window + acked_bytes, sk->sk_sndbuf / 2);
		if (cong->window > cong->threshold) {
			cong->prior_window = cong->window;
			cong->prior_threshold = cong->threshold;
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("[QUIC] %s slow_start -> cong_avoid, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
		}
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		if (!inflight) {
			cong->state = QUIC_CONG_SLOW_START;
			if (cong->threshold < cong->prior_threshold)
				cong->threshold = cong->prior_threshold;
			cong->window = max(cong->window, cong->prior_window);
			pr_debug("[QUIC] %s recovery -> slow_start, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
		} else if (cong->last_sent_number < acked_number) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("[QUIC] %s recovery -> cong_avoid, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
		}
		break;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		if (!inflight) {
			cong->state = QUIC_CONG_SLOW_START;
			if (cong->threshold < cong->prior_threshold)
				cong->threshold = cong->prior_threshold;
			cong->window = max(cong->window, cong->prior_window);
			pr_debug("[QUIC] %s cong_avoid -> slow_start, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
		} else {
			cong->window +=
				quic_packet_mss(quic_packet(sk)) * acked_bytes / cong->window;
		}
		break;
	default:
		pr_warn_once("[QUIC] %s wrong congestion state: %d", __func__, cong->state);
		return;
	}

	if (acked_number > cong->max_acked_number) {
		cong->max_acked_number = acked_number;
		cong->max_acked_transmit_ts = transmit_ts;
	}

	quic_outq_set_window(quic_outq(sk), cong->window);
}

static struct quic_cong_ops quic_congs[] = {
	{ /* QUIC_CONG_ALG_RENO */
		.quic_cwnd_update_after_sack = quic_reno_cwnd_update_after_sack,
		.quic_cwnd_update_after_timeout = quic_reno_cwnd_update_after_timeout,
	},
};

void quic_cong_cwnd_update_after_timeout(struct sock *sk, s64 packet_number, u32 transmit_ts)
{
	quic_cong(sk)->ops->quic_cwnd_update_after_timeout(sk, packet_number, transmit_ts);
}

void quic_cong_cwnd_update_after_sack(struct sock *sk, s64 acked_number, u32 transmit_ts,
				      u32 acked_bytes)
{
	quic_cong(sk)->ops->quic_cwnd_update_after_sack(sk, acked_number, transmit_ts,
							acked_bytes);
}

void quic_cong_cwnd_update(struct sock *sk, u32 window)
{
	quic_cong(sk)->window = window;
	quic_outq_set_window(quic_outq(sk), window);
}

static void quic_cong_set_rto(struct sock *sk, u32 rto)
{
	struct quic_cong *cong = quic_cong(sk);

	if (rto < QUIC_RTO_MIN)
		rto = QUIC_RTO_MIN;
	else if (rto > QUIC_RTO_MAX)
		rto = QUIC_RTO_MAX;
	cong->rto = rto;
	quic_pnmap_set_max_record_ts(quic_pnmap(sk, QUIC_CRYPTO_APP), cong->rto * 2);
	quic_crypto_set_key_update_ts(quic_crypto(sk, QUIC_CRYPTO_APP), cong->rto * 2);
	quic_timer_setup(sk, QUIC_TIMER_RTX, cong->rto);
	quic_timer_setup(sk, QUIC_TIMER_PATH, cong->rto * 3);
}

void quic_cong_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_cong *cong = quic_cong(sk);
	u8 alg = QUIC_CONG_ALG_RENO;

	if (p->congestion_control_alg < QUIC_CONG_ALG_MAX)
		alg = p->congestion_control_alg;

	cong->latest_rtt = p->initial_smoothed_rtt;
	cong->smoothed_rtt = cong->latest_rtt;
	cong->rttvar = cong->smoothed_rtt / 2;
	quic_cong_set_rto(sk, cong->smoothed_rtt + cong->rttvar);

	cong->state = QUIC_CONG_SLOW_START;
	cong->threshold = U32_MAX;
	cong->ops = &quic_congs[alg];
}

/* Estimating the Round-Trip Time */
void quic_cong_rtt_update(struct sock *sk, u32 transmit_ts, u32 ack_delay)
{
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_cong *cong = quic_cong(sk);
	u32 adjusted_rtt, rttvar_sample;

	ack_delay = ack_delay * BIT(quic_inq_ack_delay_exponent(inq));
	ack_delay = min(ack_delay, quic_inq_max_ack_delay(inq));

	cong->latest_rtt = jiffies_to_usecs(jiffies) - transmit_ts;

	if (!cong->min_rtt)
		cong->min_rtt = cong->latest_rtt;

	if (cong->min_rtt > cong->latest_rtt)
		cong->min_rtt = cong->latest_rtt;

	adjusted_rtt = cong->latest_rtt;
	if (cong->latest_rtt >= cong->min_rtt + ack_delay)
		adjusted_rtt = cong->latest_rtt - ack_delay;

	cong->smoothed_rtt = (cong->smoothed_rtt * 7 + adjusted_rtt) / 8;
	rttvar_sample = abs(cong->smoothed_rtt - adjusted_rtt);
	cong->rttvar = (cong->rttvar * 3 + rttvar_sample) / 4;

	pr_debug("[QUIC] update rto %u\n", cong->smoothed_rtt + cong->rttvar);
	quic_cong_set_rto(sk, cong->smoothed_rtt + cong->rttvar);
}
