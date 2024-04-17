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

#include <uapi/linux/quic.h>
#include "cong.h"

static void quic_reno_cwnd_update_after_timeout(struct quic_cong *cong, s64 number,
						u32 transmit_ts, s64 last_number)
{
	u32 time_threshold;

	if (number + 3 <= cong->max_acked_number) { /* packet loss check */
		time_threshold = 9 * max(cong->smoothed_rtt, cong->latest_rtt) / 8;
		time_threshold = max(time_threshold, 1000U);
		if (jiffies_to_usecs(jiffies) - transmit_ts <= time_threshold)
			return;

		/* persistent congestion check */
		time_threshold = cong->smoothed_rtt + max(4 * cong->rttvar, 1000U);
		time_threshold = (time_threshold + cong->max_ack_delay) * 3;
		if (jiffies_to_usecs(jiffies) - cong->max_acked_transmit_ts > time_threshold) {
			pr_debug("[QUIC] %s permanent congestion, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
			cong->window = cong->mss * 2;
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

	cong->last_sent_number = last_number;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->threshold = max(cong->window >> 1U, cong->mss * 2);
	cong->window = cong->threshold;
}

static void quic_reno_cwnd_update_after_sack(struct quic_cong *cong, s64 acked_number,
					     u32 transmit_ts, u32 acked_bytes, u32 inflight)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cong->window = min_t(u32, cong->window + acked_bytes, cong->max_window);
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
			cong->window += cong->mss * acked_bytes / cong->window;
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
}

static void quic_reno_cwnd_update_after_ecn(struct quic_cong *cong)
{
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

	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->threshold = max(cong->window >> 1U, cong->mss * 2);
	cong->window = cong->threshold;
}

static struct quic_cong_ops quic_congs[] = {
	{ /* QUIC_CONG_ALG_RENO */
		.cwnd_update_after_sack = quic_reno_cwnd_update_after_sack,
		.cwnd_update_after_timeout = quic_reno_cwnd_update_after_timeout,
		.cwnd_update_after_ecn = quic_reno_cwnd_update_after_ecn,
	},
};

void quic_cong_cwnd_update_after_timeout(struct quic_cong *cong, s64 number, u32 transmit_ts,
					 s64 last_number)
{
	cong->ops->cwnd_update_after_timeout(cong, number, transmit_ts,
						  last_number);
}
EXPORT_SYMBOL_GPL(quic_cong_cwnd_update_after_timeout);

void quic_cong_cwnd_update_after_sack(struct quic_cong *cong, s64 acked_number, u32 transmit_ts,
				      u32 acked_bytes, u32 inflight)
{
	cong->ops->cwnd_update_after_sack(cong, acked_number, transmit_ts,
					       acked_bytes, inflight);
}
EXPORT_SYMBOL_GPL(quic_cong_cwnd_update_after_sack);

void quic_cong_cwnd_update_after_ecn(struct quic_cong *cong)
{
	cong->ops->cwnd_update_after_ecn(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_cwnd_update_after_ecn);

static void quic_cong_rto_update(struct quic_cong *cong)
{
	u32 rto, duration;

	rto = cong->smoothed_rtt + cong->rttvar;

	if (rto < QUIC_RTO_MIN)
		rto = QUIC_RTO_MIN;
	else if (rto > QUIC_RTO_MAX)
		rto = QUIC_RTO_MAX;
	cong->rto = rto;

	duration = cong->rttvar * 4;
	if (duration < QUIC_RTO_MIN)
		duration = QUIC_RTO_MIN;
	duration += cong->smoothed_rtt;
	cong->duration = duration;

	pr_debug("[QUIC] update rto %u duration %u\n", rto, duration);
}

void quic_cong_set_param(struct quic_cong *cong, struct quic_transport_param *p)
{
	u8 alg = QUIC_CONG_ALG_RENO;

	if (p->congestion_control_alg < QUIC_CONG_ALG_MAX)
		alg = p->congestion_control_alg;

	cong->max_window = p->max_data;
	cong->max_ack_delay = p->max_ack_delay;
	cong->ack_delay_exponent = p->ack_delay_exponent;
	cong->latest_rtt = p->initial_smoothed_rtt;
	cong->smoothed_rtt = cong->latest_rtt;
	cong->rttvar = cong->smoothed_rtt / 2;
	quic_cong_rto_update(cong);

	cong->state = QUIC_CONG_SLOW_START;
	cong->threshold = U32_MAX;
	cong->ops = &quic_congs[alg];
}
EXPORT_SYMBOL_GPL(quic_cong_set_param);

/* Estimating the Round-Trip Time */
void quic_cong_rtt_update(struct quic_cong *cong, u32 transmit_ts, u32 ack_delay)
{
	u32 adjusted_rtt, rttvar_sample;

	ack_delay = ack_delay * BIT(cong->ack_delay_exponent);
	ack_delay = min(ack_delay, cong->max_ack_delay);

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
	quic_cong_rto_update(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_rtt_update);
