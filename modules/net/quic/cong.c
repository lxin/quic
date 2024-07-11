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
#include <linux/jiffies.h>
#include <net/sock.h>

#include "cong.h"

static void quic_reno_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes)
{
	u32 time_threshold;

	time_threshold = cong->smoothed_rtt + max(4 * cong->rttvar, 1000U);
	time_threshold = (time_threshold + cong->max_ack_delay) * 3;
	if (jiffies_to_usecs(jiffies) - time > time_threshold) {
		/* persistent congestion: cong_avoid -> slow_start or recovery -> slow_start */
		pr_debug("[QUIC] %s permanent congestion, cwnd: %u threshold: %u\n",
			 __func__, cong->window, cong->threshold);
		cong->window = cong->mss * 2;
		cong->state = QUIC_CONG_SLOW_START;
		return;
	}

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
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

	cong->recovery_time = jiffies_to_usecs(jiffies);
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->threshold = max(cong->window >> 1U, cong->mss * 2);
	cong->window = cong->threshold;
}

static void quic_reno_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cong->window = min_t(u32, cong->window + bytes, cong->max_window);
		if (cong->window > cong->threshold) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("[QUIC] %s slow_start -> cong_avoid, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
		}
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		if (cong->recovery_time < time) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("[QUIC] %s recovery -> cong_avoid, cwnd: %u threshold: %u\n",
				 __func__, cong->window, cong->threshold);
		}
		break;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		cong->window += cong->mss * bytes / cong->window;
		break;
	default:
		pr_warn_once("[QUIC] %s wrong congestion state: %d", __func__, cong->state);
		return;
	}
}

static void quic_reno_on_process_ecn(struct quic_cong *cong)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
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

	cong->recovery_time = jiffies_to_usecs(jiffies);
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->threshold = max(cong->window >> 1U, cong->mss * 2);
	cong->window = cong->threshold;
}

static struct quic_cong_ops quic_congs[] = {
	{ /* QUIC_CONG_ALG_RENO */
		.on_packet_acked = quic_reno_on_packet_acked,
		.on_packet_lost = quic_reno_on_packet_lost,
		.on_process_ecn = quic_reno_on_process_ecn,
	},
};

void quic_cong_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes)
{
	cong->ops->on_packet_lost(cong, time, bytes);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_lost);

void quic_cong_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes)
{
	cong->ops->on_packet_acked(cong, time, bytes);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_acked);

void quic_cong_on_process_ecn(struct quic_cong *cong)
{
	cong->ops->on_process_ecn(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_on_process_ecn);

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
void quic_cong_rtt_update(struct quic_cong *cong, u32 time, u32 ack_delay)
{
	u32 adjusted_rtt, rttvar_sample;

	ack_delay = ack_delay * BIT(cong->ack_delay_exponent);
	ack_delay = min(ack_delay, cong->max_ack_delay);

	cong->latest_rtt = jiffies_to_usecs(jiffies) - time;

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

void quic_cong_pace_update(struct quic_cong *cong, u32 bytes, struct sock *sk)
{
	u64 rate;

	if (!bytes)
		return;

	/* rate = N * congestion_window / smoothed_rtt */
	rate = 2 * cong->window * USEC_PER_SEC;
	if (likely(cong->smoothed_rtt))
		do_div(rate, cong->smoothed_rtt);

	WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate)));
	pr_debug("[QUIC] update pacing rate %lu max rate %lu srtt %u\n", sk->sk_pacing_rate,
		 sk->sk_max_pacing_rate, cong->smoothed_rtt);
}
EXPORT_SYMBOL_GPL(quic_cong_pace_update);
