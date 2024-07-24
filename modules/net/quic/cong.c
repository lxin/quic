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

static void quic_reno_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	u32 time_ssthresh;

	time_ssthresh = cong->smoothed_rtt + max(4 * cong->rttvar, 1000U);
	time_ssthresh = (time_ssthresh + cong->max_ack_delay) * 3;
	if (cong->time - time > time_ssthresh) {
		/* persistent congestion: cong_avoid -> slow_start or recovery -> slow_start */
		pr_debug("[QUIC] %s permanent congestion, cwnd: %u ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		cong->window = cong->mss * 2;
		cong->state = QUIC_CONG_SLOW_START;
		return;
	}

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		pr_debug("[QUIC] %s slow_start -> recovery, cwnd: %u ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("[QUIC] %s cong_avoid -> recovery, cwnd: %u ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_warn_once("[QUIC] %s wrong congestion state: %d", __func__, cong->state);
		return;
	}

	cong->recovery_time = cong->time;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->ssthresh = max(cong->window >> 1U, cong->mss * 2);
	cong->window = cong->ssthresh;
}

static void quic_reno_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cong->window = min_t(u32, cong->window + bytes, cong->max_window);
		if (cong->window >= cong->ssthresh) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("[QUIC] %s slow_start -> cong_avoid, cwnd: %u ssthresh: %u\n",
				 __func__, cong->window, cong->ssthresh);
		}
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		if (cong->recovery_time < time) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("[QUIC] %s recovery -> cong_avoid, cwnd: %u ssthresh: %u\n",
				 __func__, cong->window, cong->ssthresh);
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
		pr_debug("[QUIC] %s slow_start -> recovery, cwnd: %u ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("[QUIC] %s cong_avoid -> recovery, cwnd: %u ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_warn_once("[QUIC] %s wrong congestion state: %d", __func__, cong->state);
		return;
	}

	cong->recovery_time = cong->time;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->ssthresh = max(cong->window >> 1U, cong->mss * 2);
	cong->window = cong->ssthresh;
}

static struct quic_cong_ops quic_congs[] = {
	{ /* QUIC_CONG_ALG_RENO */
		.on_packet_acked = quic_reno_on_packet_acked,
		.on_packet_lost = quic_reno_on_packet_lost,
		.on_process_ecn = quic_reno_on_process_ecn,
	},
};

void quic_cong_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	cong->ops->on_packet_lost(cong, time, bytes, number);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_lost);

void quic_cong_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	cong->ops->on_packet_acked(cong, time, bytes, number);
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
	cong->ssthresh = U32_MAX;
	cong->ops = &quic_congs[alg];
}
EXPORT_SYMBOL_GPL(quic_cong_set_param);

static void quic_cong_update_pacing_time(struct quic_cong *cong, u16 bytes)
{
	unsigned long rate = READ_ONCE(cong->pacing_rate);
	u64 prior_time, credit, len_ns;

	if (!rate)
		return;

	prior_time = cong->pacing_time;
	cong->pacing_time = max(cong->pacing_time, ktime_get_ns());
	credit = cong->pacing_time - prior_time;

	/* take into account OS jitter */
	len_ns = div64_ul((u64)bytes * NSEC_PER_SEC, rate);
	len_ns -= min_t(u64, len_ns / 2, credit);
	cong->pacing_time += len_ns;
}

static void quic_cong_pace_update(struct quic_cong *cong, u32 bytes, u32 max_rate)
{
	u64 rate;

	/* rate = N * congestion_window / smoothed_rtt */
	rate = 2 * cong->window * USEC_PER_SEC;
	if (likely(cong->smoothed_rtt))
		do_div(rate, cong->smoothed_rtt);

	WRITE_ONCE(cong->pacing_rate, min_t(u64, rate, max_rate));
	pr_debug("[QUIC] update pacing rate %u max rate %u srtt %u\n",
		 cong->pacing_rate, max_rate, cong->smoothed_rtt);
}

void quic_cong_on_packet_sent(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	if (!bytes)
		return;
	if (cong->ops->on_packet_sent)
		cong->ops->on_packet_sent(cong, time, bytes, number);
	quic_cong_update_pacing_time(cong, bytes);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_sent);

void quic_cong_on_ack_recv(struct quic_cong *cong, u32 bytes, u32 max_rate)
{
	if (!bytes)
		return;
	if (cong->ops->on_ack_recv)
		cong->ops->on_ack_recv(cong, bytes, max_rate);
	quic_cong_pace_update(cong, bytes, max_rate);
}
EXPORT_SYMBOL_GPL(quic_cong_on_ack_recv);

/* Estimating the Round-Trip Time */
void quic_cong_rtt_update(struct quic_cong *cong, u32 time, u32 ack_delay)
{
	u32 adjusted_rtt, rttvar_sample;

	ack_delay = ack_delay * BIT(cong->ack_delay_exponent);
	ack_delay = min(ack_delay, cong->max_ack_delay);

	cong->latest_rtt = cong->time - time;

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

	if (cong->ops->on_rtt_update)
		cong->ops->on_rtt_update(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_rtt_update);
