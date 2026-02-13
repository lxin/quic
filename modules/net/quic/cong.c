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

#include <linux/jiffies.h>
#include <linux/quic.h>
#include <net/sock.h>

#include "common.h"
#include "cong.h"

/* CUBIC APIs */
struct quic_cubic {
	/* Variables of Interest in rfc9438#section-4.1.2 */
	u32 pending_w_add;		/* Accumulate fractional increments to W_est */
	u32 origin_point;		/* W_max */
	u32 epoch_start;		/* t_epoch */
	u32 pending_add;		/* Accumulates fractional additions to W_cubic */
	u32 w_last_max;			/* last W_max */
	u32 w_tcp;			/* W_est */
	u64 k;				/* K */

	/* HyStart++ variables in rfc9406#section-4.2 */
	u32 current_round_min_rtt;	/* currentRoundMinRTT */
	u32 css_baseline_min_rtt;	/* cssBaselineMinRtt */
	u32 last_round_min_rtt;		/* lastRoundMinRTT */
	u16 rtt_sample_count;		/* rttSampleCount */
	u16 css_rounds;			/* Counter for consecutive rounds showing RTT increase */
	s64 window_end;			/* End of current CSS round (packet number) */
};

/* HyStart++ constants in rfc9406#section-4.3 */
#define QUIC_HS_MIN_SSTHRESH		16
#define QUIC_HS_N_RTT_SAMPLE		8
#define QUIC_HS_MIN_ETA			4000
#define QUIC_HS_MAX_ETA			16000
#define QUIC_HS_MIN_RTT_DIVISOR		8
#define QUIC_HS_CSS_GROWTH_DIVISOR	4
#define QUIC_HS_CSS_ROUNDS		5

static u64 cubic_root(u64 n)
{
	u64 a, d;

	if (!n)
		return 0;

	d = (64 - __builtin_clzll(n)) / 3;
	a = BIT_ULL(d + 1);

	for (; a * a * a > n;) {
		d = div64_ul(n, a * a);
		a = div64_ul(2 * a + d, 3);
	}
	return a;
}

/* rfc9406#section-4: HyStart++ Algorithm */
static void cubic_slow_start(struct quic_cong *cong, u32 bytes, s64 number)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);
	u32 eta;

	if (cubic->window_end <= number)
		cubic->window_end = -1;

	/* cwnd = cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR) */
	if (cubic->css_baseline_min_rtt != U32_MAX)
		bytes = bytes / QUIC_HS_CSS_GROWTH_DIVISOR;
	cong->window = min_t(u32, cong->window + bytes, cong->max_window);

	if (cubic->css_baseline_min_rtt != U32_MAX) {
		/* If CSS_ROUNDS rounds are complete, enter congestion avoidance. */
		if (++cubic->css_rounds > QUIC_HS_CSS_ROUNDS) {
			cubic->css_baseline_min_rtt = U32_MAX;
			cubic->w_last_max = cong->window;
			cong->ssthresh = cong->window;
			cubic->css_rounds = 0;
		}
		return;
	}

	/* if ((rttSampleCount >= N_RTT_SAMPLE) AND
	 *     (currentRoundMinRTT != infinity) AND
	 *     (lastRoundMinRTT != infinity))
	 *   RttThresh = max(MIN_RTT_THRESH,
	 *     min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
	 *   if (currentRoundMinRTT >= (lastRoundMinRTT + RttThresh))
	 *     cssBaselineMinRtt = currentRoundMinRTT
	 *     exit slow start and enter CSS
	 */
	if (cubic->last_round_min_rtt != U32_MAX &&
	    cubic->current_round_min_rtt != U32_MAX &&
	    cong->window >= QUIC_HS_MIN_SSTHRESH * cong->mss &&
	    cubic->rtt_sample_count >= QUIC_HS_N_RTT_SAMPLE) {
		eta = cubic->last_round_min_rtt / QUIC_HS_MIN_RTT_DIVISOR;
		if (eta < QUIC_HS_MIN_ETA)
			eta = QUIC_HS_MIN_ETA;
		else if (eta > QUIC_HS_MAX_ETA)
			eta = QUIC_HS_MAX_ETA;

		pr_debug("%s: current_round_min_rtt: %u, last_round_min_rtt: %u, eta: %u\n",
			 __func__, cubic->current_round_min_rtt, cubic->last_round_min_rtt, eta);

		/* Delay increase triggers slow start exit and enter CSS. */
		if (cubic->current_round_min_rtt >= cubic->last_round_min_rtt + eta)
			cubic->css_baseline_min_rtt = cubic->current_round_min_rtt;
	}
}

/* rfc9438#section-4: CUBIC Congestion Control */
static void cubic_cong_avoid(struct quic_cong *cong, u32 bytes)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);
	u64 tx, kx, time_delta, delta, t;
	u64 target_add, tcp_add = 0;
	u64 target, m;

	if (cubic->epoch_start == U32_MAX) {
		cubic->epoch_start = cong->time;
		if (cong->window < cubic->w_last_max) {
			/*
			 *        ┌────────────────┐
			 *     3  │W    - cwnd
			 *     ╲  │ max       epoch
			 * K =  ╲ │────────────────
			 *       ╲│       C
			 */
			cubic->k = cubic->w_last_max - cong->window;
			cubic->k = cubic_root(div64_ul(cubic->k * 10, (u64)cong->mss * 4));
			cubic->origin_point = cubic->w_last_max;
		} else {
			cubic->k = 0;
			cubic->origin_point = cong->window;
		}
		cubic->w_tcp = cong->window;
		cubic->pending_add = 0;
		cubic->pending_w_add = 0;
	}

	/*
	 * t = t        - t        + RTT
	 *      current    epoch
	 */
	t = cong->time - cubic->epoch_start + cong->smoothed_rtt;
	tx = div64_ul(t << 10, USEC_PER_SEC);
	kx = (cubic->k << 10);
	if (tx > kx)
		time_delta = tx - kx;
	else
		time_delta = kx - tx;
	/*
	 *                        3
	 * W     (t) = C * (t - K)  + W
	 *  cubic                      max
	 */
	delta = cong->mss * ((((time_delta * time_delta) >> 10) * time_delta) >> 10);
	delta = div64_ul(delta * 4, 10) >> 10;
	if (tx > kx)
		target = cubic->origin_point + delta;
	else
		target = cubic->origin_point - delta;

	pr_debug("%s: tgt: %llu, delta: %llu, t: %llu, srtt: %u, tx: %llu, kx: %llu\n",
		 __func__, target, delta, t, cong->smoothed_rtt, tx, kx);
	/*
	 *          ⎧
	 *          ⎪cwnd            if  W     (t + RTT) < cwnd
	 *          ⎪                     cubic
	 *          ⎨1.5 * cwnd      if  W     (t + RTT) > 1.5 * cwnd
	 * target = ⎪                     cubic
	 *          ⎪W     (t + RTT) otherwise
	 *          ⎩ cubic
	 */
	if (target < cong->window)
		target = cong->window;
	else if (2 * target > 3 * cong->window)
		target = cong->window * 3 / 2;

	/*
	 * target - cwnd
	 * ─────────────
	 *      cwnd
	 */
	if (target > cong->window) {
		target_add = cubic->pending_add + cong->mss * (target - cong->window);
		cubic->pending_add = do_div(target_add, cong->window);
	} else {
		target_add = cubic->pending_add + cong->mss;
		cubic->pending_add = do_div(target_add, 100 * cong->window);
	}

	pr_debug("%s: target: %llu, window: %u, target_add: %llu\n",
		 __func__, target, cong->window, target_add);

	/*
	 *                        segments_acked
	 * W    = W    + α      * ──────────────
	 *  est    est    cubic        cwnd
	 */
	m = cubic->pending_w_add + cong->mss * bytes;
	cubic->pending_w_add = do_div(m, cong->window);
	cubic->w_tcp += m;

	if (cubic->w_tcp > cong->window)
		tcp_add = div64_ul((u64)cong->mss * (cubic->w_tcp - cong->window), cong->window);

	pr_debug("%s: w_tcp: %u, window: %u, tcp_add: %llu\n",
		 __func__, cubic->w_tcp, cong->window, tcp_add);

	/* W_cubic(_t_) or _W_est_, whichever is bigger. */
	cong->window += max(tcp_add, target_add);
}

static void cubic_recovery(struct quic_cong *cong)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);

	cong->recovery_time = cong->time;
	cubic->epoch_start = U32_MAX;

	/* rfc9438#section-3.4:
	 *   CUBIC sets the multiplicative window decrease factor (β__cubic_) to 0.7,
	 *   whereas Reno uses 0.5.
	 *
	 * rfc9438#section-4.6:
	 *   ssthresh =  flight_size * β      new  ssthresh
	 *
	 *   Some implementations of CUBIC currently use _cwnd_ instead of _flight_size_ when
	 *   calculating a new _ssthresh_.
	 *
	 * rfc9438#section-4.7:
	 *
	 *          ⎧       1 + β
	 *          ⎪            cubic
	 *          ⎪cwnd * ────────── if  cwnd < W_max and fast convergence
	 *   W    = ⎨           2
	 *    max   ⎪                  enabled, further reduce  W_max
	 *          ⎪
	 *          ⎩cwnd             otherwise, remember cwnd before reduction
	 */
	if (cong->window < cubic->w_last_max)
		cubic->w_last_max = cong->window * 17 / 10 / 2;
	else
		cubic->w_last_max = cong->window;

	cong->ssthresh = cong->window * 7 / 10;
	cong->ssthresh = max(cong->ssthresh, cong->min_window);
	cong->window = cong->ssthresh;
}

static int quic_cong_check_persistent_congestion(struct quic_cong *cong, u64 time)
{
	u32 ssthresh;

	/* rfc9002#section-7.6.1:
	 *   (smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay) *
	 *      kPersistentCongestionThreshold
	 */
	ssthresh = cong->smoothed_rtt + max(4 * cong->rttvar, QUIC_KGRANULARITY);
	ssthresh = (ssthresh + cong->max_ack_delay) * QUIC_KPERSISTENT_CONGESTION_THRESHOLD;
	if (cong->time - time <= ssthresh)
		return 0;

	pr_debug("%s: persistent congestion, cwnd: %u, ssthresh: %u\n",
		 __func__, cong->window, cong->ssthresh);
	cong->min_rtt_valid = 0;
	cong->window = cong->min_window;
	cong->state = QUIC_CONG_SLOW_START;
	return 1;
}

static void quic_cubic_on_packet_lost(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	if (quic_cong_check_persistent_congestion(cong, time))
		return;

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		pr_debug("%s: slow_start -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("%s: cong_avoid -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__, cong->state);
		return;
	}

	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cubic_recovery(cong);
}

static void quic_cubic_on_packet_acked(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cubic_slow_start(cong, bytes, number);
		if (cong->window >= cong->ssthresh) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("%s: slow_start -> cong_avoid, cwnd: %u, ssthresh: %u\n",
				 __func__, cong->window, cong->ssthresh);
		}
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		if (cong->recovery_time < time) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("%s: recovery -> cong_avoid, cwnd: %u, ssthresh: %u\n",
				 __func__, cong->window, cong->ssthresh);
		}
		break;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		cubic_cong_avoid(cong, bytes);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__, cong->state);
		return;
	}
}

static void quic_cubic_on_process_ecn(struct quic_cong *cong)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		pr_debug("%s: slow_start -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("%s: cong_avoid -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__, cong->state);
		return;
	}

	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cubic_recovery(cong);
}

static void quic_cubic_on_init(struct quic_cong *cong)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);

	cubic->epoch_start = U32_MAX;
	cubic->origin_point = 0;
	cubic->w_last_max = 0;
	cubic->w_tcp = 0;
	cubic->k = 0;

	cubic->current_round_min_rtt = U32_MAX;
	cubic->css_baseline_min_rtt = U32_MAX;
	cubic->last_round_min_rtt = U32_MAX;
	cubic->rtt_sample_count = 0;
	cubic->window_end = -1;
	cubic->css_rounds = 0;
}

static void quic_cubic_on_packet_sent(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);

	if (cubic->window_end != -1)
		return;

	/* rfc9406#section-4.2:
	 *   lastRoundMinRTT = currentRoundMinRTT
	 *   currentRoundMinRTT = infinity
	 *   rttSampleCount = 0
	 */
	cubic->window_end = number;
	cubic->last_round_min_rtt = cubic->current_round_min_rtt;
	cubic->current_round_min_rtt = U32_MAX;
	cubic->rtt_sample_count = 0;

	pr_debug("%s: last_round_min_rtt: %u\n", __func__, cubic->last_round_min_rtt);
}

static void quic_cubic_on_rtt_update(struct quic_cong *cong)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);

	if (cubic->window_end == -1)
		return;

	pr_debug("%s: current_round_min_rtt: %u, latest_rtt: %u\n",
		 __func__, cubic->current_round_min_rtt, cong->latest_rtt);

	/* rfc9406#section-4.2:
	 *   currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
	 *   rttSampleCount += 1
	 */
	if (cubic->current_round_min_rtt > cong->latest_rtt) {
		cubic->current_round_min_rtt = cong->latest_rtt;
		if (cubic->current_round_min_rtt < cubic->css_baseline_min_rtt) {
			cubic->css_baseline_min_rtt = U32_MAX;
			cubic->css_rounds = 0;
		}
	}
	cubic->rtt_sample_count++;
}

/* NEW RENO APIs */
static void quic_reno_on_packet_lost(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	if (quic_cong_check_persistent_congestion(cong, time))
		return;

	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		pr_debug("%s: slow_start -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("%s: cong_avoid -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__, cong->state);
		return;
	}

	cong->recovery_time = cong->time;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->ssthresh = max(cong->window >> 1U, cong->min_window);
	cong->window = cong->ssthresh;
}

static void quic_reno_on_packet_acked(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		cong->window = min_t(u32, cong->window + bytes, cong->max_window);
		if (cong->window >= cong->ssthresh) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("%s: slow_start -> cong_avoid, cwnd: %u, ssthresh: %u\n",
				 __func__, cong->window, cong->ssthresh);
		}
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		if (cong->recovery_time < time) {
			cong->state = QUIC_CONG_CONGESTION_AVOIDANCE;
			pr_debug("%s: recovery -> cong_avoid, cwnd: %u, ssthresh: %u\n",
				 __func__, cong->window, cong->ssthresh);
		}
		break;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		/* cong->window is never zero; it is initialized by quic_packet_route()
		 * during connect/accept.
		 */
		cong->window += cong->mss * bytes / cong->window;
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__, cong->state);
		return;
	}
}

static void quic_reno_on_process_ecn(struct quic_cong *cong)
{
	switch (cong->state) {
	case QUIC_CONG_SLOW_START:
		pr_debug("%s: slow_start -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	case QUIC_CONG_RECOVERY_PERIOD:
		return;
	case QUIC_CONG_CONGESTION_AVOIDANCE:
		pr_debug("%s: cong_avoid -> recovery, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		break;
	default:
		pr_debug("%s: wrong congestion state: %d\n", __func__, cong->state);
		return;
	}

	cong->recovery_time = cong->time;
	cong->state = QUIC_CONG_RECOVERY_PERIOD;
	cong->ssthresh = max(cong->window >> 1U, cong->min_window);
	cong->window = cong->ssthresh;
}

static void quic_reno_on_init(struct quic_cong *cong)
{
}

static struct quic_cong_ops quic_congs[] = {
	{ /* QUIC_CONG_ALG_RENO */
		.on_packet_acked = quic_reno_on_packet_acked,
		.on_packet_lost = quic_reno_on_packet_lost,
		.on_process_ecn = quic_reno_on_process_ecn,
		.on_init = quic_reno_on_init,
	},
	{ /* QUIC_CONG_ALG_CUBIC */
		.on_packet_acked = quic_cubic_on_packet_acked,
		.on_packet_lost = quic_cubic_on_packet_lost,
		.on_process_ecn = quic_cubic_on_process_ecn,
		.on_init = quic_cubic_on_init,
		.on_packet_sent = quic_cubic_on_packet_sent,
		.on_rtt_update = quic_cubic_on_rtt_update,
	},
};

/* COMMON APIs */
void quic_cong_on_packet_lost(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	cong->ops->on_packet_lost(cong, time, bytes, number);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_lost);

void quic_cong_on_packet_acked(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	cong->ops->on_packet_acked(cong, time, bytes, number);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_acked);

void quic_cong_on_process_ecn(struct quic_cong *cong)
{
	cong->ops->on_process_ecn(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_on_process_ecn);

/* Update Probe Timeout (PTO) and loss detection delay based on RTT stats. */
static void quic_cong_pto_update(struct quic_cong *cong)
{
	u32 pto, loss_delay;

	/* rfc9002#section-6.2.1:
	 *   PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
	 */
	pto = cong->smoothed_rtt + max(4 * cong->rttvar, QUIC_KGRANULARITY);
	cong->pto = pto + cong->max_ack_delay;

	/* rfc9002#section-6.1.2:
	 *   max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
	 */
	loss_delay = QUIC_KTIME_THRESHOLD(max(cong->smoothed_rtt, cong->latest_rtt));
	cong->loss_delay = max(loss_delay, QUIC_KGRANULARITY);

	pr_debug("%s: update pto: %u\n", __func__, pto);
}

/* Update pacing timestamp after sending 'bytes' bytes.
 *
 * This function tracks when the next packet is allowed to be sent based on pacing rate.
 */
static void quic_cong_update_pacing_time(struct quic_cong *cong, u32 bytes)
{
	u64 prior_time, credit, len_ns, rate = READ_ONCE(cong->pacing_rate);

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

/* Compute and update the pacing rate based on congestion window and smoothed RTT. */
static void quic_cong_pace_update(struct quic_cong *cong, u32 bytes, u64 max_rate)
{
	u64 rate;

	if (unlikely(!cong->smoothed_rtt))
		return;

	/* rate = N * congestion_window / smoothed_rtt */
	rate = div64_ul((u64)cong->window * USEC_PER_SEC * 2, cong->smoothed_rtt);

	WRITE_ONCE(cong->pacing_rate, min_t(u64, rate, max_rate));
	pr_debug("%s: update pacing rate: %llu, max rate: %llu, srtt: %u\n",
		 __func__, cong->pacing_rate, max_rate, cong->smoothed_rtt);
}

void quic_cong_on_packet_sent(struct quic_cong *cong, u64 time, u32 bytes, s64 number)
{
	if (!bytes)
		return;
	if (cong->ops->on_packet_sent)
		cong->ops->on_packet_sent(cong, time, bytes, number);
	quic_cong_update_pacing_time(cong, bytes);
}
EXPORT_SYMBOL_GPL(quic_cong_on_packet_sent);

void quic_cong_on_ack_recv(struct quic_cong *cong, u32 bytes, u64 max_rate)
{
	if (!bytes)
		return;
	if (cong->ops->on_ack_recv)
		cong->ops->on_ack_recv(cong, bytes, max_rate);
	quic_cong_pace_update(cong, bytes, max_rate);
}
EXPORT_SYMBOL_GPL(quic_cong_on_ack_recv);

/* rfc9002#section-5: Estimating the Round-Trip Time */
void quic_cong_rtt_update(struct quic_cong *cong, u64 time, u32 ack_delay)
{
	u32 adjusted_rtt, rttvar_sample;

	/* Ignore RTT sample if ACK delay is suspiciously large. */
	if (ack_delay > cong->max_ack_delay * 2)
		return;

	/* rfc9002#section-5.1: latest_rtt = ack_time - send_time_of_largest_acked */
	cong->latest_rtt = cong->time - time;

	/* rfc9002#section-5.2: Estimating min_rtt */
	if (!cong->min_rtt_valid) {
		cong->min_rtt = cong->latest_rtt;
		cong->min_rtt_valid = 1;
	}
	if (cong->min_rtt > cong->latest_rtt)
		cong->min_rtt = cong->latest_rtt;

	if (!cong->is_rtt_set) {
		/* rfc9002#section-5.3:
		 *   smoothed_rtt = latest_rtt
		 *   rttvar = latest_rtt / 2
		 */
		cong->smoothed_rtt = cong->latest_rtt;
		cong->rttvar = cong->smoothed_rtt / 2;
		quic_cong_pto_update(cong);
		cong->is_rtt_set = 1;
		return;
	}

	/* rfc9002#section-5.3:
	 *   adjusted_rtt = latest_rtt
	 *   if (latest_rtt >= min_rtt + ack_delay):
	 *     adjusted_rtt = latest_rtt - ack_delay
	 *   smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
	 *   rttvar_sample = abs(smoothed_rtt - adjusted_rtt)
	 *   rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
	 */
	adjusted_rtt = cong->latest_rtt;
	if (cong->latest_rtt >= cong->min_rtt + ack_delay)
		adjusted_rtt = cong->latest_rtt - ack_delay;

	cong->smoothed_rtt = (cong->smoothed_rtt * 7 + adjusted_rtt) / 8;
#ifdef abs_diff
	rttvar_sample = abs_diff(cong->smoothed_rtt, adjusted_rtt);
#else
	rttvar_sample = cong->smoothed_rtt > adjusted_rtt ?
		cong->smoothed_rtt - adjusted_rtt : adjusted_rtt - cong->smoothed_rtt;
#endif
	cong->rttvar = (cong->rttvar * 3 + rttvar_sample) / 4;
	quic_cong_pto_update(cong);

	if (cong->ops->on_rtt_update)
		cong->ops->on_rtt_update(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_rtt_update);

void quic_cong_set_algo(struct quic_cong *cong, u8 algo)
{
	if (algo >= QUIC_CONG_ALG_MAX)
		algo = QUIC_CONG_ALG_RENO;

	cong->state = QUIC_CONG_SLOW_START;
	cong->ssthresh = U32_MAX;
	cong->ops = &quic_congs[algo];
	cong->ops->on_init(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_set_algo);

void quic_cong_set_srtt(struct quic_cong *cong, u32 srtt)
{
	/* rfc9002#section-5.3:
	 *   smoothed_rtt = kInitialRtt
	 *   rttvar = kInitialRtt / 2
	 */
	cong->latest_rtt = srtt;
	cong->smoothed_rtt = cong->latest_rtt;
	cong->rttvar = cong->smoothed_rtt / 2;
	quic_cong_pto_update(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_set_srtt);

void quic_cong_init(struct quic_cong *cong)
{
	cong->max_ack_delay = QUIC_DEF_ACK_DELAY;
	cong->max_window = S32_MAX / 2;
	quic_cong_set_algo(cong, QUIC_CONG_ALG_RENO);
	quic_cong_set_srtt(cong, QUIC_RTT_INIT);
}
