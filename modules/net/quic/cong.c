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

/* CUBIC APIs */
struct quic_cubic {
	u32 pending_w_add;
	u32 origin_point;
	u32 epoch_start;
	u32 pending_add;
	u32 w_last_max;
	u32 w_tcp;
	u64 k;

	/* HyStart++ variables */
	u32 current_round_min_rtt;
	u32 css_baseline_min_rtt;
	u32 last_round_min_rtt;
	u16 rtt_sample_count;
	u16 css_rounds;
	s32 window_end;
};

/* HyStart++ constants */
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

	d = __builtin_clzll(n);
	a = 1ULL << ((64 - d) / 3 + 1);

	for (; a * a * a > n;)
		a = (2 * a + n / a / a) / 3;
	return a;
}

static void cubic_slow_start(struct quic_cong *cong, u32 bytes, s64 number)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);
	u32 eta;

	if (cubic->window_end <= number)
		cubic->window_end = -1;

	if (cubic->css_baseline_min_rtt != U32_MAX)
		bytes = bytes / QUIC_HS_CSS_GROWTH_DIVISOR;
	cong->window = min_t(u32, cong->window + bytes, cong->max_window);

	if (cubic->css_baseline_min_rtt != U32_MAX) {
		/* If CSS_ROUNDS rounds are complete, enter congestion avoidance */
		if (++cubic->css_rounds > QUIC_HS_CSS_ROUNDS) {
			cubic->css_baseline_min_rtt = U32_MAX;
			cubic->w_last_max = cong->window;
			cong->ssthresh = cong->window;
			cubic->css_rounds = 0;
		}
		return;
	}

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

		/* delay increase triggers slow start exit and enter CSS */
		if (cubic->current_round_min_rtt >= cubic->last_round_min_rtt + eta)
			cubic->css_baseline_min_rtt = cubic->current_round_min_rtt;
	}
}

static void cubic_cong_avoid(struct quic_cong *cong, u32 bytes)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);
	u32 add, target_add, tcp_add = 0;
	u64 tx, kx, time_delta, delta, t;
	u64 target, cwnd_thres;
	u64 m;

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
			cubic->k = cubic_root(cubic->k * 10 / 4 / cong->mss);
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
	 * t = t        - t
	 *      current    epoch
	 */
	t = cong->time - cubic->epoch_start;
	tx = (t << 10) / USEC_PER_SEC;
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
	delta = cong->mss * ((((time_delta * time_delta) >> 10) * time_delta) >> 10) * 4 / 10;
	delta >>= 10;
	if (tx > kx)
		target = cubic->origin_point + delta;
	else
		target = cubic->origin_point - delta;

	/*
	 * W     (t + RTT)
	 *  cubic
	 */
	cwnd_thres = (target * (((t + cong->smoothed_rtt) << 10) / USEC_PER_SEC)) >> 10;
	pr_debug("%s: target: %llu, thres: %llu, delta: %llu, t: %llu, srtt: %u, tx: %llu, kx: %llu\n",
		 __func__, target, cwnd_thres, delta, t, cong->smoothed_rtt, tx, kx);
	/*
	 *          ⎧
	 *          ⎪cwnd            if  W     (t + RTT) < cwnd
	 *          ⎪                     cubic
	 *          ⎨1.5 * cwnd      if  W     (t + RTT) > 1.5 * cwnd
	 * target = ⎪                     cubic
	 *          ⎪W     (t + RTT) otherwise
	 *          ⎩ cubic
	 */
	if (cwnd_thres < cong->window)
		target = cong->window;
	else if (2 * cwnd_thres > 3 * cong->window)
		target = cong->window * 3 / 2;
	else
		target = cwnd_thres;

	/*
	 * target - cwnd
	 * ─────────────
	 *      cwnd
	 */
	if (target > cong->window) {
		m = cubic->pending_add + cong->mss * (target - cong->window);
		target_add = m / cong->window;
		cubic->pending_add = m % cong->window;
	} else {
		m = cubic->pending_add + cong->mss;
		target_add = m / (100 * cong->window);
		cubic->pending_add = m % (100 * cong->window);
	}

	pr_debug("%s: target: %llu, window: %u, target_add: %u\n",
		 __func__, target, cong->window, target_add);

	/*
	 *                        segments_acked
	 * W    = W    + α      * ──────────────
	 *  est    est    cubic        cwnd
	 */
	m = cubic->pending_w_add + cong->mss * bytes;
	cubic->w_tcp += m / cong->window;
	cubic->pending_w_add = m % cong->window;

	if (cubic->w_tcp > cong->window)
		tcp_add = cong->mss * (cubic->w_tcp - cong->window) / cong->window;

	pr_debug("%s: w_tcp: %u, window: %u, tcp_add: %u\n",
		 __func__, cubic->w_tcp, cong->window, tcp_add);

	/* W_cubic(_t_) or _W_est_, whichever is bigger */
	add = max(tcp_add, target_add);
	cong->window += add;
}

static void cubic_recovery(struct quic_cong *cong)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);
	u32 min_cwnd;

	cong->recovery_time = cong->time;
	cubic->epoch_start = U32_MAX;
	if (cong->window < cubic->w_last_max)
		cubic->w_last_max = cong->window * 17 / 10 / 2;
	else
		cubic->w_last_max = cong->window;

	min_cwnd = 2 * cong->mss;
	cong->ssthresh = cong->window * 7 / 10;
	cong->ssthresh = max(cong->ssthresh, min_cwnd);
	cong->window = cong->ssthresh;
}

static void quic_cubic_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	u32 time_ssthresh;

	time_ssthresh = cong->smoothed_rtt + max(4 * cong->rttvar, 1000U);
	time_ssthresh = (time_ssthresh + cong->max_ack_delay) * 3;
	if (cong->time - time > time_ssthresh) {
		/* persistent congestion: cong_avoid -> slow_start or recovery -> slow_start */
		pr_debug("%s: permanent congestion, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		cong->window = cong->mss * 2;
		cong->state = QUIC_CONG_SLOW_START;
		return;
	}

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

static void quic_cubic_on_packet_acked(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
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

static void quic_cubic_on_packet_sent(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	struct quic_cubic *cubic = quic_cong_priv(cong);

	if (cubic->window_end != -1)
		return;

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
static void quic_reno_on_packet_lost(struct quic_cong *cong, u32 time, u32 bytes, s64 number)
{
	u32 time_ssthresh;

	time_ssthresh = cong->smoothed_rtt + max(4 * cong->rttvar, 1000U);
	time_ssthresh = (time_ssthresh + cong->max_ack_delay) * 3;
	if (cong->time - time > time_ssthresh) {
		/* persistent congestion: cong_avoid -> slow_start or recovery -> slow_start */
		pr_debug("%s: permanent congestion, cwnd: %u, ssthresh: %u\n",
			 __func__, cong->window, cong->ssthresh);
		cong->window = cong->mss * 2;
		cong->state = QUIC_CONG_SLOW_START;
		return;
	}

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
	cong->ssthresh = max(cong->window >> 1U, cong->mss * 2);
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

	pr_debug("%s: update rto: %u, duration: %u\n", __func__, rto, duration);
}

void quic_cong_set_config(struct quic_cong *cong, struct quic_config *c)
{
	u8 algo = QUIC_CONG_ALG_RENO;

	if (c->congestion_control_algo < QUIC_CONG_ALG_MAX)
		algo = c->congestion_control_algo;

	cong->latest_rtt = c->initial_smoothed_rtt;
	cong->smoothed_rtt = cong->latest_rtt;
	cong->rttvar = cong->smoothed_rtt / 2;
	quic_cong_rto_update(cong);

	cong->state = QUIC_CONG_SLOW_START;
	cong->ssthresh = U32_MAX;
	cong->ops = &quic_congs[algo];
	cong->ops->on_init(cong);
}
EXPORT_SYMBOL_GPL(quic_cong_set_config);

void quic_cong_set_param(struct quic_cong *cong, struct quic_transport_param *p)
{
	cong->max_window = p->max_data;
	cong->max_ack_delay = p->max_ack_delay;
	cong->ack_delay_exponent = p->ack_delay_exponent;
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
	pr_debug("%s: update pacing rate: %u, max rate: %u, srtt: %u\n",
		 __func__, cong->pacing_rate, max_rate, cong->smoothed_rtt);
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
