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

#include <linux/version.h>

#include "socket.h"

void quic_timer_sack_handler(struct sock *sk)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_connection_close close = {};

	if (quic_is_closed(sk))
		return;

	if (inq->sack_flag == QUIC_SACK_FLAG_NONE) { /* Idle timer expired, close the connection. */
		quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close);
		quic_set_state(sk, QUIC_SS_CLOSED);

		pr_debug("%s: idle timeout\n", __func__);
		return;
	}

	if (inq->sack_flag == QUIC_SACK_FLAG_APP) {
		space->need_sack = 1; /* Request an APP-level ACK frame to be generated. */
		space->sack_path = 0; /* Send delayed ACK only on the active path. */
	}

	quic_outq_transmit(sk); /* Transmit necessary frames, including ACKs or others queued. */
	inq->sack_flag = QUIC_SACK_FLAG_NONE; /* Start as idle timer. */
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);
}

static void quic_timer_sack_timeout(struct timer_list *t)
{
	struct quic_sock *qs = container_of(t, struct quic_sock, timers[QUIC_TIMER_SACK].t);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_SACK_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	quic_timer_sack_handler(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void quic_timer_loss_handler(struct sock *sk)
{
	if (quic_is_closed(sk))
		return;

	quic_outq_transmit_pto(sk);
}

static void quic_timer_loss_timeout(struct timer_list *t)
{
	struct quic_sock *qs = container_of(t, struct quic_sock, timers[QUIC_TIMER_LOSS].t);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_LOSS_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	quic_timer_loss_handler(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

#define QUIC_MAX_ALT_PROBES	3

void quic_timer_path_handler(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	u8 path = 0;

	if (quic_is_closed(sk))
		return;

	/* PATH_CHALLENGE frames are reused to keep the new path alive for NAT rebind.
	 * Skip probe attempt counting unless the path is explicitly in PROBING state.
	 */
	if (!quic_path_alt_state(paths, QUIC_PATH_ALT_PROBING))
		goto out;

	/* Increment probe attempts; give up if exceeded max allowed. */
	if (paths->alt_probes++ < QUIC_MAX_ALT_PROBES) {
		path = 1;
		goto out;
	}

	/* Probing failed; drop the alternate path. */
	quic_path_free(sk, paths, 1);

out:
	quic_outq_transmit_frame(sk, QUIC_FRAME_PATH_CHALLENGE, NULL, path, false);
	quic_timer_reset_path(sk);
}

static void quic_timer_path_timeout(struct timer_list *t)
{
	struct quic_sock *qs = container_of(t, struct quic_sock, timers[QUIC_TIMER_PATH].t);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_PATH_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	quic_timer_path_handler(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void quic_timer_reset_path(struct sock *sk)
{
	struct quic_cong *cong = quic_cong(sk);
	u64 timeout = cong->pto * 2;

	/* Calculate timeout based on cong.pto, but enforce a lower bound. */
	if (timeout < QUIC_MIN_PATH_TIMEOUT)
		timeout = QUIC_MIN_PATH_TIMEOUT;
	quic_timer_reset(sk, QUIC_TIMER_PATH, timeout);
}

void quic_timer_pmtu_handler(struct sock *sk)
{
	if (quic_is_closed(sk))
		return;

	quic_outq_transmit_probe(sk);
}

static void quic_timer_pmtu_timeout(struct timer_list *t)
{
	struct quic_sock *qs = container_of(t, struct quic_sock, timers[QUIC_TIMER_PMTU].t);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_PMTU_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	quic_timer_pmtu_handler(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void quic_timer_pace_handler(struct sock *sk)
{
	if (quic_is_closed(sk))
		return;

	quic_outq_transmit(sk);
}

static enum hrtimer_restart quic_timer_pace_timeout(struct hrtimer *hr)
{
	struct quic_sock *qs = container_of(hr, struct quic_sock, timers[QUIC_TIMER_PACE].hr);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_TSQ_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	quic_timer_pace_handler(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return HRTIMER_NORESTART;
}

void quic_timer_reset(struct sock *sk, u8 type, u64 timeout)
{
	struct timer_list *t = quic_timer(sk, type);

	if (timeout && !mod_timer(t, jiffies + usecs_to_jiffies(timeout)))
		sock_hold(sk);
}

void quic_timer_start(struct sock *sk, u8 type, u64 timeout)
{
	struct timer_list *t;
	struct hrtimer *hr;

	if (type == QUIC_TIMER_PACE) {
		hr = quic_timer(sk, type);

		if (!hrtimer_is_queued(hr)) {
			hrtimer_start(hr, ns_to_ktime(timeout), HRTIMER_MODE_ABS_PINNED_SOFT);
			sock_hold(sk);
		}
		return;
	}

	t = quic_timer(sk, type);
	if (timeout && !timer_pending(t)) {
		if (!mod_timer(t, jiffies + usecs_to_jiffies(timeout)))
			sock_hold(sk);
	}
}

void quic_timer_stop(struct sock *sk, u8 type)
{
	if (type == QUIC_TIMER_PACE) {
		if (hrtimer_try_to_cancel(quic_timer(sk, type)) == 1)
			sock_put(sk);
		return;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	if (timer_delete(quic_timer(sk, type)))
#else
	if (del_timer(quic_timer(sk, type)))
#endif
		sock_put(sk);
}

void quic_timer_init(struct sock *sk)
{
	struct hrtimer *hr;

	timer_setup(quic_timer(sk, QUIC_TIMER_LOSS), quic_timer_loss_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_SACK), quic_timer_sack_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_PATH), quic_timer_path_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_PMTU), quic_timer_pmtu_timeout, 0);

	hr = quic_timer(sk, QUIC_TIMER_PACE);
	/* Use hrtimer for pace timer, ensuring precise control over send timing. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
	hrtimer_setup(hr, quic_timer_pace_timeout, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED_SOFT);
#else
	hrtimer_init(hr, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED_SOFT);
	hr->function = quic_timer_pace_timeout;
#endif
}

void quic_timer_free(struct sock *sk)
{
	quic_timer_stop(sk, QUIC_TIMER_LOSS);
	quic_timer_stop(sk, QUIC_TIMER_SACK);
	quic_timer_stop(sk, QUIC_TIMER_PATH);
	quic_timer_stop(sk, QUIC_TIMER_PMTU);
	quic_timer_stop(sk, QUIC_TIMER_PACE);
}
