// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "socket.h"
#include "frame.h"

static void quic_timer_delay_ack_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_ACK].timer);
	struct sock *sk = &qs->inet.sk;
	u8 level = QUIC_CRYPTO_APP;
	struct sk_buff *skb;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&quic_timer(sk, QUIC_TIMER_ACK)->timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	if (quic_is_establishing(sk)) { /* try to flush ACKs to Handshake packets */
		quic_outq_flush(sk);
		goto out;
	}

	skb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
	if (skb)
		quic_outq_ctrl_tail(sk, skb, false);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_timer_rtx_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_RTX].timer);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&quic_timer(sk, QUIC_TIMER_RTX)->timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	quic_outq_retransmit(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_timer_idle_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_IDLE].timer);
	struct quic_connection_close *close;
	struct sock *sk = &qs->inet.sk;
	u8 frame[100] = {};

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&quic_timer(sk, QUIC_TIMER_IDLE)->timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	/* Notify userspace, which is most likely waiting for a packet on the
	 * rcv queue.
	 */
	close = (void *)frame;
	close->errcode = 0;	/* Not an error, only a timer runout. */
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close)) {
		quic_timer_reset(sk, QUIC_TIMER_IDLE);
		goto out;
	}
	quic_set_state(sk, QUIC_SS_CLOSED);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
	pr_debug("[QUIC] IDLE TIMEOUT\n");
}

static void quic_timer_probe_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_PROBE].timer);
	struct sock *sk = &qs->inet.sk;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&quic_timer(sk, QUIC_TIMER_PROBE)->timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	quic_outq_transmit_probe(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_timer_path_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_PATH].timer);
	struct sock *sk = &qs->inet.sk;
	struct quic_path_addr *path;
	struct sk_buff *skb;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&quic_timer(sk, QUIC_TIMER_PATH)->timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	path = quic_src(sk);
	if (path->sent_cnt) {
		if (path->sent_cnt >= 5) {
			path->sent_cnt = 0;
			goto out;
		}
		skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
		path->sent_cnt++;
		quic_timer_reset(sk, QUIC_TIMER_PATH);
	}

	path = quic_dst(sk);
	if (path->sent_cnt) {
		if (path->sent_cnt >= 5) {
			path->sent_cnt = 0;
			path->active = !path->active;
			goto out;
		}
		skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
		path->sent_cnt++;
		quic_timer_reset(sk, QUIC_TIMER_PATH);
	}

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void quic_timer_reset(struct sock *sk, u8 type)
{
	struct quic_timer *t = quic_timer(sk, type);

	if (t->timeout && !mod_timer(&t->timer, jiffies + t->timeout))
		sock_hold(sk);
}

void quic_timer_start(struct sock *sk, u8 type)
{
	struct quic_timer *t = quic_timer(sk, type);

	if (t->timeout && !timer_pending(&t->timer)) {
		if (!mod_timer(&t->timer, jiffies + t->timeout))
			sock_hold(sk);
	}
}

void quic_timer_stop(struct sock *sk, u8 type)
{
	if (del_timer(&quic_timer(sk, type)->timer))
		sock_put(sk);
}

void quic_timer_setup(struct sock *sk, u8 type, u32 timeout)
{
	quic_timer(sk, type)->timeout = usecs_to_jiffies(timeout);
}

void quic_timers_init(struct sock *sk)
{
	struct quic_transport_param *p = quic_local(sk);
	struct quic_timer *t;

	t = quic_timer(sk, QUIC_TIMER_RTX);
	timer_setup(&t->timer, quic_timer_rtx_timeout, 0);
	quic_timer_setup(sk, QUIC_TIMER_RTX, p->initial_smoothed_rtt);

	t = quic_timer(sk, QUIC_TIMER_ACK);
	timer_setup(&t->timer, quic_timer_delay_ack_timeout, 0);
	quic_timer_setup(sk, QUIC_TIMER_ACK, p->max_ack_delay);

	/* Initialize the idle timer's handler. The timeout value isn't known
	 * until the socket context is set.
	 */
	t = quic_timer(sk, QUIC_TIMER_IDLE);
	timer_setup(&t->timer, quic_timer_idle_timeout, 0);
	quic_timer_setup(sk, QUIC_TIMER_IDLE, p->max_idle_timeout);

	t = quic_timer(sk, QUIC_TIMER_PROBE);
	timer_setup(&t->timer, quic_timer_probe_timeout, 0);
	quic_timer_setup(sk, QUIC_TIMER_PROBE, p->plpmtud_probe_timeout);

	t = quic_timer(sk, QUIC_TIMER_PATH);
	timer_setup(&t->timer, quic_timer_path_timeout, 0);
	quic_timer_setup(sk, QUIC_TIMER_PATH, p->initial_smoothed_rtt * 3);
}

void quic_timers_free(struct sock *sk)
{
	quic_timer_stop(sk, QUIC_TIMER_RTX);
	quic_timer_stop(sk, QUIC_TIMER_ACK);
	quic_timer_stop(sk, QUIC_TIMER_IDLE);
	quic_timer_stop(sk, QUIC_TIMER_PROBE);
	quic_timer_stop(sk, QUIC_TIMER_PATH);
}
