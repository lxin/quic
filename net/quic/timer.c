/* SPDX-License-Identifier: GPL-2.0-or-later */
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
	struct sk_buff *skb;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(&qs->timers[QUIC_TIMER_ACK].timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	skb = quic_frame_create(sk, QUIC_FRAME_ACK, NULL);
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
		if (!mod_timer(&qs->timers[QUIC_TIMER_RTX].timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

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
		if (!mod_timer(&qs->timers[QUIC_TIMER_IDLE].timer, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	quic_set_state(sk, QUIC_STATE_USER_CLOSED);

	/* Notify userspace, which is most likely waiting for a packet on the
	 * rcv queue.
	 */
	close = (void *)frame;
	close->errcode = 0;	/* Not an error, only a timer runout. */
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close);
	sk->sk_state_change(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
	pr_debug("[QUIC] IDLE TIMEOUT\n");
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
	struct quic_timer *t;

	t = quic_timer(sk, QUIC_TIMER_RTX);
	timer_setup(&t->timer, quic_timer_rtx_timeout, 0);

	t = quic_timer(sk, QUIC_TIMER_ACK);
	timer_setup(&t->timer, quic_timer_delay_ack_timeout, 0);

	/* Initialize the idle timer's handler. The timeout value isn't known
	 * until the socket context is set.
	 */
	t = quic_timer(sk, QUIC_TIMER_IDLE);
	timer_setup(&t->timer, quic_timer_idle_timeout, 0);
}

void quic_timers_free(struct sock *sk)
{
	quic_timer_stop(sk, QUIC_TIMER_RTX);
	quic_timer_stop(sk, QUIC_TIMER_ACK);
	quic_timer_stop(sk, QUIC_TIMER_IDLE);
}
