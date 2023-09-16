/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
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

void quic_timer_reset(struct sock *sk, u8 type)
{
	struct quic_timer *t = quic_timer(sk, type);

	if (!mod_timer(&t->timer, jiffies + t->timeout))
		sock_hold(sk);
}

void quic_timer_start(struct sock *sk, u8 type)
{
	struct quic_timer *t = quic_timer(sk, type);

	if (!timer_pending(&t->timer)) {
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
	t->timeout = usecs_to_jiffies(quic_cong_rto(quic_cong(sk)));
	timer_setup(&t->timer, quic_timer_rtx_timeout, 0);

	t = quic_timer(sk, QUIC_TIMER_ACK);
	t->timeout = usecs_to_jiffies(quic_outq_max_ack_delay(quic_outq(sk)));
	timer_setup(&t->timer, quic_timer_delay_ack_timeout, 0);
}

void quic_timers_free(struct sock *sk)
{
	quic_timer_stop(sk, QUIC_TIMER_RTX);
	quic_timer_stop(sk, QUIC_TIMER_ACK);
}
