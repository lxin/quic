/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_TIMER_RTX		0
#define QUIC_TIMER_ACK		1
#define QUIC_TIMER_MAX		2

struct quic_timer {
	struct timer_list timer;
	unsigned long timeout;
};

void quic_timer_reset(struct sock *sk, u8 type);
void quic_timer_start(struct sock *sk, u8 type);
void quic_timer_stop(struct sock *sk, u8 type);
void quic_timers_init(struct sock *sk);
void quic_timers_free(struct sock *sk);
