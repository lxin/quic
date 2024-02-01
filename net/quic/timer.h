/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_TIMER_RTX		0
#define QUIC_TIMER_ACK		1
#define QUIC_TIMER_IDLE		2
#define QUIC_TIMER_PROBE	3
#define QUIC_TIMER_PATH		4

#define QUIC_TIMER_MAX		5

struct quic_timer {
	struct timer_list timer;
	unsigned long timeout;
};

void quic_timer_setup(struct sock *sk, u8 type, u32 timeout);
void quic_timer_reset(struct sock *sk, u8 type);
void quic_timer_start(struct sock *sk, u8 type);
void quic_timer_stop(struct sock *sk, u8 type);
void quic_timers_init(struct sock *sk);
void quic_timers_free(struct sock *sk);
