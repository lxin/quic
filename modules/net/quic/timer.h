/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

enum {
	QUIC_TIMER_AP_LOSS = QUIC_CRYPTO_APP,
	QUIC_TIMER_IN_LOSS = QUIC_CRYPTO_INITIAL,
	QUIC_TIMER_HS_LOSS = QUIC_CRYPTO_HANDSHAKE,
	QUIC_TIMER_SACK,
	QUIC_TIMER_PATH,
	QUIC_TIMER_PACE,
	QUIC_TIMER_MAX,
};

struct quic_timer {
	union {
		struct timer_list t;
		struct hrtimer hr;
	};
};

#define QUIC_MIN_PROBE_TIMEOUT	5000000

#define QUIC_MIN_IDLE_TIMEOUT	1000000
#define QUIC_DEF_IDLE_TIMEOUT	30000000

void quic_timer_reduce(struct sock *sk, u8 type, u64 timeout);
void quic_timer_reset(struct sock *sk, u8 type, u64 timeout);
void quic_timer_start(struct sock *sk, u8 type, u64 timeout);
void quic_timer_stop(struct sock *sk, u8 type);
void quic_timer_init(struct sock *sk);
void quic_timer_free(struct sock *sk);

void quic_timer_loss_handler(struct sock *sk, u8 level);
void quic_timer_pace_handler(struct sock *sk);
void quic_timer_path_handler(struct sock *sk);
void quic_timer_sack_handler(struct sock *sk);
