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
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_SACK]);
	u8 level = QUIC_CRYPTO_APP, frame[100] = {};
	struct quic_connection_close *close;
	struct sock *sk = &qs->inet.sk;
	struct quic_inqueue *inq;
	struct sk_buff *skb;
	u32 timeout;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(t, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	inq = quic_inq(sk);
	if (quic_inq_need_sack(inq)) {
		skb = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
		quic_inq_set_need_sack(inq, 0);
		goto out;
	}

	close = (void *)frame;
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close)) {
		timeout = quic_inq_max_idle_timeout(inq);
		quic_timer_start(sk, QUIC_TIMER_SACK, timeout);
		goto out;
	}
	quic_set_state(sk, QUIC_SS_CLOSED);
	pr_debug("[QUIC] IDLE TIMEOUT\n");
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_timer_loss_timeout(struct sock *sk, u8 level)
{
	struct quic_pnmap *pnmap;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(quic_timer(sk, level), jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	pnmap = quic_pnmap(sk, level);
	if (quic_pnmap_loss_ts(pnmap)) {
		if (quic_outq_retransmit_mark(sk, level, 0))
			quic_outq_transmit(sk);
		goto out;
	}

	if (quic_pnmap_last_sent_ts(pnmap))
		quic_outq_transmit_one(sk, level);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void quic_timer_ap_loss_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_AP_LOSS]);

	quic_timer_loss_timeout(&qs->inet.sk, QUIC_TIMER_AP_LOSS);
}

static void quic_timer_in_loss_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_IN_LOSS]);

	quic_timer_loss_timeout(&qs->inet.sk, QUIC_TIMER_IN_LOSS);
}

static void quic_timer_hs_loss_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_HS_LOSS]);

	quic_timer_loss_timeout(&qs->inet.sk, QUIC_TIMER_HS_LOSS);
}

static void quic_timer_path_timeout(struct timer_list *t)
{
	struct quic_sock *qs = from_timer(qs, t, timers[QUIC_TIMER_PATH]);
	struct sock *sk = &qs->inet.sk;
	struct quic_path_addr *path;
	struct quic_packet *packet;
	struct sk_buff *skb;
	u8 cnt, probe = 1;
	u32 timeout;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (!mod_timer(t, jiffies + (HZ / 20)))
			sock_hold(sk);
		goto out;
	}

	if (quic_is_closed(sk))
		goto out;

	timeout = quic_cong_rto(quic_cong(sk)) * 3;
	packet = quic_packet(sk);
	path = quic_src(sk);
	cnt = quic_path_sent_cnt(path);
	if (cnt) {
		probe = 0;
		if (cnt >= 5) {
			quic_path_set_sent_cnt(path, 0);
			quic_packet_set_ecn_probes(packet, 0);
			goto out;
		}
		skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
		quic_path_set_sent_cnt(path, cnt + 1);
		quic_timer_start(sk, QUIC_TIMER_PATH, timeout);
	}

	path = quic_dst(sk);
	cnt = quic_path_sent_cnt(path);
	if (cnt) {
		probe = 0;
		if (cnt >= 5) {
			quic_path_set_sent_cnt(path, 0);
			quic_path_swap_active(path);
			quic_packet_set_ecn_probes(packet, 0);
			goto out;
		}
		skb = quic_frame_create(sk, QUIC_FRAME_PATH_CHALLENGE, path);
		if (skb)
			quic_outq_ctrl_tail(sk, skb, false);
		quic_path_set_sent_cnt(path, cnt + 1);
		quic_timer_start(sk, QUIC_TIMER_PATH, timeout);
	}

	if (probe)
		quic_outq_transmit_probe(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

void quic_timer_reset(struct sock *sk, u8 type, u32 timeout)
{
	struct timer_list *t = quic_timer(sk, type);

	if (timeout && !mod_timer(t, jiffies + usecs_to_jiffies(timeout)))
		sock_hold(sk);
}

void quic_timer_reduce(struct sock *sk, u8 type, u32 timeout)
{
	struct timer_list *t = quic_timer(sk, type);

	if (timeout && !timer_reduce(t, jiffies + usecs_to_jiffies(timeout)))
		sock_hold(sk);
}

void quic_timer_start(struct sock *sk, u8 type, u32 timeout)
{
	struct timer_list *t = quic_timer(sk, type);

	if (timeout && !timer_pending(t)) {
		if (!mod_timer(t, jiffies + usecs_to_jiffies(timeout)))
			sock_hold(sk);
	}
}

void quic_timer_stop(struct sock *sk, u8 type)
{
	if (del_timer(quic_timer(sk, type)))
		sock_put(sk);
}

void quic_timer_init(struct sock *sk)
{
	timer_setup(quic_timer(sk, QUIC_TIMER_AP_LOSS), quic_timer_ap_loss_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_IN_LOSS), quic_timer_in_loss_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_HS_LOSS), quic_timer_hs_loss_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_SACK), quic_timer_delay_ack_timeout, 0);
	timer_setup(quic_timer(sk, QUIC_TIMER_PATH), quic_timer_path_timeout, 0);
}

void quic_timer_free(struct sock *sk)
{
	quic_timer_stop(sk, QUIC_TIMER_AP_LOSS);
	quic_timer_stop(sk, QUIC_TIMER_IN_LOSS);
	quic_timer_stop(sk, QUIC_TIMER_HS_LOSS);
	quic_timer_stop(sk, QUIC_TIMER_SACK);
	quic_timer_stop(sk, QUIC_TIMER_PATH);
}
