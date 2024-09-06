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

#include "socket.h"

static void quic_outq_transmit_ctrl(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *tmp;
	struct list_head *head;

	head =  &outq->control_list;
	list_for_each_entry_safe(frame, tmp, head, list) {
		if (!quic_crypto_send_ready(quic_crypto(sk, frame->level)))
			break;
		if (quic_packet_config(sk, frame->level, frame->path_alt))
			break;
		if (quic_packet_tail(sk, frame, 0)) {
			outq->data_inflight += frame->bytes;
			continue; /* packed and conintue with the next frame */
		}
		quic_packet_create(sk); /* build and xmit the packed frames */
		tmp = frame; /* go back but still pack the current frame */
	}
}

static bool quic_outq_pacing_check(struct sock *sk, u16 bytes)
{
	u64 pacing_time = quic_cong_pacing_time(quic_cong(sk));

	if (pacing_time <= ktime_get_ns())
		return false;

	quic_timer_start(sk, QUIC_TIMER_PACE, pacing_time);
	return true;
}

static void quic_outq_transmit_dgram(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *tmp;
	u8 level = outq->data_level;
	struct list_head *head;

	if (!quic_crypto_send_ready(quic_crypto(sk, level)))
		return;

	head =  &outq->datagram_list;
	list_for_each_entry_safe(frame, tmp, head, list) {
		if (outq->data_inflight + frame->bytes > outq->window)
			break;
		if (quic_outq_pacing_check(sk, frame->bytes))
			break;
		if (quic_packet_config(sk, level, frame->path_alt))
			break;
		if (quic_packet_tail(sk, frame, 1)) {
			outq->data_inflight += frame->bytes;
			continue;
		}
		quic_packet_create(sk);
		tmp = frame;
	}
}

static int quic_outq_flow_control(struct sock *sk, struct quic_frame *frame)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *nframe = NULL;
	struct quic_stream *stream;
	u32 len = frame->bytes;
	u8 blocked = 0;

	/* congestion control */
	if (outq->data_inflight + len > outq->window)
		blocked = 1;

	/* send flow control */
	stream = frame->stream;
	if (stream->send.bytes + len > stream->send.max_bytes) {
		if (!stream->send.data_blocked &&
		    stream->send.last_max_bytes < stream->send.max_bytes) {
			nframe = quic_frame_create(sk, QUIC_FRAME_STREAM_DATA_BLOCKED, stream);
			if (nframe)
				quic_outq_ctrl_tail(sk, nframe, true);
			stream->send.last_max_bytes = stream->send.max_bytes;
			stream->send.data_blocked = 1;
		}
		blocked = 1;
	}
	if (outq->bytes + len > outq->max_bytes) {
		if (!outq->data_blocked && outq->last_max_bytes < outq->max_bytes) {
			nframe = quic_frame_create(sk, QUIC_FRAME_DATA_BLOCKED, outq);
			if (nframe)
				quic_outq_ctrl_tail(sk, nframe, true);
			outq->last_max_bytes = outq->max_bytes;
			outq->data_blocked = 1;
		}
		blocked = 1;
	}

	if (nframe)
		quic_outq_transmit_ctrl(sk);
	return blocked;
}

static void quic_outq_transmit_stream(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *tmp;
	u8 level = outq->data_level;
	struct list_head *head;

	if (!quic_crypto_send_ready(quic_crypto(sk, level)))
		return;

	head = &outq->stream_list;
	list_for_each_entry_safe(frame, tmp, head, list) {
		if (!level && quic_outq_flow_control(sk, frame))
			break;
		if (quic_outq_pacing_check(sk, frame->bytes))
			break;
		if (quic_packet_config(sk, level, frame->path_alt))
			break;
		if (quic_packet_tail(sk, frame, 0)) {
			frame->stream->send.frags++;
			frame->stream->send.bytes += frame->bytes;
			outq->bytes += frame->bytes;
			outq->data_inflight += frame->bytes;
			continue;
		}
		quic_packet_create(sk);
		tmp = frame;
	}
}

/* pack and transmit frames from outqueue */
int quic_outq_transmit(struct sock *sk)
{
	quic_outq_transmit_ctrl(sk);

	quic_outq_transmit_dgram(sk);

	quic_outq_transmit_stream(sk);

	return quic_packet_flush(sk);
}

void quic_outq_wfree(int len, struct sock *sk)
{
	if (!len)
		return;

	WARN_ON(refcount_sub_and_test(len, &sk->sk_wmem_alloc));
	sk_wmem_queued_add(sk, -len);
	sk_mem_uncharge(sk, len);

	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

void quic_outq_set_owner_w(int len, struct sock *sk)
{
	if (!len)
		return;

	refcount_add(len, &sk->sk_wmem_alloc);
	sk_wmem_queued_add(sk, len);
	sk_mem_charge(sk, len);
}

void quic_outq_stream_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream = frame->stream;

	if (stream->send.state == QUIC_STREAM_SEND_STATE_READY)
		stream->send.state = QUIC_STREAM_SEND_STATE_SEND;

	if (frame->type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		if (quic_stream_send_active(streams) == stream->id)
			quic_stream_set_send_active(streams, -1);
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}

	list_add_tail(&frame->list, &quic_outq(sk)->stream_list);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_dgram_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	list_add_tail(&frame->list, &quic_outq(sk)->datagram_list);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_ctrl_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	struct list_head *head = &quic_outq(sk)->control_list;
	struct quic_frame *pos;

	if (frame->level) { /* prioritize handshake frames */
		list_for_each_entry(pos, head, list) {
			if (!pos->level) {
				head = &pos->list;
				break;
			}
		}
	}
	list_add_tail(&frame->list, head);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_transmitted_tail(struct sock *sk, struct quic_frame *frame)
{
	struct list_head *head = &quic_outq(sk)->transmitted_list;
	struct quic_frame *pos;

	if (frame->level) { /* prioritize handshake frames */
		list_for_each_entry(pos, head, list) {
			if (!pos->level) {
				head = &pos->list;
				break;
			}
		}
	}
	list_add_tail(&frame->list, head);
}

void quic_outq_transmit_probe(struct sock *sk)
{
	struct quic_path_dst *d = (struct quic_path_dst *)quic_dst(sk);
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	u8 taglen = quic_packet_taglen(quic_packet(sk));
	struct quic_config *c = quic_config(sk);
	struct quic_frame *frame;
	u32 pathmtu;
	s64 number;

	if (!quic_is_established(sk))
		return;

	frame = quic_frame_create(sk, QUIC_FRAME_PING, &d->pl.probe_size);
	if (frame) {
		number = quic_pnspace_next_pn(space);
		quic_outq_ctrl_tail(sk, frame, false);

		pathmtu = quic_path_pl_send(quic_dst(sk), number);
		if (pathmtu)
			quic_packet_mss_update(sk, pathmtu + taglen);
	}

	quic_timer_reset(sk, QUIC_TIMER_PATH, c->plpmtud_probe_interval);
}

void quic_outq_transmit_close(struct sock *sk, u8 type, u32 errcode, u8 level)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close close = {};
	struct quic_frame *frame;

	if (!errcode)
		return;

	close.errcode = errcode;
	close.frame = type;
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close))
		return;

	quic_outq_set_close_errcode(outq, errcode);
	quic_outq_set_close_frame(outq, type);

	frame = quic_frame_create(sk, QUIC_FRAME_CONNECTION_CLOSE, NULL);
	if (frame) {
		frame->level = level;
		quic_outq_ctrl_tail(sk, frame, false);
	}
	quic_set_state(sk, QUIC_SS_CLOSED);
}

void quic_outq_transmit_app_close(struct sock *sk)
{
	u32 errcode = QUIC_TRANSPORT_ERROR_APPLICATION;
	u8 type = QUIC_FRAME_CONNECTION_CLOSE, level;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame;

	if (quic_is_established(sk)) {
		level = QUIC_CRYPTO_APP;
		type = QUIC_FRAME_CONNECTION_CLOSE_APP;
	} else if (quic_is_establishing(sk)) {
		level = QUIC_CRYPTO_INITIAL;
		quic_outq_set_close_errcode(outq, errcode);
	} else {
		return;
	}

	/* send close frame only when it's NOT idle timeout or closed by peer */
	frame = quic_frame_create(sk, type, NULL);
	if (frame) {
		frame->level = level;
		quic_outq_ctrl_tail(sk, frame, false);
	}
}

void quic_outq_transmitted_sack(struct sock *sk, u8 level, s64 largest, s64 smallest,
				s64 ack_largest, u32 ack_delay)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	struct quic_crypto *crypto = quic_crypto(sk, level);
	u32 pathmtu, rto, acked = 0, bytes = 0, pbytes = 0;
	struct quic_path_addr *path = quic_dst(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_config *c = quic_config(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_stream_update update;
	struct quic_frame *frame, *tmp;
	struct quic_stream *stream;
	bool raise_timer, complete;
	struct list_head *head;

	pr_debug("%s: largest: %llu, smallest: %llu\n", __func__, largest, smallest);
	if (quic_path_pl_confirm(path, largest, smallest)) {
		pathmtu = quic_path_pl_recv(path, &raise_timer, &complete);
		if (pathmtu)
			quic_packet_mss_update(sk, pathmtu + quic_packet_taglen(quic_packet(sk)));
		if (!complete)
			quic_outq_transmit_probe(sk);
		if (raise_timer) /* reuse probe timer as raise timer */
			quic_timer_reset(sk, QUIC_TIMER_PATH, c->plpmtud_probe_interval * 30);
	}

	head = &outq->transmitted_list;
	list_for_each_entry_safe_reverse(frame, tmp, head, list) {
		if (level != frame->level)
			continue;
		if (frame->number > largest)
			continue;
		if (frame->number < smallest)
			break;
		stream = frame->stream;
		if (frame->bytes) {
			if (stream && !(--stream->send.frags) &&
			    stream->send.state == QUIC_STREAM_SEND_STATE_SENT) {
				update.id = stream->id;
				update.state = QUIC_STREAM_SEND_STATE_RECVD;
				if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update)) {
					stream->send.frags++;
					continue;
				}
				stream->send.state = update.state;
			}
			if (!quic_frame_is_crypto(frame->type))
				pbytes += frame->bytes;
		} else if (frame->type == QUIC_FRAME_RESET_STREAM) {
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
			update.errcode = stream->send.errcode;
			if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
				continue;
			stream->send.state = update.state;
		} else if (frame->type == QUIC_FRAME_STREAM_DATA_BLOCKED) {
			stream->send.data_blocked = 0;
		} else if (frame->type == QUIC_FRAME_DATA_BLOCKED) {
			outq->data_blocked = 0;
		}

		if (frame->ecn)
			quic_set_sk_ecn(sk, INET_ECN_ECT_0);

		quic_pnspace_set_max_pn_acked_seen(space, frame->number);
		quic_pnspace_dec_inflight(space, frame->len);
		outq->data_inflight -= frame->bytes;
		list_del(&frame->list);
		acked += frame->bytes;

		if (frame->first) {
			if (frame->number == ack_largest) {
				quic_cong_rtt_update(cong, frame->sent_time, ack_delay);
				rto = quic_cong_rto(cong);
				quic_pnspace_set_max_time_limit(space, rto * 2);
				quic_crypto_set_key_update_time(crypto, rto * 2);
			}
			if (pbytes) {
				bytes += pbytes;
				quic_cong_on_packet_acked(cong, frame->sent_time, pbytes,
							  frame->number);
				quic_outq_sync_window(sk);
				pbytes = 0;
			}
		}

		quic_frame_free(frame);
	}

	outq->rtx_count = 0;
	quic_outq_wfree(acked, sk);
	quic_cong_on_ack_recv(cong, bytes, READ_ONCE(sk->sk_max_pacing_rate));
}

void quic_outq_update_loss_timer(struct sock *sk, u8 level)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	u32 timeout, now = jiffies_to_usecs(jiffies);

	timeout = quic_pnspace_loss_time(space);
	if (timeout)
		goto out;

	if (!quic_pnspace_inflight(space))
		return quic_timer_stop(sk, level);

	timeout = quic_cong_duration(quic_cong(sk));
	timeout *= (1 + quic_outq(sk)->rtx_count);
	timeout += quic_pnspace_last_sent_time(space);
out:
	if (timeout < now)
		timeout = now + 1;
	quic_timer_reduce(sk, level, timeout - now);
}

void quic_outq_sync_window(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);
	u32 window = quic_cong_window(cong);

	if (window == outq->window)
		return;
	outq->window = window;

	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return;
	if (sk->sk_sndbuf > 2 * window)
		if (sk_stream_wspace(sk) > 0)
			sk->sk_write_space(sk);
	sk->sk_sndbuf = 2 * window;
}

/* put the timeout frame back to the corresponding outqueue */
static void quic_outq_retransmit_one(struct sock *sk, struct quic_frame *frame)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *pos, *tmp;
	struct list_head *head;

	head = &outq->control_list;
	if (frame->bytes && !quic_frame_is_crypto(frame->type)) {
		head = &outq->stream_list;
		frame->stream->send.frags--;
		frame->stream->send.bytes -= frame->bytes;
		outq->bytes -= frame->bytes;
	}

	list_for_each_entry_safe(pos, tmp, head, list) {
		if (frame->level < pos->level)
			continue;
		if (frame->level > pos->level) {
			head = &pos->list;
			break;
		}
		if (!pos->offset || frame->offset < pos->offset) {
			head = &pos->list;
			break;
		}
	}
	list_add_tail(&frame->list, head);
}

int quic_outq_retransmit_mark(struct sock *sk, u8 level, u8 immediate)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	u32 time, now, rto, count = 0, freed = 0, bytes = 0;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_frame *frame, *tmp;
	struct list_head *head;

	quic_pnspace_set_loss_time(space, 0);
	now = jiffies_to_usecs(jiffies);
	quic_cong_set_time(cong, now);
	head = &outq->transmitted_list;
	list_for_each_entry_safe(frame, tmp, head, list) {
		if (level != frame->level)
			continue;

		rto = quic_cong_rto(cong);
		if (!immediate && frame->sent_time + rto > now &&
		    frame->number + 6 > quic_pnspace_max_pn_acked_seen(space)) {
			quic_pnspace_set_loss_time(space, frame->sent_time + rto);
			break;
		}

		quic_pnspace_dec_inflight(space, frame->len);
		outq->data_inflight -= frame->bytes;
		list_del(&frame->list);
		bytes += frame->bytes;

		if (frame->last && bytes) {
			time = quic_pnspace_max_pn_acked_time(space);
			quic_cong_on_packet_lost(cong, time, bytes, frame->number);
			quic_outq_sync_window(sk);
			bytes = 0;
		}
		if (quic_frame_is_dgram(frame->type)) { /* no need to retransmit dgram */
			freed += frame->bytes;
			quic_frame_free(frame);
		} else {
			quic_outq_retransmit_one(sk, frame); /* mark as loss */
			count++;
		}
	}
	quic_outq_wfree(freed, sk);
	quic_outq_update_loss_timer(sk, level);
	return count;
}

void quic_outq_retransmit_list(struct sock *sk, struct list_head *head)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *tmp;
	int bytes = 0;

	list_for_each_entry_safe(frame, tmp, head, list) {
		list_del(&frame->list);
		outq->data_inflight -= frame->bytes;
		if (quic_frame_is_dgram(frame->type)) {
			bytes += frame->bytes;
			quic_frame_free(frame);
			continue;
		}
		quic_outq_retransmit_one(sk, frame);
	}
	quic_outq_wfree(bytes, sk);
}

void quic_outq_transmit_one(struct sock *sk, u8 level)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u32 probe_size = QUIC_MIN_UDP_PAYLOAD;
	struct quic_frame *frame;

	quic_packet_set_max_snd_count(packet, 1);
	if (quic_outq_transmit(sk))
		goto out;

	if (quic_outq_retransmit_mark(sk, level, 0)) {
		quic_packet_set_max_snd_count(packet, 1);
		if (quic_outq_transmit(sk))
			goto out;
	}

	frame = quic_frame_create(sk, QUIC_FRAME_PING, &probe_size);
	if (frame) {
		frame->level = level;
		quic_outq_ctrl_tail(sk, frame, false);
	}
out:
	outq->rtx_count++;
	quic_outq_update_loss_timer(sk, level);
}

void quic_outq_validate_path(struct sock *sk, struct quic_frame *frame,
			     struct quic_path_addr *path)
{
	u8 local = quic_path_udp_bind(path), path_alt = QUIC_PATH_ALT_DST;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_config *c = quic_config(sk);
	struct quic_frame *pos;
	struct list_head *head;

	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_MIGRATION, &local))
		return;

	if (local) {
		quic_path_swap_active(path);
		path_alt = QUIC_PATH_ALT_SRC;
	}
	quic_path_addr_free(sk, path, 1);
	quic_set_sk_addr(sk, quic_path_addr(path, 0), local);
	quic_path_set_sent_cnt(path, 0);
	quic_timer_stop(sk, QUIC_TIMER_PATH);
	quic_timer_reset(sk, QUIC_TIMER_PATH, c->plpmtud_probe_interval);

	head = &outq->control_list;
	list_for_each_entry(pos, head, list)
		pos->path_alt &= ~path_alt;

	head = &outq->transmitted_list;
	list_for_each_entry(pos, head, list)
		pos->path_alt &= ~path_alt;

	frame->path_alt &= ~path_alt;
	quic_packet_set_ecn_probes(quic_packet(sk), 0);
}

void quic_outq_stream_purge(struct sock *sk, struct quic_stream *stream)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *tmp;
	struct quic_pnspace *space;
	struct list_head *head;
	int bytes = 0;

	head = &outq->transmitted_list;
	list_for_each_entry_safe(frame, tmp, head, list) {
		if (frame->stream != stream)
			continue;

		space = quic_pnspace(sk, frame->level);
		quic_pnspace_dec_inflight(space, frame->len);
		outq->data_inflight -= frame->bytes;
		list_del(&frame->list);
		bytes += frame->bytes;

		quic_frame_free(frame);
	}

	head = &outq->stream_list;
	list_for_each_entry_safe(frame, tmp, head, list) {
		if (frame->stream != stream)
			continue;
		list_del(&frame->list);
		bytes += frame->bytes;
		quic_frame_free(frame);
	}
	quic_outq_wfree(bytes, sk);
}

void quic_outq_list_purge(struct sock *sk, struct list_head *head)
{
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		list_del(&frame->list);
		bytes += frame->bytes;
		quic_frame_free(frame);
	}
	quic_outq_wfree(bytes, sk);
}

static void quic_outq_encrypted_work(struct work_struct *work)
{
	struct quic_sock *qs = container_of(work, struct quic_sock, outq.work);
	struct sock *sk = &qs->inet.sk;
	struct sk_buff_head *head;
	struct quic_crypto_cb *cb;
	struct sk_buff *skb;

	lock_sock(sk);
	head = &sk->sk_write_queue;
	if (sock_flag(sk, SOCK_DEAD)) {
		skb_queue_purge(head);
		goto out;
	}

	skb = skb_dequeue(head);
	while (skb) {
		cb = QUIC_CRYPTO_CB(skb);
		if (quic_packet_config(sk, cb->level, cb->path_alt)) {
			kfree_skb(skb);
			skb = skb_dequeue(head);
			continue;
		}
		/* the skb here is ready to send */
		cb->resume = 1;
		quic_packet_xmit(sk, skb);
		skb = skb_dequeue(head);
	}
	quic_packet_flush(sk);
out:
	release_sock(sk);
	sock_put(sk);
}

void quic_outq_encrypted_tail(struct sock *sk, struct sk_buff *skb)
{
	struct quic_outqueue *outq = quic_outq(sk);

	sock_hold(sk);
	skb_queue_tail(&sk->sk_write_queue, skb);

	if (!schedule_work(&outq->work))
		sock_put(sk);
}

void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	u32 remote_idle, local_idle, pmtu;

	outq->max_datagram_frame_size = p->max_datagram_frame_size;
	pmtu = min_t(u32, dst_mtu(__sk_dst_get(sk)), QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - quic_encap_len(sk));

	outq->max_udp_payload_size = p->max_udp_payload_size;
	outq->ack_delay_exponent = p->ack_delay_exponent;
	outq->max_idle_timeout = p->max_idle_timeout;
	outq->max_ack_delay = p->max_ack_delay;
	outq->grease_quic_bit = p->grease_quic_bit;
	outq->disable_1rtt_encryption = p->disable_1rtt_encryption;
	outq->max_bytes = p->max_data;

	remote_idle = outq->max_idle_timeout;
	local_idle = quic_inq_max_idle_timeout(inq);
	if (remote_idle && (!local_idle || remote_idle < local_idle))
		quic_inq_set_max_idle_timeout(inq, remote_idle);

	if (quic_inq_disable_1rtt_encryption(inq) && outq->disable_1rtt_encryption)
		quic_packet_set_taglen(quic_packet(sk), 0);
}

void quic_outq_init(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	INIT_LIST_HEAD(&outq->stream_list);
	INIT_LIST_HEAD(&outq->control_list);
	INIT_LIST_HEAD(&outq->datagram_list);
	INIT_LIST_HEAD(&outq->transmitted_list);
	skb_queue_head_init(&sk->sk_write_queue);
	INIT_WORK(&outq->work, quic_outq_encrypted_work);
}

void quic_outq_free(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	quic_outq_list_purge(sk, &outq->transmitted_list);
	quic_outq_list_purge(sk, &outq->datagram_list);
	quic_outq_list_purge(sk, &outq->control_list);
	quic_outq_list_purge(sk, &outq->stream_list);
	kfree(outq->close_phrase);
}
