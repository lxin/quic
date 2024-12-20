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

static int quic_outq_limit_check(struct sock *sk, u8 type, u16 frame_len)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_path_addr *path = quic_dst(sk);
	u16 len;

	if (outq->single && outq->count)
		return -1;

	/* congestion control */
	if (!outq->single && quic_frame_ack_eliciting(type)) {
		len = quic_packet_frame_len(packet) + frame_len;
		if (outq->inflight + len > outq->window)
			return -1;
	}

	/* amplificationlimit */
	if (quic_is_serv(sk) && !quic_path_validated(path)) {
		len = quic_packet_len(packet) + frame_len + quic_packet_taglen(packet);
		if (quic_path_ampl_sndlen(path) + len > quic_path_ampl_rcvlen(path) * 3)
			return -1;
	}

	return 0;
}

static int quic_outq_transmit_flush(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	int count = outq->count;

	outq->count = 0;
	if (!quic_packet_empty(packet))
		count += quic_packet_create(sk);
	quic_packet_flush(sk);

	return count;
}

static void quic_outq_transmit_ctrl(struct sock *sk, u8 level)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;

	if (!quic_crypto_send_ready(quic_crypto(sk, level)))
		return;

	if (quic_pnspace_need_sack(space)) {
		frame = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
		if (frame) {
			frame->path_alt = quic_pnspace_path_alt(space);
			if (quic_packet_config(sk, frame->level, frame->path_alt) ||
			    quic_outq_limit_check(sk, frame->type, frame->len) ||
			    !quic_packet_tail(sk, frame)) {
				quic_frame_put(frame);
				return;
			}
			/* clear it only if the sack frame can be sent */
			quic_pnspace_set_need_sack(space, 0);
		}
	}

	head = &outq->control_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (!frame->level && level)
			break;
		if (frame->level != level)
			continue;
		if (quic_packet_config(sk, frame->level, frame->path_alt))
			break;
		if (quic_outq_limit_check(sk, frame->type, frame->len))
			break;
		if (quic_packet_tail(sk, frame))
			continue;
		outq->count += quic_packet_create(sk);
		next = frame;
	}
}

static void quic_outq_transmit_dgram(struct sock *sk, u8 level)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;

	if (level != QUIC_CRYPTO_APP)
		return;
	if (!quic_crypto_send_ready(quic_crypto(sk, outq->data_level)))
		return;

	head = &outq->datagram_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (quic_packet_config(sk, outq->data_level, frame->path_alt))
			break;
		if (quic_outq_limit_check(sk, frame->type, frame->len))
			break;
		if (quic_packet_tail(sk, frame))
			continue;
		outq->count += quic_packet_create(sk);
		next = frame;
	}
}

static int quic_outq_flow_control(struct sock *sk, struct quic_stream *stream, u16 bytes)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame = NULL;
	u8 blocked = 0;

	/* send flow control */
	if (stream->send.bytes + bytes > stream->send.max_bytes) {
		if (!stream->send.data_blocked &&
		    stream->send.last_max_bytes < stream->send.max_bytes) {
			frame = quic_frame_create(sk, QUIC_FRAME_STREAM_DATA_BLOCKED, stream);
			if (frame)
				quic_outq_ctrl_tail(sk, frame, true);
			stream->send.last_max_bytes = stream->send.max_bytes;
			stream->send.data_blocked = 1;
		}
		blocked = 1;
	}
	if (outq->bytes + bytes > outq->max_bytes) {
		if (!outq->data_blocked && outq->last_max_bytes < outq->max_bytes) {
			frame = quic_frame_create(sk, QUIC_FRAME_DATA_BLOCKED, outq);
			if (frame)
				quic_outq_ctrl_tail(sk, frame, true);
			outq->last_max_bytes = outq->max_bytes;
			outq->data_blocked = 1;
		}
		blocked = 1;
	}

	if (frame)
		quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_APP);
	return blocked;
}

static int quic_outq_delay_check(struct sock *sk, u8 level, u8 nodelay)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u64 pacing_time;

	if (level) /* do not delay for early data */
		return 0;

	/* pacing control */
	pacing_time = quic_cong_pacing_time(quic_cong(sk));
	if (pacing_time > ktime_get_ns()) {
		quic_timer_start(sk, QUIC_TIMER_PACE, pacing_time);
		return 1;
	}

	/* nagle algorithm */
	if (nodelay)
		return 0;
	if (!quic_packet_empty(packet))
		return 0;
	if ((quic_config(sk)->stream_data_nodelay || !outq->inflight) &&
	    !outq->force_delay)
		return 0;
	if (outq->stream_list_len > quic_packet_mss(packet))
		return 0;
	return 1;
}

static void quic_outq_transmit_stream(struct sock *sk, u8 level)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;

	if (level != QUIC_CRYPTO_APP)
		return;
	if (!quic_crypto_send_ready(quic_crypto(sk, outq->data_level)))
		return;

	head = &outq->stream_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (quic_outq_flow_control(sk, frame->stream, frame->bytes))
			break;
		if (quic_packet_config(sk, outq->data_level, frame->path_alt))
			break;
		if (quic_outq_limit_check(sk, frame->type, frame->len))
			break;
		if (quic_outq_delay_check(sk, outq->data_level, frame->nodelay))
			break;
		if (quic_packet_tail(sk, frame)) {
			frame->stream->send.bytes += frame->bytes;
			outq->bytes += frame->bytes;
			outq->stream_list_len -= frame->len;
			continue;
		}
		outq->count += quic_packet_create(sk);
		next = frame;
	}
}

static int quic_outq_transmit_old(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;

	head = &outq->transmitted_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (!frame->level && outq->level)
			break;
		if (frame->level != outq->level)
			continue;
		if (!quic_frame_retransmittable(frame->type))
			continue;
		if (!quic_crypto_send_ready(quic_crypto(sk, frame->level)))
			break;
		if (quic_packet_config(sk, frame->level, frame->path_alt))
			break;
		if (quic_outq_limit_check(sk, frame->type, frame->len))
			break;
		if (quic_packet_tail(sk, frame))
			continue; /* packed and conintue with the next frame */
		outq->count += quic_packet_create(sk); /* build and xmit the packed frames */
		next = frame; /* go back but still pack the current frame */
	}

	return quic_outq_transmit_flush(sk);
}

/* pack and transmit frames from outqueue */
int quic_outq_transmit(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	if (!outq->single) {
		quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_INITIAL);
		quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_HANDSHAKE);
	}

	quic_outq_transmit_ctrl(sk, outq->level);
	quic_outq_transmit_dgram(sk, outq->level);
	quic_outq_transmit_stream(sk, outq->level);

	return quic_outq_transmit_flush(sk);
}

static void quic_outq_wfree(int len, struct sock *sk)
{
	if (!len)
		return;

	WARN_ON(refcount_sub_and_test(len, &sk->sk_wmem_alloc));
	sk_wmem_queued_add(sk, -len);
	sk_mem_uncharge(sk, len);

	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

static void quic_outq_set_owner_w(int len, struct sock *sk)
{
	if (!len)
		return;

	refcount_add(len, &sk->sk_wmem_alloc);
	sk_wmem_queued_add(sk, len);
	sk_mem_charge(sk, len);
}

int quic_outq_stream_append(struct sock *sk, struct quic_msginfo *info, u8 pack)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_stream *stream = info->stream;
	struct quic_frame *frame;
	struct list_head *head;
	int len, bytes;

	head = &outq->stream_list;
	if (list_empty(head))
		return -1;
	frame = list_last_entry(head, struct quic_frame, list);
	if (frame->stream != stream || frame->nodelay || frame->offset >= 0)
		return -1;

	len = frame->len;
	bytes = quic_frame_stream_append(sk, frame, info, pack);
	if (bytes < 0 || !pack)
		return bytes;

	outq->stream_list_len += (frame->len - len);
	if (frame->type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		if (quic_stream_send_active_id(streams) == stream->id)
			quic_stream_set_send_active_id(streams, -1);
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}
	quic_outq_set_owner_w((int)bytes, sk);

	return bytes;
}

void quic_outq_stream_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream = frame->stream;
	struct quic_outqueue *outq = quic_outq(sk);

	if (stream->send.state == QUIC_STREAM_SEND_STATE_READY)
		stream->send.state = QUIC_STREAM_SEND_STATE_SEND;

	if (frame->type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		if (quic_stream_send_active_id(streams) == stream->id)
			quic_stream_set_send_active_id(streams, -1);
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}

	outq->stream_list_len += frame->len;
	stream->send.frags++;
	quic_outq_set_owner_w((int)frame->bytes, sk);
	list_add_tail(&frame->list, &outq->stream_list);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_dgram_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	quic_outq_set_owner_w((int)frame->bytes, sk);
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
			if (frame->level > pos->level)
				continue;
			if (frame->level < pos->level) {
				head = &pos->list;
				break;
			}
		}
	}
	quic_outq_set_owner_w((int)frame->bytes, sk);
	list_add_tail(&frame->list, head);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_transmitted_tail(struct sock *sk, struct quic_frame *frame)
{
	struct list_head *head = &quic_outq(sk)->transmitted_list;
	struct quic_frame *pos;

	list_for_each_entry(pos, head, list) {
		if (!frame->level) {
			if (pos->level)
				continue;
			goto offset;
		}
		if (!pos->level) {
			head = &pos->list;
			break;
		}
		if (frame->level > pos->level)
			continue;
		if (frame->level < pos->level) {
			head = &pos->list;
			break;
		}
offset:
		if (frame->offset < pos->offset) {
			head = &pos->list;
			break;
		}
	}
	frame->transmitted = 1;
	list_add_tail(&frame->list, head);
}

void quic_outq_packet_sent_tail(struct sock *sk, struct quic_packet_sent *sent)
{
	struct list_head *head = &quic_outq(sk)->packet_sent_list;
	struct quic_packet_sent *pos;

	if (sent->level) {
		list_for_each_entry(pos, head, list) {
			if (!pos->level) {
				head = &pos->list;
				break;
			}
			if (sent->level > pos->level)
				continue;
			if (sent->level < pos->level) {
				head = &pos->list;
				break;
			}
		}
	}
	list_add_tail(&sent->list, head);
}

void quic_outq_transmit_probe(struct sock *sk)
{
	struct quic_path_dst *d = (struct quic_path_dst *)quic_dst(sk);
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	u32 taglen = quic_packet_taglen(quic_packet(sk));
	u32 pathmtu, probe_size = d->pl.probe_size;
	struct quic_config *c = quic_config(sk);
	struct quic_frame *frame;
	s64 number;

	if (!quic_is_established(sk))
		return;

	if (quic_packet_config(sk, QUIC_CRYPTO_APP, 0))
		return;

	frame = quic_frame_create(sk, QUIC_FRAME_PING, &probe_size);
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
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close);

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

static void quic_outq_psent_sack_frames(struct sock *sk, struct quic_packet_sent *sent)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_stream_update update;
	struct quic_stream *stream;
	struct quic_frame *frame;
	int acked = 0, i;

	for (i = 0; i < sent->frames; i++) {
		frame = sent->frame_array[i];
		if (list_empty(&frame->list)) {
			quic_frame_put(frame);
			continue;
		}
		quic_frame_put(frame);

		stream = frame->stream;
		if (quic_frame_stream(frame->type)) {
			stream->send.frags--;
			if (!stream->send.frags &&
			    stream->send.state == QUIC_STREAM_SEND_STATE_SENT) {
				update.id = stream->id;
				update.state = QUIC_STREAM_SEND_STATE_RECVD;
				quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

				stream->send.state = update.state;
				quic_stream_send_put(streams, stream, quic_is_serv(sk));
				sk->sk_write_space(sk);
			}
		} else if (quic_frame_reset_stream(frame->type)) {
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
			update.errcode = stream->send.errcode;
			quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update);

			stream->send.state = update.state;
			quic_stream_send_put(streams, stream, quic_is_serv(sk));
			sk->sk_write_space(sk);
		} else if (quic_frame_stream_data_blocked(frame->type)) {
			stream->send.data_blocked = 0;
		} else if (quic_frame_data_blocked(frame->type)) {
			outq->data_blocked = 0;
		}

		acked += frame->bytes;
		frame->transmitted = 0;
		list_del_init(&frame->list);
		quic_frame_put(frame);
	}
	quic_outq_wfree(acked, sk);
}

static void quic_outq_path_confirm(struct sock *sk, u8 level, s64 largest, s64 smallest)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_path_addr *path = quic_dst(sk);
	struct quic_config *c = quic_config(sk);
	bool raise_timer, complete;
	u32 pathmtu;

	if (quic_path_validated(path) || level == QUIC_CRYPTO_HANDSHAKE)
		outq->pto_count = 0;

	if (!quic_path_pl_confirm(path, largest, smallest))
		return;

	pathmtu = quic_path_pl_recv(path, &raise_timer, &complete);
	if (pathmtu)
		quic_packet_mss_update(sk, pathmtu + quic_packet_taglen(quic_packet(sk)));
	if (!complete)
		quic_outq_transmit_probe(sk);
	if (raise_timer) /* reuse probe timer as raise timer */
		quic_timer_reset(sk, QUIC_TIMER_PATH, (u64)c->plpmtud_probe_interval * 30);
}

void quic_outq_transmitted_sack(struct sock *sk, u8 level, s64 largest, s64 smallest,
				s64 ack_largest, u32 ack_delay)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	struct quic_crypto *crypto = quic_crypto(sk, level);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_packet_sent *sent, *next;
	u32 pto, acked = 0;

	quic_outq_path_confirm(sk, level, largest, smallest);
	pr_debug("%s: largest: %llu, smallest: %llu\n", __func__, largest, smallest);

	list_for_each_entry_safe_reverse(sent, next, &outq->packet_sent_list, list) {
		if (level != sent->level)
			continue;
		if (sent->number > largest)
			continue;
		if (sent->number < smallest)
			break;

		if (sent->ecn)
			quic_set_sk_ecn(sk, INET_ECN_ECT_0);

		outq->inflight -= sent->frame_len;
		quic_outq_psent_sack_frames(sk, sent);
		quic_pnspace_dec_inflight(space, sent->frame_len);

		if (sent->number == ack_largest) {
			quic_pnspace_set_max_pn_acked_seen(space, sent->number);
			quic_cong_rtt_update(cong, sent->sent_time, ack_delay);

			pto = quic_cong_pto(cong);
			quic_pnspace_set_max_time_limit(space, pto * 2);
			quic_crypto_set_key_update_time(crypto, pto * 2);
		}
		quic_cong_on_packet_acked(cong, sent->sent_time, sent->frame_len, sent->number);
		quic_outq_sync_window(sk, quic_cong_window(cong));

		acked += sent->frame_len;
		list_del(&sent->list);
		kfree(sent);
	}

	quic_cong_on_ack_recv(cong, acked, READ_ONCE(sk->sk_max_pacing_rate));
}

/* GetLossTimeAndSpace() */
static u32 quic_outq_get_loss_time(struct sock *sk, u8 *level)
{
	struct quic_pnspace *s;
	u32 time, t;

	s = quic_pnspace(sk, QUIC_CRYPTO_INITIAL);
	t = quic_pnspace_loss_time(s);
	time = t;
	*level = QUIC_CRYPTO_INITIAL;

	s = quic_pnspace(sk, QUIC_CRYPTO_HANDSHAKE);
	t = quic_pnspace_loss_time(s);
	if (t && (!time || time > t)) {
		time = t;
		*level = QUIC_CRYPTO_HANDSHAKE;
	}

	s = quic_pnspace(sk, QUIC_CRYPTO_APP);
	t = quic_pnspace_loss_time(s);
	if (t && (!time || time > t)) {
		time = t;
		*level = QUIC_CRYPTO_APP;
	}

	return time;
}

/* GetPtoTimeAndSpace() */
static u32 quic_outq_get_pto_time(struct sock *sk, u8 *level)
{
	u32 duration, t, time = 0, now = jiffies_to_usecs(jiffies);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_pnspace *s;

	duration = quic_cong_pto(quic_cong(sk)) * (1 << outq->pto_count);

	if (!outq->inflight) {
		*level = QUIC_CRYPTO_INITIAL;
		if (quic_crypto_send_ready(quic_crypto(sk, QUIC_CRYPTO_HANDSHAKE)))
			*level = QUIC_CRYPTO_HANDSHAKE;
		return now + duration;
	}

	s = quic_pnspace(sk, QUIC_CRYPTO_INITIAL);
	if (quic_pnspace_inflight(s)) {
		t = quic_pnspace_last_sent_time(s) + duration;
		time = t;
		*level = QUIC_CRYPTO_INITIAL;
	}

	s = quic_pnspace(sk, QUIC_CRYPTO_HANDSHAKE);
	if (quic_pnspace_inflight(s)) {
		t = quic_pnspace_last_sent_time(s) + duration;
		if (!time || time > t) {
			time = t;
			*level = QUIC_CRYPTO_HANDSHAKE;
		}
	}

	if (time)
		return time;

	s =  quic_pnspace(sk, QUIC_CRYPTO_APP);
	if (quic_pnspace_inflight(s)) {
		duration += (outq->max_ack_delay * (1 << outq->pto_count));
		t = quic_pnspace_last_sent_time(s) + duration;
		if (!time || time > t) {
			time = t;
			*level = QUIC_CRYPTO_APP;
		}
	}

	return time;
}

/* SetLossDetectionTimer() */
void quic_outq_update_loss_timer(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 time, now = jiffies_to_usecs(jiffies);
	u8 level, valid;

	time = quic_outq_get_loss_time(sk, &level);
	if (time)
		goto out;

	valid = quic_path_validated(quic_dst(sk));
	if (!outq->inflight && (quic_is_serv(sk) || valid))
		return quic_timer_stop(sk, QUIC_TIMER_LOSS);

	time = quic_outq_get_pto_time(sk, &level);

out:
	time = (time > now) ? (time - now) : 1;
	quic_timer_reset(sk, QUIC_TIMER_LOSS, time);
}

void quic_outq_sync_window(struct sock *sk, u32 window)
{
	struct quic_outqueue *outq = quic_outq(sk);

	if (outq->window == window)
		return;
	outq->window = window;

	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return;
	if (sk->sk_sndbuf > (int)window * 2)
		if (sk_stream_wspace(sk) > 0)
			sk->sk_write_space(sk);
	sk->sk_sndbuf = (int)window * 2;
}

/* put the timeout frame back to the corresponding outqueue */
static void quic_outq_retransmit_frame(struct sock *sk, struct quic_frame *frame)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *pos;
	struct list_head *head;

	head = &outq->control_list;
	if (quic_frame_stream(frame->type)) {
		head = &outq->stream_list;

		frame->stream->send.bytes -= frame->bytes;
		outq->bytes -= frame->bytes;
		outq->stream_list_len += frame->len;
	}

	list_for_each_entry(pos, head, list) {
		if (!frame->level) {
			if (pos->level)
				continue;
			goto offset;
		}
		if (!pos->level) {
			head = &pos->list;
			break;
		}
		if (frame->level > pos->level)
			continue;
		if (frame->level < pos->level) {
			head = &pos->list;
			break;
		}
offset:
		if (pos->offset < 0 || frame->offset < pos->offset) {
			head = &pos->list;
			break;
		}
	}
	list_add_tail(&frame->list, head);
	QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_RETRANS);
}

static void quic_outq_psent_retransmit_frames(struct sock *sk, struct quic_packet_sent *sent)
{
	struct quic_frame *frame;
	int bytes = 0, i;

	for (i = 0; i < sent->frames; i++) {
		frame = sent->frame_array[i];
		if (list_empty(&frame->list)) {
			quic_frame_put(frame);
			continue;
		}
		quic_frame_put(frame);

		if (frame->transmitted) {
			list_del_init(&frame->list);

			if (!quic_frame_retransmittable(frame->type)) {
				bytes += frame->bytes;
				quic_frame_put(frame);
				continue;
			}
			frame->transmitted = 0;
			quic_outq_retransmit_frame(sk, frame); /* mark as loss */
		}
	}
	quic_outq_wfree(bytes, sk);
}

/* DetectAndRemoveLostPackets() */
void quic_outq_retransmit_mark(struct sock *sk, u8 level, u8 immediate)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_packet_sent *sent, *next;
	u32 time, now, pto, loss_time;
	s64 seen;

	seen = quic_pnspace_max_pn_acked_seen(space);
	time = quic_pnspace_max_pn_acked_time(space);
	now = jiffies_to_usecs(jiffies);
	pto = quic_cong_pto(cong);

	quic_pnspace_set_loss_time(space, 0);
	quic_cong_set_time(cong, now);

	list_for_each_entry_safe(sent, next, &outq->packet_sent_list, list) {
		if (level && !sent->level)
			break;
		if (level != sent->level)
			continue;
		if (!immediate && sent->number > seen)
			break;

		if (!immediate && sent->sent_time + pto > now && sent->number + 3 > seen) {
			loss_time = quic_pnspace_loss_time(space);
			if (!loss_time || loss_time > sent->sent_time + pto) {
				loss_time = sent->sent_time + pto;
				quic_pnspace_set_loss_time(space, loss_time);
			}
			break;
		}

		outq->inflight -= sent->frame_len;
		quic_outq_psent_retransmit_frames(sk, sent);
		quic_pnspace_dec_inflight(space, sent->frame_len);

		quic_cong_on_packet_lost(cong, time, sent->frame_len, sent->number);
		quic_outq_sync_window(sk, quic_cong_window(cong));

		list_del(&sent->list);
		kfree(sent);
	}
}

void quic_outq_retransmit_list(struct sock *sk, struct list_head *head)
{
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		list_del_init(&frame->list);

		if (!quic_frame_retransmittable(frame->type)) {
			bytes += frame->bytes;
			quic_frame_put(frame);
			continue;
		}
		frame->transmitted = 0;
		quic_outq_retransmit_frame(sk, frame);
	}
	quic_outq_wfree(bytes, sk);
}

/* OnLossDetectionTimeout() */
void quic_outq_transmit_pto(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame;
	u32 time, probe_size = 0;
	u8 level;

	time = quic_outq_get_loss_time(sk, &level);
	if (time) {
		quic_outq_retransmit_mark(sk, level, 0);
		quic_outq_update_loss_timer(sk);
		quic_outq_transmit(sk);
		return;
	}

	quic_outq_get_pto_time(sk, &level);

	outq->single = 1;
	outq->level = level;
	if (quic_outq_transmit(sk) || quic_outq_transmit_old(sk))
		goto out;

	if (quic_packet_config(sk, level, 0))
		goto out;

	frame = quic_frame_create(sk, QUIC_FRAME_PING, &probe_size);
	if (frame) {
		frame->level = level;
		quic_outq_ctrl_tail(sk, frame, false);
	}

out:
	outq->level = 0;
	outq->single = 0;
	if (outq->pto_count < 4)
		outq->pto_count++;
	quic_outq_update_loss_timer(sk);
}

void quic_outq_validate_path(struct sock *sk, struct quic_frame *frame,
			     struct quic_path_addr *path)
{
	u8 local = quic_path_udp_bind(path), path_alt = QUIC_PATH_ALT_DST;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_config *c = quic_config(sk);
	struct quic_frame *pos;
	struct list_head *head;

	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_MIGRATION, &local);

	if (local) {
		quic_path_swap_active(path);
		path_alt = QUIC_PATH_ALT_SRC;
	} else {
		quic_path_set_validated(path, 1);
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
}

void quic_outq_stream_list_purge(struct sock *sk, struct quic_stream *stream)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, &outq->transmitted_list, list) {
		if (frame->stream != stream)
			continue;

		bytes += frame->bytes;
		list_del_init(&frame->list);
		quic_frame_put(frame);
	}

	list_for_each_entry_safe(frame, next, &outq->stream_list, list) {
		if (frame->stream != stream)
			continue;

		outq->stream_list_len -= frame->len;
		bytes += frame->bytes;
		list_del_init(&frame->list);
		quic_frame_put(frame);
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
	INIT_LIST_HEAD(&outq->packet_sent_list);
	skb_queue_head_init(&sk->sk_write_queue);
	INIT_WORK(&outq->work, quic_outq_encrypted_work);
}

static void quic_outq_psent_list_purge(struct sock *sk, struct list_head *head)
{
	struct quic_packet_sent *sent, *next;

	list_for_each_entry_safe(sent, next, head, list) {
		quic_outq_psent_sack_frames(sk, sent);
		list_del(&sent->list);
		kfree(sent);
	}
}

static void quic_outq_list_purge(struct sock *sk, struct list_head *head)
{
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		bytes += frame->bytes;
		list_del_init(&frame->list);
		quic_frame_put(frame);
	}
	quic_outq_wfree(bytes, sk);
}

void quic_outq_free(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	quic_outq_psent_list_purge(sk, &outq->packet_sent_list);
	quic_outq_list_purge(sk, &outq->transmitted_list);
	quic_outq_list_purge(sk, &outq->datagram_list);
	quic_outq_list_purge(sk, &outq->control_list);
	quic_outq_list_purge(sk, &outq->stream_list);
	kfree(outq->close_phrase);
}
