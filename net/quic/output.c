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
#include "frame.h"

static void quic_outq_transmit_ctrl(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	struct sk_buff *skb, *tmp;
	int ret;

	head =  &outq->control_list;
	skb_queue_walk_safe(head, skb, tmp) {
		snd_cb = QUIC_SND_CB(skb);
		if (!quic_crypto_send_ready(quic_crypto(sk, snd_cb->level)))
			break;
		ret = quic_packet_config(sk, snd_cb->level, snd_cb->path_alt);
		if (ret) { /* filtered out this frame */
			if (ret > 0)
				continue;
			break;
		}
		if (quic_packet_tail(sk, skb, head, 0))
			continue; /* packed and conintue with the next frame */
		quic_packet_create(sk); /* build and xmit the packed frames */
		tmp = skb; /* go back but still pack the current frame */
	}
}

static void quic_outq_transmit_dgram(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u8 level = outq->data_level;
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	struct sk_buff *skb, *tmp;
	int ret;

	if (!quic_crypto_send_ready(quic_crypto(sk, level)))
		return;

	head =  &outq->datagram_list;
	skb_queue_walk_safe(head, skb, tmp) {
		if (outq->data_inflight + skb->len > outq->window)
			break;
		snd_cb = QUIC_SND_CB(skb);
		ret = quic_packet_config(sk, level, snd_cb->path_alt);
		if (ret) {
			if (ret > 0)
				continue;
			break;
		}
		if (quic_packet_tail(sk, skb, head, 1)) {
			outq->data_inflight += snd_cb->data_bytes;
			continue;
		}
		quic_packet_create(sk);
		tmp = skb;
	}
}

static int quic_outq_flow_control(struct sock *sk, struct sk_buff *skb)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 len = QUIC_SND_CB(skb)->data_bytes;
	struct sk_buff *nskb = NULL;
	struct quic_stream *stream;
	u8 blocked = 0;

	/* congestion control */
	if (outq->data_inflight + len > outq->window)
		blocked = 1;

	/* send flow control */
	stream = QUIC_SND_CB(skb)->stream;
	if (stream->send.bytes + len > stream->send.max_bytes) {
		if (!stream->send.data_blocked &&
		    stream->send.last_max_bytes < stream->send.max_bytes) {
			nskb = quic_frame_create(sk, QUIC_FRAME_STREAM_DATA_BLOCKED, stream);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			stream->send.last_max_bytes = stream->send.max_bytes;
			stream->send.data_blocked = 1;
		}
		blocked = 1;
	}
	if (outq->bytes + len > outq->max_bytes) {
		if (!outq->data_blocked && outq->last_max_bytes < outq->max_bytes) {
			nskb = quic_frame_create(sk, QUIC_FRAME_DATA_BLOCKED, outq);
			if (nskb)
				quic_outq_ctrl_tail(sk, nskb, true);
			outq->last_max_bytes = outq->max_bytes;
			outq->data_blocked = 1;
		}
		blocked = 1;
	}

	if (nskb)
		quic_outq_transmit_ctrl(sk);
	return blocked;
}

static void quic_outq_transmit_stream(struct sock *sk)
{
	struct sk_buff_head *head = &sk->sk_write_queue;
	struct quic_outqueue *outq = quic_outq(sk);
	u8 level = outq->data_level;
	struct quic_snd_cb *snd_cb;
	struct sk_buff *skb, *tmp;
	int ret;

	if (!quic_crypto_send_ready(quic_crypto(sk, level)))
		return;

	skb_queue_walk_safe(head, skb, tmp) {
		if (!level && quic_outq_flow_control(sk, skb))
			break;
		snd_cb = QUIC_SND_CB(skb);
		ret = quic_packet_config(sk, level, snd_cb->path_alt);
		if (ret) {
			if (ret > 0)
				continue;
			break;
		}
		if (quic_packet_tail(sk, skb, head, 0)) {
			snd_cb->stream->send.frags++;
			snd_cb->stream->send.bytes += snd_cb->data_bytes;
			outq->bytes += snd_cb->data_bytes;
			outq->data_inflight += snd_cb->data_bytes;
			continue;
		}
		quic_packet_create(sk);
		tmp = skb;
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

static void quic_outq_wfree(struct sk_buff *skb)
{
	int len = QUIC_SND_CB(skb)->data_bytes;
	struct sock *sk = skb->sk;

	WARN_ON(refcount_sub_and_test(len, &sk->sk_wmem_alloc));
	sk_wmem_queued_add(sk, -len);
	sk_mem_uncharge(sk, len);

	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

static void quic_outq_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	int len = QUIC_SND_CB(skb)->data_bytes;

	refcount_add(len, &sk->sk_wmem_alloc);
	sk_wmem_queued_add(sk, len);
	sk_mem_charge(sk, len);

	skb->sk = sk;
	skb->destructor = quic_outq_wfree;
}

void quic_outq_stream_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	struct quic_stream *stream = QUIC_SND_CB(skb)->stream;
	struct quic_stream_table *streams = quic_streams(sk);

	if (stream->send.state == QUIC_STREAM_SEND_STATE_READY)
		stream->send.state = QUIC_STREAM_SEND_STATE_SEND;

	if (QUIC_SND_CB(skb)->frame_type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		if (quic_stream_send_active(streams) == stream->id)
			quic_stream_set_send_active(streams, -1);
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}

	quic_outq_set_owner_w(skb, sk);
	__skb_queue_tail(&sk->sk_write_queue, skb);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_dgram_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	quic_outq_set_owner_w(skb, sk);
	__skb_queue_tail(&quic_outq(sk)->datagram_list, skb);
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_ctrl_tail(struct sock *sk, struct sk_buff *skb, bool cork)
{
	struct sk_buff_head *head = &quic_outq(sk)->control_list;
	struct sk_buff *pos;

	if (QUIC_SND_CB(skb)->level) { /* prioritize handshake frames */
		skb_queue_walk(head, pos) {
			if (!QUIC_SND_CB(pos)->level) {
				__skb_queue_before(head, pos, skb);
				goto out;
			}
		}
	}
	__skb_queue_tail(head, skb);
out:
	if (!cork)
		quic_outq_transmit(sk);
}

void quic_outq_transmitted_tail(struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff_head *head = &quic_outq(sk)->transmitted_list;
	struct sk_buff *pos;

	if (QUIC_SND_CB(skb)->level) { /* prioritize handshake frames */
		skb_queue_walk(head, pos) {
			if (!QUIC_SND_CB(pos)->level) {
				__skb_queue_before(head, pos, skb);
				return;
			}
		}
	}
	__skb_queue_tail(head, skb);
}

void quic_outq_transmit_probe(struct sock *sk)
{
	struct quic_path_dst *d = (struct quic_path_dst *)quic_dst(sk);
	struct quic_pnmap *pnmap = quic_pnmap(sk, QUIC_CRYPTO_APP);
	u8 taglen = quic_packet_taglen(quic_packet(sk));
	struct quic_inqueue *inq = quic_inq(sk);
	struct sk_buff *skb;
	u32 pathmtu;
	s64 number;

	if (!quic_is_established(sk))
		return;

	skb = quic_frame_create(sk, QUIC_FRAME_PING, &d->pl.probe_size);
	if (skb) {
		number = quic_pnmap_next_number(pnmap);
		quic_outq_ctrl_tail(sk, skb, false);

		pathmtu = quic_path_pl_send(quic_dst(sk), number);
		if (pathmtu)
			quic_packet_mss_update(sk, pathmtu + taglen);
	}

	quic_timer_reset(sk, QUIC_TIMER_PATH, quic_inq_probe_timeout(inq));
}

void quic_outq_transmit_close(struct sock *sk, u8 frame, u32 errcode, u8 level)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_connection_close close = {};
	struct sk_buff *skb;

	if (!errcode)
		return;

	close.errcode = errcode;
	close.frame = frame;
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close))
		return;

	quic_outq_set_close_errcode(outq, errcode);
	quic_outq_set_close_frame(outq, frame);

	skb = quic_frame_create(sk, QUIC_FRAME_CONNECTION_CLOSE, NULL);
	if (skb) {
		QUIC_SND_CB(skb)->level = level;
		quic_outq_ctrl_tail(sk, skb, false);
	}
	quic_set_state(sk, QUIC_SS_CLOSED);
}

void quic_outq_transmit_app_close(struct sock *sk)
{
	u32 errcode = QUIC_TRANSPORT_ERROR_APPLICATION;
	u8 type = QUIC_FRAME_CONNECTION_CLOSE, level;
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff *skb;

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
	skb = quic_frame_create(sk, type, NULL);
	if (skb) {
		QUIC_SND_CB(skb)->level = level;
		quic_outq_ctrl_tail(sk, skb, false);
	}
}

void quic_outq_transmitted_sack(struct sock *sk, u8 level, s64 largest, s64 smallest,
				s64 ack_largest, u32 ack_delay)
{
	u32 pathmtu, acked_bytes = 0, transmit_ts = 0, rto, taglen;
	struct quic_path_addr *path = quic_dst(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct quic_stream_update update;
	struct quic_stream *stream;
	struct quic_snd_cb *snd_cb;
	bool raise_timer, complete;
	struct quic_crypto *crypto;
	struct sk_buff *skb, *tmp;
	struct sk_buff_head *head;
	struct quic_pnmap *pnmap;
	s64 acked_number = 0;

	pr_debug("[QUIC] %s largest: %llu, smallest: %llu\n", __func__, largest, smallest);
	if (quic_path_pl_confirm(path, largest, smallest)) {
		pathmtu = quic_path_pl_recv(path, &raise_timer, &complete);
		if (pathmtu) {
			taglen = quic_packet_taglen(quic_packet(sk));
			quic_packet_mss_update(sk, pathmtu + taglen);
		}
		if (!complete)
			quic_outq_transmit_probe(sk);
		if (raise_timer) /* reuse probe timer as raise timer */
			quic_timer_reset(sk, QUIC_TIMER_PATH, quic_inq_probe_timeout(inq) * 30);
	}

	head = &outq->transmitted_list;
	skb_queue_reverse_walk_safe(head, skb, tmp) {
		snd_cb = QUIC_SND_CB(skb);
		if (level != snd_cb->level)
			continue;
		if (snd_cb->number > largest)
			continue;
		if (snd_cb->number < smallest)
			break;
		pnmap = quic_pnmap(sk, level);
		if (snd_cb->number == ack_largest) {
			quic_cong_rtt_update(cong, snd_cb->transmit_ts, ack_delay);
			rto = quic_cong_rto(cong);
			crypto = quic_crypto(sk, level);
			quic_pnmap_set_max_record_ts(pnmap, rto * 2);
			quic_crypto_set_key_update_ts(crypto, rto * 2);
		}
		if (!acked_number) {
			acked_number = snd_cb->number;
			transmit_ts = snd_cb->transmit_ts;
		}

		if (snd_cb->ecn)
			quic_set_sk_ecn(sk, INET_ECN_ECT_0);

		stream = snd_cb->stream;
		if (snd_cb->data_bytes) {
			if (!stream)
				goto unlink;
			stream->send.frags--;
			if (stream->send.frags || stream->send.state != QUIC_STREAM_SEND_STATE_SENT)
				goto unlink;
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RECVD;
			if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update)) {
				stream->send.frags++;
				continue;
			}
			stream->send.state = update.state;
		} else if (snd_cb->frame_type == QUIC_FRAME_RESET_STREAM) {
			update.id = stream->id;
			update.state = QUIC_STREAM_SEND_STATE_RESET_RECVD;
			update.errcode = stream->send.errcode;
			if (quic_inq_event_recv(sk, QUIC_EVENT_STREAM_UPDATE, &update))
				continue;
			stream->send.state = update.state;
		} else if (snd_cb->frame_type == QUIC_FRAME_STREAM_DATA_BLOCKED) {
			stream->send.data_blocked = 0;
		} else if (snd_cb->frame_type == QUIC_FRAME_DATA_BLOCKED) {
			outq->data_blocked = 0;
		}
unlink:
		quic_pnmap_set_max_pn_acked(pnmap, snd_cb->number);
		acked_bytes += snd_cb->data_bytes;

		quic_pnmap_dec_inflight(pnmap, skb->len);
		outq->data_inflight -= snd_cb->data_bytes;
		outq->inflight -= skb->len;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}

	outq->rtx_count = 0;
	if (!acked_bytes)
		return;
	quic_cong_cwnd_update_after_sack(cong, acked_number, transmit_ts,
					 acked_bytes, outq->data_inflight);
	quic_outq_set_window(outq, quic_cong_window(cong));
}

void quic_outq_update_loss_timer(struct sock *sk, u8 level)
{
	struct quic_pnmap *pnmap = quic_pnmap(sk, level);
	u32 timeout, now = jiffies_to_usecs(jiffies);

	timeout = quic_pnmap_loss_ts(pnmap);
	if (timeout)
		goto out;

	if (!quic_pnmap_inflight(pnmap))
		return quic_timer_stop(sk, level);

	timeout = quic_cong_duration(quic_cong(sk));
	timeout *= (1 + quic_outq(sk)->rtx_count);
	timeout += quic_pnmap_last_sent_ts(pnmap);
out:
	if (timeout < now)
		timeout = now + 1;
	quic_timer_reduce(sk, level, timeout - now);
}

/* put the timeout frame back to the corresponding outqueue */
static void quic_outq_retransmit_one(struct sock *sk, struct sk_buff *skb)
{
	struct quic_snd_cb *snd_cb = QUIC_SND_CB(skb), *pos_cb;
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff_head *head;
	struct sk_buff *pos;

	head = &outq->control_list;
	if (snd_cb->data_bytes) {
		head = &sk->sk_write_queue;
		snd_cb->stream->send.frags--;
		snd_cb->stream->send.bytes -= snd_cb->data_bytes;
		outq->bytes -= snd_cb->data_bytes;
	}

	skb_queue_walk(head, pos) {
		pos_cb = QUIC_SND_CB(pos);
		if (snd_cb->level < pos_cb->level)
			continue;
		if (snd_cb->level > pos_cb->level) {
			__skb_queue_before(head, pos, skb);
			return;
		}
		if (!pos_cb->first_number || snd_cb->first_number < pos_cb->first_number) {
			__skb_queue_before(head, pos, skb);
			return;
		}
	}
	__skb_queue_tail(head, skb);
}

int quic_outq_retransmit_mark(struct sock *sk, u8 level, u8 immediate)
{
	struct quic_pnmap *pnmap = quic_pnmap(sk, level);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);
	u32 transmit_ts, now, rto, count = 0;
	struct quic_snd_cb *snd_cb;
	struct sk_buff_head *head;
	struct sk_buff *skb, *tmp;
	s64 number, last;

	quic_pnmap_set_loss_ts(pnmap, 0);
	last = quic_pnmap_next_number(pnmap) - 1;
	now = jiffies_to_usecs(jiffies);
	head = &outq->transmitted_list;
	skb_queue_walk_safe(head, skb, tmp) {
		snd_cb = QUIC_SND_CB(skb);
		if (level != snd_cb->level)
			continue;
		transmit_ts = snd_cb->transmit_ts;
		number = snd_cb->number;
		rto = quic_cong_rto(cong);
		if (!immediate && transmit_ts + rto > now && number + 6 > pnmap->max_pn_acked) {
			quic_pnmap_set_loss_ts(pnmap, transmit_ts + rto);
			break;
		}
		quic_pnmap_dec_inflight(pnmap, skb->len);
		outq->data_inflight -= snd_cb->data_bytes;
		outq->inflight -= skb->len;
		__skb_unlink(skb, head);
		if (quic_frame_is_dgram(snd_cb->frame_type)) { /* no need to retransmit dgram */
			kfree_skb(skb);
		} else {
			quic_outq_retransmit_one(sk, skb); /* mark as loss */
			count++;
		}

		if (snd_cb->data_bytes) {
			quic_cong_cwnd_update_after_timeout(cong, number, transmit_ts, last);
			quic_outq_set_window(outq, quic_cong_window(cong));
		}
	}
	quic_outq_update_loss_timer(sk, level);
	return count;
}

void quic_outq_retransmit_list(struct sock *sk, struct sk_buff_head *head)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct sk_buff *skb;

	skb =  __skb_dequeue(head);
	while (skb) {
		outq->data_inflight -= QUIC_SND_CB(skb)->data_bytes;
		if (quic_frame_is_dgram(QUIC_SND_CB(skb)->frame_type))
			kfree_skb(skb);
		else
			quic_outq_retransmit_one(sk, skb);
		skb =  __skb_dequeue(head);
	}
}

void quic_outq_transmit_one(struct sock *sk, u8 level)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u32 probe_size = QUIC_MIN_UDP_PAYLOAD;
	struct sk_buff *skb;

	quic_packet_set_filter(sk, level, 1);
	if (quic_outq_transmit(sk))
		goto out;

	if (quic_outq_retransmit_mark(sk, level, 0)) {
		quic_packet_set_filter(sk, level, 1);
		if (quic_outq_transmit(sk))
			goto out;
	}

	skb = quic_frame_create(sk, QUIC_FRAME_PING, &probe_size);
	if (skb) {
		QUIC_SND_CB(skb)->level = level;
		quic_outq_ctrl_tail(sk, skb, false);
	}
out:
	outq->rtx_count++;
	quic_outq_update_loss_timer(sk, level);
}

void quic_outq_validate_path(struct sock *sk, struct sk_buff *skb, struct quic_path_addr *path)
{
	u8 local = quic_path_udp_bind(path), path_alt = QUIC_PATH_ALT_DST;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct sk_buff_head *head;
	struct sk_buff *fskb;

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
	quic_timer_reset(sk, QUIC_TIMER_PATH, quic_inq_probe_timeout(inq));

	head = &outq->control_list;
	skb_queue_walk(head, fskb)
		QUIC_SND_CB(fskb)->path_alt &= ~path_alt;

	head = &outq->transmitted_list;
	skb_queue_walk(head, fskb)
		QUIC_SND_CB(fskb)->path_alt &= ~path_alt;

	QUIC_RCV_CB(skb)->path_alt &= ~path_alt;
	quic_packet_set_ecn_probes(quic_packet(sk), 0);
}

void quic_outq_stream_purge(struct sock *sk, struct quic_stream *stream)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_snd_cb *snd_cb;
	struct sk_buff *skb, *tmp;
	struct sk_buff_head *head;
	struct quic_pnmap *pnmap;

	head = &outq->transmitted_list;
	skb_queue_walk_safe(head, skb, tmp) {
		snd_cb = QUIC_SND_CB(skb);
		if (snd_cb->stream != stream)
			continue;
		pnmap = quic_pnmap(sk, snd_cb->level);
		quic_pnmap_dec_inflight(pnmap, skb->len);
		outq->data_inflight -= snd_cb->data_bytes;
		outq->inflight -= skb->len;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}

	head = &sk->sk_write_queue;
	skb_queue_walk_safe(head, skb, tmp) {
		if (QUIC_SND_CB(skb)->stream != stream)
			continue;
		__skb_unlink(skb, head);
		kfree_skb(skb);
	}
}

static void quic_outq_encrypted_work(struct work_struct *work)
{
	struct quic_sock *qs = container_of(work, struct quic_sock, outq.work);
	struct sock *sk = &qs->inet.sk;
	struct sk_buff_head *head;
	struct sk_buff *skb;

	lock_sock(sk);
	head = &quic_outq(sk)->encrypted_list;
	if (sock_flag(sk, SOCK_DEAD)) {
		skb_queue_purge(head);
		goto out;
	}

	skb = skb_dequeue(head);
	while (skb) {
		struct quic_snd_cb *snd_cb = QUIC_SND_CB(skb);

		quic_packet_config(sk, snd_cb->level, snd_cb->path_alt);
		/* the skb here is ready to send */
		quic_packet_xmit(sk, skb, 1);
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
	skb_queue_tail(&outq->encrypted_list, skb);

	if (!schedule_work(&outq->work))
		sock_put(sk);
}

void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	u32 remote_idle, local_idle;

	outq->max_datagram_frame_size = p->max_datagram_frame_size;
	outq->max_udp_payload_size = p->max_udp_payload_size;
	outq->ack_delay_exponent = p->ack_delay_exponent;
	outq->max_idle_timeout = p->max_idle_timeout;
	outq->max_ack_delay = p->max_ack_delay;
	outq->grease_quic_bit = p->grease_quic_bit;
	outq->disable_1rtt_encryption = p->disable_1rtt_encryption;

	outq->max_bytes = p->max_data;
	sk->sk_sndbuf = 2 * p->max_data;

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

	skb_queue_head_init(&outq->control_list);
	skb_queue_head_init(&outq->datagram_list);
	skb_queue_head_init(&outq->encrypted_list);
	skb_queue_head_init(&outq->transmitted_list);
	INIT_WORK(&outq->work, quic_outq_encrypted_work);
}

void quic_outq_free(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	__skb_queue_purge(&sk->sk_write_queue);
	__skb_queue_purge(&outq->transmitted_list);
	__skb_queue_purge(&outq->datagram_list);
	__skb_queue_purge(&outq->control_list);
	kfree(outq->close_phrase);
}
