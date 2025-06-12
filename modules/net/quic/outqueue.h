/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_outqueue {
	struct list_head packet_sent_list;	/* Sent packets, for ACK + loss detection */
	struct list_head transmitted_list;	/* Frames needing retransmission if lost */
	struct list_head datagram_list;		/* DATAGRAM frames waiting to be sent */
	struct list_head control_list;		/* ACK, PING, CONNECTION_CLOSE, etc. */
	struct list_head stream_list;		/* STREAM frames queued for transmission */
	struct work_struct work;	/* Workqueue item to process async crypto completion */

	/* Flow Control */
	u64 last_max_bytes;		/* Maximum send bytes advertised by peer at last update */
	u64 max_bytes;			/* Current maximum bytes we are allowed to send to */
	u64 bytes;			/* Bytes already sent to peer */

	/* Transport Parameters (from peer) */
	u16 max_datagram_frame_size;	/* Transport parameter in rfc9000#section-18.2 */
	u16 max_udp_payload_size;	/* Transport parameter in rfc9000#section-18.2 */
	/* Transport parameter Version Information related in rfc9368#section-3 */
	u8 disable_compatible_version:1;
	/* Transport parameter in draft-banks-quic-disable-encryption#section-2.1 */
	u8 disable_1rtt_encryption:1;
	u8 grease_quic_bit:1;		/* Transport parameter in rfc9287.html#section-3 */
	u8 stateless_reset:1;		/* Transport parameter in rfc9000#section-18.2 */
	u8 ack_delay_exponent;		/* Transport parameter in rfc9000#section-18.2 */
	u32 max_idle_timeout;		/* Transport parameter in rfc9000#section-18.2 */
	u32 max_ack_delay;		/* Transport parameter in rfc9000#section-18.2 */
	u64 max_data;			/* Transport parameter in rfc9000#section-18.2 */

	u32 stream_list_len;		/* Combined payload length in stream_list */
	u32 unsent_bytes;		/* Bytes queued but never transmitted */
	u32 inflight;			/* Bytes from ack-eliciting frames in flight */
	u32 window;			/* Congestion-controlled send window size */
	u16 count;			/* Packets sent in current transmit round */

	/* Close Information */
	u8 *close_phrase;	/* Optional phrase to send in CONNECTION_CLOSE frame */
	u32 close_errcode;	/* Application or transport close error code */
	u8  close_frame;	/* Frame type to use in CONNECTION_CLOSE */

	/* Use for 0-RTT/1-RTT DATA (re)transmit, as QUIC_SKB_CB(skb)->level is always
	 * QUIC_CRYPTO_APP. Set this level to QUIC_CRYPTO_EARLY or QUIC_CRYPTO_APP
	 * when the corresponding crypto is ready for send.
	 */
	u8 data_level;
	u8 pto_count;		/* PTO (Probe Timeout) count since last packet received */
	u8 token_pending:1;	/* NEW_TOKEN sent, awaiting ACK */
	u8 data_blocked:1;	/* Blocked by flow control (needs MAX_DATA) */
	u8 force_delay:1;	/* Delay send due to MSG_MORE / Nagle logic */
	u8 single:1;		/* Transmit only one packet this round */
};

void quic_outq_stream_tail(struct sock *sk, struct quic_frame *frame, bool cork);
void quic_outq_dgram_tail(struct sock *sk, struct quic_frame *frame, bool cork);
void quic_outq_ctrl_tail(struct sock *sk, struct quic_frame *frame, bool cork);
void quic_outq_update_path(struct sock *sk, u8 path);
void quic_outq_transmit_pto(struct sock *sk);

int quic_outq_transmit_frame(struct sock *sk, u8 type, void *data, u8 path, u8 cork);
int quic_outq_transmit_retire_conn_id(struct sock *sk, u64 prior, u8 path, u8 cork);
int quic_outq_transmit_new_conn_id(struct sock *sk, u64 prior, u8 path, u8 cork);
int quic_outq_stream_append(struct sock *sk, struct quic_msginfo *info, u8 pack);
int quic_outq_probe_path_alt(struct sock *sk, u8 cork);
int quic_outq_transmit(struct sock *sk);

void quic_outq_transmitted_sack(struct sock *sk, u8 level, s64 largest,
				s64 smallest, s64 ack_largest, u32 ack_delay);
void quic_outq_packet_sent_tail(struct sock *sk, struct quic_packet_sent *info);
void quic_outq_transmitted_tail(struct sock *sk, struct quic_frame *frame);
void quic_outq_retransmit_list(struct sock *sk, struct list_head *head);
void quic_outq_retransmit_mark(struct sock *sk, u8 level, u8 immediate);
void quic_outq_update_loss_timer(struct sock *sk);

void quic_outq_transmit_close(struct sock *sk, u8 frame, u32 errcode, u8 level);
void quic_outq_stream_list_purge(struct sock *sk, struct quic_stream *stream);
void quic_outq_encrypted_tail(struct sock *sk, struct sk_buff *skb);
void quic_outq_transmit_app_close(struct sock *sk);
void quic_outq_transmit_probe(struct sock *sk);

void quic_outq_get_param(struct sock *sk, struct quic_transport_param *p);
void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_outq_sync_window(struct sock *sk, u32 window);
void quic_outq_init(struct sock *sk);
void quic_outq_free(struct sock *sk);

int quic_outq_flow_control(struct sock *sk, struct quic_stream *stream, u16 bytes, u8 sndblock);
u64 quic_outq_wspace(struct sock *sk, struct quic_stream *stream);
