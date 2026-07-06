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
	/* Sent packets, for ACK + loss detection */
	struct list_head packet_sent_list;
	/* Frames needing retransmission if lost */
	struct list_head transmitted_list;
	struct list_head datagram_list; /* DATAGRAM frames queued for sending */
	struct list_head control_list;  /* ACK, PING, CONNECTION_CLOSE, etc. */
	struct list_head stream_list;   /* STREAM frames queued for sending */

	/* Flow Control */
	u64 last_max_bytes; /* Maximum send bytes peer allowed at last update */
	u64 max_bytes;      /* Current maximum bytes we can send */
	u64 bytes;          /* Bytes already sent to peer */

	/* Use for 0-RTT/1-RTT DATA (re)transmit, as QUIC_SKB_CB(skb)->level is
	 * always QUIC_CRYPTO_APP. Set this level to QUIC_CRYPTO_EARLY or
	 * QUIC_CRYPTO_APP when the corresponding crypto is ready for send.
	 */
	u8 data_level;
	u8 pto_count; /* PTO (Probe Timeout) count since last packet received */

	u8 token_pending:1; /* NEW_TOKEN sent, awaiting ACK */
	u8 data_blocked:1;  /* Blocked by flow control (needs MAX_DATA) */
	u8 force_delay:1;   /* Delay send due to MSG_MORE / Nagle logic */
	u8 single:1;        /* Transmit only one packet this round */

	/* Transport Parameters (from peer) */
	u8 disable_compatible_version:1; /* rfc9368#section-3 */
	/* draft-banks-quic-disable-encryption#section-2.1 */
	u8 disable_1rtt_encryption:1;
	u8 grease_quic_bit:1;        /* rfc9287#section-3 */
	u8 stateless_reset:1;        /* rfc9000#section-18.2 */
	u8 ack_delay_exponent;       /* rfc9000#section-18.2 */
	u16 max_datagram_frame_size; /* rfc9221#section-3 */
	u16 max_udp_payload_size;    /* rfc9000#section-18.2 */
	u32 max_idle_timeout;        /* rfc9000#section-18.2 */
	u32 max_ack_delay;           /* rfc9000#section-18.2 */
	u64 max_data;                /* rfc9000#section-18.2 */

	u32 stream_list_len; /* Combined payload length in stream_list */
	u32 unsent_bytes;    /* Bytes queued but never transmitted */
	u32 inflight;        /* Bytes from ack-eliciting frames in flight */
	u32 window;          /* Congestion-controlled send window size */
	u16 count;           /* Packets sent in current transmit round */

	/* Kernel consumers: nofity userspace handshake */
	u8 receive_session_ticket; /* Expect session ticket from userspace */
	u8 certificate_request;    /* Request certificate from userspace */
	u32 payload_cipher_type;   /* Preferred cipher type for userspace */

	u32 version; /* Preferred QUIC version */
	/* Server: perform address validation (Retry) */
	u8 validate_peer_address:1;
	/* Disable Nagle-like coalescing for STREAM data */
	u8 stream_data_nodelay:1;
	u8 close_pending:1; /* CONNECTION_CLOSE frame pending transmission */

	/* Close Information */
	u8  close_frame;   /* Frame type in CONNECTION_CLOSE */
	u32 close_errcode; /* Application or transport close error code */
	u8  *close_phrase; /* Optional phrase in CONNECTION_CLOSE frame */
};

void quic_outq_stream_tail(struct sock *sk, struct quic_frame *frame,
			   bool cork);
void quic_outq_dgram_tail(struct sock *sk, struct quic_frame *frame, bool cork);
void quic_outq_ctrl_tail(struct sock *sk, struct quic_frame *frame, bool cork,
			 gfp_t gfp);
void quic_outq_transmit_pto(struct sock *sk);
void quic_outq_update_path(struct sock *sk);

int quic_outq_transmit_frame(struct sock *sk, u8 type, void *data, u8 path,
			     bool cork, gfp_t gfp);
int quic_outq_transmit_retire_conn_id(struct sock *sk, u64 prior, u8 path,
				      bool cork, gfp_t gfp);
int quic_outq_transmit_new_conn_id(struct sock *sk, u64 prior, u8 path,
				   bool cork, gfp_t gfp);
int quic_outq_stream_append(struct sock *sk, struct quic_msginfo *info,
			    bool pack);
int quic_outq_probe_path_alt(struct sock *sk, bool cork, gfp_t gfp);
int quic_outq_transmit(struct sock *sk, gfp_t gfp);

void quic_outq_transmitted_sack(struct sock *sk, u8 level, s64 largest,
				s64 smallest, s64 ack_largest, u32 ack_delay,
				gfp_t gfp);
void quic_outq_packet_sent_tail(struct sock *sk, struct quic_packet_sent *info);
void quic_outq_transmitted_tail(struct sock *sk, struct quic_frame *frame);
void quic_outq_retransmit_mark(struct sock *sk, u8 level, bool immediate);
void quic_outq_retransmit_list(struct sock *sk, struct list_head *head);
void quic_outq_update_loss_timer(struct sock *sk);

void quic_outq_list_purge(struct sock *sk, struct list_head *head,
			  struct quic_stream *stream);
void quic_outq_transmit_close(struct sock *sk, u8 frame, u32 errcode, u8 level);
void quic_outq_transmit_probe(struct sock *sk, gfp_t gfp);
void quic_outq_transmit_app_close(struct sock *sk);

void quic_outq_get_param(struct sock *sk, struct quic_transport_param *p);
void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_outq_sync_window(struct sock *sk, u32 window);
void quic_outq_init(struct sock *sk);
void quic_outq_free(struct sock *sk);

int quic_outq_flow_control(struct sock *sk, struct quic_stream *stream,
			   u16 bytes, bool sndblock);
u64 quic_outq_wspace(struct sock *sk, struct quic_stream *stream);
