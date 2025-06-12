/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_MAX_ACK_DELAY_EXPONENT	20
#define QUIC_DEF_ACK_DELAY_EXPONENT	3

enum {
	QUIC_SACK_FLAG_NONE,	/* No SACK pending; used for idle timeout handling */
	QUIC_SACK_FLAG_XMIT,	/* Send previously queued SACK frames */
	QUIC_SACK_FLAG_APP,	/* Generate and send new APP-level SACK frames */
};

struct quic_inqueue {
	struct sk_buff_head backlog_list;	/* Packets waiting for crypto keys */
	struct list_head handshake_list;	/* CRYPTO frames awaiting reassembly */
	struct list_head stream_list;		/* STREAM frames awaiting reassembly */
	struct list_head early_list;		/* 0-RTT STREAM frames already reassembled */
	struct list_head recv_list;		/* Reassembled frames ready for user delivery */
	struct work_struct work;	/* Workqueue item to process async crypto completion */

	/* Flow Control */
	u64 max_bytes;			/* Maximum data allowed to be received */
	u64 bytes;			/* Data already read by the application */

	/* Transport Parameters (local) */
	u16 max_datagram_frame_size;	/* Transport parameter in and rfc9000#section-18.2 */
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
	u64 highest;			/* Highest received offset across all streams */
	u32 timeout;			/* Idle timeout duration*/
	u32 events;			/* Event bitmask for notifications */

	u8 sack_flag:2;			/* SACK timer handling flag; See QUIC_SACK_FLAG_* */
};

int quic_inq_handshake_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_stream_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_dgram_recv(struct sock *sk, struct quic_frame *frame);
int quic_inq_event_recv(struct sock *sk, u8 event, void *args);

void quic_inq_stream_list_purge(struct sock *sk, struct quic_stream *stream);
void quic_inq_decrypted_tail(struct sock *sk, struct sk_buff *skb);
void quic_inq_backlog_tail(struct sock *sk, struct sk_buff *skb);
void quic_inq_data_read(struct sock *sk, u32 bytes);

void quic_inq_flow_control(struct sock *sk, struct quic_stream *stream, u32 bytes);
void quic_inq_get_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_set_param(struct sock *sk, struct quic_transport_param *p);
void quic_inq_init(struct sock *sk);
void quic_inq_free(struct sock *sk);
