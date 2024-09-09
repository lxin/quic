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

#include <linux/version.h>
#include <net/gro.h>

#include "socket.h"

#define QUIC_VERSION_NUM	2

static u32 quic_versions[QUIC_VERSION_NUM][3] = {
	/* version,	compatible versions */
	{ QUIC_VERSION_V1,	QUIC_VERSION_V2,	0 },
	{ QUIC_VERSION_V2,	QUIC_VERSION_V1,	0 },
};

u32 *quic_packet_compatible_versions(u32 version)
{
	u8 i;

	for (i = 0; i < QUIC_VERSION_NUM; i++)
		if (version == quic_versions[i][0])
			return quic_versions[i];
	return NULL;
}

static u8 quic_packet_version_get_type(u32 version, u8 type)
{
	if (version == QUIC_VERSION_V1)
		return type;

	switch (type) {
	case QUIC_PACKET_INITIAL_V2:
		return QUIC_PACKET_INITIAL;
	case QUIC_PACKET_0RTT_V2:
		return QUIC_PACKET_0RTT;
	case QUIC_PACKET_HANDSHAKE_V2:
		return QUIC_PACKET_HANDSHAKE;
	case QUIC_PACKET_RETRY_V2:
		return QUIC_PACKET_RETRY;
	default:
		return -1;
	}
	return -1;
}

static u8 quic_packet_version_put_type(u32 version, u8 type)
{
	if (version == QUIC_VERSION_V1)
		return type;

	switch (type) {
	case QUIC_PACKET_INITIAL:
		return QUIC_PACKET_INITIAL_V2;
	case QUIC_PACKET_0RTT:
		return QUIC_PACKET_0RTT_V2;
	case QUIC_PACKET_HANDSHAKE:
		return QUIC_PACKET_HANDSHAKE_V2;
	case QUIC_PACKET_RETRY:
		return QUIC_PACKET_RETRY_V2;
	default:
		return -1;
	}
	return -1;
}

static int quic_packet_get_version_and_connid(struct quic_packet *packet, u8 **pp, u32 *plen)
{
	u8 *p = *pp;
	u64 len, v;

	if (!quic_get_int(pp, plen, &v, 1))
		return -EINVAL;

	if (!quic_get_int(pp, plen, &v, QUIC_VERSION_LEN))
		return -EINVAL;
	packet->version = v;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(&packet->dcid, *pp, len);
	*plen -= len;
	*pp += len;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(&packet->scid, *pp, len);
	*plen -= len;
	*pp += len;

	packet->len = *pp - p;
	return 0;
}

int quic_packet_version_change(struct sock *sk, struct quic_conn_id *conn_id, u32 version)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);

	/* initial keys must be updated when version changes */
	quic_crypto_destroy(crypto);
	if (quic_crypto_initial_keys_install(crypto, conn_id, version, quic_is_serv(sk)))
		return -EINVAL;
	quic_config(sk)->version = version;
	return 0;
}

int quic_packet_select_version(struct sock *sk, u32 *versions, u8 count)
{
	u32 best = 0;
	u8 i, j;

	for (i = 0; i < count; i++) {
		for (j = 0; j < QUIC_VERSION_NUM; j++) {
			if (versions[i] == quic_versions[j][0] && best < versions[i]) {
				best = versions[i];
				goto found;
			}
		}
	}
	return -1;
found:
	if (best == quic_config(sk)->version)
		return 0;
	return quic_packet_version_change(sk, quic_outq_orig_dcid(quic_outq(sk)), best);
}

static int quic_packet_get_token(struct quic_data *token, u8 **pp, u32 *plen)
{
	u64 len;

	if (!quic_get_var(pp, plen, &len) || len > *plen)
		return -EINVAL;
	quic_data(token, *pp, len);
	*plen -= len;
	*pp += len;
	return 0;
}

static void quic_packet_get_addrs(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);

	packet->sa = &packet->saddr;
	packet->da = &packet->daddr;
	quic_get_msg_addr(sk, packet->sa, skb, 0);
	quic_get_msg_addr(sk, packet->da, skb, 1);
}

/* Retry Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 3,
 *   Unused (4),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Retry Token (..),
 *   Retry Integrity Tag (128),
 * }
 */

static struct sk_buff *quic_packet_retry_create(struct sock *sk)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	u8 *p, token[72], tag[16];
	struct quic_conn_id dcid;
	int len, hlen, tokenlen;
	struct quichshdr *hdr;
	struct sk_buff *skb;

	p = token;
	p = quic_put_int(p, 1, 1); /* retry token flag */
	if (quic_crypto_generate_token(crypto, packet->da, quic_addr_len(sk),
				       &packet->dcid, token, &tokenlen))
		return NULL;

	quic_conn_id_generate(&dcid); /* new dcid for retry */
	len = 1 + QUIC_VERSION_LEN + 1 + packet->scid.len + 1 + dcid.len + tokenlen + 16;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq_grease_quic_bit(quic_outq(sk));
	hdr->type = quic_packet_version_put_type(packet->version, QUIC_PACKET_RETRY);
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, packet->version, QUIC_VERSION_LEN);
	p = quic_put_int(p, packet->scid.len, 1);
	p = quic_put_data(p, packet->scid.data, packet->scid.len);
	p = quic_put_int(p, dcid.len, 1);
	p = quic_put_data(p, dcid.data, dcid.len);
	p = quic_put_data(p, token, tokenlen);
	if (quic_crypto_get_retry_tag(crypto, skb, &packet->dcid, packet->version, tag)) {
		kfree_skb(skb);
		return NULL;
	}
	p = quic_put_data(p, tag, 16);

	return skb;
}

static int quic_packet_retry_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, packet->da, packet->sa))
		return -EINVAL;
	skb = quic_packet_retry_create(sk);
	if (!skb)
		return -ENOMEM;
	quic_lower_xmit(sk, skb, packet->da, packet->sa);
	return 0;
}

/* Version Negotiation Packet {
 *   Header Form (1) = 1,
 *   Unused (7),
 *   Version (32) = 0,
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..2040),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..2040),
 *   Supported Version (32) ...,
 * }
 */

static struct sk_buff *quic_packet_version_create(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quichshdr *hdr;
	struct sk_buff *skb;
	int len, hlen;
	u8 *p;

	len = 1 + QUIC_VERSION_LEN + 1 + packet->scid.len + 1 + packet->dcid.len +
	      QUIC_VERSION_LEN * 2;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq_grease_quic_bit(quic_outq(sk));
	hdr->type = 0;
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, 0, QUIC_VERSION_LEN);
	p = quic_put_int(p, packet->scid.len, 1);
	p = quic_put_data(p, packet->scid.data, packet->scid.len);
	p = quic_put_int(p, packet->dcid.len, 1);
	p = quic_put_data(p, packet->dcid.data, packet->dcid.len);
	p = quic_put_int(p, QUIC_VERSION_V1, QUIC_VERSION_LEN);
	p = quic_put_int(p, QUIC_VERSION_V2, QUIC_VERSION_LEN);

	return skb;
}

static int quic_packet_version_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, packet->da, packet->sa))
		return -EINVAL;
	skb = quic_packet_version_create(sk);
	if (!skb)
		return -ENOMEM;
	quic_lower_xmit(sk, skb, packet->da, packet->sa);
	return 0;
}

/* Stateless Reset {
 *   Fixed Bits (2) = 1,
 *   Unpredictable Bits (38..),
 *   Stateless Reset Token (128),
 * }
 */

static struct sk_buff *quic_packet_stateless_reset_create(struct sock *sk)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;
	u8 *p, token[16];
	int len, hlen;

	if (quic_crypto_generate_stateless_reset_token(crypto, packet->dcid.data,
						       packet->dcid.len, token, 16))
		return NULL;

	len = 64;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, hlen + len);

	p = skb_push(skb, len);
	get_random_bytes(p, len);

	skb_reset_transport_header(skb);
	quic_hdr(skb)->form = 0;
	quic_hdr(skb)->fixed = 1;

	p += (len - 16);
	p = quic_put_data(p, token, 16);

	return skb;
}

static int quic_packet_stateless_reset_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, packet->da, packet->sa))
		return -EINVAL;
	skb = quic_packet_stateless_reset_create(sk);
	if (!skb)
		return -ENOMEM;
	quic_lower_xmit(sk, skb, packet->da, packet->sa);
	return 0;
}

static int quic_packet_refuse_close_transmit(struct sock *sk, u32 errcode)
{
	struct quic_conn_id_set *source = quic_source(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_conn_id *active;
	struct quic_frame *frame;
	int err;

	active = quic_conn_id_active(source);
	quic_conn_id_update(active, packet->dcid.data, packet->dcid.len);
	quic_path_addr_set(quic_src(sk), packet->sa, 1);
	quic_path_addr_set(quic_dst(sk), packet->da, 1);

	err = quic_packet_version_change(sk, active, packet->version);
	if (err)
		return err;

	quic_outq_set_close_errcode(quic_outq(sk), errcode);
	frame = quic_frame_create(sk, QUIC_FRAME_CONNECTION_CLOSE, NULL);
	if (frame) {
		frame->level = QUIC_CRYPTO_INITIAL;
		frame->path_alt = (QUIC_PATH_ALT_SRC | QUIC_PATH_ALT_DST);
		quic_outq_ctrl_tail(sk, frame, false);
	}
	return 0;
}

static int quic_packet_listen_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	int err = 0, errcode, len = skb->len;
	u8 *p = skb->data, type, retry = 0;
	struct quic_crypto *crypto;
	struct quic_conn_id odcid;
	struct quic_data token;

	/* set af_ops for now in case sk_family != addr.v4.sin_family */
	quic_set_af_ops(sk, quic_af_ops_get_skb(skb));
	quic_packet_get_addrs(sk, skb);
	if (quic_request_sock_exists(sk))
		goto enqueue;

	if (QUIC_CRYPTO_CB(skb)->backlog && quic_accept_sock_exists(sk, skb))
		goto out; /* moved skb to another sk backlog */

	if (!quic_hshdr(skb)->form) { /* stateless reset always by listen sock */
		if (len < 17) {
			err = -EINVAL;
			kfree_skb(skb);
			goto out;
		}
		quic_conn_id_update(&packet->dcid, (u8 *)quic_hdr(skb) + 1, 16);
		err = quic_packet_stateless_reset_transmit(sk);
		consume_skb(skb);
		goto out;
	}

	if (quic_packet_get_version_and_connid(packet, &p, &len)) {
		err = -EINVAL;
		kfree_skb(skb);
		goto out;
	}

	if (!quic_packet_compatible_versions(packet->version)) { /* version negotication */
		err = quic_packet_version_transmit(sk);
		consume_skb(skb);
		goto out;
	}

	type = quic_packet_version_get_type(packet->version, quic_hshdr(skb)->type);
	if (type != QUIC_PACKET_INITIAL) { /* stateless reset for handshake */
		err = quic_packet_stateless_reset_transmit(sk);
		consume_skb(skb);
		goto out;
	}

	if (quic_packet_get_token(&token, &p, &len)) {
		err = -EINVAL;
		kfree_skb(skb);
		goto out;
	}
	quic_conn_id_update(&odcid, packet->dcid.data, packet->dcid.len);
	if (quic_config(sk)->validate_peer_address) {
		if (!token.len) {
			err = quic_packet_retry_transmit(sk);
			consume_skb(skb);
			goto out;
		}
		crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
		err = quic_crypto_verify_token(crypto, packet->da, quic_addr_len(sk),
					       &odcid, token.data, token.len);
		if (err) {
			errcode = QUIC_TRANSPORT_ERROR_INVALID_TOKEN;
			err = quic_packet_refuse_close_transmit(sk, errcode);
			consume_skb(skb);
			goto out;
		}
		retry = *(u8 *)token.data;
	}

	err = quic_request_sock_enqueue(sk, &odcid, retry);
	if (err) {
		errcode = QUIC_TRANSPORT_ERROR_CONNECTION_REFUSED;
		err = quic_packet_refuse_close_transmit(sk, errcode);
		consume_skb(skb);
		goto out;
	}
enqueue:
	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > sk->sk_rcvbuf) {
		err = -ENOBUFS;
		kfree_skb(skb);
		goto out;
	}

	skb_set_owner_r(skb, sk); /* handle it later when accepting the sock */
	quic_inq_backlog_tail(sk, skb);
	sk->sk_data_ready(sk);
out:
	quic_set_af_ops(sk, quic_af_ops_get(sk->sk_family));
	return err;
}

static int quic_packet_stateless_reset_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_connection_close close = {};
	u8 *token;

	if (skb->len < 22)
		return -EINVAL;

	token = skb->data + skb->len - 16;
	if (!quic_conn_id_token_exists(id_set, token))
		return -EINVAL; /* not a stateless reset and the caller will free skb */

	close.errcode = QUIC_TRANSPORT_ERROR_CRYPTO;
	if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close))
		return -ENOMEM;
	quic_set_state(sk, QUIC_SS_CLOSED);
	consume_skb(skb);
	pr_debug("%s: peer reset\n", __func__);
	return 0;
}

static int quic_packet_handshake_retry_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u32 len = skb->len - packet->len, version;
	u8 *p = skb->data + packet->len, tag[16];
	struct quic_conn_id *active;

	if (len < 16)
		goto err;
	version = quic_config(sk)->version;
	if (quic_crypto_get_retry_tag(crypto, skb, quic_outq_orig_dcid(outq), version, tag) ||
	    memcmp(tag, p + len - 16, 16))
		goto err;
	if (quic_data_dup(quic_token(sk), p, len - 16))
		goto err;
	/* similar to version change, update the initial keys */
	if (quic_packet_version_change(sk, &packet->scid, version))
		goto err;
	active = quic_conn_id_active(quic_dest(sk));
	quic_conn_id_update(active, packet->scid.data, packet->scid.len);
	quic_outq_set_retry(outq, 1);
	quic_outq_set_retry_dcid(outq, active);
	quic_outq_retransmit_mark(sk, QUIC_CRYPTO_INITIAL, 1);
	quic_outq_transmit(sk);

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

static int quic_packet_handshake_version_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	int len = skb->len - packet->len;
	u8 *p = skb->data + packet->len;
	u64 version, best = 0;

	if (len < 4)
		goto err;

	while (len >= 4) {
		quic_get_int(&p, &len, &version, QUIC_VERSION_LEN);
		if (quic_packet_compatible_versions(version) && best < version)
			best = version;
	}
	if (best) {
		if (quic_packet_version_change(sk, &packet->scid, best))
			goto err;
		quic_outq_retransmit_mark(sk, QUIC_CRYPTO_INITIAL, 1);
		quic_outq_transmit(sk);
	}

	consume_skb(skb);
	return 0;
err:
	kfree_skb(skb);
	return -EINVAL;
}

static void quic_packet_decrypt_done(struct sk_buff *skb, int err)
{
	if (err) {
		kfree_skb(skb);
		pr_debug("%s: err: %d\n", __func__, err);
		return;
	}

	quic_inq_decrypted_tail(skb->sk, skb);
}

static int quic_packet_handshake_header_process(struct sock *sk, struct sk_buff *skb)
{
	u8 *p = (u8 *)quic_hshdr(skb), type = quic_hshdr(skb)->type;
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	int len = skb->len, version;
	struct quic_data token;
	u64 length;

	quic_packet_reset(packet);
	if (quic_packet_get_version_and_connid(packet, &p, &len))
		return -EINVAL;
	version = packet->version;
	if (!version) {
		quic_packet_handshake_version_process(sk, skb);
		packet->level = 0;
		return 0;
	}
	type = quic_packet_version_get_type(version, type);
	if (version != quic_config(sk)->version) {
		if (type != QUIC_PACKET_INITIAL || !quic_packet_compatible_versions(version))
			return -EINVAL;
		/* change to this compatible version */
		if (quic_packet_version_change(sk, quic_outq_orig_dcid(quic_outq(sk)), version))
			return -EINVAL;
	}
	switch (type) {
	case QUIC_PACKET_INITIAL:
		if (quic_packet_get_token(&token, &p, &len))
			return -EINVAL;
		packet->level = QUIC_CRYPTO_INITIAL;
		if (!quic_is_serv(sk) && token.len) {
			packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			return -EINVAL;
		}
		break;
	case QUIC_PACKET_HANDSHAKE:
		if (!quic_crypto_recv_ready(quic_crypto(sk, QUIC_CRYPTO_HANDSHAKE))) {
			quic_inq_backlog_tail(sk, skb);
			return 0;
		}
		packet->level = QUIC_CRYPTO_HANDSHAKE;
		break;
	case QUIC_PACKET_0RTT:
		if (!quic_crypto_recv_ready(quic_crypto(sk, QUIC_CRYPTO_EARLY))) {
			quic_inq_backlog_tail(sk, skb);
			return 0;
		}
		packet->level = QUIC_CRYPTO_EARLY;
		break;
	case QUIC_PACKET_RETRY:
		quic_packet_handshake_retry_process(sk, skb);
		packet->level = 0;
		return 0;
	default:
		return -EINVAL;
	}

	if (!quic_get_var(&p, &len, &length) || length > len)
		return -EINVAL;
	cb->length = length;
	cb->number_offset = p - skb->data;
	return 0;
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_frame frame = {}, *nframe;
	struct quic_conn_id *active;
	struct quic_crypto *crypto;
	struct quic_pnspace *space;
	struct quichshdr *hshdr;
	int err = -EINVAL;
	u8 level;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	while (skb->len > 0) {
		hshdr = quic_hshdr(skb);
		if (!hshdr->form) { /* handle it later when setting 1RTT key */
			cb->number_offset = 0;
			return quic_packet_process(sk, skb);
		}
		if (quic_packet_handshake_header_process(sk, skb))
			goto err;
		if (!packet->level)
			return 0;

		/* Do decryption */
		crypto = quic_crypto(sk, packet->level);
		level = (packet->level % QUIC_CRYPTO_EARLY);
		space = quic_pnspace(sk, level);

		cb->number_max = quic_pnspace_max_pn_seen(space);
		cb->crypto_done = quic_packet_decrypt_done;
		err = quic_crypto_decrypt(crypto, skb);
		if (err) {
			if (err == -EINPROGRESS)
				return err;
			packet->errcode = cb->errcode;
			goto err;
		}
		if (hshdr->reserved) {
			packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			goto err;
		}

		pr_debug("%s: recvd, num: %llu, level: %d, len: %d\n",
			 __func__, cb->number, packet->level, skb->len);

		err = quic_pnspace_check(space, cb->number);
		if (err) {
			err = -EINVAL;
			goto err;
		}

		frame.data = skb->data + cb->number_offset + cb->number_len;
		frame.len = cb->length - cb->number_len - packet->taglen[1];
		frame.level = packet->level;
		frame.skb = skb;
		err = quic_frame_process(sk, &frame);
		if (err)
			goto err;
		err = quic_pnspace_mark(space, cb->number);
		if (err)
			goto err;
		skb_pull(skb, cb->number_offset + cb->length);
		if (packet->ack_eliciting) {
			if (!quic_is_serv(sk) && packet->level == QUIC_CRYPTO_INITIAL) {
				active = quic_conn_id_active(quic_dest(sk));
				quic_conn_id_update(active, packet->scid.data, packet->scid.len);
			}
			nframe = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
			if (nframe) {
				quic_outq_ctrl_tail(sk, nframe, true);
				/* in case userspace doesn't send any packets, use SACK
				 * timer to send these SACK frames out.
				 */
				if (!quic_inq_need_sack(inq)) {
					quic_timer_reset(sk, QUIC_TIMER_SACK,
							 quic_inq_max_ack_delay(inq));
					quic_inq_set_need_sack(inq, 1);
				}
			}
		}
		cb->resume = 0;
		skb_reset_transport_header(skb);
	}

	if (!quic_inq_need_sack(inq)) /* delay sack timer is reused as idle timer */
		quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_idle_timeout(inq));

	consume_skb(skb);
	return 0;
err:
	pr_debug("%s: failed, num: %llu, level: %d, err: %d\n",
		 __func__, cb->number, packet->level, err);
	quic_outq_transmit_close(sk, frame.type, packet->errcode, packet->level);
	kfree_skb(skb);
	return err;
}

static int quic_packet_app_process_done(struct sock *sk, struct sk_buff *skb)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_frame *frame;
	u8 key_phase, level = 0;

	quic_pnspace_inc_ecn_count(space, quic_get_msg_ecn(sk, skb));

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	if (packet->non_probing && cb->number == quic_pnspace_max_pn_seen(space)) {
		if (!quic_conn_id_disable_active_migration(quic_dest(sk)) &&
		    (cb->path_alt & QUIC_PATH_ALT_DST))
			quic_sock_change_daddr(sk, packet->da, quic_addr_len(sk));
		if (quic_outq_pref_addr(quic_outq(sk)) &&
		    (cb->path_alt & QUIC_PATH_ALT_SRC))
			quic_sock_change_saddr(sk, NULL, 0);
	}

	if (cb->key_update) {
		key_phase = cb->key_phase;
		if (!quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase)) {
			quic_crypto_set_key_pending(crypto, 0);
			quic_crypto_set_key_update_send_time(crypto, 0);
		}
	}

	if (!packet->ack_eliciting)
		goto out;

	if (!packet->ack_immediate && !quic_pnspace_has_gap(space) &&
	    packet->rcv_count++ < packet->max_rcv_count - 1) {
		if (!quic_inq_need_sack(inq))
			quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_ack_delay(inq));
		quic_inq_set_need_sack(inq, 2);
		goto out;
	}
	packet->rcv_count = 0;
	frame = quic_frame_create(sk, QUIC_FRAME_ACK, &level);
	if (frame) {
		frame->path_alt = cb->path_alt;
		quic_outq_ctrl_tail(sk, frame, true);
	}

out:
	consume_skb(skb);
	if (!quic_inq_need_sack(inq)) /* delay sack timer is reused as idle timer */
		quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_idle_timeout(inq));
	if (quic_is_established(sk))
		quic_outq_transmit(sk);
	return 0;
}

static int quic_packet_app_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quichdr *hdr = quic_hdr(skb);
	struct quic_frame frame = {};
	int err = -EINVAL, taglen;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	quic_packet_reset(packet);
	if (!hdr->fixed && !quic_inq_grease_quic_bit(quic_inq(sk)))
		goto err;

	if (!quic_crypto_recv_ready(crypto)) {
		quic_inq_backlog_tail(sk, skb);
		return 0;
	}

	/* Do decryption */
	if (!cb->number_offset)
		cb->number_offset = quic_conn_id_active(quic_source(sk))->len + sizeof(*hdr);
	cb->length = skb->len - cb->number_offset;
	cb->number_max = quic_pnspace_max_pn_seen(space);

	taglen = quic_packet_taglen(packet);
	cb->crypto_done = quic_packet_decrypt_done;
	if (!taglen)
		cb->resume = 1; /* !taglen means disable_1rtt_encryption */
	err = quic_crypto_decrypt(crypto, skb);
	if (err) {
		if (err == -EINPROGRESS)
			return err;
		if (!quic_packet_stateless_reset_process(sk, skb))
			return 0;
		packet->errcode = cb->errcode;
		goto err;
	}
	if (hdr->reserved) {
		packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		goto err;
	}

	pr_debug("%s: recvd, num: %llu, len: %d\n", __func__, cb->number, skb->len);

	err = quic_pnspace_check(space, cb->number);
	if (err) {
		if (err > 0) { /* dup packet, send ack immediately */
			packet->ack_eliciting = 1;
			packet->ack_immediate = 1;
			goto out;
		}
		packet->errcode = QUIC_TRANSPORT_ERROR_INTERNAL;
		err = -EINVAL;
		goto err;
	}

	/* Set path_alt so that the replies will choose the correct path */
	quic_packet_get_addrs(sk, skb);
	if (!quic_path_cmp(quic_src(sk), 1, packet->sa))
		cb->path_alt |= QUIC_PATH_ALT_SRC;

	if (quic_path_cmp(quic_dst(sk), 0, packet->da)) {
		quic_path_addr_set(quic_dst(sk), packet->da, 1);
		cb->path_alt |= QUIC_PATH_ALT_DST;
	}

	frame.data = skb->data + cb->number_offset + cb->number_len;
	frame.len = cb->length - cb->number_len - taglen;
	frame.skb = skb;
	err = quic_frame_process(sk, &frame);
	if (err)
		goto err;
	err = quic_pnspace_mark(space, cb->number);
	if (err)
		goto err;

out:
	return quic_packet_app_process_done(sk, skb);

err:
	pr_debug("%s: failed, num: %llu, len: %d, err: %d\n",
		 __func__, cb->number, skb->len, err);
	quic_outq_transmit_close(sk, frame.type, packet->errcode, 0);
	kfree_skb(skb);
	return err;
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb)
{
	if (quic_is_listen(sk))
		return quic_packet_listen_process(sk, skb);

	if (quic_is_closed(sk)) {
		kfree_skb(skb);
		return 0;
	}

	if (quic_hdr(skb)->form)
		return quic_packet_handshake_process(sk, skb);

	return quic_packet_app_process(sk, skb);
}

#define TLS_MT_CLIENT_HELLO	1
#define TLS_EXT_alpn		16

static int quic_packet_get_alpn(struct quic_data *alpn, u8 *p, u32 len)
{
	int err = -EINVAL, found = 0;
	u64 length, type;

	if (!quic_get_int(&p, &len, &type, 1) || type != TLS_MT_CLIENT_HELLO)
		return err;
	if (!quic_get_int(&p, &len, &length, 3) || length < 35 || length > len)
		return err;
	len = length - 35;
	p += 35; /* legacy_version + random + legacy_session_id. */

	if (!quic_get_int(&p, &len, &length, 2) || length > len) /* cipher_suites */
		return err;
	len -= length;
	p += length;

	if (!quic_get_int(&p, &len, &length, 1) || length > len) /* legacy_compression_methods */
		return err;
	len -= length;
	p += length;

	/* TLS Extensions */
	if (!quic_get_int(&p, &len, &length, 2) || length > len)
		return err;
	len = length;
	while (len > 4) {
		if (!quic_get_int(&p, &len, &type, 2))
			break;
		if (!quic_get_int(&p, &len, &length, 2) || length > len)
			break;
		if (type == TLS_EXT_alpn) {
			len = length;
			found = 1;
			break;
		}
		p += length;
		len -= length;
	}
	if (!found) {
		quic_data(alpn, p, 0);
		return 0;
	}

	/* ALPNs */
	if (!quic_get_int(&p, &len, &length, 2) || length > len)
		return err;
	quic_data(alpn, p, length);
	len = length;
	while (len) {
		if (!quic_get_int(&p, &len, &length, 1) || length > len) {
			quic_data(alpn, NULL, 0);
			return err;
		}
		len -= length;
		p += length;
	}
	pr_debug("%s: alpn_len: %d\n", __func__, alpn->len);
	return alpn->len;
}

int quic_packet_parse_alpn(struct sk_buff *skb, struct quic_data *alpn)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quichshdr *hdr = quic_hshdr(skb);
	int len = skb->len, err = -EINVAL;
	u8 *p = skb->data, *data, type;
	struct quic_crypto *crypto;
	struct quic_packet packet;
	struct quic_data token;
	u64 offset, length;

	if (!hdr->form) /* send stateless reset later */
		return 0;
	if (quic_packet_get_version_and_connid(&packet, &p, &len))
		return -EINVAL;
	if (!quic_packet_compatible_versions(packet.version)) /* send version negotication later */
		return 0;
	type = quic_packet_version_get_type(packet.version, hdr->type);
	if (type != QUIC_PACKET_INITIAL) /* send stateless reset later */
		return 0;
	if (quic_packet_get_token(&token, &p, &len))
		return -EINVAL;
	if (!quic_get_var(&p, &len, &length) || length > len)
		return err;
	cb->length = length;
	crypto = kzalloc(sizeof(*crypto), GFP_ATOMIC);
	if (!crypto)
		return -ENOMEM;
	data = kmemdup(skb->data, skb->len, GFP_ATOMIC);
	if (!data) {
		kfree(crypto);
		return -ENOMEM;
	}
	err = quic_crypto_initial_keys_install(crypto, &packet.dcid, packet.version, 1);
	if (err)
		goto out;
	cb->number_offset = p - skb->data;
	cb->crypto_done = quic_packet_decrypt_done;
	err = quic_crypto_decrypt(crypto, skb);
	if (err) {
		memcpy(skb->data, data, skb->len);
		goto out;
	}
	cb->resume = 1;

	/* QUIC CRYPTO frame */
	err = -EINVAL;
	p += cb->number_len;
	len = cb->length - cb->number_len - QUIC_TAG_LEN;
	if (!len-- || *p++ != QUIC_FRAME_CRYPTO)
		goto out;
	if (!quic_get_var(&p, &len, &offset) || offset)
		goto out;
	if (!quic_get_var(&p, &len, &length) || length > len)
		goto out;

	/* TLS CLIENT_HELLO message */
	err = quic_packet_get_alpn(alpn, p, length);

out:
	quic_crypto_destroy(crypto);
	kfree(crypto);
	kfree(data);
	return err;
}

/* make these fixed for easy coding */
#define QUIC_PACKET_NUMBER_LEN	4
#define QUIC_PACKET_LENGTH_LEN	4

static u8 *quic_packet_pack_frames(struct sock *sk, struct sk_buff *skb, s64 number, u8 level)
{
	u32 now = jiffies_to_usecs(jiffies), len = 0, bytes = 0;
	struct quic_pnspace *space = quic_pnspace(sk, level);
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_frame *frame, *next, *tmp = NULL;
	u8 *p = skb->data + packet->len, ecn = 0;
	struct list_head *head;

	cb->number_len = QUIC_PACKET_NUMBER_LEN;
	cb->number_offset = packet->len;
	cb->number = number;
	cb->level = packet->level;
	cb->path_alt = packet->path_alt;

	p = quic_put_int(p, number, cb->number_len);

	head = &packet->frame_list;
	list_for_each_entry_safe(frame, next, head, list) {
		list_del(&frame->list);
		p = quic_put_data(p, frame->data, frame->len);
		pr_debug("%s: num: %llu, type: %u, packet_len: %u, frame_len: %u, level: %u\n",
			 __func__, number, frame->type, skb->len, frame->len, packet->level);
		if (!quic_frame_retransmittable(frame->type)) {
			quic_frame_free(frame);
			continue;
		}
		tmp = frame;
		tmp->last = 0;
		tmp->first = !len;
		len += frame->len;

		if (!quic_frame_is_crypto(frame->type))
			bytes += frame->bytes;

		if (!packet->level && !ecn && packet->ecn_probes < 3) {
			packet->ecn_probes++;
			ecn = INET_ECN_ECT_0;
		}
		frame->ecn = ecn;
		cb->ecn = ecn;

		quic_outq_transmitted_tail(sk, frame);
		if (!frame->sent_time)
			frame->offset = number;
		frame->number = number;
		frame->sent_time = now;
	}

	packet->snd_count++;
	if (!len)
		return p;

	tmp->last = 1;
	quic_pnspace_inc_inflight(space, len);
	quic_pnspace_set_last_sent_time(space, now);
	quic_outq_update_loss_timer(sk, level);
	quic_cong_on_packet_sent(quic_cong(sk), now, bytes, number);
	return p;
}

/* Initial Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 0,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Token Length (i),
 *   Token (..),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 *
 * Handshake Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 2,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 */

static struct sk_buff *quic_packet_handshake_create(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 *p, type, level = packet->level;
	u32 version, len, hlen, plen = 0;
	struct quic_conn_id_set *id_set;
	struct quic_conn_id *active;
	struct quichshdr *hdr;
	struct sk_buff *skb;
	s64 number;

	type = QUIC_PACKET_INITIAL;
	if (level == QUIC_CRYPTO_HANDSHAKE) {
		type = QUIC_PACKET_HANDSHAKE;
	} else if (level == QUIC_CRYPTO_EARLY) {
		type = QUIC_PACKET_0RTT;
		level = QUIC_CRYPTO_APP; /* space level */
	}
	version = quic_config(sk)->version;

	len = packet->len;
	if (level == QUIC_CRYPTO_INITIAL && !quic_is_serv(sk) &&
	    packet->ack_eliciting && len < (QUIC_MIN_UDP_PAYLOAD - QUIC_TAG_LEN)) {
		len = QUIC_MIN_UDP_PAYLOAD - QUIC_TAG_LEN;
		plen = len - packet->len;
	}

	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[1], GFP_ATOMIC);
	if (!skb) {
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, hlen + len);

	number = quic_pnspace_inc_next_pn(quic_pnspace(sk, level));
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq_grease_quic_bit(quic_outq(sk));
	hdr->type = quic_packet_version_put_type(version, type);
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, version, QUIC_VERSION_LEN);

	id_set = quic_dest(sk);
	active = quic_conn_id_active(id_set);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	id_set = quic_source(sk);
	active = quic_conn_id_active(id_set);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	if (level == QUIC_CRYPTO_INITIAL) {
		hlen = 0;
		if (!quic_is_serv(sk))
			hlen = quic_token(sk)->len;
		p = quic_put_var(p, hlen);
		p = quic_put_data(p, quic_token(sk)->data, hlen);
	}

	packet->len = p + QUIC_PACKET_LENGTH_LEN - skb->data;
	p = quic_put_int(p, len - packet->len + QUIC_TAG_LEN, QUIC_PACKET_LENGTH_LEN);
	*(p - 4) |= (QUIC_PACKET_LENGTH_LEN << 5);

	p = quic_packet_pack_frames(sk, skb, number, level);
	if (plen)
		memset(p, 0, plen);
	return skb;
}

static int quic_packet_number_check(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnspace *space;

	space = quic_pnspace(sk, (packet->level % QUIC_CRYPTO_EARLY));
	if (quic_pnspace_next_pn(space) + 1 <= QUIC_PN_MAP_MAX_PN)
		return 0;

	quic_outq_retransmit_list(sk, &packet->frame_list);

	if (!quic_is_closed(sk)) {
		struct quic_connection_close *close;
		u8 frame[10] = {};

		close = (void *)frame;
		close->errcode = 0;
		if (quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close))
			return -ENOMEM;
		quic_set_state(sk, QUIC_SS_CLOSED);
	}
	return -EPIPE;
}

/* 0-RTT Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 1,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 */

static struct sk_buff *quic_packet_app_create(struct sock *sk)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	u8 *p, level = packet->level;
	struct quic_conn_id *active;
	struct sk_buff *skb;
	struct quichdr *hdr;
	u32 len, hlen;
	s64 number;

	len = packet->len;
	hlen = quic_encap_len(sk) + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[0], GFP_ATOMIC);
	if (!skb) {
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, hlen + len);

	number = quic_pnspace_inc_next_pn(quic_pnspace(sk, level));
	hdr = skb_push(skb, len);
	hdr->form = 0;
	hdr->fixed = !quic_outq_grease_quic_bit(quic_outq(sk));
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	active = quic_conn_id_active(id_set);
	p = quic_put_data(p, active->data, active->len);
	packet->len = active->len + sizeof(struct quichdr);

	quic_packet_pack_frames(sk, skb, number, level);
	return skb;
}

void quic_packet_mss_update(struct sock *sk, int mss)
{
	struct quic_packet *packet = quic_packet(sk);
	int max_udp, mss_dgram;

	max_udp = quic_outq_max_udp(quic_outq(sk));
	if (max_udp && mss > max_udp)
		mss = max_udp;
	packet->mss[0] = mss;
	packet->max_rcv_count = QUIC_PATH_MAX_PMTU / mss + 1;
	quic_cong_set_mss(quic_cong(sk), packet->mss[0] - packet->taglen[0]);

	mss_dgram = quic_outq_max_dgram(quic_outq(sk));
	if (!mss_dgram)
		return;
	if (mss_dgram > mss)
		mss_dgram = mss;
	packet->mss[1] = mss_dgram;
}

int quic_packet_route(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_path_addr *s = quic_src(sk);
	struct quic_path_addr *d = quic_dst(sk);
	struct quic_config *c = quic_config(sk);
	int err, pmtu;

	packet->sa = quic_path_addr(s, packet->path_alt & QUIC_PATH_ALT_SRC);
	packet->da = quic_path_addr(d, packet->path_alt & QUIC_PATH_ALT_DST);
	err = quic_flow_route(sk, packet->da, packet->sa);
	if (err)
		return err;

	pmtu = min_t(u32, dst_mtu(__sk_dst_get(sk)), QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - quic_encap_len(sk));

	if (!quic_path_sent_cnt(s) && !quic_path_sent_cnt(d)) {
		quic_path_pl_reset(d);
		quic_timer_reset(sk, QUIC_TIMER_PATH, c->plpmtud_probe_interval);
	}
	return 0;
}

int quic_packet_config(struct sock *sk, u8 level, u8 path_alt)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	int hlen = sizeof(struct quichdr);

	if (packet->max_snd_count &&
	    packet->snd_count >= packet->max_snd_count)
		return -1;

	if (!list_empty(&packet->frame_list))
		return 0;

	packet->ack_eliciting = 0;
	packet->ipfragok = 0;
	packet->padding = 0;
	hlen += QUIC_PACKET_NUMBER_LEN; /* packet number */
	hlen += quic_conn_id_active(id_set)->len;
	if (level) {
		hlen += 1;
		id_set = quic_source(sk);
		hlen += 1 + quic_conn_id_active(id_set)->len;
		if (level == QUIC_CRYPTO_INITIAL)
			hlen += quic_var_len(quic_token(sk)->len) + quic_token(sk)->len;
		hlen += QUIC_VERSION_LEN; /* version */
		hlen += QUIC_PACKET_LENGTH_LEN; /* length */
		packet->ipfragok = !!c->plpmtud_probe_interval;
	}
	packet->len = hlen;
	packet->overhead = hlen;
	packet->level = level;
	packet->path_alt = path_alt;

	return quic_packet_route(sk) < 0 ? -1 : 0;
}

static void quic_packet_encrypt_done(struct sk_buff *skb, int err)
{
	if (err) {
		kfree_skb(skb);
		pr_debug("%s: err: %d\n", __func__, err);
		return;
	}

	quic_outq_encrypted_tail(skb->sk, skb);
}

static int quic_packet_bundle(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto_cb *head_cb, *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *p;

	if (!packet->head) {
		packet->head = skb;
		cb->last = skb;
		goto out;
	}

	if (packet->head->len + skb->len >= packet->mss[0]) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = skb;
		cb->last = skb;
		goto out;
	}
	p = packet->head;
	head_cb = QUIC_CRYPTO_CB(p);
	if (head_cb->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		head_cb->last->next = skb;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;
	head_cb->last = skb;
	head_cb->ecn |= cb->ecn;

out:
	return !cb->level;
}

int quic_packet_xmit(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	int err;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	if (!packet->taglen[quic_hdr(skb)->form]) /* !taglen means disable_1rtt_encryption */
		goto xmit;

	cb->crypto_done = quic_packet_encrypt_done;
	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb);
	if (err) {
		if (err != -EINPROGRESS)
			kfree_skb(skb);
		return err;
	}

xmit:
	if (quic_packet_bundle(sk, skb)) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = NULL;
	}
	return 0;
}

void quic_packet_create(struct sock *sk)
{
	struct sk_buff *skb;
	int err;

	err = quic_packet_number_check(sk);
	if (err)
		goto err;

	if (quic_packet(sk)->level)
		skb = quic_packet_handshake_create(sk);
	else
		skb = quic_packet_app_create(sk);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}

	err = quic_packet_xmit(sk, skb);
	if (err && err != -EINPROGRESS)
		goto err;
	return;
err:
	pr_debug("%s: err: %d\n", __func__, err);
}

int quic_packet_flush(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	u16 count;

	if (!list_empty(&packet->frame_list))
		quic_packet_create(sk);

	if (packet->head) {
		quic_lower_xmit(sk, packet->head, packet->da, packet->sa);
		packet->head = NULL;
	}
	count = packet->snd_count;

	packet->max_snd_count = 0;
	packet->snd_count = 0;
	return count;
}

int quic_packet_tail(struct sock *sk, struct quic_frame *frame, u8 dgram)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 taglen;

	if (frame->level != (packet->level % QUIC_CRYPTO_EARLY) ||
	    frame->path_alt != packet->path_alt || packet->padding)
		return 0;

	taglen = packet->taglen[!!packet->level];
	if (packet->len + frame->len > packet->mss[dgram] - taglen) {
		if (packet->len != packet->overhead)
			return 0;
		if (frame->type != QUIC_FRAME_PING)
			packet->ipfragok = 1;
	}
	if (frame->padding)
		packet->padding = frame->padding;

	if (quic_frame_ack_eliciting(frame->type))
		packet->ack_eliciting = 1;

	list_move_tail(&frame->list, &packet->frame_list);
	packet->len += frame->len;
	return frame->len;
}

void quic_packet_init(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	INIT_LIST_HEAD(&packet->frame_list);
	packet->taglen[0] = QUIC_TAG_LEN;
	packet->taglen[1] = QUIC_TAG_LEN;
	packet->mss[0] = QUIC_TAG_LEN;
	packet->mss[1] = QUIC_TAG_LEN;
}
