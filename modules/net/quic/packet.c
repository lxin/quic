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

#define QUIC_HLEN(dcid, scid)	(1 + QUIC_VERSION_LEN + 1 + (dcid)->len + 1 + (scid)->len)

#define QUIC_VERSION_NUM	2

static u32 quic_versions[QUIC_VERSION_NUM][4] = {
	/* version,	compatible versions */
	{ QUIC_VERSION_V1,	QUIC_VERSION_V2,	QUIC_VERSION_V1,	0 },
	{ QUIC_VERSION_V2,	QUIC_VERSION_V2,	QUIC_VERSION_V1,	0 },
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

static int quic_packet_get_version_and_connid(struct quic_conn_id *dcid, struct quic_conn_id *scid,
					      u32 *version, u8 **pp, u32 *plen)
{
	u64 len, v;

	if (!quic_get_int(pp, plen, &v, 1))
		return -EINVAL;

	if (!quic_get_int(pp, plen, &v, QUIC_VERSION_LEN))
		return -EINVAL;
	*version = v;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(dcid, *pp, len);
	*plen -= len;
	*pp += len;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(scid, *pp, len);
	*plen -= len;
	*pp += len;
	return 0;
}

static int quic_packet_version_change(struct sock *sk, struct quic_conn_id *dcid, u32 version)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);

	quic_crypto_destroy(crypto);

	if (quic_crypto_initial_keys_install(crypto, dcid, version, quic_is_serv(sk)))
		return -1;

	quic_packet(sk)->version = version;
	return 0;
}

int quic_packet_select_version(struct sock *sk, u32 *versions, u8 count)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	u8 i, pref_found = 0, ch_found = 0;
	u32 preferred, chosen, best = 0;

	preferred = c->version ?: QUIC_VERSION_V1;
	chosen = packet->version;

	for (i = 0; i < count; i++) {
		if (!quic_packet_compatible_versions(versions[i]))
			continue;
		if (preferred == versions[i])
			pref_found = 1;
		if (chosen == versions[i])
			ch_found = 1;
		if (best < versions[i])
			best = versions[i];
	}

	if (!pref_found && !ch_found && !best)
		return -1;

	if (quic_is_serv(sk)) {
		if (pref_found)
			best = preferred;
		else if (ch_found)
			best = chosen;
	} else {
		if (ch_found)
			best = chosen;
		else if (pref_found)
			best = preferred;
	}

	if (packet->version == best)
		return 0;

	return quic_packet_version_change(sk, quic_path_orig_dcid(quic_paths(sk)), best);
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

void quic_packet_rcv_err_pmtu(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	u32 pathmtu, info, taglen;
	struct dst_entry *dst;
	bool reset_timer;

	if (!ip_sk_accept_pmtu(sk))
		return;

	info = clamp(quic_path_mtu_info(paths), QUIC_PATH_MIN_PMTU, QUIC_PATH_MAX_PMTU);
	if (!c->plpmtud_probe_interval) {
		if (quic_packet_route(sk) < 0)
			return;

		dst = __sk_dst_get(sk);
		dst->ops->update_pmtu(dst, sk, NULL, info, true);
		quic_packet_mss_update(sk, info - packet->hlen);
		quic_outq_retransmit_mark(sk, QUIC_CRYPTO_APP, 1);
		quic_outq_update_loss_timer(sk);
		quic_outq_transmit(sk);
		return;
	}
	taglen = quic_packet_taglen(packet);
	info = info - packet->hlen - taglen;
	pathmtu = quic_path_pl_toobig(paths, info, &reset_timer);
	if (reset_timer)
		quic_timer_reset(sk, QUIC_TIMER_PMTU, c->plpmtud_probe_interval);
	if (pathmtu)
		quic_packet_mss_update(sk, pathmtu + taglen);
}

static int quic_packet_rcv_err(struct sk_buff *skb)
{
	union quic_addr daddr, saddr;
	struct sock *sk = NULL;
	int ret = 0;
	u32 info;

	quic_get_msg_addrs(&daddr, &saddr, skb);
	sk = quic_sock_lookup(skb, &daddr, &saddr, NULL);
	if (!sk)
		return -ENOENT;

	bh_lock_sock(sk);
	if (quic_is_listen(sk))
		goto out;

	if (quic_get_mtu_info(skb, &info))
		goto out;

	ret = 1; /* processed with common mtud */
	quic_path_set_mtu_info(quic_paths(sk), info);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}
	quic_packet_rcv_err_pmtu(sk);
out:
	bh_unlock_sock(sk);
	return ret;
}

int quic_packet_get_dcid(struct quic_conn_id *dcid, struct sk_buff *skb)
{
	u32 plen = skb->len;
	u8 *p = skb->data;
	u64 len;

	if (plen < 1 + QUIC_VERSION_LEN)
		return -EINVAL;
	plen -= (1 + QUIC_VERSION_LEN);
	p += (1 + QUIC_VERSION_LEN);

	if (!quic_get_int(&p, &plen, &len, 1) ||
	    len > plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(dcid, p, len);
	return 0;
}

static struct sock *quic_packet_get_sock(struct sk_buff *skb)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct net *net = dev_net(skb->dev);
	struct quic_conn_id dcid, *conn_id;
	union quic_addr daddr, saddr;
	struct sock *sk = NULL;

	if (skb->len < sizeof(struct quichdr))
		return NULL;

	if (!quic_hdr(skb)->form) {
		if (skb->len < 1 + QUIC_CONN_ID_DEF_LEN)
			return NULL;
		conn_id = quic_conn_id_lookup(net, skb->data + 1, QUIC_CONN_ID_DEF_LEN);
		if (conn_id) {
			cb->conn_id = conn_id;
			return quic_conn_id_sk(conn_id);
		}

		quic_get_msg_addrs(&daddr, &saddr, skb);
		sk = quic_listen_sock_lookup(skb, &daddr, &saddr);
		if (sk)
			return sk;
		return quic_sock_lookup(skb, &daddr, &saddr, NULL);
	}

	if (quic_packet_get_dcid(&dcid, skb))
		return NULL;
	conn_id = quic_conn_id_lookup(net, dcid.data, dcid.len);
	if (conn_id)
		return quic_conn_id_sk(conn_id);

	quic_get_msg_addrs(&daddr, &saddr, skb);
	sk = quic_sock_lookup(skb, &daddr, &saddr, &dcid);
	if (sk)
		return sk;
	return quic_listen_sock_lookup(skb, &daddr, &saddr);
}

int quic_packet_rcv(struct sk_buff *skb, u8 err)
{
	struct net *net = dev_net(skb->dev);
	struct sock *sk;

	if (unlikely(err))
		return quic_packet_rcv_err(skb);

	skb_pull(skb, skb_transport_offset(skb));

	sk = quic_packet_get_sock(skb);
	if (!sk)
		goto err;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVDROP);
			bh_unlock_sock(sk);
			goto err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVBACKLOGS);
	} else {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVFASTPATHS);
		sk->sk_backlog_rcv(sk, skb); /* quic_packet_process */
	}
	bh_unlock_sock(sk);
	return 0;

err:
	kfree_skb(skb);
	return -EINVAL;
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
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u32 len, tlen, hlen;

	quic_put_int(token, 1, 1); /* retry token flag */
	if (quic_crypto_generate_token(crypto, &packet->daddr, sizeof(packet->daddr),
				       &packet->dcid, token, &tlen))
		return NULL;

	quic_conn_id_generate(&dcid); /* new dcid for retry */
	len = QUIC_HLEN(&dcid, &packet->scid) + tlen + 16;
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, (int)(hlen + len));

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
	p = quic_put_data(p, token, tlen);
	if (quic_crypto_get_retry_tag(crypto, skb, &packet->dcid, packet->version, tag)) {
		kfree_skb(skb);
		return NULL;
	}
	quic_put_data(p, tag, 16);

	return skb;
}

static int quic_packet_retry_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *da = &packet->daddr;
	union quic_addr *sa = &packet->saddr;
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, da, sa))
		return -EINVAL;

	packet->hlen = quic_encap_len(da);
	skb = quic_packet_retry_create(sk);
	if (!skb)
		return -ENOMEM;

	quic_lower_xmit(sk, skb, da, sa);
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
	u32 len, hlen;
	u8 *p;

	len = QUIC_HLEN(&packet->dcid, &packet->scid) + QUIC_VERSION_LEN * 2;
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, (int)(hlen + len));

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
	quic_put_int(p, QUIC_VERSION_V2, QUIC_VERSION_LEN);

	return skb;
}

static int quic_packet_version_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *sa = &packet->saddr;
	union quic_addr *da = &packet->daddr;
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, da, sa))
		return -EINVAL;

	packet->hlen = quic_encap_len(da);
	skb = quic_packet_version_create(sk);
	if (!skb)
		return -ENOMEM;

	quic_lower_xmit(sk, skb, da, sa);
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
	u32 len, hlen;

	if (quic_crypto_generate_stateless_reset_token(crypto, packet->dcid.data,
						       packet->dcid.len, token, 16))
		return NULL;

	len = 64;
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, (int)(hlen + len));

	p = skb_push(skb, len);
	get_random_bytes(p, len);

	skb_reset_transport_header(skb);
	quic_hdr(skb)->form = 0;
	quic_hdr(skb)->fixed = 1;

	p += (len - 16);
	quic_put_data(p, token, 16);

	return skb;
}

static int quic_packet_stateless_reset_transmit(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *sa = &packet->saddr;
	union quic_addr *da = &packet->daddr;
	struct sk_buff *skb;

	__sk_dst_reset(sk);
	if (quic_flow_route(sk, da, sa))
		return -EINVAL;

	packet->hlen = quic_encap_len(da);
	skb = quic_packet_stateless_reset_create(sk);
	if (!skb)
		return -ENOMEM;

	quic_lower_xmit(sk, skb, da, sa);
	return 0;
}

static int quic_packet_refuse_close_transmit(struct sock *sk, u32 errcode)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *sa = &packet->saddr;
	union quic_addr *da = &packet->daddr;
	u8 level = QUIC_CRYPTO_INITIAL;
	struct quic_conn_id *active;

	active = quic_conn_id_active(id_set);
	quic_conn_id_update(active, packet->dcid.data, packet->dcid.len);
	quic_path_set_saddr(paths, 1, sa);
	quic_path_set_daddr(paths, 1, da);

	if (quic_packet_version_change(sk, active, packet->version))
		return -EINVAL;
	quic_outq_set_close_errcode(quic_outq(sk), errcode);
	quic_outq_transmit_frame(sk, QUIC_FRAME_CONNECTION_CLOSE, &level, 1, false);
	return 0;
}

static int quic_packet_listen_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	u32 version, errcode, len = skb->len;
	u8 *p = skb->data, type, retry = 0;
	struct net *net = sock_net(sk);
	struct quic_crypto *crypto;
	struct quic_conn_id odcid;
	struct quic_data token;
	int err = 0;

	if (!quic_hshdr(skb)->form) { /* stateless reset always by listen sock */
		if (len < 17) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
			err = -EINVAL;
			kfree_skb(skb);
			goto out;
		}
		quic_conn_id_update(&packet->dcid, (u8 *)quic_hdr(skb) + 1, 16);
		err = quic_packet_stateless_reset_transmit(sk);
		consume_skb(skb);
		goto out;
	}

	if (quic_packet_get_version_and_connid(&packet->dcid, &packet->scid, &version, &p, &len)) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		err = -EINVAL;
		kfree_skb(skb);
		goto out;
	}

	quic_get_msg_addrs(&packet->saddr, &packet->daddr, skb);
	if (quic_request_sock_exists(sk))
		goto enqueue;

	if (quic_accept_sock_exists(sk, skb))
		goto out; /* moved skb to another sk backlog */

	if (!quic_packet_compatible_versions(version)) { /* version negotiation */
		err = quic_packet_version_transmit(sk);
		consume_skb(skb);
		goto out;
	}

	type = quic_packet_version_get_type(version, quic_hshdr(skb)->type);
	if (type != QUIC_PACKET_INITIAL) { /* stateless reset for handshake */
		err = quic_packet_stateless_reset_transmit(sk);
		consume_skb(skb);
		goto out;
	}

	if (quic_packet_get_token(&token, &p, &len)) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		err = -EINVAL;
		kfree_skb(skb);
		goto out;
	}
	packet->version = version;
	quic_conn_id_update(&odcid, packet->dcid.data, packet->dcid.len);
	if (quic_config(sk)->validate_peer_address) {
		if (!token.len) {
			err = quic_packet_retry_transmit(sk);
			consume_skb(skb);
			goto out;
		}
		crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
		err = quic_crypto_verify_token(crypto, &packet->daddr, sizeof(packet->daddr),
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
	if (atomic_read(&sk->sk_rmem_alloc) + skb->len > (u32)sk->sk_rcvbuf) {
		err = -ENOBUFS;
		kfree_skb(skb);
		goto out;
	}

	skb_set_owner_r(skb, sk); /* handle it later when accepting the sock */
	quic_inq_backlog_tail(sk, skb);
	sk->sk_data_ready(sk);
out:
	return err;
}

static int quic_packet_stateless_reset_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_connection_close *close;
	u8 *token, buf[16] = {};

	if (skb->len < 22)
		return -EINVAL;

	token = skb->data + skb->len - 16;
	if (!quic_conn_id_token_exists(id_set, token))
		return -EINVAL; /* not a stateless reset and the caller will free skb */

	close = (void *)buf;
	close->errcode = QUIC_TRANSPORT_ERROR_CRYPTO;
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close);
	quic_set_state(sk, QUIC_SS_CLOSED);
	consume_skb(skb);
	pr_debug("%s: peer reset\n", __func__);
	return 0;
}

static int quic_packet_handshake_retry_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_conn_id *active;
	u32 hlen, len, version;
	u8 *p, tag[16];

	hlen = QUIC_HLEN(&packet->dcid, &packet->scid);
	len = skb->len - hlen;
	if (len < 16)
		goto err;
	p = skb->data + hlen;
	version = packet->version;
	if (quic_crypto_get_retry_tag(crypto, skb, quic_path_orig_dcid(paths), version, tag) ||
	    memcmp(tag, p + len - 16, 16))
		goto err;
	if (quic_data_dup(quic_token(sk), p, len - 16))
		goto err;
	/* similar to version change, update the initial keys */
	if (quic_packet_version_change(sk, &packet->scid, version))
		goto err;
	active = quic_conn_id_active(quic_dest(sk));
	quic_conn_id_update(active, packet->scid.data, packet->scid.len);
	quic_path_set_retry(paths, 1);
	quic_path_set_retry_dcid(paths, active);
	quic_outq_retransmit_mark(sk, QUIC_CRYPTO_INITIAL, 1);
	quic_outq_update_loss_timer(sk);
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
	u64 version, best = 0;
	u32 hlen, len;
	u8 *p;

	hlen = QUIC_HLEN(&packet->dcid, &packet->scid);
	len = skb->len - hlen;
	if (len < 4)
		goto err;

	p = skb->data + hlen;
	while (len >= 4) {
		quic_get_int(&p, &len, &version, QUIC_VERSION_LEN);
		if (quic_packet_compatible_versions(version) && best < version)
			best = version;
	}
	if (best) {
		if (quic_packet_version_change(sk, &packet->scid, best))
			goto err;
		quic_outq_retransmit_mark(sk, QUIC_CRYPTO_INITIAL, 1);
		quic_outq_update_loss_timer(sk);
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
		QUIC_INC_STATS(sock_net(skb->sk), QUIC_MIB_PKT_DECDROP);
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
	u32 len = skb->len, version;
	struct quic_data token;
	u64 length;

	quic_packet_reset(packet);
	if (quic_packet_get_version_and_connid(&packet->dcid, &packet->scid, &version, &p, &len))
		return -EINVAL;
	if (!version) {
		quic_packet_handshake_version_process(sk, skb);
		packet->level = 0;
		return 0;
	}
	type = quic_packet_version_get_type(version, type);
	if (version != packet->version) {
		if (type != QUIC_PACKET_INITIAL || !quic_packet_compatible_versions(version))
			return -EINVAL;
		if (quic_packet_version_change(sk, quic_path_orig_dcid(quic_paths(sk)), version))
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

	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		return -EINVAL;
	cb->length = (u16)length;
	cb->number_offset = (u16)(p - skb->data);
	return 0;
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_cong *cong = quic_cong(sk);
	struct net *net = sock_net(sk);
	u8 is_serv = quic_is_serv(sk);
	struct quic_conn_id *conn_id;
	struct quic_frame frame = {};
	struct quic_crypto *crypto;
	struct quic_pnspace *space;
	struct udphdr *uh;
	int err = -EINVAL;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	while (skb->len > 0) {
		if (!quic_hshdr(skb)->form) { /* handle it later when setting 1RTT key */
			/* treat it as a padding if dcid does not match */
			conn_id = &packet->dcid;
			if (conn_id->len > skb->len - 1 ||
			    memcmp(conn_id->data, skb->data + 1, conn_id->len)) {
				if (!quic_path_validated(paths))
					quic_path_inc_ampl_rcvlen(paths, skb->len);
				break;
			}
			cb->number_offset = 0;
			quic_packet_process(sk, skb);
			skb = NULL;
			break;
		}
		if (quic_packet_handshake_header_process(sk, skb)) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
			goto err;
		}
		if (!packet->level)
			return 0;

		/* Do decryption */
		crypto = quic_crypto(sk, packet->level);
		space = quic_pnspace(sk, packet->level);

		cb->number_max = quic_pnspace_max_pn_seen(space);
		cb->crypto_done = quic_packet_decrypt_done;
		err = quic_crypto_decrypt(crypto, skb);
		if (err) {
			if (err == -EINPROGRESS) {
				QUIC_INC_STATS(net, QUIC_MIB_PKT_DECBACKLOGS);
				return err;
			}
			QUIC_INC_STATS(net, QUIC_MIB_PKT_DECDROP);
			packet->errcode = cb->errcode;
			goto err;
		}
		if (!cb->resume)
			QUIC_INC_STATS(net, QUIC_MIB_PKT_DECFASTPATHS);
		if (quic_hshdr(skb)->reserved) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
			packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			goto err;
		}

		pr_debug("%s: recvd, num: %llu, level: %d, len: %d\n",
			 __func__, cb->number, packet->level, skb->len);

		quic_pnspace_set_time(space, cb->time);
		err = quic_pnspace_check(space, cb->number);
		if (err) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVNUMDROP);
			err = -EINVAL;
			goto err;
		}

		quic_cong_set_time(cong, cb->time);
		frame.data = skb->data + cb->number_offset + cb->number_len;
		frame.len = cb->length - cb->number_len - packet->taglen[1];
		frame.level = packet->level;
		frame.skb = skb;
		err = quic_frame_process(sk, &frame);
		if (err) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVFRMDROP);
			goto err;
		}
		err = quic_pnspace_mark(space, cb->number);
		if (err)
			goto err;

		quic_pnspace_inc_ecn_count(space, quic_get_msg_ecn(skb));

		if (packet->has_sack) {
			quic_outq_retransmit_mark(sk, packet->level, 0);
			quic_outq_update_loss_timer(sk);
		}

		if (!quic_path_validated(paths)) {
			quic_path_inc_ampl_rcvlen(paths, cb->number_offset + cb->length);
			if (packet->level == QUIC_CRYPTO_HANDSHAKE) {
				quic_path_set_validated(paths, 1);
				quic_outq_transmitted_sack(sk, QUIC_CRYPTO_INITIAL,
							   QUIC_PN_MAP_MAX_PN, 0, -1, 0);
			}
		}
		skb_pull(skb, cb->number_offset + cb->length);

		cb->resume = 0;
		skb_reset_transport_header(skb);
		if (!packet->ack_requested)
			continue;

		quic_pnspace_set_need_sack(space, 1);
		quic_pnspace_set_sack_path(space, 0);

		if (packet->level == QUIC_CRYPTO_INITIAL) {
			if (!is_serv) {
				conn_id = quic_conn_id_active(quic_dest(sk));
				quic_conn_id_update(conn_id, packet->scid.data, packet->scid.len);
				continue;
			}
			uh = quic_udphdr(skb);
			if (ntohs(uh->len) - sizeof(*uh) < QUIC_MIN_UDP_PAYLOAD) {
				packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
				err = -EINVAL;
				goto err;
			}
		}
	}
	/* in case userspace doesn't send any packets, use SACK
	 * timer to send these SACK frames out.
	 */
	if (!quic_inq_need_sack(inq)) {
		quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_ack_delay(inq));
		quic_inq_set_need_sack(inq, 1);
	}
	if (quic_path_blocked(paths)) {
		quic_path_set_blocked(paths, 0);
		quic_outq_update_loss_timer(sk);
	}

	consume_skb(skb);
	return 0;
err:
	pr_debug("%s: failed, num: %llu, level: %d, err: %d\n",
		 __func__, cb->number, packet->level, err);
	quic_outq_transmit_close(sk, frame.type, packet->errcode, packet->level);
	kfree_skb(skb);
	return err;
}

static void quic_packet_path_alt_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);

	if (cb->path) {
		if (quic_path_alt_state(paths, QUIC_PATH_ALT_NONE))
			quic_outq_probe_path_alt(sk, true);
		return;
	}

	if (!packet->non_probing || cb->number != cb->number_max ||
	    !quic_path_alt_state(paths, QUIC_PATH_ALT_SWAPPED))
		return;

	quic_path_free(sk, paths, 1);
	quic_conn_id_set_alt(quic_dest(sk), NULL);
	quic_conn_id_set_active(quic_source(sk), cb->conn_id);
}

static int quic_packet_app_process_done(struct sock *sk, struct sk_buff *skb)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	s64 max_bidi = 0, max_uni = 0;
	u8 frame;

	quic_pnspace_inc_ecn_count(space, quic_get_msg_ecn(skb));

	/* connection migration check: an endpoint only changes the address to which
	 * it sends packets in response to the highest-numbered non-probing packet.
	 */
	quic_packet_path_alt_process(sk, skb);

	if (!quic_path_validated(paths))
		quic_path_inc_ampl_rcvlen(paths, skb->len);

	if (packet->has_sack) {
		quic_outq_retransmit_mark(sk, 0, 0);
		quic_outq_update_loss_timer(sk);
	}

	if (quic_stream_max_streams_update(streams, &max_uni, &max_bidi)) {
		if (max_uni) {
			frame = QUIC_FRAME_MAX_STREAMS_UNI;
			quic_outq_transmit_frame(sk, frame, &max_uni, 0, true);
		}
		if (max_bidi) {
			frame = QUIC_FRAME_MAX_STREAMS_BIDI;
			quic_outq_transmit_frame(sk, frame, &max_bidi, 0, true);
		}
	}

	if (!packet->ack_requested)
		goto out;

	if (!packet->ack_immediate) {
		if (!quic_inq_need_sack(inq))
			quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_ack_delay(inq));
		quic_inq_set_need_sack(inq, 2);
		goto out;
	}
	quic_pnspace_set_need_sack(space, 1);
	quic_pnspace_set_sack_path(space, cb->path);

out:
	if (quic_is_established(sk)) {
		if (!quic_inq_need_sack(inq))
			quic_timer_reset(sk, QUIC_TIMER_IDLE, quic_inq_timeout(inq));
		quic_outq_transmit(sk);
	} else if (!quic_inq_need_sack(inq)) {
		quic_inq_set_need_sack(inq, 1);
		quic_timer_reset(sk, QUIC_TIMER_SACK, quic_inq_max_ack_delay(inq));
	}
	consume_skb(skb);
	return 0;
}

static int quic_packet_app_process(struct sock *sk, struct sk_buff *skb)
{
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct net *net = sock_net(sk);
	struct quic_frame frame = {};
	u8 taglen, key_phase, active;
	int err = -EINVAL;
	u64 number;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	quic_packet_reset(packet);
	if (!quic_hdr(skb)->fixed && !quic_inq_grease_quic_bit(quic_inq(sk))) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		goto err;
	}

	if (!quic_crypto_recv_ready(crypto)) {
		quic_inq_backlog_tail(sk, skb);
		return 0;
	}

	/* Do decryption */
	if (!cb->conn_id) {
		cb->conn_id = quic_conn_id_get(source, skb->data + 1, QUIC_CONN_ID_DEF_LEN);
		if (!cb->conn_id) {
			if (!quic_packet_stateless_reset_process(sk, skb))
				return 0;
			goto err;
		}
	}
	cb->number_offset = cb->conn_id->len + 1;
	cb->length = (u16)(skb->len - cb->number_offset);
	cb->number_max = quic_pnspace_max_pn_seen(space);

	taglen = quic_packet_taglen(packet);
	cb->crypto_done = quic_packet_decrypt_done;
	if (!taglen)
		cb->resume = 1; /* !taglen means disable_1rtt_encryption */
	err = quic_crypto_decrypt(crypto, skb);
	if (err) {
		if (err == -EINPROGRESS) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_DECBACKLOGS);
			return err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_DECDROP);
		if (cb->key_update) {
			key_phase = cb->key_phase;
			quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase);
			goto err;
		}
		packet->errcode = cb->errcode;
		goto err;
	}
	if (cb->key_update) {
		key_phase = cb->key_phase;
		quic_inq_event_recv(sk, QUIC_EVENT_KEY_UPDATE, &key_phase);
	}
	if (!cb->resume)
		QUIC_INC_STATS(net, QUIC_MIB_PKT_DECFASTPATHS);
	if (quic_hdr(skb)->reserved) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		packet->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		goto err;
	}

	pr_debug("%s: recvd, num: %llu, len: %d\n", __func__, cb->number, skb->len);

	quic_pnspace_set_time(space, cb->time);
	err = quic_pnspace_check(space, cb->number);
	if (err) {
		if (err > 0) { /* dup packet, send ack immediately */
			packet->ack_requested = 1;
			packet->ack_immediate = 1;
			goto out;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVNUMDROP);
		err = -EINVAL;
		goto err;
	}

	quic_get_msg_addrs(&packet->saddr, &packet->daddr, skb);
	/* Set path so that the replies will choose the correct path */
	cb->path = quic_path_detect_alt(quic_paths(sk), &packet->saddr, &packet->daddr);
	active = (cb->conn_id == quic_conn_id_active(source));
	if (cb->path && !quic_conn_id_select_alt(dest, active)) {
		number = quic_conn_id_first_number(dest);
		quic_outq_transmit_frame(sk, QUIC_FRAME_RETIRE_CONNECTION_ID, &number, 0, false);
		goto err;
	}

	quic_cong_set_time(quic_cong(sk), cb->time);
	frame.data = skb->data + cb->number_offset + cb->number_len;
	frame.len = cb->length - cb->number_len - taglen;
	frame.path = cb->path;
	frame.skb = skb;
	err = quic_frame_process(sk, &frame);
	if (err) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVFRMDROP);
		goto err;
	}
	err = quic_pnspace_mark(space, cb->number);
	if (err)
		goto err;

out:
	return quic_packet_app_process_done(sk, skb);

err:
	pr_debug("%s: failed, num: %llu, len: %d, err: %d\n",
		 __func__, cb->number, skb->len, err);
	quic_outq_transmit_close(sk, packet->errframe, packet->errcode, 0);
	kfree_skb(skb);
	return err;
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb)
{
	if (quic_is_closed(sk)) {
		kfree_skb(skb);
		return 0;
	}

	if (quic_is_listen(sk))
		return quic_packet_listen_process(sk, skb);

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
	if (!quic_get_int(&p, &len, &length, 3) || length < 35)
		return err;
	if (len > (u32)length) /* incomplete TLS msg */
		len = length;
	len -= 35;
	p += 35; /* legacy_version + random + legacy_session_id. */

	if (!quic_get_int(&p, &len, &length, 2) || length > (u64)len) /* cipher_suites */
		return err;
	len -= length;
	p += length;

	/* legacy_compression_methods */
	if (!quic_get_int(&p, &len, &length, 1) || length > (u64)len)
		return err;
	len -= length;
	p += length;

	/* TLS Extensions */
	if (!quic_get_int(&p, &len, &length, 2))
		return err;
	if (len > (u32)length)
		len = length;
	while (len > 4) {
		if (!quic_get_int(&p, &len, &type, 2))
			break;
		if (!quic_get_int(&p, &len, &length, 2))
			break;
		if (len < (u32)length) /* incomplete TLS extensions */
			return 0;
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
	if (!quic_get_int(&p, &len, &length, 2) || length > (u64)len)
		return err;
	quic_data(alpn, p, length);
	len = length;
	while (len) {
		if (!quic_get_int(&p, &len, &length, 1) || length > (u64)len) {
			quic_data(alpn, NULL, 0);
			return err;
		}
		len -= length;
		p += length;
	}
	pr_debug("%s: alpn_len: %d\n", __func__, alpn->len);
	return 0;
}

int quic_packet_parse_alpn(struct sk_buff *skb, struct quic_data *alpn)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct net *net = dev_net(skb->dev);
	u8 *p = skb->data, *data, type;
	struct quic_conn_id dcid, scid;
	u32 len = skb->len, version;
	struct quic_crypto *crypto;
	struct quic_data token;
	u64 offset, length;
	int err = -EINVAL;

	if (!quic_hshdr(skb)->form) /* send stateless reset later */
		return 0;
	if (quic_packet_get_version_and_connid(&dcid, &scid, &version, &p, &len))
		return -EINVAL;
	if (!quic_packet_compatible_versions(version)) /* send version negotiation later */
		return 0;
	type = quic_packet_version_get_type(version, quic_hshdr(skb)->type);
	if (type != QUIC_PACKET_INITIAL) /* send stateless reset later */
		return 0;
	if (quic_packet_get_token(&token, &p, &len))
		return -EINVAL;
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		return err;
	cb->length = (u16)length;
	crypto = kzalloc(sizeof(*crypto), GFP_ATOMIC);
	if (!crypto)
		return -ENOMEM;
	data = kmemdup(skb->data, skb->len, GFP_ATOMIC);
	if (!data) {
		kfree(crypto);
		return -ENOMEM;
	}
	err = quic_crypto_initial_keys_install(crypto, &dcid, version, 1);
	if (err)
		goto out;
	cb->number_offset = (u16)(p - skb->data);
	cb->crypto_done = quic_packet_decrypt_done;
	err = quic_crypto_decrypt(crypto, skb);
	if (err) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_DECDROP);
		memcpy(skb->data, data, skb->len);
		goto out;
	}
	QUIC_INC_STATS(net, QUIC_MIB_PKT_DECFASTPATHS);
	cb->resume = 1;

	/* QUIC CRYPTO frame */
	p += cb->number_len;
	len = cb->length - cb->number_len - QUIC_TAG_LEN;
	for (; len && !(*p); p++, len--) /* skip the padding frame */
		;
	if (!len-- || *p++ != QUIC_FRAME_CRYPTO)
		goto out;
	if (!quic_get_var(&p, &len, &offset) || offset)
		goto out;
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
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

static u8 *quic_packet_pack_frames(struct sock *sk, struct sk_buff *skb,
				   struct quic_packet_sent *sent, u16 off)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	u32 now = jiffies_to_usecs(jiffies);
	struct quic_frame *frame, *next;
	struct quic_frame_frag *frag;
	struct quic_pnspace *space;
	u8 *p = skb->data + off;
	s64 number;
	u16 i = 0;

	space = quic_pnspace(sk, packet->level);
	number = quic_pnspace_inc_next_pn(space);

	cb->number_len = QUIC_PACKET_NUMBER_LEN;
	cb->number_offset = off;
	cb->number = number;
	cb->level = packet->level;
	cb->path = packet->path;

	p = quic_put_int(p, number, cb->number_len);

	list_for_each_entry_safe(frame, next, &packet->frame_list, list) {
		list_del(&frame->list);
		p = quic_put_data(p, frame->data, frame->size);
		for (frag = frame->flist; frag; frag = frag->next)
			p = quic_put_data(p, frag->data, frag->size);
		pr_debug("%s: num: %llu, type: %u, packet_len: %u, frame_len: %u, level: %u\n",
			 __func__, number, frame->type, skb->len, frame->len, packet->level);
		if (!quic_frame_ack_eliciting(frame->type) || quic_frame_ping(frame->type)) {
			quic_frame_put(frame);
			continue;
		}
		if (frame->offset < 0)
			frame->offset = number;
		quic_outq_transmitted_tail(sk, frame);
		sent->frame_array[i++] = quic_frame_get(frame);
	}

	if (quic_is_serv(sk) && !quic_path_validated(paths))
		quic_path_inc_ampl_sndlen(paths, (u16)skb->len + quic_packet_taglen(packet));

	if (quic_is_established(sk) && !quic_path_alt_state(paths, QUIC_PATH_ALT_PROBING))
		quic_timer_reset_path(sk);

	if (packet->ack_eliciting)
		quic_pnspace_set_last_sent_time(space, now);

	if (!sent)
		return p;

	if (!packet->level && quic_path_ecn_probes(paths) < 3) {
		quic_path_inc_ecn_probes(paths);
		cb->ecn = INET_ECN_ECT_0;
		sent->ecn = INET_ECN_ECT_0;
	}
	sent->number = number;
	sent->sent_time = now;
	sent->frame_len = packet->frame_len;
	sent->level = (packet->level % QUIC_CRYPTO_EARLY);

	quic_outq_inc_inflight(quic_outq(sk), sent->frame_len);
	quic_pnspace_inc_inflight(space, sent->frame_len);
	quic_outq_packet_sent_tail(sk, sent);

	quic_cong_on_packet_sent(quic_cong(sk), sent->sent_time, sent->frame_len, number);
	quic_outq_update_loss_timer(sk);
	return p;
}

static struct quic_packet_sent *quic_packet_sent_alloc(u16 frames)
{
	u32 len = frames * sizeof(struct quic_frame *);
	struct quic_packet_sent *sent;

	sent = kzalloc(sizeof(*sent) + len, GFP_ATOMIC);
	if (sent)
		sent->frames = frames;

	return sent;
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
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_packet *packet = quic_packet(sk);
	u8 type, fixed = 1, level = packet->level;
	struct quic_packet_sent *sent = NULL;
	struct quic_conn_id *active;
	u32 len, hlen, plen = 0;
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u16 off;
	u8 *p;

	type = QUIC_PACKET_INITIAL;
	if (level == QUIC_CRYPTO_HANDSHAKE) {
		type = QUIC_PACKET_HANDSHAKE;
		fixed = !quic_outq_grease_quic_bit(quic_outq(sk));
	} else if (level == QUIC_CRYPTO_EARLY) {
		type = QUIC_PACKET_0RTT;
	}

	len = packet->len;
	if (packet->ack_eliciting) {
		hlen = QUIC_MIN_UDP_PAYLOAD - packet->taglen[1];
		if (level == QUIC_CRYPTO_INITIAL && len < hlen) {
			len = hlen;
			plen = len - packet->len;
		}
	}
	if (packet->frames) {
		sent = quic_packet_sent_alloc(packet->frames);
		if (!sent) {
			quic_outq_retransmit_list(sk, &packet->frame_list);
			return NULL;
		}
	}

	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[1], GFP_ATOMIC);
	if (!skb) {
		kfree(sent);
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, (int)(hlen + len));

	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = fixed;
	hdr->type = quic_packet_version_put_type(packet->version, type);
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;
	skb_reset_transport_header(skb);

	p = (u8 *)hdr + 1;
	p = quic_put_int(p, packet->version, QUIC_VERSION_LEN);

	active = quic_conn_id_active(dest);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	active = quic_conn_id_active(source);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	if (level == QUIC_CRYPTO_INITIAL) {
		hlen = 0;
		if (!quic_is_serv(sk))
			hlen = quic_token(sk)->len;
		p = quic_put_var(p, hlen);
		p = quic_put_data(p, quic_token(sk)->data, hlen);
	}

	off = (u16)(p + QUIC_PACKET_LENGTH_LEN - skb->data);
	p = quic_put_int(p, len - off + QUIC_TAG_LEN, QUIC_PACKET_LENGTH_LEN);
	*(p - 4) |= (QUIC_PACKET_LENGTH_LEN << 5);

	p = quic_packet_pack_frames(sk, skb, sent, off);
	if (plen)
		memset(p, 0, plen);
	return skb;
}

static int quic_packet_number_check(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnspace *space;

	space = quic_pnspace(sk, packet->level);
	if (quic_pnspace_next_pn(space) + 1 <= QUIC_PN_MAP_MAX_PN)
		return 0;

	quic_outq_retransmit_list(sk, &packet->frame_list);

	if (!quic_is_closed(sk)) {
		struct quic_connection_close *close;
		u8 buf[16] = {};

		close = (void *)buf;
		close->errcode = 0;
		quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, close);
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
	struct quic_packet_sent *sent = NULL;
	struct quic_conn_id *active;
	struct sk_buff *skb;
	struct quichdr *hdr;
	u32 len, hlen;
	u16 off;

	if (packet->frames) {
		sent = quic_packet_sent_alloc(packet->frames);
		if (!sent) {
			quic_outq_retransmit_list(sk, &packet->frame_list);
			return NULL;
		}
	}

	len = packet->len;
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[0], GFP_ATOMIC);
	if (!skb) {
		kfree(sent);
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, (int)(hlen + len));

	hdr = skb_push(skb, len);
	hdr->form = 0;
	hdr->fixed = !quic_outq_grease_quic_bit(quic_outq(sk));
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;
	skb_reset_transport_header(skb);

	active = quic_conn_id_choose(id_set, packet->path);
	quic_put_data((u8 *)hdr + 1, active->data, active->len);
	off = (u16)(active->len + sizeof(struct quichdr));

	quic_packet_pack_frames(sk, skb, sent, off);
	return skb;
}

void quic_packet_mss_update(struct sock *sk, u32 mss)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);
	u32 max_udp, mss_dgram;

	max_udp = quic_outq_max_udp(outq);
	if (max_udp && mss > max_udp)
		mss = max_udp;
	packet->mss[0] = (u16)mss;
	quic_cong_set_mss(cong, packet->mss[0] - packet->taglen[0]);
	quic_outq_sync_window(sk, quic_cong_window(cong));

	mss_dgram = quic_outq_max_dgram(outq);
	if (!mss_dgram)
		return;
	if (mss_dgram > mss)
		mss_dgram = mss;
	packet->mss[1] = (u16)mss_dgram;
}

int quic_packet_route(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	union quic_addr *sa, *da;
	u32 pmtu;
	int err;

	da = quic_path_daddr(paths, packet->path);
	sa = quic_path_saddr(paths, packet->path);
	err = quic_flow_route(sk, da, sa);
	if (err)
		return err;

	packet->hlen = quic_encap_len(da);
	pmtu = min_t(u32, dst_mtu(__sk_dst_get(sk)), QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - packet->hlen);

	quic_path_pl_reset(paths);
	quic_timer_reset(sk, QUIC_TIMER_PMTU, c->plpmtud_probe_interval);
	return 0;
}

int quic_packet_config(struct sock *sk, u8 level, u8 path)
{
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	u32 hlen = sizeof(struct quichdr);

	if (!quic_packet_empty(packet))
		return 0;

	packet->ack_eliciting = 0;
	packet->frame_len = 0;
	packet->ipfragok = 0;
	packet->padding = 0;
	packet->frames = 0;
	hlen += QUIC_PACKET_NUMBER_LEN; /* packet number */
	hlen += quic_conn_id_choose(dest, path)->len;
	if (level) {
		hlen += 1;
		hlen += 1 + quic_conn_id_active(source)->len;
		if (level == QUIC_CRYPTO_INITIAL)
			hlen += quic_var_len(quic_token(sk)->len) + quic_token(sk)->len;
		hlen += QUIC_VERSION_LEN; /* version */
		hlen += QUIC_PACKET_LENGTH_LEN; /* length */
		packet->ipfragok = !!c->plpmtud_probe_interval;
	}
	packet->level = level;
	packet->len = (u16)hlen;
	packet->overhead = (u8)hlen;

	if (packet->path != path) {
		packet->path = path;
		__sk_dst_reset(sk);
	}

	if (quic_packet_route(sk) < 0)
		return -1;
	return 0;
}

static void quic_packet_encrypt_done(struct sk_buff *skb, int err)
{
	if (err) {
		QUIC_INC_STATS(sock_net(skb->sk), QUIC_MIB_PKT_ENCDROP);
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
		quic_packet_flush(sk);
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
	struct net *net = sock_net(sk);
	int err;

	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	if (!packet->taglen[quic_hdr(skb)->form]) /* !taglen means disable_1rtt_encryption */
		goto xmit;

	cb->crypto_done = quic_packet_encrypt_done;
	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb);
	if (err) {
		if (err != -EINPROGRESS) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCDROP);
			kfree_skb(skb);
			return err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCBACKLOGS);
		return err;
	}
	if (!cb->resume)
		QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCFASTPATHS);

xmit:
	if (quic_packet_bundle(sk, skb))
		quic_packet_flush(sk);
	return 0;
}

int quic_packet_create(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;
	int err;

	err = quic_packet_number_check(sk);
	if (err)
		goto err;

	if (packet->level)
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

	return !!packet->frames;
err:
	pr_debug("%s: err: %d\n", __func__, err);
	return 0;
}

void quic_packet_flush(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *sa, *da;

	if (packet->head) {
		da = quic_path_daddr(paths, packet->path);
		sa = quic_path_saddr(paths, packet->path);
		quic_lower_xmit(sk, packet->head, da, sa);
		packet->head = NULL;
	}
}

int quic_packet_tail(struct sock *sk, struct quic_frame *frame)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 taglen;

	if (frame->level != (packet->level % QUIC_CRYPTO_EARLY) ||
	    frame->path != packet->path || packet->padding)
		return 0;

	taglen = quic_packet_taglen(packet);
	if (packet->len + frame->len > packet->mss[frame->dgram] - taglen) {
		if (packet->len != packet->overhead)
			return 0;
		if (!quic_frame_ping(frame->type))
			packet->ipfragok = 1;
	}
	if (frame->padding)
		packet->padding = frame->padding;

	if (quic_frame_ack_eliciting(frame->type)) {
		packet->ack_eliciting = 1;
		if (!quic_frame_ping(frame->type)) {
			packet->frames++;
			packet->frame_len += frame->len;
		}
	}

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

	packet->version = QUIC_VERSION_V1;
}
