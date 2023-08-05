// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is the userspace handshake part for the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <gnutls/crypto.h>

#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include <linux/quic.h>

enum {
	QUIC_STATE_CLOSED,
	QUIC_STATE_CONNECTING,
	QUIC_STATE_CONNECTED,
};

struct quic_key {
	uint8_t key[64];
	uint8_t keylen;
};

struct quic_cid {
	uint8_t cid[20];
	uint8_t cidlen;
};

struct quic_endpoint {
	struct sockaddr_in la;	/* local address */
	struct sockaddr_in ra;	/* remote address */
	int sockfd;		/* IPPROTO_QUIC type socket */

	uint8_t state;	/* internal state */
	uint8_t	ready;	/* mark handshake is sucessful */
	uint8_t	dead;	/* reason why handshake failed */
	timer_t	timer;	/* timer for retransmission */

	uint32_t connecting_ts[2];	/* to calculate the initial rtt */
	struct quic_key secret[2];	/* secrets for sending and receiving */
	struct quic_cid connid[2];	/* source and dest connection IDs */

	char keyfile[2][100];	/* private key & certificate or psk file */
	int (*server_session_new)(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd);
	int (*client_session_new)(struct quic_endpoint *ep);

	ngtcp2_conn *conn;	/* connection structure from libngtcp2 */
	ngtcp2_crypto_conn_ref conn_ref;	/* used in session hook */
};

static uint64_t quic_get_timestamp()
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int quic_handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_endpoint *ep = user_data;

	ep->state = QUIC_STATE_CONNECTED;
	ep->ready = 1;
	return 0;
}

static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_endpoint *ep = user_data;

	ep->state = QUIC_STATE_CONNECTED;
	ep->ready = ngtcp2_conn_is_server(conn);
	ep->connecting_ts[1] = quic_get_timestamp() / NGTCP2_MICROSECONDS;

	return 0;
}

static void quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
					 uint8_t *token, size_t cidlen, void *user_data)
{
	if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen))
		return NGTCP2_ERR_CALLBACK_FAILURE;
	cid->datalen = cidlen;
	if (gnutls_rnd(GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN))
		return NGTCP2_ERR_CALLBACK_FAILURE;
	return 0;
}

static int quic_recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
				       void *user_data)
{
	struct quic_endpoint *ep = user_data;

	ep->state = QUIC_STATE_CONNECTING;
	ep->connecting_ts[0] = quic_get_timestamp() / NGTCP2_MICROSECONDS;

	return ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);
}

static int quic_client_initial_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_endpoint *ep = user_data;

	ep->state = QUIC_STATE_CONNECTING;
	ep->connecting_ts[0] = quic_get_timestamp() / NGTCP2_MICROSECONDS;

	return ngtcp2_crypto_client_initial_cb(conn, user_data);
}

static int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
				    uint64_t offset, const uint8_t *data, size_t datalen,
				    void *user_data, void *stream_user_data)
{
	return 0;
}

static int quic_recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level, void *user_data)
{
	return 0;
}

static int quic_recv_tx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level, void *user_data)
{
	return 0;
}

static int quic_recv_datagram_cb(ngtcp2_conn *conn, uint32_t flags,
				 const uint8_t *data, size_t datalen, void *user_data)
{
	return 0;
}

static int quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	return 0;
}

static int quic_dcid_status_cb(ngtcp2_conn *conn, ngtcp2_connection_id_status_type type, uint64_t seq,
			       const ngtcp2_cid *cid, const uint8_t *token, void *user_data)
{
	struct quic_endpoint *ep = user_data;

	if (type != NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE)
		return 0;
	memcpy(ep->connid[1].cid, cid->data, cid->datalen);
	ep->connid[1].cidlen = cid->datalen;
	return 0;
}

static void quic_ngtcp2_conn_callbacks_init(ngtcp2_callbacks *callbacks)
{
	memset(callbacks, 0, sizeof(*callbacks));
	callbacks->rand = quic_rand_cb;
	callbacks->get_new_connection_id = quic_get_new_connection_id_cb;
	callbacks->recv_client_initial = quic_recv_client_initial_cb;
	callbacks->client_initial = quic_client_initial_cb;
	callbacks->handshake_confirmed = quic_handshake_confirmed_cb;
	callbacks->handshake_completed = quic_handshake_completed_cb;
	callbacks->recv_stream_data = quic_recv_stream_data_cb;
	callbacks->recv_rx_key = quic_recv_rx_key_cb;
	callbacks->recv_tx_key = quic_recv_tx_key_cb;
	callbacks->recv_datagram = quic_recv_datagram_cb;
	callbacks->stream_open = quic_stream_open_cb;
	callbacks->dcid_status = quic_dcid_status_cb;

	callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
	callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
	callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
	callbacks->update_key = ngtcp2_crypto_update_key_cb;
	callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
	callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
	callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
}

static ngtcp2_conn *quic_session_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct quic_endpoint *ep = conn_ref->user_data;

	return ep->conn;
}

static int quic_session_secret_func(gnutls_session_t session, gnutls_record_encryption_level_t l,
				    const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
	ngtcp2_conn *conn = conn_ref->get_conn(conn_ref);
	struct quic_endpoint *ep = conn_ref->user_data;
	ngtcp2_encryption_level level;
	char key[64], iv[64], hp[64];

	level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(l);
	if (rx_secret) {
		if (ngtcp2_crypto_derive_and_install_rx_key(conn, key, iv, hp, level,
							    rx_secret, secretlen))
			return -1;
		if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
			memcpy(ep->secret[0].key, rx_secret, secretlen);
			ep->secret[0].keylen = secretlen;
		}
	}

	if (tx_secret) {
		if (ngtcp2_crypto_derive_and_install_tx_key(conn, key, iv, hp, level,
							    tx_secret, secretlen))
			return -1;
		if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
			memcpy(ep->secret[1].key, tx_secret, secretlen);
			ep->secret[1].keylen = secretlen;
		}
	}

	return 0;
}

static int quic_client_connection_new(struct quic_endpoint *ep)
{
	ngtcp2_transport_params params;
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
	ngtcp2_path_storage ps;
	ngtcp2_cid scid, dcid;

	ngtcp2_transport_params_default(&params);
	params.initial_max_stream_data_bidi_local = 64 * 1024;
	params.initial_max_stream_data_bidi_remote = 64 * 1024;
	params.initial_max_stream_data_uni = 64 * 1024;
	params.initial_max_data = 128 * 1024;
	params.initial_max_streams_bidi = 100;
	params.initial_max_streams_uni = 100;
	params.max_idle_timeout = 30 * NGTCP2_SECONDS;
	params.active_connection_id_limit = 7;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_get_timestamp();
	settings.handshake_timeout = 30 * NGTCP2_SECONDS;
	quic_ngtcp2_conn_callbacks_init(&callbacks);

	scid.datalen = 17;
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
	memcpy(ep->connid[0].cid, scid.data, scid.datalen);
	ep->connid[0].cidlen = scid.datalen;
	dcid.datalen = 18;
	gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
	memcpy(ep->connid[1].cid, dcid.data, dcid.datalen);
	ep->connid[1].cidlen = dcid.datalen;
	ngtcp2_path_storage_init(&ps, (void *)&ep->la, sizeof(ep->la),
				 (void *)&ep->ra, sizeof(ep->ra), NULL);

	return ngtcp2_conn_client_new(&ep->conn, &dcid, &scid, &ps.path, NGTCP2_PROTO_VER_V1,
				      &callbacks, &settings, &params, NULL, ep);
}

static int quic_server_connection_new(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	ngtcp2_transport_params params;
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
	ngtcp2_path_storage ps;
	ngtcp2_cid scid, dcid;

	ngtcp2_transport_params_default(&params);
	params.initial_max_stream_data_bidi_local = 64 * 1024;
	params.initial_max_stream_data_bidi_remote = 64 * 1024;
	params.initial_max_stream_data_uni = 64 * 1024;
	params.initial_max_data = 128 * 1024;
	params.initial_max_streams_bidi = 100;
	params.initial_max_streams_uni = 100;
	params.max_idle_timeout = 30 * NGTCP2_SECONDS;
	params.active_connection_id_limit = 7;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_get_timestamp();
	settings.handshake_timeout = 30 * NGTCP2_SECONDS;
	quic_ngtcp2_conn_callbacks_init(&callbacks);

	params.original_dcid = hd->dcid;
	params.original_dcid_present = 1;
	settings.token = hd->token;
	settings.tokenlen = hd->tokenlen;
	scid.datalen = 18;
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
	memcpy(ep->connid[0].cid, scid.data, scid.datalen);
	ep->connid[0].cidlen = scid.datalen;
	dcid = hd->scid;
	memcpy(ep->connid[1].cid, dcid.data, dcid.datalen);
	ep->connid[1].cidlen = dcid.datalen;
	ngtcp2_path_storage_init(&ps, (void *)&ep->la, sizeof(ep->la),
				 (void *)&ep->ra, sizeof(ep->ra), NULL);

	return ngtcp2_conn_server_new(&ep->conn, &dcid, &scid, &ps.path, hd->version,
				      &callbacks, &settings, &params, NULL, ep);
}

#define MODES "%DISABLE_TLS13_COMPAT_MODE"
#define CIPHERS "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:+PSK"
#define GROUPS "-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define PRIORITY MODES":"CIPHERS":"GROUPS

static int quic_client_set_x509_session(struct quic_endpoint *ep)
{
	gnutls_certificate_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_certificate_allocate_credentials(&cred))
		return -1;
	if (gnutls_certificate_set_x509_system_trust(cred) < 0)
		goto err_cred;

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_CLIENT))
		goto err_cred;
	if (gnutls_priority_set_direct(session, PRIORITY, NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_client_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

	if (quic_client_connection_new(ep))
		goto err_session;
	ngtcp2_conn_set_tls_native_handle(ep->conn, session);
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
	printf("session creation failed\n");
	return -1;
}

static int quic_psk_set_client_credentials_file(gnutls_psk_client_credentials_t cred, char *psk)
{
	gnutls_datum_t gkey, pkey;
	char identity[256], *key;
	int len, fd, err = -1;

	fd = open(psk, O_RDONLY);
	if (fd == -1)
		return -1;

	len = read(fd, identity, sizeof(identity));
	if (len < 0)
		goto out;
	identity[len - 1] = '\0';
	key = strchr(identity, ':');
	if (!key)
		goto out;
	*key = '\0';
	key++;

	gkey.data = key;
	gkey.size = strlen(key);
	gnutls_hex_decode2(&gkey, &pkey);

	err = gnutls_psk_set_client_credentials(cred, identity, &pkey, GNUTLS_PSK_KEY_RAW);
out:
	close(fd);
	return err;
}

static int quic_client_set_psk_session(struct quic_endpoint *ep)
{
	gnutls_psk_client_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_psk_allocate_client_credentials(&cred))
		return -1;
	if (quic_psk_set_client_credentials_file(cred, ep->keyfile[0]))
		goto err_cred;

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_CLIENT))
		goto err_cred;
	if (gnutls_priority_set_direct(session, PRIORITY, NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_client_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);

	if (quic_client_connection_new(ep))
		goto err_session;
	ngtcp2_conn_set_tls_native_handle(ep->conn, session);
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_client_credentials(cred);
	printf("session creation failed\n");
	return -1;
}

static int quic_server_set_x509_session(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	gnutls_certificate_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_certificate_allocate_credentials(&cred))
		return -1;
	if (gnutls_certificate_set_x509_system_trust(cred) < 0)
		goto err_cred;
	if (gnutls_certificate_set_x509_key_file(cred, ep->keyfile[1], ep->keyfile[0],
						 GNUTLS_X509_FMT_PEM))
		goto err_cred;

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_SERVER))
		goto err_cred;
	if (gnutls_priority_set_direct(session, PRIORITY, NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_server_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

	if (quic_server_connection_new(ep, hd))
		goto err_session;
	ngtcp2_conn_set_tls_native_handle(ep->conn, session);
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
	printf("session creation failed\n");
	return -1;
}

static int quic_server_set_psk_session(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	gnutls_psk_server_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_psk_allocate_server_credentials(&cred))
		return -1;
	if (gnutls_psk_set_server_credentials_file(cred, ep->keyfile[0]))
		return -1;

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_SERVER))
		goto err_cred;
	if (gnutls_priority_set_direct(session, PRIORITY, NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_server_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);

	if (quic_server_connection_new(ep, hd))
		goto err_session;
	ngtcp2_conn_set_tls_native_handle(ep->conn, session);
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_server_credentials(cred);
	printf("session creation failed\n");
	return -1;
}

static void quic_handshake_read(struct quic_endpoint *ep)
{
	int state, ret, len, count = 0;
	struct sockaddr_in a = {};
	ngtcp2_pkt_info pi = {0};
	ngtcp2_path_storage ps;
	ngtcp2_pkt_hd hd;
	uint8_t buf[2000];

	do {
		state = ep->state;
		len = sizeof(a);
		ret = recvfrom(ep->sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&a, &len);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ep->dead = 1;
			break;
		}
		if (ep->conn && memcmp(&ep->ra, &a, sizeof(a))) /* not for this connection, skip */
			break;
		if (!ep->conn) {
			memcpy(&ep->ra, &a, sizeof(a));
			if (ngtcp2_accept(&hd, buf, ret) || ep->server_session_new(ep, &hd)) {
				ep->dead = 2;
				break;
			}
		}
		ngtcp2_path_storage_init(&ps, (void *)&ep->la, sizeof(a),
					 (void *)&ep->ra, sizeof(a), NULL);
		if (ngtcp2_conn_read_pkt(ep->conn, &ps.path, &pi, buf, ret, quic_get_timestamp())) {
			ep->dead = 3;
			break;
		}
	} while (ep->state == state && !ep->dead && !ep->ready);
}

static void quic_handshake_write(struct quic_endpoint *ep)
{
	struct itimerspec its = {};
	uint64_t expiry, now, nsec;
	ngtcp2_vec datav = {};
	ngtcp2_path_storage p;
	ngtcp2_pkt_info pi;
	uint8_t buf[2048];
	ngtcp2_ssize len;
	int ret, pos = 0;

	now = quic_get_timestamp();
	ngtcp2_path_storage_zero(&p);
	while (1) {
		ret = ngtcp2_conn_writev_stream(ep->conn, &p.path, &pi, &buf[pos],
						sizeof(buf) - pos, &len, 0, -1, &datav, 0, now);
		if (ret < 0)
			break;
		pos += ret;
		if (!pos)
			break;
		if (ret == 0 || ret < 1200) { /* try to merge the sh and hs packets */
			sendto(ep->sockfd, buf, pos, 0, (struct sockaddr *)&ep->ra, sizeof(ep->ra));
			break;
		}
	}

	expiry = ngtcp2_conn_get_expiry(ep->conn);
	nsec = expiry < now ? 1 : expiry - now;
	its.it_value.tv_sec  = nsec / NGTCP2_SECONDS;
	its.it_value.tv_nsec = nsec % NGTCP2_SECONDS;
	timer_settime(ep->timer, 0, &its, NULL);
}

static void quic_timer_handler(union sigval arg)
{
	struct quic_endpoint *ep = arg.sival_ptr;

	if (ngtcp2_conn_handle_expiry(ep->conn, quic_get_timestamp())) {
		ep->dead = 4;
		return;
	}
	quic_handshake_write(ep);
}

static int quic_do_handshake(struct quic_endpoint *ep)
{
	struct timeval tv, ntv = {1, 0};
	int ret, len = sizeof(tv);
	struct sigevent sev = {};

	if (getsockopt(ep->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len) ||
	    setsockopt(ep->sockfd, SOL_SOCKET, SO_RCVTIMEO, &ntv, sizeof(ntv)))
		return -1;

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = quic_timer_handler;
	sev.sigev_value.sival_ptr = ep;
	timer_create(CLOCK_REALTIME, &sev, &ep->timer);

	if (ep->conn)
		quic_handshake_write(ep);
	while (1) {
		quic_handshake_read(ep);
		if (ep->dead)
			break;
		if (ep->ready)
			break;
		quic_handshake_write(ep);
	}

	timer_delete(ep->timer);
	if (setsockopt(ep->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
		return -1;

	return ep->dead;
}

static void quic_context_copy_transport_params(struct quic_endpoint *ep,
					       struct quic_transport_param *param,
					       const ngtcp2_transport_params *p)
{
	param->max_udp_payload_size = p->max_udp_payload_size;
	param->ack_delay_exponent = p->ack_delay_exponent;
	param->max_ack_delay = p->max_ack_delay / NGTCP2_MICROSECONDS;
	param->initial_max_data = p->initial_max_data;
	param->initial_max_stream_data_bidi_local = p->initial_max_stream_data_bidi_local;
	param->initial_max_stream_data_bidi_remote = p->initial_max_stream_data_bidi_remote;
	param->initial_max_stream_data_uni = p->initial_max_stream_data_uni;
	param->initial_max_streams_bidi = p->initial_max_streams_bidi;
	param->initial_max_streams_uni = p->initial_max_streams_uni;
	param->initial_smoothed_rtt = ep->connecting_ts[1] - ep->connecting_ts[0];
}

static int quic_set_socket_context(struct quic_endpoint *ep, int state)
{
	const ngtcp2_transport_params *p;
	struct quic_context context;
	const ngtcp2_cid *dest;
	ngtcp2_cid source[3];
	int count;

	memset(&context, 0, sizeof(context));
	memcpy(context.source.data, ep->connid[0].cid, ep->connid[0].cidlen);
	context.source.len = ep->connid[0].cidlen;
	memcpy(context.dest.data, ep->connid[1].cid, ep->connid[1].cidlen);
	context.dest.len = ep->connid[1].cidlen;

	p = ngtcp2_conn_get_local_transport_params(ep->conn);
	quic_context_copy_transport_params(ep, &context.local, p);
	p = ngtcp2_conn_get_remote_transport_params(ep->conn);
	quic_context_copy_transport_params(ep, &context.remote, p);

	memcpy(&context.src, &ep->la, sizeof(ep->la));
	memcpy(&context.dst, &ep->ra, sizeof(ep->ra));
	memcpy(context.recv.secret, ep->secret[0].key, ep->secret[0].keylen);
	memcpy(context.send.secret, ep->secret[1].key, ep->secret[1].keylen);

	context.state = state;
	if (setsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_CONTEXT, &context, sizeof(context))) {
		printf("socket setsockopt context failed\n");
		return -1;
	}
	return 0;
}

static int quic_client_do_handshake(struct quic_endpoint *ep)
{
	struct sockaddr_in sa, *la = &sa;
	int state, len, err;

	if (connect(ep->sockfd, (struct sockaddr *)&ep->ra, sizeof(ep->ra))) {
		printf("socket connect failed\n");
		return -1;
	}
	len = sizeof(*la);
	if (getsockname(ep->sockfd, (struct sockaddr *)la, &len)) {
		printf("socket getsockname failed\n");
		return -1;
	}
	memcpy(&ep->la, la, sizeof(*la));

	state = QUIC_STATE_USER_CONNECTING;
	if (setsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_STATE, &state, sizeof(state))) {
		printf("socket setsockopt state failed\n");
		return -1;
	}

	if (ep->client_session_new(ep))
		return -1;

	err = quic_do_handshake(ep);
	if (err) {
		printf("handshake failed, reason: %d\n", err);
		goto out;
	}

	err = quic_set_socket_context(ep, QUIC_STATE_CLIENT_CONNECTED);
out:
	ngtcp2_conn_del(ep->conn);
	return err;
}

static int quic_server_do_handshake(struct quic_endpoint *ep)
{
	struct sockaddr_in sa, *la = &sa;
	int state, len, err;

	len = sizeof(*la);
	if (getsockname(ep->sockfd, (struct sockaddr *)la, &len)) {
		printf("socket getsockname failed\n");
		return -1;
	}
	memcpy(&ep->la, la, sizeof(*la));

	state = QUIC_STATE_USER_CONNECTING;
	if (setsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_STATE, &state, sizeof(state))) {
		printf("socket setsockopt state failed\n");
		return -1;
	}

	err = quic_do_handshake(ep);
	if (err) {
		printf("handshake failed, reason: %d\n", err);
		goto out;
	}

	err = quic_set_socket_context(ep, QUIC_STATE_SERVER_CONNECTED);
out:
	ngtcp2_conn_del(ep->conn);
	return err;
}

/**
 * quic_client_psk_handshake - start a QUIC handshake with PSK mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @ra: peer server address
 * @psk: PSK file
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_psk_handshake(int sockfd, struct sockaddr_in *ra, char *psk)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	strcpy(ep.keyfile[0], psk);
	memcpy(&ep.ra, ra, sizeof(*ra));
	ep.client_session_new = quic_client_set_psk_session;

	return quic_client_do_handshake(&ep);
}

/**
 * quic_client_x509_handshake - start a QUIC handshake with Certificate mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @ra: peer server address
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_x509_handshake(int sockfd, struct sockaddr_in *ra)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	memcpy(&ep.ra, ra, sizeof(*ra));
	ep.client_session_new = quic_client_set_x509_session;

	return quic_client_do_handshake(&ep);
}

/**
 * quic_server_psk_handshake - start a QUIC handshake with PSK mode from server side
 * @sockfd: IPPROTO_QUIC type socket
 * @psk: PSK file
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_psk_handshake(int sockfd, char *psk)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	strcpy(ep.keyfile[0], psk);
	ep.server_session_new = quic_server_set_psk_session;

	return quic_server_do_handshake(&ep);
}

/**
 * quic_client_x509_handshake - start a QUIC handshake with Certificate mode from server side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey: private key file
 * @cert: certificate file
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_x509_handshake(int sockfd, char *pkey, char *cert)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	strcpy(ep.keyfile[0], pkey);
	strcpy(ep.keyfile[1], cert);
	ep.server_session_new = quic_server_set_x509_session;

	return quic_server_do_handshake(&ep);
}

/**
 * quic_recvmsg - receive msg and also get stream ID and flag
 * @sockfd: IPPROTO_QUIC type socket
 * @msg: msg buffer
 * @len: msg buffer length
 * @sid: stream ID got from kernel
 * @flag: stream flag got from kernel
 *
 * Return values:
 * - On success, the number of bytes received.
 * - On error, -1 is returned, and errno is set to indicate the error.
 */
int quic_recvmsg(int sockfd, void *msg, size_t len, uint32_t *sid, uint32_t *flag)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_rcvinfo))];
	struct cmsghdr *cmsg = NULL;
	struct quic_rcvinfo rinfo;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg;
	iov.iov_len = len;

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(sockfd, &inmsg, 0);
	if (error < 0)
		return error;

	if (!sid)
		return error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (SOL_QUIC == cmsg->cmsg_level && QUIC_RCVINFO == cmsg->cmsg_type)
			break;
	if (cmsg)
		memcpy(&rinfo, CMSG_DATA(cmsg), sizeof(struct quic_rcvinfo));

	*sid = rinfo.stream_id;
	*flag = rinfo.stream_flag;
	return error;
}

/**
 * quic_sendmsg - send msg with stream ID and flag
 * @sockfd: IPPROTO_QUIC type socket
 * @msg: msg to send
 * @len: the length of the msg to send
 * @sid: stream ID
 * @flag: stream flag
 *
 * Return values:
 * - On success, return the number of bytes sent.
 * - On error, -1 is returned, and errno is set to indicate the error.
 */
int quic_sendmsg(int sockfd, const void *msg, size_t len, uint32_t sid, uint32_t flag)
{
	struct quic_sndinfo *sinfo;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char outcmsg[CMSG_SPACE(sizeof(*sinfo))];

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg;
	iov.iov_len = len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_sndinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_sndinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_sndinfo));
	sinfo->stream_id = sid;
	sinfo->stream_flag = flag;

	return sendmsg(sockfd, &outmsg, 0);
}
