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

#include <linux/tls.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include "handshake.h"

enum {
	QUIC_STATE_CLOSED,
	QUIC_STATE_CONNECTING,
	QUIC_STATE_CONNECTED,
};

struct quic_data {
	uint8_t data[128];
	uint32_t data_len;
};

struct quic_endpoint {
	int sockfd;		/* IPPROTO_QUIC type socket */

	uint8_t state;	/* internal state */
	uint8_t	ready;	/* mark handshake is sucessful */
	uint8_t	dead;	/* reason why handshake failed */
	timer_t	timer;	/* timer for retransmission */

	uint32_t connecting_ts[2];	/* to calculate the initial rtt */
	uint32_t cipher_type;		/* cipher type from linux/tls.h */
	struct quic_data alpn;		/* alpn from kernel socket */
	struct quic_data token;		/* token from kernel socket */
	struct quic_data secret[2];	/* secrets for sending and receiving */
	struct quic_data connid[2];	/* source and dest connection IDs */

	struct quic_handshake_parms *parms;
	int (*session_new)(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd);
	int (*cred_setkey)(struct quic_endpoint *ep, void *cred);

	ngtcp2_path_storage ps;	/* local and remote addresses */
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
	printf("warning: new connection id is not allowed from user space!\n");
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
	memcpy(ep->connid[1].data, cid->data, cid->datalen);
	ep->connid[1].data_len = cid->datalen;
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
	uint8_t key[64], iv[64], hp[64];

	level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(l);
	if (rx_secret) {
		if (ngtcp2_crypto_derive_and_install_rx_key(conn, key, iv, hp, level,
							    rx_secret, secretlen))
			return -1;
		if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
			memcpy(ep->secret[0].data, rx_secret, secretlen);
			ep->secret[0].data_len = secretlen;
		}
	}

	if (tx_secret) {
		if (ngtcp2_crypto_derive_and_install_tx_key(conn, key, iv, hp, level,
							    tx_secret, secretlen))
			return -1;
		if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
			memcpy(ep->secret[1].data, tx_secret, secretlen);
			ep->secret[1].data_len = secretlen;
		}
	}

	return 0;
}

static char priority[100] = "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+";

static char *quic_get_priority(struct quic_endpoint *ep)
{
	switch (ep->cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		strcat(priority, "AES-128-GCM");
		break;
	case TLS_CIPHER_AES_GCM_256:
		strcat(priority, "AES-256-GCM");
		break;
	case TLS_CIPHER_AES_CCM_128:
		strcat(priority, "AES-128-CCM");
		break;
	case TLS_CIPHER_CHACHA20_POLY1305:
		strcat(priority, "CHACHA20-POLY1305");
		break;
	default:
		strcat(priority, "AES-128-GCM:+AES-256-GCM:+AES-128-CCM:+CHACHA20-POLY1305");
		ep->cipher_type = 0;
		break;
	}
	return priority;
}

static int quic_get_cipher_type(struct quic_endpoint *ep)
{
	gnutls_cipher_algorithm_t type;

	type = gnutls_cipher_get(ngtcp2_conn_get_tls_native_handle(ep->conn));
	switch (type) {
	case GNUTLS_CIPHER_AES_128_GCM:
		ep->cipher_type = TLS_CIPHER_AES_GCM_128;
		break;
	case GNUTLS_CIPHER_AES_256_GCM:
		ep->cipher_type = TLS_CIPHER_AES_GCM_256;
		break;
	case GNUTLS_CIPHER_AES_128_CCM:
		ep->cipher_type = TLS_CIPHER_AES_CCM_128;
		break;
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		ep->cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		break;
	default:
		printf("invalid gnutls cipher type %d\n", type);
		return -1;
	}
	return 0;
}

static int quic_client_connection_new(struct quic_endpoint *ep)
{
	ngtcp2_transport_params params;
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
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
	settings.handshake_timeout = (ep->parms->timeout ?: 30000) * NGTCP2_MILLISECONDS;
	if (ep->token.data_len) {
		settings.token = ep->token.data;
		settings.tokenlen= ep->token.data_len;
	}
	quic_ngtcp2_conn_callbacks_init(&callbacks);

	scid.datalen = 17;
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
	memcpy(ep->connid[0].data, scid.data, scid.datalen);
	ep->connid[0].data_len = scid.datalen;
	dcid.datalen = 18;
	gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
	memcpy(ep->connid[1].data, dcid.data, dcid.datalen);
	ep->connid[1].data_len = dcid.datalen;

	return ngtcp2_conn_client_new(&ep->conn, &dcid, &scid, &ep->ps.path, NGTCP2_PROTO_VER_V1,
				      &callbacks, &settings, &params, NULL, ep);
}

static int quic_server_connection_new(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	ngtcp2_transport_params params;
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
	ngtcp2_cid scid, dcid;

	ngtcp2_transport_params_default(&params);
	params.initial_max_stream_data_bidi_local = 64 * 1024;
	params.initial_max_stream_data_bidi_remote = 64 * 1024;
	params.initial_max_stream_data_uni = 64 * 1024;
	params.initial_max_data = 16 * 1024 * 1024;
	params.initial_max_streams_bidi = 100;
	params.initial_max_streams_uni = 100;
	params.max_idle_timeout = 30 * NGTCP2_SECONDS;
	params.active_connection_id_limit = 7;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_get_timestamp();
	settings.handshake_timeout = (ep->parms->timeout ?: 30000) * NGTCP2_MILLISECONDS;
	quic_ngtcp2_conn_callbacks_init(&callbacks);

	params.original_dcid = hd->dcid;
	params.original_dcid_present = 1;
	settings.token = hd->token;
	settings.tokenlen = hd->tokenlen;
	scid.datalen = 18;
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
	memcpy(ep->connid[0].data, scid.data, scid.datalen);
	ep->connid[0].data_len = scid.datalen;
	dcid = hd->scid;
	memcpy(ep->connid[1].data, dcid.data, dcid.datalen);
	ep->connid[1].data_len = dcid.datalen;

	return ngtcp2_conn_server_new(&ep->conn, &dcid, &scid, &ep->ps.path, hd->version,
				      &callbacks, &settings, &params, NULL, ep);
}

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

static int quic_client_x509_cb(gnutls_session_t session)
{
	ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
	struct quic_endpoint *ep = conn_ref->user_data;
	struct quic_handshake_parms *parms = ep->parms;
	const gnutls_datum_t *peercerts;
	unsigned int i, status;
	int ret;

	ret = gnutls_certificate_verify_peers3(session, parms->peername, &status);
	if (ret != GNUTLS_E_SUCCESS || status)
		return -1;

	peercerts = gnutls_certificate_get_peers(session, &parms->num_keys);
	if (!peercerts || !parms->num_keys)
		return -1;
	if (parms->num_keys > ARRAY_SIZE(parms->keys))
		parms->num_keys = ARRAY_SIZE(parms->keys);
	for (i = 0; i < parms->num_keys; i++)
		parms->keys[0] = peercerts[i];

	return 0;
}

static int quic_client_set_x509_cred(struct quic_endpoint *ep, void *cred)
{
	gnutls_privkey_t privkey = ep->parms->privkey;
	gnutls_pcert_st  *cert = ep->parms->cert;

	if (!privkey || !cert)
		return 0;

	return gnutls_certificate_set_key(cred, NULL, 0, cert, 1, privkey);
}

static int quic_client_set_x509_session(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	gnutls_certificate_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_certificate_allocate_credentials(&cred))
		return -1;
	if (gnutls_certificate_set_x509_system_trust(cred) < 0)
		goto err_cred;
	if (ep->cred_setkey(ep, cred))
		goto err_cred;
	gnutls_certificate_set_verify_function(cred, quic_client_x509_cb);

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_CLIENT))
		goto err_cred;
	if (gnutls_priority_set_direct(session, quic_get_priority(ep), NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_client_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ep->parms->peername)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS,
				ep->parms->peername, strlen(ep->parms->peername));
	if (ep->alpn.data_len) {
		gnutls_datum_t alpn = {
			.data = ep->alpn.data,
			.size = strlen(ep->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}

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

static int quic_client_set_psk_cred(struct quic_endpoint *ep, void *cred)
{
	unsigned char identity[256], *key;
	char *psk = ep->parms->names[0];
	gnutls_datum_t gkey, pkey;
	int len, fd, err = -1;

	fd = open(psk, O_RDONLY);
	if (fd == -1)
		return -1;

	len = read(fd, identity, sizeof(identity));
	if (len < 0 || len > 256)
		goto out;
	key = strchr(identity, ':');
	if (!key)
		goto out;
	*key = '\0';
	key++;
	gkey.data = key;

	key = strchr(key, '\n');
	if (!key) {
		gkey.size = identity + len - gkey.data;
	} else {
		*key = '\0';
		gkey.size = strlen(gkey.data);
	}
	if (gnutls_hex_decode2(&gkey, &pkey))
		goto out;

	err = gnutls_psk_set_client_credentials(cred, identity, &pkey, GNUTLS_PSK_KEY_RAW);
out:
	close(fd);
	return err;
}

static int quic_client_set_psk_cred_tlshd(struct quic_endpoint *ep, void *cred)
{
	gnutls_datum_t *key = &ep->parms->keys[0];
	char *identity = ep->parms->names[0];

	ep->parms->peername = identity;

	return gnutls_psk_set_client_credentials(cred, identity, key, GNUTLS_PSK_KEY_RAW);
}

static int quic_client_set_psk_session(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	gnutls_psk_client_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_psk_allocate_client_credentials(&cred))
		return -1;
	if (ep->cred_setkey(ep, cred))
		goto err_cred;

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_CLIENT))
		goto err_cred;
	if (gnutls_priority_set_direct(session, quic_get_priority(ep), NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_client_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ep->alpn.data_len) {
		gnutls_datum_t alpn = {
			.data = ep->alpn.data,
			.size = strlen(ep->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}

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

static int quic_server_x509_cb(gnutls_session_t session)
{
	ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
	struct quic_endpoint *ep = conn_ref->user_data;
	struct quic_handshake_parms *parms = ep->parms;
	const gnutls_datum_t *peercerts;
	unsigned int i, status;
	int ret;

	ret = gnutls_certificate_verify_peers3(session, NULL, &status);
	if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND)
		return 0;
	if (ret != GNUTLS_E_SUCCESS || status)
		return -1;

	peercerts = gnutls_certificate_get_peers(session, &parms->num_keys);
	if (!peercerts || !parms->num_keys)
		return -1;
	if (parms->num_keys > ARRAY_SIZE(parms->keys))
		parms->num_keys = ARRAY_SIZE(parms->keys);
	for (i = 0; i < parms->num_keys; i++)
		parms->keys[0] = peercerts[i];

	return 0;
}

static int quic_server_set_x509_cred(struct quic_endpoint *ep, void *cred)
{
	char *pkey = ep->parms->names[0];
	char *cert = ep->parms->names[1];

	return gnutls_certificate_set_x509_key_file(cred, cert, pkey, GNUTLS_X509_FMT_PEM);
}

static int quic_server_set_x509_cred_tlshd(struct quic_endpoint *ep, void *cred)
{
	gnutls_privkey_t privkey = ep->parms->privkey;
	gnutls_pcert_st  *cert = ep->parms->cert;

	return gnutls_certificate_set_key(cred, NULL, 0, cert, 1, privkey);
}

static int quic_alpn_cb(gnutls_session_t session, unsigned int htype, unsigned when,
			unsigned int incoming, const gnutls_datum_t *msg)
{
	ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
	struct quic_endpoint *ep = conn_ref->user_data;
	gnutls_datum_t alpn;
	int ret;

	if (!ep->alpn.data_len)
		return 0;

	ret = gnutls_alpn_get_selected_protocol(session, &alpn);
	if (ret)
		return ret;

	if (strlen(ep->alpn.data) != alpn.size ||
	    memcmp(ep->alpn.data, alpn.data, alpn.size))
		return -1;

	return 0;
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
	if (ep->cred_setkey(ep, cred))
		goto err_cred;
	gnutls_certificate_set_verify_function(cred, quic_server_x509_cb);

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_SERVER))
		goto err_cred;
	if (gnutls_priority_set_direct(session, quic_get_priority(ep), NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_server_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, quic_alpn_cb);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ep->alpn.data_len) {
		gnutls_datum_t alpn = {
			.data = ep->alpn.data,
			.size = strlen(ep->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}

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

static int quic_server_set_psk_cred(struct quic_endpoint *ep, void *cred)
{
	char *psk = ep->parms->names[0];

	return gnutls_psk_set_server_credentials_file(cred, psk);
}

static int quic_server_psk_cb(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
	ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
	struct quic_endpoint *ep = conn_ref->user_data;
	int i;

	for (i = 0; i < ep->parms->num_keys; i++)
		if (!strcmp(ep->parms->names[i], username))
			break;
	if (i == ep->parms->num_keys)
		return -1;

	ep->parms->peername = ep->parms->names[i];
	*key = ep->parms->keys[i];
	return 0;
}

static int quic_server_set_psk_cred_tlshd(struct quic_endpoint *ep, void *cred)
{
	gnutls_psk_set_server_credentials_function(cred, quic_server_psk_cb);
	return 0;
}

static int quic_server_set_psk_session(struct quic_endpoint *ep, ngtcp2_pkt_hd *hd)
{
	gnutls_psk_server_credentials_t cred;
	ngtcp2_crypto_conn_ref *conn_ref;
	gnutls_session_t session;

	if (gnutls_psk_allocate_server_credentials(&cred))
		return -1;
	if (ep->cred_setkey(ep, cred))
		return -1;

	conn_ref = &ep->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = ep;
	if (gnutls_init(&session, GNUTLS_SERVER))
		goto err_cred;
	if (gnutls_priority_set_direct(session, quic_get_priority(ep), NULL))
		goto err_session;
	gnutls_session_set_ptr(session, conn_ref);
	if (ngtcp2_crypto_gnutls_configure_server_session(session))
		goto err_session;
	gnutls_handshake_set_secret_function(session, quic_session_secret_func);
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, quic_alpn_cb);
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ep->alpn.data_len) {
		gnutls_datum_t alpn = {
			.data = ep->alpn.data,
			.size = strlen(ep->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}

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
	ngtcp2_sockaddr_union a = {};
	ngtcp2_pkt_info pi = {0};
	ngtcp2_pkt_hd hd;
	uint8_t buf[2048];

	do {
		state = ep->state;
		len = sizeof(a);
		ret = recvfrom(ep->sockfd, buf, sizeof(buf), 0, &a.sa, &len);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ep->dead = 1;
			break;
		}
		if (ep->conn && memcmp(ep->ps.path.remote.addr, &a.sa, len)) /* not for this connection, skip */
			break;
		if (!ep->conn) {
			ngtcp2_addr_copy_byte(&ep->ps.path.remote, &a.sa, len);
			if (ngtcp2_accept(&hd, buf, ret) || ep->session_new(ep, &hd)) {
				ep->dead = 2;
				break;
			}
		}
		if (ngtcp2_conn_read_pkt(ep->conn, &ep->ps.path, &pi, buf, ret, quic_get_timestamp())) {
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
	ngtcp2_pkt_info pi;
	uint8_t buf[2048];
	ngtcp2_ssize len;
	int ret, pos = 0;

	now = quic_get_timestamp();
	while (1) {
		ret = ngtcp2_conn_writev_stream(ep->conn, NULL, &pi, &buf[pos],
						sizeof(buf) - pos, &len, 0, -1, &datav, 0, now);
		if (ret < 0)
			break;
		pos += ret;
		if (!pos)
			break;
		if (ret == 0 || ret < 1200 || ep->state == QUIC_STATE_CONNECTED) { /* try to merge the sh and hs packets */
			sendto(ep->sockfd, buf, pos, 0, ep->ps.path.remote.addr, ep->ps.path.remote.addrlen);
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

	if (timer_delete(ep->timer))
		return -1;
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
	param->max_idle_timeout = p->max_idle_timeout / NGTCP2_MICROSECONDS;
	param->initial_max_data = p->initial_max_data;
	param->active_connection_id_limit = p->active_connection_id_limit;
	param->initial_max_stream_data_bidi_local = p->initial_max_stream_data_bidi_local;
	param->initial_max_stream_data_bidi_remote = p->initial_max_stream_data_bidi_remote;
	param->initial_max_stream_data_uni = p->initial_max_stream_data_uni;
	param->initial_max_streams_bidi = p->initial_max_streams_bidi;
	param->initial_max_streams_uni = p->initial_max_streams_uni;
	param->initial_smoothed_rtt = ep->connecting_ts[1] - ep->connecting_ts[0];
}

static int quic_set_socket_context(struct quic_endpoint *ep, uint8_t is_serv)
{
	const ngtcp2_transport_params *p;
	struct quic_context context;
	const ngtcp2_cid *dest;
	ngtcp2_cid source[3];
	int count, cipher;

	memset(&context, 0, sizeof(context));
	memcpy(context.source.data, ep->connid[0].data, ep->connid[0].data_len);
	context.source.len = ep->connid[0].data_len;
	memcpy(context.dest.data, ep->connid[1].data, ep->connid[1].data_len);
	context.dest.len = ep->connid[1].data_len;

	p = ngtcp2_conn_get_local_transport_params(ep->conn);
	quic_context_copy_transport_params(ep, &context.local, p);
	p = ngtcp2_conn_get_remote_transport_params(ep->conn);
	quic_context_copy_transport_params(ep, &context.remote, p);

	if (!ep->cipher_type && quic_get_cipher_type(ep))
		return -1;
	context.recv.type = ep->cipher_type;
	context.send.type = ep->cipher_type;
	memcpy(context.recv.secret, ep->secret[0].data, ep->secret[0].data_len);
	memcpy(context.send.secret, ep->secret[1].data, ep->secret[1].data_len);

	context.is_serv = is_serv;
	if (setsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_CONTEXT, &context, sizeof(context))) {
		printf("socket setsockopt context failed\n");
		return -1;
	}
	return 0;
}

static int quic_client_do_handshake(struct quic_endpoint *ep)
{
	int state, err, len;

	ngtcp2_path_storage_zero(&ep->ps);
	ep->ps.path.local.addrlen = sizeof(ep->ps.local_addrbuf);
	if (getsockname(ep->sockfd, ep->ps.path.local.addr, &ep->ps.path.local.addrlen)) {
		printf("socket getsockname failed\n");
		return -1;
	}
	ep->ps.path.remote.addrlen = sizeof(ep->ps.remote_addrbuf);
	if (getpeername(ep->sockfd, ep->ps.path.remote.addr, &ep->ps.path.remote.addrlen)) {
		printf("socket getpeername failed\n");
		return -1;
	}

	ep->alpn.data_len = sizeof(ep->alpn.data);
	if (getsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, ep->alpn.data,
		       &ep->alpn.data_len)) {
		printf("socket getsockopt alpn failed\n");
		return -1;
	}
	ep->token.data_len = sizeof(ep->token.data);
	if (getsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, ep->token.data,
		       &ep->token.data_len)) {
		printf("socket getsockopt token failed\n");
		return -1;
	}
	len = sizeof(ep->cipher_type);
	if (getsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_CIPHER, &ep->cipher_type, &len)) {
		printf("socket getsockopt token failed\n");
		return -1;
	}
	if (ep->session_new(ep, NULL))
		return -1;

	err = quic_do_handshake(ep);
	if (err) {
		printf("handshake failed, reason: %d\n", err);
		goto out;
	}

	err = quic_set_socket_context(ep, 0);
out:
	ngtcp2_conn_del(ep->conn);
	return err;
}

static int quic_server_do_handshake(struct quic_endpoint *ep)
{
	int state, err, len;

	ngtcp2_path_storage_zero(&ep->ps);
	ep->ps.path.local.addrlen = sizeof(ep->ps.local_addrbuf);
	if (getsockname(ep->sockfd, ep->ps.path.local.addr, &ep->ps.path.local.addrlen)) {
		printf("socket getsockname failed\n");
		return -1;
	}

	ep->alpn.data_len = sizeof(ep->alpn.data);
	if (getsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, ep->alpn.data,
		       &ep->alpn.data_len)) {
		printf("socket getsockopt alpn failed\n");
		return -1;
	}
	len = sizeof(ep->cipher_type);
	if (getsockopt(ep->sockfd, SOL_QUIC, QUIC_SOCKOPT_CIPHER, &ep->cipher_type, &len)) {
		printf("socket getsockopt token failed\n");
		return -1;
	}
	err = quic_do_handshake(ep);
	if (err) {
		printf("handshake failed, reason: %d\n", err);
		goto out;
	}

	err = quic_set_socket_context(ep, 1);
out:
	ngtcp2_conn_del(ep->conn);
	return err;
}

/**
 * quic_client_psk_handshake - start a QUIC handshake with PSK mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @psk: PSK file
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_psk_handshake(int sockfd, char *psk)
{
	struct quic_handshake_parms parms = {};
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = &parms;
	ep.parms->names[0] = psk;
	ep.session_new = quic_client_set_psk_session;
	ep.cred_setkey = quic_client_set_psk_cred;

	return quic_client_do_handshake(&ep);
}

/**
 * quic_client_psk_tlshd - start a QUIC handshake with PSK mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameter for psk identities and keys.
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_psk_tlshd(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = parms;
	ep.session_new = quic_client_set_psk_session;
	ep.cred_setkey = quic_client_set_psk_cred_tlshd;

	return quic_client_do_handshake(&ep);
}

/**
 * quic_client_x509_handshake - start a QUIC handshake with Certificate mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_x509_handshake(int sockfd, char *pkey, char *cert)
{
	struct quic_handshake_parms parms = {};
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = &parms;
	ep.parms->names[0] = pkey;
	ep.parms->names[1] = cert;
	ep.session_new = quic_client_set_x509_session;
	ep.cred_setkey = quic_client_set_x509_cred;

	return quic_client_do_handshake(&ep);
}

/**
 * quic_client_x509_tlshd - start a QUIC handshake with Certificate mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameters for certificate and private key and (optional) servername.
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_x509_tlshd(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = parms;
	ep.session_new = quic_client_set_x509_session;
	ep.cred_setkey = quic_client_set_x509_cred;

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
	struct quic_handshake_parms parms = {};
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = &parms;
	ep.parms->names[0] = psk;
	ep.session_new = quic_server_set_psk_session;
	ep.cred_setkey = quic_server_set_psk_cred;

	return quic_server_do_handshake(&ep);
}

/**
 * quic_server_psk_tlshd - start a QUIC handshake with PSK mode from server side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameter for psk identities and keys.
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_psk_tlshd(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = parms;
	ep.session_new = quic_server_set_psk_session;
	ep.cred_setkey = quic_server_set_psk_cred_tlshd;

	return quic_server_do_handshake(&ep);
}

/**
 * quic_server_x509_handshake - start a QUIC handshake with Certificate mode from server side
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
	struct quic_handshake_parms parms = {};
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = &parms;
	ep.parms->names[0] = pkey;
	ep.parms->names[1] = cert;
	ep.session_new = quic_server_set_x509_session;
	ep.cred_setkey = quic_server_set_x509_cred;

	return quic_server_do_handshake(&ep);
}

/**
 * quic_server_x509_tlshd - start a QUIC handshake with Certificate mode from server side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameters for certificate and private key
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_x509_tlshd(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_endpoint ep = {};

	ep.sockfd = sockfd;
	ep.parms = parms;
	ep.session_new = quic_server_set_x509_session;
	ep.cred_setkey = quic_server_set_x509_cred_tlshd;

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
int quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag)
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
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_RCVINFO == cmsg->cmsg_type)
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
int quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag)
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
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_sndinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_sndinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_sndinfo));
	sinfo->stream_id = sid;
	sinfo->stream_flag = flag;

	return sendmsg(sockfd, &outmsg, 0);
}
