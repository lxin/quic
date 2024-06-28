/*
 * Perform a QUIC server-side handshake.
 *
 * Copyright (c) 2024 Red Hat, Inc.
 *
 * libquic is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "libquic.h"

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

static int quic_dataum_copy(gnutls_datum_t *dest, const gnutls_datum_t *source)
{
	dest->data = malloc(source->size);
	if (!dest->data)
		return -ENOMEM;
	memcpy(dest->data, source->data, source->size);
	dest->size = source->size;
	return 0;
}

static int quic_server_alpn_verify(gnutls_session_t session, unsigned int htype, unsigned int when,
				   unsigned int incoming, const gnutls_datum_t *msg)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_datum_t alpn = {};
	int ret;

	if (!conn->alpns[0])
		return 0;

	ret = gnutls_alpn_get_selected_protocol(session, &alpn);
	if (ret) {
		quic_log_gnutls_error(ret);
		return ret;
	}
	if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn.data, alpn.size)) {
		quic_log_error("socket setsockopt alpn error %d %u", errno, alpn.size);
		return -1;
	}
	quic_log_debug("  ALPN verify: %u %u %u %u", htype, when, incoming, msg->size);
	return 0;
}

static int quic_server_anti_replay_db_add_func(void *dbf, time_t exp_time,
					       const gnutls_datum_t *key,
					       const gnutls_datum_t *data)
{
	quic_log_debug("  Anti replay: %u %u %u %u", !!dbf, exp_time, key->size, data->size);
	return 0;
}

static gnutls_anti_replay_t quic_server_anti_replay;

static int quic_server_x509_verify_function(gnutls_session_t session)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_handshake_parms *parms = conn->parms;
	const gnutls_datum_t *peercerts;
	unsigned int i, status;
	int ret;

	ret = gnutls_certificate_verify_peers3(session, NULL, &status);
	if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND)
		return 0;
	if (ret != GNUTLS_E_SUCCESS) {
		quic_log_gnutls_error(ret);
		return -1;
	}
	if (status) {
		quic_log_error("cert verify failed error %u", status);
		return -1;
	}

	peercerts = gnutls_certificate_get_peers(session, &parms->num_keys);
	if (!peercerts || !parms->num_keys) {
		quic_log_error("cert is not found error %d", ENOKEY);
		return -1;
	}
	quic_log_debug("  The peer offered %u certificate(s)", parms->num_keys);

	if (parms->num_keys > ARRAY_SIZE(parms->keys))
		parms->num_keys = ARRAY_SIZE(parms->keys);
	for (i = 0; i < parms->num_keys; i++) {
		if (quic_dataum_copy(&parms->keys[i], &peercerts[i])) {
			quic_log_error("cert copy failed error %d", ENOMEM);
			goto err;
		}
	}
	return 0;
err:
	for (i = 0; i < parms->num_keys; i++) {
		free(parms->keys[i].data);
		parms->keys[i].size = 0;
	}
	return -1;
}

static int quic_server_psk_cb(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_handshake_parms *parms = conn->parms;
	int i;

	for (i = 0; i < parms->num_keys; i++)
		if (!strcmp(parms->names[i], username))
			break;
	if (i == parms->num_keys) {
		quic_log_error("psk is not found error %d", ENOKEY);
		return -1;
	}

	parms->peername = parms->names[i];

	if (quic_dataum_copy(key, &parms->keys[i])) {
		quic_log_error("key copy failed error %d", ENOMEM);
		return -1;
	}
	return 0;
}

static int quic_server_set_x509_session(struct quic_conn *conn)
{
	struct quic_handshake_parms *parms = conn->parms;
	gnutls_certificate_credentials_t cred;
	char *cafile = parms->cafile;
	gnutls_datum_t ticket_key;
	gnutls_session_t session;
	int ret = -EINVAL;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	if (cafile)
		ret = gnutls_certificate_set_x509_trust_file(cred, cafile, GNUTLS_X509_FMT_PEM);
	else
		ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	ret = gnutls_certificate_set_key(cred, NULL, 0, parms->cert, 1, parms->privkey);
	if (ret)
		goto err_cred;
	quic_log_debug("System trust: Loaded %d certificate(s).", ret);

	gnutls_certificate_set_verify_function(cred, quic_server_x509_verify_function);

	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;

	if (!quic_server_anti_replay) {
		ret = gnutls_anti_replay_init(&quic_server_anti_replay);
		if (ret)
			goto err_session;
		gnutls_anti_replay_set_add_function(quic_server_anti_replay,
						    quic_server_anti_replay_db_add_func);
		gnutls_anti_replay_set_ptr(quic_server_anti_replay, NULL);
	}
	gnutls_anti_replay_enable(session, quic_server_anti_replay);
	ret = gnutls_record_set_max_early_data_size(session, 0xffffffffu);
	if (ret)
		goto err_session;

	conn->session = session;
	gnutls_session_set_ptr(session, conn);
	ret = quic_conn_configure_session(conn);
	if (ret)
		goto err_session;
	ticket_key.data = conn->ticket;
	ticket_key.size = conn->ticket_len;
	ret = gnutls_session_ticket_enable_server(session, &ticket_key);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, quic_server_alpn_verify);
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;
	gnutls_certificate_server_set_request(session, conn->cert_req);

	conn->is_serv = 1;
	return 0;
err_session:
	conn->session = NULL;
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	quic_log_gnutls_error(ret);
	return ret;
}

static int quic_server_set_psk_session(struct quic_conn *conn)
{
	gnutls_psk_server_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_psk_allocate_server_credentials(&cred);
	if (ret)
		goto err;
	gnutls_psk_set_server_credentials_function(cred, quic_server_psk_cb);

	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err_cred;
	conn->session = session;
	gnutls_session_set_ptr(session, conn);
	ret = quic_conn_configure_session(conn);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, quic_server_alpn_verify);
	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret)
		goto err_session;

	conn->is_serv = 1;
	return 0;
err_session:
	conn->session = NULL;
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_server_credentials(cred);
err:
	quic_log_gnutls_error(ret);
	return ret;
}

/**
 * quic_server_handshake_parms - send a QUIC Server Initial
 * @parms: handshake parameters
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_server_handshake_parms(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_conn *conn;
	int ret;

	conn = quic_conn_create(sockfd, parms);
	if (!conn)
		return -errno;

	if (parms->num_keys)
		ret = quic_server_set_psk_session(conn);
	else
		ret = quic_server_set_x509_session(conn);
	if (ret)
		goto out;

	ret = quic_conn_start_handshake(conn);
out:
	quic_conn_destroy(conn);
	return ret;
}

/**
 * quic_server_handshake - start a QUIC handshake with Certificate or PSK mode on server side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey: private key file or pre-shared key file
 * @cert: certificate file or null
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_server_handshake(int sockfd, char *pkey_file, char *cert_file)
{
	struct quic_handshake_parms parms = {};
	gnutls_pcert_st gcert;
	int ret;

	parms.timeout = 15000;
	if (!cert_file) {
		ret = quic_file_read_psk(pkey_file, parms.names, parms.keys);
		if (ret <= 0) {
			quic_log_error("read psk file error %d", EINVAL);
			return -EINVAL;
		}
		parms.num_keys = ret;
		goto start;
	}

	parms.cert = &gcert;
	if (quic_file_read_pkey(pkey_file, &parms.privkey)) {
		quic_log_error("read pkey file error %d", EINVAL);
		return -EINVAL;
	}
	if (quic_file_read_cert(cert_file, &parms.cert)) {
		quic_log_error("read cert file error %d", EINVAL);
		return -EINVAL;
	}
start:
	return quic_server_handshake_parms(sockfd, &parms);
}
