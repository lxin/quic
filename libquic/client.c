/*
 * Perform a QUIC client-side handshake.
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

static int quic_client_x509_verify_function(gnutls_session_t session)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_handshake_parms *parms = conn->parms;
	const gnutls_datum_t *peercerts;
	unsigned int i, status;
	int ret;

	ret = gnutls_certificate_verify_peers3(session, parms->peername, &status);
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

static int quic_client_ticket_recv(gnutls_session_t session, unsigned int htype,
					 unsigned int when, unsigned int incoming,
					 const gnutls_datum_t *msg)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	int ret, sockfd = conn->sockfd;
	gnutls_datum_t ticket;

	if (htype != GNUTLS_HANDSHAKE_NEW_SESSION_TICKET)
		return 0;

	conn->completed = 1;
	ret = gnutls_session_get_data2(session, &ticket);
	if (ret) {
		quic_log_gnutls_error(ret);
		return ret;
	}

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, ticket.data, ticket.size);
	if (ret) {
		quic_log_error("socket setsockopt session ticket error %d %u", errno, ticket.size);
		return -1;
	}
	quic_log_debug("  Ticket recv: %u %u %u", when, incoming, msg->size);
	return 0;
}

#define QUIC_NO_CERT_AUTH	3

static int quic_client_set_x509_session(struct quic_conn *conn)
{
	struct quic_handshake_parms *parms = conn->parms;
	gnutls_certificate_credentials_t cred;
	char *cafile = parms->cafile;
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
	quic_log_debug("System trust: Loaded %d certificate(s).", ret);

	if (conn->cert_req == QUIC_NO_CERT_AUTH) {
		gnutls_certificate_set_verify_flags(cred, GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 |
							  GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5);
		gnutls_certificate_set_flags(cred, GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH |
						   GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK);
	} else {
		gnutls_certificate_set_verify_function(cred, quic_client_x509_verify_function);
		if (parms->cert && parms->privkey)
			gnutls_certificate_set_key(cred, NULL, 0, parms->cert, 1, parms->privkey);
	}

	ret = gnutls_init(&session, GNUTLS_CLIENT |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, quic_client_ticket_recv);
	conn->session = session;
	gnutls_session_set_ptr(session, conn);
	ret = quic_conn_configure_session(conn);
	if (ret)
		goto err_session;
	if (conn->ticket_len) {
		ret = gnutls_session_set_data(session, conn->ticket, conn->ticket_len);
		if (ret)
			goto err_session;
	}
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;
	if (parms->peername) {
		ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS,
					     parms->peername, strlen(parms->peername));
		if (ret)
			goto err_session;
	}
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

static int quic_client_set_psk_session(struct quic_conn *conn)
{
	struct quic_handshake_parms *parms = conn->parms;
	gnutls_datum_t *key = &parms->keys[0];
	gnutls_psk_client_credentials_t cred;
	char *identity = parms->names[0];
	gnutls_session_t session;
	int ret = -EINVAL;

	ret = gnutls_psk_allocate_client_credentials(&cred);
	if (ret)
		goto err;
	parms->peername = identity;
	ret = gnutls_psk_set_client_credentials(cred, identity, key, GNUTLS_PSK_KEY_RAW);
	if (ret)
		goto err_cred;

	ret = gnutls_init(&session, GNUTLS_CLIENT);
	if (ret)
		goto err_cred;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, quic_client_ticket_recv);
	conn->session = session;
	gnutls_session_set_ptr(session, conn);
	ret = quic_conn_configure_session(conn);
	if (ret)
		goto err_session;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret)
		goto err_session;
	return 0;
err_session:
	conn->session = NULL;
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_client_credentials(cred);
err:
	free(identity);
	quic_log_gnutls_error(ret);
	return ret;
}

/**
 * quic_client_handshake_parms - send a QUIC Client Initial
 * @parms: handshake parameters
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_client_handshake_parms(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_conn *conn;
	int ret;

	conn = quic_conn_create(sockfd, parms);
	if (!conn)
		return -errno;

	if (parms->num_keys)
		ret = quic_client_set_psk_session(conn);
	else
		ret = quic_client_set_x509_session(conn);
	if (ret)
		goto out;

	ret = quic_conn_start_handshake(conn);
out:
	quic_conn_destroy(conn);
	return ret;
}

/**
 * quic_client_handshake - start a QUIC handshake with Certificate or PSK mode on client side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey_file: private key file (optional) or pre-shared key file
 * @cert_file: certificate file (optional) or null
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_client_handshake(int sockfd, char *pkey_file, char *cert_file)
{
	struct quic_handshake_parms parms = {};
	gnutls_pcert_st gcert;
	int ret;

	parms.timeout = 15000;
	if (!cert_file) {
		if (!pkey_file)
			goto start;
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
	return quic_client_handshake_parms(sockfd, &parms);
}
