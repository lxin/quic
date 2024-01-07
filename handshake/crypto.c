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

#include "connection.h"

#define QUIC_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1	0x39u
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))

static enum quic_crypto_level get_crypto_level(gnutls_record_encryption_level_t level)
{
	if (level == GNUTLS_ENCRYPTION_LEVEL_INITIAL)
		return QUIC_CRYPTO_INITIAL;
	if (level == GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE)
		return QUIC_CRYPTO_HANDSHAKE;
	if (level == GNUTLS_ENCRYPTION_LEVEL_APPLICATION)
		return QUIC_CRYPTO_APP;
	if (level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
		return QUIC_CRYPTO_EARLY;
	print_warn("[WARN] %s: %d\n", __func__, level);
	return QUIC_CRYPTO_MAX;
}

static gnutls_record_encryption_level_t get_encryption_level(uint8_t level)
{
	if (level == QUIC_CRYPTO_INITIAL)
		return GNUTLS_ENCRYPTION_LEVEL_INITIAL;
	if (level == QUIC_CRYPTO_HANDSHAKE)
		return GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE;
	if (level == QUIC_CRYPTO_APP)
		return GNUTLS_ENCRYPTION_LEVEL_APPLICATION;
	if (level == QUIC_CRYPTO_EARLY)
		return GNUTLS_ENCRYPTION_LEVEL_EARLY;
	print_warn("[WARN] %s: %d\n", __func__, level);
	return QUIC_CRYPTO_MAX;
}

int quic_crypto_read_write_crypto_data(struct quic_conn *conn, uint8_t level,
				       const uint8_t *data, size_t datalen)
{
	gnutls_session_t session = conn->session;
	int rv;

	level = get_encryption_level(level);
	if (datalen > 0) {
		rv = gnutls_handshake_write(session, level, data, datalen);
		if (rv != 0) {
			if (!gnutls_error_is_fatal(rv))
				return 0;
			goto err;
		}
	}

	rv = gnutls_handshake(session);
	if (rv < 0) {
		if (!gnutls_error_is_fatal(rv))
			return 0;
		goto err;
	}
	return 0;
err:
	gnutls_alert_send_appropriate(session, rv);
	print_error("read write crypto data failed\n");
	return rv;
}

static int dataum_copy(gnutls_datum_t *dest, const gnutls_datum_t *source)
{
	dest->data = malloc(source->size);
	if (!dest->data)
		return -ENOMEM;
	dest->size = source->size;
	return 0;
}

static int client_x509_verify(gnutls_session_t session)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_handshake_parms *parms = conn->parms;
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
	for (i = 0; i < parms->num_keys; i++) {
		if (dataum_copy(&parms->keys[i], &peercerts[i]))
			goto err;
	}
	return 0;
err:
	for (i = 0; i < parms->num_keys; i++) {
		free(parms->keys[i].data);
		parms->keys[i].size = 0;
	}
	return -1;
}

static int client_set_x509_cred(struct quic_conn *conn, void *cred)
{
	gnutls_privkey_t privkey = conn->parms->privkey;
	gnutls_pcert_st  *cert = conn->parms->cert;

	if (!privkey || !cert)
		return 0;

	return gnutls_certificate_set_key(cred, NULL, 0, cert, 1, privkey);
}

static uint32_t tls_cipher_type_get(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
		return TLS_CIPHER_AES_GCM_128;
	case GNUTLS_CIPHER_AES_128_CCM:
		return TLS_CIPHER_AES_CCM_128;
	case GNUTLS_CIPHER_AES_256_GCM:
		return TLS_CIPHER_AES_GCM_256;
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return TLS_CIPHER_CHACHA20_POLY1305;
	default:
		return 0;
	}
}

static int secret_func(gnutls_session_t session,
		       gnutls_record_encryption_level_t level,
		       const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	gnutls_cipher_algorithm_t type  = gnutls_cipher_get(session);
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_crypto_secret secret = {};
	int len = sizeof(secret);

	if (conn->completed)
		return 0;

	if (level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
		type = gnutls_early_cipher_get(session);

	secret.level = get_crypto_level(level);
	secret.type = tls_cipher_type_get(type);
	if (tx_secret) {
		secret.send = 1;
		memcpy(secret.secret, tx_secret, secretlen);
		if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			print_error("socket setsockopt tx crypto_secret failed %d\n", level);
			return -1;
		}
	}
	if (rx_secret) {
		secret.send = 0;
		memcpy(secret.secret, rx_secret, secretlen);
		if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			print_error("socket setsockopt rx crypto_secret failed %d\n", level);
			return -1;
		}
		if (secret.level == QUIC_CRYPTO_APP) {
			if (conn->is_serv)
				gnutls_session_ticket_send(session, 1, 0);
			if (!conn->recv_ticket)
				conn->completed = 1;
		}
	}
	print_debug("  %s: %d %d %d\n", __func__, secret.level, !!tx_secret, !!rx_secret);
	return 0;
}

static int alert_read_func(gnutls_session_t session,
                           gnutls_record_encryption_level_t gtls_level,
                           gnutls_alert_level_t alert_level,
                           gnutls_alert_description_t alert_desc)
{
	print_warn("[WARN] %s: %d\n", __func__, alert_desc);
	return 0;
}

static int tp_recv_func(gnutls_session_t session, const uint8_t *buf, size_t len)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);

        if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, len)) {
                print_error("socket setsockopt transport_param_ext failed\n");
                return -1;
        }
	return 0;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	uint8_t buf[256];
	unsigned int len;
	int rv;

        len = sizeof(buf);
        if (getsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, &len)) {
                print_error("socket getsockopt transport_param_ext failed\n");
                return -1;
        }

	rv = gnutls_buffer_append_data(extdata, buf, len);
	if (rv != 0)
		return -1;

	return 0;
}

static int read_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
		     gnutls_handshake_description_t htype, const void *data, size_t datalen)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_frame *frame;
	uint32_t len = datalen;

	if (htype == GNUTLS_HANDSHAKE_KEY_UPDATE)
		return 0;

	while (len > 0) {
		frame = malloc(sizeof(*frame));
		memset(frame, 0, sizeof(*frame));
		frame->data.buflen = len;
		if (len > 1200)
			frame->data.buflen = 1200;
		memcpy(frame->data.buf, data, frame->data.buflen);

		frame->level = get_crypto_level(level);
		if (!conn->send_list) {
			conn->send_list = frame;
		} else {
			conn->send_last->next = frame;
		}
		conn->send_last = frame;

		len -= frame->data.buflen;
		data += frame->data.buflen;
	}

	print_debug("  %s: %d %d %d\n", __func__, level, htype, datalen);
	return 0;
}

static int crypto_gnutls_configure_session(gnutls_session_t session)
{
	gnutls_handshake_set_secret_function(session, secret_func);
	gnutls_handshake_set_read_function(session, read_func);
	gnutls_alert_set_read_function(session, alert_read_func);

	return gnutls_session_ext_register(
		session, "QUIC Transport Parameters",
		QUIC_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1, GNUTLS_EXT_TLS, tp_recv_func,
		tp_send_func, NULL, NULL, NULL,
		GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE);
}

static char priority[] = "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+";

static char *get_priority(struct quic_conn *conn)
{
	char *p = (char *)conn->priority.data;

	memcpy(p, priority, strlen(priority));
	switch (conn->cipher) {
	case TLS_CIPHER_AES_GCM_128:
		strcat(p, "AES-128-GCM");
		break;
	case TLS_CIPHER_AES_GCM_256:
		strcat(p, "AES-256-GCM");
		break;
	case TLS_CIPHER_AES_CCM_128:
		strcat(p, "AES-128-CCM");
		break;
	case TLS_CIPHER_CHACHA20_POLY1305:
		strcat(p, "CHACHA20-POLY1305");
		break;
	default:
		strcat(p, "AES-128-GCM:+AES-256-GCM:+AES-128-CCM:+CHACHA20-POLY1305");
		conn->cipher = 0;
		break;
	}
	conn->priority.datalen = strlen(p) + 1;
	return p;
}

static int session_ticket_recv(gnutls_session_t session, unsigned int htype, unsigned when,
			       unsigned int incoming, const gnutls_datum_t *msg)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_datum_t ticket;
	int ret;

	if (htype != GNUTLS_HANDSHAKE_NEW_SESSION_TICKET)
		return 0;

	conn->completed = 1;
	ret = gnutls_session_get_data2(session, &ticket);
	if (ret)
		return ret;

	ret = setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET,
			 ticket.data, ticket.size);
	if (ret) {
		print_debug("setsocket set session ticket %d\n", ticket.size);
		return ret;
	}
	return 0;
}

int quic_crypto_client_set_x509_session(struct quic_conn *conn)
{
	gnutls_certificate_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	ret = client_set_x509_cred(conn, cred);
	if (ret)
		goto err_cred;
	gnutls_certificate_set_verify_function(cred, client_x509_verify);

	ret = gnutls_init(&session, GNUTLS_CLIENT |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;
	ret = gnutls_priority_set_direct(session, get_priority(conn), NULL);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, session_ticket_recv);
	gnutls_session_set_ptr(session, conn);
	ret = crypto_gnutls_configure_session(session);
	if (ret)
		goto err_session;
	if (conn->ticket.buflen) {
		if (gnutls_session_set_data(session, conn->ticket.buf, conn->ticket.buflen))
			goto err_session;
	}
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (conn->parms->peername)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS,
				       conn->parms->peername, strlen(conn->parms->peername));
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen((char *)conn->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	print_error("session creation failed\n");
	return ret;
}

static int client_set_psk_cred(struct quic_conn *conn, void *cred)
{
	gnutls_datum_t *key = &conn->parms->keys[0];
	char *identity = conn->parms->names[0];

	conn->parms->peername = identity;

	return gnutls_psk_set_client_credentials(cred, identity, key, GNUTLS_PSK_KEY_RAW);
}

int quic_crypto_client_set_psk_session(struct quic_conn *conn)
{
	gnutls_psk_client_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_psk_allocate_client_credentials(&cred);
	if (ret)
		goto err;
	ret = client_set_psk_cred(conn, cred);
	if (ret)
		goto err_cred;

	ret = gnutls_init(&session, GNUTLS_CLIENT);
	if (ret)
		goto err_cred;
	ret = gnutls_priority_set_direct(session, get_priority(conn), NULL);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, session_ticket_recv);
	gnutls_session_set_ptr(session, conn);
	ret = crypto_gnutls_configure_session(session);
	if (ret)
		goto err_session;
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen((char *)conn->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_client_credentials(cred);
err:
	print_error("session creation failed\n");
	return ret;
}

static int server_x509_verify(gnutls_session_t session)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_handshake_parms *parms = conn->parms;
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
	for (i = 0; i < parms->num_keys; i++) {
		if (dataum_copy(&parms->keys[i], &peercerts[i]))
			goto err;
	}
	return 0;
err:
	for (i = 0; i < parms->num_keys; i++) {
		free(parms->keys[i].data);
		parms->keys[i].size = 0;
	}
	return -1;
}

static int server_set_x509_cred(struct quic_conn *conn, void *cred)
{
	gnutls_privkey_t privkey = conn->parms->privkey;
	gnutls_pcert_st  *cert = conn->parms->cert;

	return gnutls_certificate_set_key(cred, NULL, 0, cert, 1, privkey);
}

static int server_alpn_verify(gnutls_session_t session, unsigned int htype, unsigned when,
			      unsigned int incoming, const gnutls_datum_t *msg)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_datum_t alpn;
	int ret;

	if (!conn->alpn.datalen)
		return 0;

	ret = gnutls_alpn_get_selected_protocol(session, &alpn);
	if (ret)
		return ret;

	if (strlen((char *)conn->alpn.data) != alpn.size ||
	    memcmp(conn->alpn.data, alpn.data, alpn.size))
		return -1;

	return 0;
}

static int anti_replay_db_add_func(void *dbf, time_t exp_time, const gnutls_datum_t *key,
				   const gnutls_datum_t *data)
{
	return 0;
}

static gnutls_anti_replay_t anti_replay; /* TODO: make it per listen socket */

int quic_crypto_server_set_x509_session(struct quic_conn *conn)
{
	gnutls_certificate_credentials_t cred;
	gnutls_datum_t ticket_key;
	gnutls_session_t session;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	ret = server_set_x509_cred(conn, cred);
	if (ret)
		goto err_cred;

	gnutls_certificate_set_verify_function(cred, server_x509_verify);

	conn->is_serv = 1;
	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;
	ret = gnutls_priority_set_direct(session, get_priority(conn), NULL);
	if (ret)
		goto err_session;

	if (!anti_replay) {
		gnutls_anti_replay_init(&anti_replay);
		gnutls_anti_replay_set_add_function(anti_replay, anti_replay_db_add_func);
		gnutls_anti_replay_set_ptr(anti_replay, NULL);
	}
	gnutls_anti_replay_enable(session, anti_replay);
	gnutls_record_set_max_early_data_size(session, 0xffffffffu);

	gnutls_session_set_ptr(session, conn);
	ret = crypto_gnutls_configure_session(session);
	if (ret)
		goto err_session;
	ticket_key.data = conn->ticket.buf;
	ticket_key.size = conn->ticket.buflen;
	ret = gnutls_session_ticket_enable_server(session, &ticket_key);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, server_alpn_verify);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	gnutls_certificate_server_set_request(session, conn->cert_req);
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen((char *)conn->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}

	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	print_error("session creation failed\n");
	return ret;
}

static int server_psk_verify(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	int i;

	for (i = 0; i < conn->parms->num_keys; i++)
		if (!strcmp(conn->parms->names[i], username))
			break;
	if (i == conn->parms->num_keys)
		return -1;

	conn->parms->peername = conn->parms->names[i];
	*key = conn->parms->keys[i];
	return 0;
}

static int server_set_psk_cred(struct quic_conn *conn, void *cred)
{
	gnutls_psk_set_server_credentials_function(cred, server_psk_verify);
	return 0;
}

int quic_crypto_server_set_psk_session(struct quic_conn *conn)
{
	gnutls_psk_server_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_psk_allocate_server_credentials(&cred);
	if (ret)
		goto err;
	ret = server_set_psk_cred(conn, cred);
	if (ret)
		goto err;

	conn->is_serv = 1;
	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err_cred;
	ret = gnutls_priority_set_direct(session, get_priority(conn), NULL);
	if (ret)
		goto err_session;
	gnutls_session_set_ptr(session, conn);
	ret = crypto_gnutls_configure_session(session);
	if (ret)
		goto err_session;
	gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
					   GNUTLS_HOOK_POST, server_alpn_verify);
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen((char *)conn->alpn.data),
		};
		gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_server_credentials(cred);
err:
	print_error("session creation failed\n");
	return ret;
}
