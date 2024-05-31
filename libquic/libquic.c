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

#include <gnutls/crypto.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/tls.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include "netinet/quic.h"

#define MAX_BUFLEN	4096

struct quic_buf {
	uint32_t buflen;
	uint8_t buf[MAX_BUFLEN];
};

struct quic_frame {
	struct quic_frame *next;
	struct quic_buf data;
	uint8_t level;
};

struct quic_data {
	uint8_t data[144];
	uint32_t datalen;
};

struct quic_conn {
	struct quic_handshake_parms *parms;
	struct quic_data priority;
	struct quic_data alpn;
	uint32_t cipher;
	int sockfd;

	gnutls_session_t session;
	struct quic_buf ticket;
	uint8_t recv_ticket:1;
	uint8_t completed:1;
	uint8_t cert_req:2;
	uint8_t is_serv:1;
	uint8_t errcode;
	timer_t timer;

	struct quic_frame *send_list;
	struct quic_frame *send_last;
	struct quic_frame frame;
};

extern quic_log_func pr_error;
extern quic_log_func pr_warn;
extern quic_log_func pr_debug;

int quic_crypto_read_write_crypto_data(struct quic_conn *conn, uint8_t encryption_level,
				       const uint8_t *data, size_t datalen);
int quic_crypto_client_set_x509_session(struct quic_conn *conn);
int quic_crypto_server_set_x509_session(struct quic_conn *conn);
int quic_crypto_client_set_psk_session(struct quic_conn *conn);
int quic_crypto_server_set_psk_session(struct quic_conn *conn);

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
	pr_warn("%s: %d\n", __func__, level);
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
	pr_warn("%s: %d\n", __func__, level);
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
	pr_error("read write crypto data failed\n");
	return rv;
}

static int dataum_copy(gnutls_datum_t *dest, const gnutls_datum_t *source)
{
	dest->data = malloc(source->size);
	if (!dest->data)
		return -ENOMEM;
	memcpy(dest->data, source->data, source->size);
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

	if (conn->cert_req == 3) /* no certificate verification */
		return 0;
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
			pr_error("socket setsockopt tx crypto_secret failed %d\n", level);
			return -1;
		}
	}
	if (rx_secret) {
		secret.send = 0;
		memcpy(secret.secret, rx_secret, secretlen);
		if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			pr_error("socket setsockopt rx crypto_secret failed %d\n", level);
			return -1;
		}
		if (secret.level == QUIC_CRYPTO_APP) {
			if (conn->is_serv)
				gnutls_session_ticket_send(session, 1, 0);
			if (!conn->recv_ticket)
				conn->completed = 1;
		}
	}
	pr_debug("  %s: %d %d %d\n", __func__, secret.level, !!tx_secret, !!rx_secret);
	return 0;
}

static int alert_read_func(gnutls_session_t session, gnutls_record_encryption_level_t gtls_level,
			   gnutls_alert_level_t alert_level, gnutls_alert_description_t alert_desc)
{
	pr_warn("%s: %d\n", __func__, alert_desc);
	return 0;
}

static int tp_recv_func(gnutls_session_t session, const uint8_t *buf, size_t len)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);

	if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, len)) {
		pr_error("socket setsockopt transport_param_ext failed\n");
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
		pr_error("socket getsockopt transport_param_ext failed\n");
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
		if (!conn->send_list)
			conn->send_list = frame;
		else
			conn->send_last->next = frame;
		conn->send_last = frame;

		len -= frame->data.buflen;
		data += frame->data.buflen;
	}

	pr_debug("  %s: %d %d %d\n", __func__, level, htype, datalen);
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

static char priority[] =
	"%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+";

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

static int session_ticket_recv(gnutls_session_t session, unsigned int htype, unsigned int when,
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
		pr_debug("setsocket set session ticket %d\n", ticket.size);
		return ret;
	}
	return 0;
}

static int session_set_alpns(gnutls_session_t session, char *data)
{
	char *alpn = strtok(data, ",");
	gnutls_datum_t alpns[10];
	int count = 0;

	while (alpn) {
		while (*alpn == ' ')
			alpn++;

		alpns[count].data = (unsigned char *)alpn;
		alpns[count].size = strlen(alpn);
		if (++count >= 10)
			return -EINVAL;
		alpn = strtok(NULL, ",");
	}

	gnutls_alpn_set_protocols(session, alpns, count, GNUTLS_ALPN_MANDATORY);
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
	if (conn->parms->cafile)
		ret = gnutls_certificate_set_x509_trust_file(cred, conn->parms->cafile,
							     GNUTLS_X509_FMT_PEM);
	else
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
		ret = session_set_alpns(session, (char *)conn->alpn.data);
		if (ret)
			goto err_session;
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	pr_error("session creation failed\n");
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
		ret = session_set_alpns(session, (char *)conn->alpn.data);
		if (ret)
			goto err_session;
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_client_credentials(cred);
err:
	pr_error("session creation failed\n");
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

static int server_alpn_verify(gnutls_session_t session, unsigned int htype, unsigned int when,
			      unsigned int incoming, const gnutls_datum_t *msg)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_datum_t alpn = {};
	int ret;

	if (!conn->alpn.datalen)
		return 0;

	ret = gnutls_alpn_get_selected_protocol(session, &alpn);
	if (ret)
		return ret;
	if (setsockopt(conn->sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn.data, alpn.size)) {
		pr_error("socket setsockopt alpn failed %d\n", alpn.size);
		return -1;
	}
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
	if (conn->parms->cafile)
		ret = gnutls_certificate_set_x509_trust_file(cred, conn->parms->cafile,
							     GNUTLS_X509_FMT_PEM);
	else
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
		ret = session_set_alpns(session, (char *)conn->alpn.data);
		if (ret)
			goto err_session;
	}

	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	pr_error("session creation failed\n");
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

	if (dataum_copy(key, &conn->parms->keys[i]))
		return -1;
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
		ret = session_set_alpns(session, (char *)conn->alpn.data);
		if (ret)
			goto err_session;
	}
	conn->session = session;
	return 0;
err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_psk_free_server_credentials(cred);
err:
	pr_error("session creation failed\n");
	return ret;
}
static int read_psk_file(char *psk, char *identity[], gnutls_datum_t *pkey)
{
	unsigned char *end, *key, *buf;
	int fd, err = -1, i = 0;
	struct stat statbuf;
	gnutls_datum_t gkey;
	unsigned int size;

	fd = open(psk, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;

	size = (unsigned int)statbuf.st_size;
	buf = malloc(size);
	if (!buf)
		goto out;
	if (read(fd, buf, size) == -1) {
		free(buf);
		goto out;
	}

	end = buf + size - 1;
	do {
		key = (unsigned char *)strchr((char *)buf, ':');
		if (!key)
			goto out;
		*key = '\0';
		identity[i] = (char *)buf;

		key++;
		gkey.data = key;

		buf = (unsigned char *)strchr((char *)key, '\n');
		if (!buf) {
			gkey.size = end - gkey.data;
			buf = end;
			goto decode;
		}
		*buf = '\0';
		buf++;
		gkey.size = strlen((char *)gkey.data);
decode:
		if (gnutls_hex_decode2(&gkey, &pkey[i]))
			goto out;
		i++;
	} while (buf < end);

	err = i;
out:
	close(fd);
	return err;
}

static int read_datum(const char *file, gnutls_datum_t *data)
{
	struct stat statbuf;
	unsigned int size;
	int ret = -1;
	void *buf;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;
	if (statbuf.st_size < 0 || statbuf.st_size > INT_MAX)
		goto out;
	size = (unsigned int)statbuf.st_size;
	buf = malloc(size);
	if (!buf)
		goto out;
	if (read(fd, buf, size) == -1) {
		free(buf);
		goto out;
	}
	data->data = buf;
	data->size = size;
	ret = 0;
out:
	close(fd);
	return ret;
}

static int read_pkey_file(char *file, gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_privkey_init(privkey);
	if (ret)
		goto out;

	ret = gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
out:
	free(data.data);
	return ret;
}

static int read_cert_file(char *file, gnutls_pcert_st **cert)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_pcert_import_x509_raw(*cert, &data, GNUTLS_X509_FMT_PEM, 0);
	free(data.data);

	return ret;
}

static void timer_handler(union sigval arg)
{
	struct quic_conn *conn = arg.sival_ptr;

	conn->errcode = ETIMEDOUT;
}

static int set_nonblocking(int sockfd, uint8_t nonblocking)
{
	int flags = fcntl(sockfd, F_GETFL, 0);

	if (flags == -1) {
		pr_error("fcntl");
		return -1;
	}

	if (nonblocking)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(sockfd, F_SETFL, flags) == -1) {
		pr_error("fcntl");
		return -1;
	}
	return 0;
}

static int setup_timer(struct quic_conn *conn)
{
	uint64_t msec = conn->parms->timeout;
	struct itimerspec its = {};
	struct sigevent sev = {};

	if (set_nonblocking(conn->sockfd, 1))
		return -1;

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = timer_handler;
	sev.sigev_value.sival_ptr = conn;
	timer_create(CLOCK_REALTIME, &sev, &conn->timer);

	its.it_value.tv_sec  = msec / 1000;
	its.it_value.tv_nsec = (msec % 1000) * 1000000;
	timer_settime(conn->timer, 0, &its, NULL);
	return 0;
}

static int delete_timer(struct quic_conn *conn)
{
	set_nonblocking(conn->sockfd, 0);
	timer_delete(conn->timer);
	return 0;
}

static int get_transport_param(struct quic_conn *conn)
{
	struct quic_transport_param param = {};
	int sockfd = conn->sockfd;
	unsigned int len;

	len = sizeof(conn->alpn.data);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, conn->alpn.data, &len)) {
		pr_error("socket getsockopt alpn failed\n");
		return -1;
	}
	conn->alpn.datalen = len;
	len = sizeof(conn->ticket.buf);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, conn->ticket.buf, &len)) {
		pr_error("socket getsockopt session ticket failed\n");
		return -1;
	}
	conn->ticket.buflen = len;
	len = sizeof(param);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &len)) {
		pr_error("socket getsockopt transport param failed\n");
		return -1;
	}
	conn->recv_ticket = param.receive_session_ticket;
	conn->cert_req = param.certificate_request;
	conn->cipher = param.payload_cipher_type;
	conn->sockfd = sockfd;
	return 0;
}

static int conn_destroy(struct quic_conn *conn)
{
	struct quic_frame *frame = conn->send_list;
	int ret;

	while (frame) {
		conn->send_list = frame->next;
		free(frame);
		frame = conn->send_list;
	}
	delete_timer(conn);
	gnutls_deinit(conn->session);
	ret = conn->errcode;
	free(conn);
	return -ret;
}

static struct quic_conn *conn_create(int sockfd, struct quic_handshake_parms *parms, uint8_t server)
{
	struct quic_conn *conn;

	conn = malloc(sizeof(*conn));
	if (!conn)
		return NULL;

	memset(conn, 0, sizeof(*conn));
	conn->parms = parms;
	conn->sockfd = sockfd;

	if (get_transport_param(conn))
		goto err;

	if (setup_timer(conn))
		goto err;

	return conn;
err:
	conn_destroy(conn);
	return NULL;
}

static int conn_sendmsg(int sockfd, struct quic_frame *frame)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	int flags = 0;

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)frame->data.buf;
	iov.iov_len = frame->data.buflen;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;
	if (frame->next)
		flags = MSG_MORE;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
	info->crypto_level = frame->level;

	return sendmsg(sockfd, &outmsg, flags);
}

static int conn_recvmsg(int sockfd, struct quic_frame *frame)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info info;
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	frame->data.buflen = 0;
	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = frame->data.buf;
	iov.iov_len = sizeof(frame->data.buf);

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(sockfd, &inmsg, 0);
	if (error < 0)
		return error;
	frame->data.buflen = error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_HANDSHAKE_INFO == cmsg->cmsg_type)
			break;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
		frame->level = info.crypto_level;
	}

	return error;
}

static int conn_handshake_completed(struct quic_conn *conn)
{
	return conn->completed || conn->errcode;
}

static void conn_do_handshake(struct quic_conn *conn)
{
	int ret, sockfd = conn->sockfd;
	struct timeval tv = {1, 0};
	struct quic_frame *frame;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	while (!conn_handshake_completed(conn)) {
		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0) {
			conn->errcode = errno;
			return;
		}
		frame = &conn->frame;
		while (!conn_handshake_completed(conn)) {
			ret = conn_recvmsg(sockfd, frame);
			if (ret <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				conn->errcode = errno;
				return;
			}
			pr_debug("v %s RECV: %d %d\n", __func__, frame->data.buflen, frame->level);
			ret = quic_crypto_read_write_crypto_data(conn, frame->level,
								 frame->data.buf,
								 frame->data.buflen);
			if (ret) {
				conn->errcode = -ret;
				return;
			}
		}

		frame = conn->send_list;
		while (frame) {
			pr_debug("^ %s SEND: %d %d\n", __func__, frame->data.buflen, frame->level);
			ret = conn_sendmsg(sockfd, frame);
			if (ret < 0) {
				conn->errcode = errno;
				return;
			}
			conn->send_list = frame->next;
			free(frame);
			frame = conn->send_list;
		}
	}
}

static int quic_log_level = 2;

static void _pr_debug(char const *fmt, ...)
{
	va_list arg;

	if (quic_log_level < 3)
		return;
	printf("[DEBUG] ");
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

static void _pr_warn(char const *fmt, ...)
{
	va_list arg;

	if (quic_log_level < 2)
		return;
	printf("[WARN] ");
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

static void _pr_error(char const *fmt, ...)
{
	va_list arg;

	if (quic_log_level < 1)
		return;
	printf("[ERROR] ");
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

quic_log_func pr_error = _pr_error;
quic_log_func pr_warn  = _pr_warn;
quic_log_func pr_debug = _pr_debug;

/**
 * quic_set_log_level - change the log_level
 * @level: the level it changes to, the value can be:
 *
 * 1: LOGLEVEL_ERROR
 * 2: LOGLEVEL_WARN (default)
 * 3: LOGLEVEL_DEBUG
 */
void quic_set_log_level(int level)
{
	quic_log_level = level;
}

/**
 * quic_set_log_funcs - change the log_func for each level
 * @debug: the log func for debug log level
 * @warn:  the log func for warn  log level
 * @error: the log func for error log level
 */
void quic_set_log_funcs(quic_log_func debug, quic_log_func warn, quic_log_func error)
{
	if (debug)
		pr_debug = debug;
	if (warn)
		pr_warn  = warn;
	if (error)
		pr_error = error;
}

/**
 * quic_client_handshake_parms - start a QUIC handshake with Certificate or PSK mode on client side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameters for handshake, see struct quic_handshake_parms
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_handshake_parms(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_frame *frame;
	struct quic_conn *conn;
	int ret, level;

	conn = conn_create(sockfd, parms, 0);
	if (!conn)
		return -ENOMEM;

	ret = parms->num_keys ? quic_crypto_client_set_psk_session(conn)
			      : quic_crypto_client_set_x509_session(conn);
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	level = QUIC_CRYPTO_INITIAL;
	ret = quic_crypto_read_write_crypto_data(conn, level, NULL, 0);
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	frame = conn->send_list;
	while (frame) {
		pr_debug("^ %s SEND: %d %d\n", __func__, frame->data.buflen, frame->level);
		ret = conn_sendmsg(sockfd, frame);
		if (ret < 0) {
			conn->errcode = errno;
			goto out;
		}
		conn->send_list = frame->next;
		free(frame);
		frame = conn->send_list;
	}

	conn_do_handshake(conn);
out:
	return conn_destroy(conn);
}

/**
 * quic_server_handshake_parms - start a QUIC handshake with Certificate or PSK mode on server side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameters for handshake, see struct quic_handshake_parms
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_handshake_parms(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_conn *conn;
	int ret;

	conn = conn_create(sockfd, parms, 1);
	if (!conn)
		return -ENOMEM;

	ret = parms->num_keys ? quic_crypto_server_set_psk_session(conn)
			      : quic_crypto_server_set_x509_session(conn);
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	conn_do_handshake(conn);
out:
	return conn_destroy(conn);
}

/**
 * quic_client_handshake - start a QUIC handshake with Certificate or PSK mode on client side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey_file: private key file (optional) or pre-shared key file
 * @cert_file: certificate file (optional) or null
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
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
		ret = read_psk_file(pkey_file, parms.names, parms.keys);
		if (ret <= 0) {
			pr_error("parse psk file failed\n");
			return -1;
		}
		parms.num_keys = ret;
		goto start;
	}

	parms.cert = &gcert;
	if (read_pkey_file(pkey_file, &parms.privkey) ||
	    read_cert_file(cert_file, &parms.cert)) {
		pr_error("parse prikey or cert files failed\n");
		return -1;
	}
start:
	return quic_client_handshake_parms(sockfd, &parms);
}

/**
 * quic_server_handshake - start a QUIC handshake with Certificate or PSK mode on server side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey: private key file or pre-shared key file
 * @cert: certificate file or null
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_handshake(int sockfd, char *pkey_file, char *cert_file)
{
	struct quic_handshake_parms parms = {};
	gnutls_pcert_st gcert;
	int ret;

	parms.timeout = 15000;
	if (!cert_file) {
		ret = read_psk_file(pkey_file, parms.names, parms.keys);
		if (ret <= 0) {
			pr_error("parse psk file failed\n");
			return -1;
		}
		parms.num_keys = ret;
		goto start;
	}

	parms.cert = &gcert;
	if (read_pkey_file(pkey_file, &parms.privkey) ||
	    read_cert_file(cert_file, &parms.cert)) {
		pr_error("parse prikey or cert files failed\n");
		return -1;
	}
start:
	return quic_server_handshake_parms(sockfd, &parms);
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
ssize_t quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info info;
	struct cmsghdr *cmsg = NULL;
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
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_STREAM_INFO == cmsg->cmsg_type)
			break;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(struct quic_stream_info));
		*sid = info.stream_id;
		*flag = info.stream_flag;
	}
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
ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;

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
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	outmsg.msg_controllen = cmsg->cmsg_len;
	info = (struct quic_stream_info *)CMSG_DATA(cmsg);
	info->stream_id = sid;
	info->stream_flag = flag;

	return sendmsg(sockfd, &outmsg, 0);
}
