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

#define QUIC_INITIAL_SALT_V1	\
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))

#define QUIC_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1	0x39u

#define QUIC_PKT_NUMLEN_MASK 0x03

static int hkdf_extract(gnutls_mac_algorithm_t prf, uint8_t *dest, const uint8_t *secret, size_t secretlen,
			const uint8_t *salt, size_t saltlen)
{
	gnutls_datum_t _secret = {(void *)secret, (unsigned int)secretlen};
	gnutls_datum_t _salt = {(void *)salt, (unsigned int)saltlen};

	return gnutls_hkdf_extract(prf, &_secret, &_salt, dest);
}

static int hkdf_expand(gnutls_mac_algorithm_t prf, uint8_t *dest, size_t destlen, const uint8_t *secret,
		       size_t secretlen, const uint8_t *info, size_t infolen)
{
	gnutls_datum_t _secret = {(void *)secret, (unsigned int)secretlen};
	gnutls_datum_t _info = {(void *)info, (unsigned int)infolen};

	return gnutls_hkdf_expand(prf, &_secret, &_info, dest, destlen);
}

static int hkdf_expand_label(gnutls_mac_algorithm_t prf, uint8_t *dest, size_t destlen, const uint8_t *secret,
			     size_t secretlen, const uint8_t *label, size_t labellen) {
	static const uint8_t LABEL[] = "tls13 ";
	uint8_t info[256];
	uint8_t *p = info;

	*p++ = (uint8_t)(destlen / 256);
	*p++ = (uint8_t)(destlen % 256);
	*p++ = (uint8_t)(sizeof(LABEL) - 1 + labellen);
	memcpy(p, LABEL, sizeof(LABEL) - 1);
	p += sizeof(LABEL) - 1;
	memcpy(p, label, labellen);
	p += labellen;
	*p++ = 0;

	return hkdf_expand(prf, dest, destlen, secret, secretlen, info, (size_t)(p - info));
}

static int quic_crypto_derive_initial_secrets(struct quic_key *rx_key, struct quic_key *tx_key,
					      uint8_t *data, uint32_t len, uint8_t is_serv)
{
	gnutls_mac_algorithm_t prf = GNUTLS_DIG_SHA256;
	static const uint8_t CLABEL[] = "client in";
	static const uint8_t SLABEL[] = "server in";
	uint8_t initial_secret[32];
	uint8_t *client_secret;
	uint8_t *server_secret;
	const uint8_t *salt;
	size_t saltlen;
	int ret;

	salt = (const uint8_t *)QUIC_INITIAL_SALT_V1;
	saltlen = sizeof(QUIC_INITIAL_SALT_V1) - 1;
	ret = hkdf_extract(prf, initial_secret, data, len, salt, saltlen);
	if (ret)
		goto err;
	if (is_serv) {
		client_secret = rx_key->secret.data;
		server_secret = tx_key->secret.data;
	} else {
		client_secret = tx_key->secret.data;
		server_secret = rx_key->secret.data;
	}

	len = sizeof(CLABEL) - 1;
	ret = hkdf_expand_label(prf, client_secret, 32, initial_secret, 32, CLABEL, len);
	if (ret)
		goto err;
	len = sizeof(SLABEL) - 1;
	ret = hkdf_expand_label(prf, server_secret, 32, initial_secret, 32, SLABEL, len);
	if (ret)
		goto err;

	rx_key->prf_type = prf;
	tx_key->prf_type = prf;
	rx_key->secret.datalen = 32;
	tx_key->secret.datalen = 32;
	rx_key->aead_type = GNUTLS_CIPHER_AES_128_GCM;
	tx_key->aead_type = GNUTLS_CIPHER_AES_128_GCM;
	rx_key->cipher_type = GNUTLS_CIPHER_AES_128_CBC;
	tx_key->cipher_type = GNUTLS_CIPHER_AES_128_CBC;
	return 0;
err:
	print_error("derive initial secrets failed\n");
	return ret;
}

static int quic_crypto_derive_packet_protection_key(struct quic_key *key)
{
	static const uint8_t KEY_LABEL_V1[] = "quic key";
	static const uint8_t IV_LABEL_V1[] = "quic iv";
	static const uint8_t HP_KEY_LABEL_V1[] = "quic hp";
	static const uint8_t KEY_LABEL_V2[] = "quicv2 key";
	static const uint8_t IV_LABEL_V2[] = "quicv2 iv";
	static const uint8_t HP_KEY_LABEL_V2[] = "quicv2 hp";
	const uint8_t *key_label;
	size_t key_labellen;
	const uint8_t *iv_label;
	size_t iv_labellen;
	const uint8_t *hp_key_label;
	size_t hp_key_labellen;
	gnutls_datum_t tls_key;
	int ret;

	key->key.datalen = gnutls_cipher_get_key_size(key->aead_type);
	key_label = KEY_LABEL_V1;
	key_labellen = sizeof(KEY_LABEL_V1) - 1;

	key->iv.datalen = gnutls_cipher_get_iv_size(key->aead_type);
	iv_label = IV_LABEL_V1;
	iv_labellen = sizeof(IV_LABEL_V1) - 1;

	key->hp_key.datalen = gnutls_cipher_get_key_size(key->cipher_type);
	hp_key_label = HP_KEY_LABEL_V1;
	hp_key_labellen = sizeof(HP_KEY_LABEL_V1) - 1;

	ret = hkdf_expand_label(key->prf_type, key->key.data, key->key.datalen, key->secret.data,
				key->secret.datalen, key_label, key_labellen);
	if (ret)
		goto err;

	ret = hkdf_expand_label(key->prf_type, key->iv.data, key->iv.datalen, key->secret.data,
				key->secret.datalen, iv_label, iv_labellen);
	if (ret)
		goto err;

	ret = hkdf_expand_label(key->prf_type, key->hp_key.data, key->hp_key.datalen, key->secret.data,
				key->secret.datalen, hp_key_label, hp_key_labellen);
	if (ret)
		goto err;

	tls_key.data = key->key.data;
	tls_key.size = key->key.datalen;
	ret = gnutls_aead_cipher_init(&key->aead, key->aead_type, &tls_key);
	if (ret)
		goto err;

	tls_key.data = key->hp_key.data;
	tls_key.size = key->hp_key.datalen;
	ret = gnutls_cipher_init(&key->cipher, key->cipher_type, &tls_key, NULL);
	if (ret)
		goto err;

	quic_debug_dump_key(key);
	return 0;
err:
	print_error("derive packet protection key failed\n");
	return ret;
}

int quic_crypto_derive_initial_keys(struct quic_conn *conn, uint8_t *data, uint32_t len)
{
	int ret;

	ret = quic_crypto_derive_initial_secrets(&conn->in_key[0], &conn->in_key[1],
						 data, len, conn->context.is_serv);
	if (ret)
		return ret;
	ret = quic_crypto_derive_packet_protection_key(&conn->in_key[0]);
	if (ret)
		return ret;
	return quic_crypto_derive_packet_protection_key(&conn->in_key[1]);
}

int quic_crypto_read_write_crypto_data(struct quic_conn *conn, uint8_t encryption_level,
				       const uint8_t *data, size_t datalen)
{
	gnutls_session_t session = conn->session;
	int rv;

	if (datalen > 0) {
		rv = gnutls_handshake_write(session, encryption_level, data, datalen);
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
	for (i = 0; i < parms->num_keys; i++)
		parms->keys[0] = peercerts[i];

	return 0;
}

static int client_set_x509_cred(struct quic_conn *conn, void *cred)
{
	gnutls_privkey_t privkey = conn->parms->privkey;
	gnutls_pcert_st  *cert = conn->parms->cert;

	if (!privkey || !cert)
		return 0;

	return gnutls_certificate_set_key(cred, NULL, 0, cert, 1, privkey);
}

static gnutls_cipher_algorithm_t crypto_get_cipher_type(gnutls_cipher_algorithm_t cipher) {
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_128_CCM:
		return GNUTLS_CIPHER_AES_128_CBC;
	case GNUTLS_CIPHER_AES_256_GCM:
	case GNUTLS_CIPHER_AES_256_CCM:
		return GNUTLS_CIPHER_AES_256_CBC;
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return GNUTLS_CIPHER_CHACHA20_32;
	default:
		return GNUTLS_CIPHER_UNKNOWN;
	}
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
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_key *key;

	if (rx_secret) {
		if (level == GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE) {
			key = &conn->hs_key[0];
			key->prf_type = gnutls_prf_hash_get(session);
			key->aead_type = gnutls_cipher_get(session);
			key->cipher_type = crypto_get_cipher_type(key->aead_type);
			memcpy(key->secret.data, rx_secret, secretlen);
			key->secret.datalen = secretlen;
			if (quic_crypto_derive_packet_protection_key(key))
				return -1;
		} else if (level == GNUTLS_ENCRYPTION_LEVEL_APPLICATION) {
			print_debug("  %s completed\n", __func__);
			conn->state = QUIC_CONN_HANDSHAKE_STATE_COMPLETED;
			if (conn->context.is_serv) {
				print_debug("  %s confirmed\n", __func__);
				conn->state = QUIC_CONN_HANDSHAKE_STATE_CONFIRMED;
			}
			conn->context.recv.type = tls_cipher_type_get(gnutls_cipher_get(session));
			memcpy(conn->context.recv.secret, rx_secret, secretlen);
		} else {
			return -1;
		}
	}

	if (tx_secret) {
		if (level == GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE) {
			key = &conn->hs_key[1];
			key->prf_type = gnutls_prf_hash_get(session);
			key->aead_type = gnutls_cipher_get(session);
			key->cipher_type = crypto_get_cipher_type(key->aead_type);
			memcpy(key->secret.data, tx_secret, secretlen);
			key->secret.datalen = secretlen;
			if (quic_crypto_derive_packet_protection_key(key))
				return -1;
		} else if (level == GNUTLS_ENCRYPTION_LEVEL_APPLICATION) {
			conn->state = QUIC_CONN_HANDSHAKE_STATE_COMPLETED;
			conn->context.send.type = tls_cipher_type_get(gnutls_cipher_get(session));
			memcpy(conn->context.send.secret, tx_secret, secretlen);
		} else {
			return -1;
		}
	}
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

static int tp_recv_func(gnutls_session_t session, const uint8_t *data, size_t datalen)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	int rv;

	rv = quic_packet_decode_transport_params(conn, data, datalen);
	if (rv != 0)
		return -1;
	return 0;
}

static int tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	uint8_t buf[256];
	int rv, nwrite;

	nwrite = quic_packet_encode_transport_params(conn, buf, sizeof(buf));
	if (nwrite < 0)
		return -1;

	rv = gnutls_buffer_append_data(extdata, buf, (size_t)nwrite);
	if (rv != 0)
		return -1;

	return 0;
}

static int read_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
		     gnutls_handshake_description_t htype, const void *data, size_t datalen)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_pktns *pktns;
	struct quic_frame *frame;
	uint32_t len = datalen;

	if (level == GNUTLS_ENCRYPTION_LEVEL_INITIAL) {
		pktns = &conn->in_pktns;
	} else if (level == GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE) {
		pktns = &conn->hs_pktns;
	} else {
		return -1;
	}

	while (len > 0) {
		frame = malloc(sizeof(*frame));
		memset(frame, 0, sizeof(*frame));
		frame->data.buflen = len;
		if (len > 1024)
			frame->data.buflen = 1024;
		memcpy(frame->data.buf, data, frame->data.buflen);

		frame->offset = pktns->send_offset;
		if (!pktns->send_list) {
			pktns->send_list = frame;
		} else {
			pktns->send_last->next = frame;
		}
		pktns->send_offset += frame->data.buflen;
		pktns->send_last = frame;

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

static char priority[100] = "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+";

static char *get_priority(struct quic_conn *conn)
{
	switch (conn->cipher) {
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
		conn->cipher = 0;
		break;
	}
	return priority;
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

	ret = gnutls_init(&session, GNUTLS_CLIENT);
	if (ret)
		goto err_cred;
	ret = gnutls_priority_set_direct(session, get_priority(conn), NULL);
	if (ret)
		goto err_session;
	gnutls_session_set_ptr(session, conn);
	ret = crypto_gnutls_configure_session(session);
	if (ret)
		goto err_session;
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (conn->parms->peername)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS,
				       conn->parms->peername, strlen(conn->parms->peername));
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen(conn->alpn.data),
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
	gnutls_session_set_ptr(session, conn);
	ret = crypto_gnutls_configure_session(session);
	if (ret)
		goto err_session;
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen(conn->alpn.data),
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
	for (i = 0; i < parms->num_keys; i++)
		parms->keys[0] = peercerts[i];

	return 0;
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

	if (strlen(conn->alpn.data) != alpn.size ||
	    memcmp(conn->alpn.data, alpn.data, alpn.size))
		return -1;

	return 0;
}

int quic_crypto_server_set_x509_session(struct quic_conn *conn)
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
	ret = server_set_x509_cred(conn, cred);
	if (ret)
		goto err_cred;
	gnutls_certificate_set_verify_function(cred, server_x509_verify);

	ret = gnutls_init(&session, GNUTLS_SERVER);
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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	gnutls_certificate_server_set_request(session, conn->parms->cert_req);
	if (conn->alpn.datalen) {
		gnutls_datum_t alpn = {
			.data = conn->alpn.data,
			.size = strlen(conn->alpn.data),
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

	ret = gnutls_init(&session, GNUTLS_SERVER);
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
			.size = strlen(conn->alpn.data),
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

int quic_crypto_encrypt(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	uint8_t *pkt = &packet->buf[hd->offset], *aad = pkt, nonce[12], mask[16];
	uint8_t *payload = pkt + hd->hdlen, *dest = payload, *sample, *p;
	uint64_t n = htobe64((uint64_t)(hd->number));
	uint32_t payloadlen = hd->length - hd->numlen;
	size_t aadlen = hd->hdlen, i, ctext_len;
	struct quic_key *key = hd->key;
	int ret;

	memcpy(nonce, key->iv.data, key->iv.datalen);
	for (i = 0; i < 8; ++i)
		nonce[key->iv.datalen - 8 + i] ^= ((uint8_t *)&n)[i];

	ctext_len = payloadlen + 16;
	ret = gnutls_aead_cipher_encrypt(key->aead, nonce, 12, aad, aadlen, 16,
					 payload, payloadlen, dest, &ctext_len);
	if (ret)
		return ret;
	packet->buflen += 16;

	sample = pkt + hd->num_offset + 4;
	switch (key->cipher_type) {
	case GNUTLS_CIPHER_AES_128_CBC:
	case GNUTLS_CIPHER_AES_256_CBC: {
		uint8_t buf[16], iv[16];

		memset(iv, 0, sizeof(iv));
		gnutls_cipher_set_iv(key->cipher, iv, sizeof(iv));
		ret = gnutls_cipher_encrypt2(key->cipher, sample, 16, buf, sizeof(buf));
		if (ret)
			return ret;
		memcpy(mask, buf, 5);
	} break;
	case GNUTLS_CIPHER_CHACHA20_32: {
		static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
		uint8_t buf[5 + 16];

		gnutls_cipher_set_iv(key->cipher, (void *)sample, 16);
		ret = gnutls_cipher_encrypt2(key->cipher, PLAINTEXT, sizeof(PLAINTEXT) - 1,
					     buf, sizeof(buf));
		if (ret)
			return ret;
		memcpy(mask, buf, 5);
	} break;
	}

	p = pkt;
	*p = (uint8_t)(*p ^ (mask[0] & 0x0f));

	p = pkt + hd->num_offset;
	for (i = 0; i < 1; ++i)
		*(p + i) ^= mask[i + 1];
	return 0;
}

int quic_crypto_decrypt(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd)
{
	uint8_t *pkt = &packet->buf[hd->offset], *aad = pkt;
	uint8_t *payload, *sample, *dest, i, *p;
	uint32_t buflen, payloadlen, aadlen;
	struct quic_key *key = hd->key;
	uint8_t mask[16], nonce[12];
	size_t ptext_len;
	uint64_t n;
	int ret;

	buflen = packet->buflen - hd->offset;
	if (hd->num_offset + 4 + 16 > buflen)
		return -EINVAL;

	sample = pkt + hd->num_offset + 4;
	switch (key->cipher_type) {
	case GNUTLS_CIPHER_AES_128_CBC:
	case GNUTLS_CIPHER_AES_256_CBC: {
		uint8_t buf[16], iv[16];

		memset(iv, 0, sizeof(iv));
		gnutls_cipher_set_iv(key->cipher, iv, sizeof(iv));
		ret = gnutls_cipher_encrypt2(key->cipher, sample, 16, buf, sizeof(buf));
		if (ret)
			return ret;
		memcpy(mask, buf, 5);
	} break;
	case GNUTLS_CIPHER_CHACHA20_32: {
		static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
		uint8_t buf[5 + 16];

		gnutls_cipher_set_iv(key->cipher, (void *)sample, 16);
		ret = gnutls_cipher_encrypt2(key->cipher, PLAINTEXT, sizeof(PLAINTEXT) - 1,
					     buf, sizeof(buf));
		if (ret)
			return ret;
		memcpy(mask, buf, 5);
	} break;
	}

	pkt[0] = (uint8_t)(pkt[0] ^ (mask[0] & 0x0f));
	hd->numlen = (uint32_t)((pkt[0] & QUIC_PKT_NUMLEN_MASK) + 1);
	p = pkt + hd->num_offset;
	for (i = 0; i < hd->numlen; ++i)
		*p++ = *(pkt + hd->num_offset + i) ^ mask[i + 1];
	hd->number = quic_packet_get_num(p - hd->numlen, hd->numlen);
	hd->hdlen = hd->num_offset + hd->numlen;

	n = htobe64((uint64_t)(hd->number));
	memcpy(nonce, key->iv.data, key->iv.datalen);
	for (i = 0; i < 8; ++i)
		nonce[key->iv.datalen - 8 + i] ^= ((uint8_t *)&n)[i];

	payload = pkt + hd->hdlen;
	dest = payload;
	payloadlen = hd->length - hd->numlen;
	aadlen = hd->hdlen;
	ptext_len = payloadlen - 16;
	ret = gnutls_aead_cipher_decrypt(key->aead, nonce, 12, aad, aadlen, 16,
					 payload, payloadlen, dest, &ptext_len);
	if (ret)
		return ret;

	hd->length -= 16;
	return 0;
}
