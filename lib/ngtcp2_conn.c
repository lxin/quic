#include "core.h"

static int quic_ngtcp2_conn_init_cred(struct quic_connection *conn)
{
	gnutls_certificate_credentials_t *cred = &conn->cred;
	struct quic_endpoint *ep = conn->ep;
	int ret;

	ret = gnutls_certificate_allocate_credentials(cred);
	if (ret) {
		printf("gnutls_certificate_allocate_credentials failed\n");
		return -1;
	}

	ret = gnutls_certificate_set_x509_system_trust(*cred);
	if (ret < 0) {
		printf("gnutls_certificate_set_x509_system_trust failed\n");
		return -1;
	}

	if (!ep->certificate[0] || !ep->private_key[0])
		return 0;

	ret = gnutls_certificate_set_x509_key_file(*cred, ep->certificate,
						   ep->private_key, GNUTLS_X509_FMT_PEM);
	if (ret) {
		printf("gnutls_certificate_set_x509_key_file failed\n");
		return -1;
	}

	return 0;
}

static ngtcp2_conn *quic_session_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct quic_connection *conn = conn_ref->user_data;

	return conn->conn;
}

static int quic_session_hook_func(gnutls_session_t session, unsigned int htype, unsigned int when,
				  unsigned int incoming, const gnutls_datum_t *msg)
{
	return 0;
}

static int quic_secret_func(gnutls_session_t session, gnutls_record_encryption_level_t gtls_level,
			    const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
	ngtcp2_conn *conn = conn_ref->get_conn(conn_ref);
	const ngtcp2_crypto_ctx *crypto_ctx = ngtcp2_conn_get_crypto_ctx(conn);
	struct quic_connection *qconn = conn_ref->user_data;
	ngtcp2_encryption_level level;
	char key[64], iv[64], hp[64];

	level = ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(gtls_level);
	qlog("%s %d, %d %d, %d\n", __func__, secretlen, rx_secret, tx_secret, level);
	if (rx_secret) {
		if (ngtcp2_crypto_derive_and_install_rx_key(conn, key, iv, hp, level,
							    rx_secret, secretlen))
			return -1;
		if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
			size_t ivlen = ngtcp2_crypto_packet_protection_ivlen(&crypto_ctx->aead);
			size_t keylen = ngtcp2_crypto_aead_keylen(&crypto_ctx->aead);

			qlog("application_traffic rx secret:\n");
			print_secrets(rx_secret, secretlen, key, keylen, iv, ivlen, hp, 16);
			memcpy(qconn->secret[0].key, rx_secret, secretlen);
			qconn->secret[0].keylen = secretlen;
		}
	}

	if (tx_secret) {
		if (ngtcp2_crypto_derive_and_install_tx_key(conn, key, iv, hp, level,
							    tx_secret, secretlen))
			return -1;
		if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
			size_t ivlen = ngtcp2_crypto_packet_protection_ivlen(&crypto_ctx->aead);
			size_t keylen = ngtcp2_crypto_aead_keylen(&crypto_ctx->aead);

			qlog("application_traffic tx secret:\n");
			print_secrets(tx_secret, secretlen, key, keylen, iv, ivlen, hp, 16);
			memcpy(qconn->secret[1].key, tx_secret, secretlen);
			qconn->secret[1].keylen = secretlen;
		}
	}

	return 0;
}

#define MODES "%DISABLE_TLS13_COMPAT_MODE"
#define CIPHERS "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM"
#define GROUPS "-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:+GROUP-SECP384R1:+GROUP-SECP521R1"
#define PRIORITY MODES":"CIPHERS":"GROUPS

static int quic_ngtcp2_conn_init_session(struct quic_connection *conn)
{
	gnutls_session_t *session = &conn->session;
	gnutls_certificate_credentials_t cred;
	struct quic_endpoint *ep = conn->ep;
	ngtcp2_crypto_conn_ref *conn_ref;
	int ret, flag;

	if (quic_ngtcp2_conn_init_cred(conn))
		return -1;

	cred = conn->cred;
	conn_ref = &conn->conn_ref;
	conn_ref->get_conn = quic_session_get_conn;
	conn_ref->user_data = conn;
	flag = ep->is_serv ? GNUTLS_SERVER : GNUTLS_CLIENT;
	ret = gnutls_init(session, flag | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret) {
		printf("gnutls_init failed.\n");
		return -1;
	}
	ret = gnutls_priority_set_direct(*session, PRIORITY, NULL);
	if (ret) {
		printf("gnutls_priority_set_direct failed.\n");
		return -1;
	}
	gnutls_handshake_set_hook_function(*session, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, quic_session_hook_func);
	gnutls_server_name_set(*session, GNUTLS_NAME_DNS, "localhost", strlen("localhost"));
	gnutls_session_set_ptr(*session, conn_ref);
	ret = ep->is_serv ? ngtcp2_crypto_gnutls_configure_server_session(*session)
			  : ngtcp2_crypto_gnutls_configure_client_session(*session);
	if (ret) {
		printf("ngtcp2_crypto_gnutls_configure_server/client_session failed.\n");
		return -1;
	}
	gnutls_handshake_set_secret_function(*session, quic_secret_func);
	gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cred);
	return 0;
}

int quic_ngtcp2_conn_init(struct quic_connection *conn, ngtcp2_pkt_hd *hd)
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

	quic_ngtcp2_conn_callbacks_init(&callbacks);

	if (quic_ngtcp2_conn_init_session(conn)) {
		printf("fail to create session\n");
		return -1;
	}

	ngtcp2_path_storage_init(&ps, (void *)&conn->la, sizeof(conn->la),
				 (void *)&conn->ra, sizeof(conn->ra), NULL);

	if (!conn->ep->is_serv) {
		scid.datalen = 17;
		gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
		dcid.datalen = 18;
		gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
		if (ngtcp2_conn_client_new(&conn->conn, &dcid, &scid, &ps.path,
					   NGTCP2_PROTO_VER_V1, &callbacks, &settings,
					   &params, NULL, conn))
			return -1;

		ngtcp2_conn_set_tls_native_handle(conn->conn, conn->session);
		return 0;
	}

	params.original_dcid = hd->dcid;
	params.original_dcid_present = 1;
	settings.token = hd->token;
	settings.tokenlen = hd->tokenlen;

	scid.datalen = 18;
	gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
	dcid = hd->scid;
	if (ngtcp2_conn_server_new(&conn->conn, &dcid, &scid, &ps.path,
				   hd->version, &callbacks, &settings,
				   &params, NULL, conn))
		return -1;
	ngtcp2_conn_set_tls_native_handle(conn->conn, conn->session);
	return 0;
}
