#include "core.h"
#include <sys/time.h>

static uint32_t quic_get_microtime()
{
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	return currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
}

static int quic_handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_connection *qconn = user_data;

	qlog("%s!\n", __func__);
	qconn->state = QUIC_STATE_CONNECTED;
	qconn->is_ready = 1;
	return 0;
}

static int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_connection *qconn = user_data;

	qlog("%s!\n", __func__);
	qconn->state = QUIC_STATE_CONNECTED;
	qconn->is_ready = qconn->ep->is_serv;
	qconn->connected_ts = quic_get_microtime();

	return 0;
}

static void quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

static int quic_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
					 uint8_t *token, size_t cidlen, void *user_data)
{
	qlog("%s %d\n", __func__, cidlen);

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
	struct quic_connection *qconn = user_data;

	qlog("%s!\n", __func__);
	qconn->state = QUIC_STATE_CONNECTING;
	qconn->connecting_ts = quic_get_microtime();

	return ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);
}

static int quic_client_initial_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_connection *qconn = user_data;

	qlog("%s!\n", __func__);
	qconn->state = QUIC_STATE_CONNECTING;
	qconn->connecting_ts = quic_get_microtime();

	return ngtcp2_crypto_client_initial_cb(conn, user_data);
}

static int quic_update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
			      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
			      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
			      const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
			      size_t secretlen, void *user_data)
{
	const ngtcp2_crypto_ctx *crypto_ctx = ngtcp2_conn_get_crypto_ctx(conn);
	const ngtcp2_crypto_aead *aead = &crypto_ctx->aead;
	size_t keylen = ngtcp2_crypto_aead_keylen(aead);
	size_t ivlen = ngtcp2_crypto_packet_protection_ivlen(aead);
	char rx_key[64], tx_key[64];

	qlog("%s!\n", __func__);

	if (ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_aead_ctx,
				     rx_key, rx_iv, tx_aead_ctx, tx_key,
				     tx_iv, current_rx_secret, current_tx_secret,
				     secretlen) != 0) {
		return -1;
	}

	qlog("application_traffic rx secret:\n");
	print_secrets(rx_secret, secretlen, rx_key, keylen, rx_iv, ivlen, NULL, 0);
	qlog("application_traffic tx secret:\n");
	print_secrets(tx_secret, secretlen, tx_key, keylen, tx_iv, ivlen, NULL, 0);

	return 0;
}

static int quic_recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
				    uint64_t offset, const uint8_t *data, size_t datalen,
				    void *user_data)
{
	qlog("%s %d\n", __func__, encryption_level);

	return ngtcp2_crypto_recv_crypto_data_cb(conn, encryption_level, offset, data, datalen,
						 user_data);
}

static int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
				    uint64_t offset, const uint8_t *data, size_t datalen,
				    void *user_data, void *stream_user_data)
{
	struct quic_connection *qconn = user_data;
	struct quic_message *msg;

	qlog("%s %d\n", __func__, stream_id);
	msg = quic_message_new(data, datalen, stream_id, flags, offset);
	if (!msg)
		return -ENOMEM;

	quic_message_rcvq_enqueue(qconn, msg);
	return 0;
}

static int quic_recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level, void *user_data)
{
	qlog("%s %d\n", __func__, level);
	return 0;
}

static int quic_recv_tx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level, void *user_data)
{
	qlog("%s %d\n", __func__, level);
	return 0;
}

static int quic_recv_datagram_cb(ngtcp2_conn *conn, uint32_t flags,
				 const uint8_t *data, size_t datalen, void *user_data)
{
	qlog("%s %d\n", __func__, datalen);
	return 0;
}

static int quic_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	qlog("%s %d\n", __func__, stream_id);
	return 0;
}

void quic_ngtcp2_conn_callbacks_init(ngtcp2_callbacks *callbacks)
{
	memset(callbacks, 0, sizeof(*callbacks));
	callbacks->rand = quic_rand_cb;
	callbacks->get_new_connection_id = quic_get_new_connection_id_cb;
	callbacks->recv_client_initial = quic_recv_client_initial_cb;
	callbacks->client_initial = quic_client_initial_cb;
	callbacks->handshake_confirmed = quic_handshake_confirmed_cb;
	callbacks->handshake_completed = quic_handshake_completed_cb;
	callbacks->update_key = quic_update_key_cb;
	callbacks->recv_stream_data = quic_recv_stream_data_cb;
	callbacks->recv_crypto_data = quic_recv_crypto_data_cb;
	callbacks->recv_rx_key = quic_recv_rx_key_cb;
	callbacks->recv_tx_key = quic_recv_tx_key_cb;
	callbacks->recv_datagram = quic_recv_datagram_cb;
	callbacks->stream_open = quic_stream_open_cb;

	callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
	callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
	callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
	callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
	callbacks->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	callbacks->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	callbacks->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	callbacks->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
}
