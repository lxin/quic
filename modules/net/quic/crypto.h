/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_TAG_LEN	16
#define QUIC_IV_LEN	12
#define QUIC_KEY_LEN	32
#define QUIC_SECRET_LEN	48

#define QUIC_TOKEN_FLAG_REGULAR		0
#define QUIC_TOKEN_FLAG_RETRY		1
#define QUIC_TOKEN_TIMEOUT_REGULAR	3000000
#define QUIC_TOKEN_TIMEOUT_RETRY	600000000

struct quic_cipher {
	u32 secretlen;
	u32 keylen;

	char *shash;
	char *aead;
	char *skc;
};

struct quic_crypto {
	struct crypto_skcipher *tx_hp_tfm;
	struct crypto_skcipher *rx_hp_tfm;
	struct crypto_shash *secret_tfm;
	struct crypto_aead *tx_tfm[2];
	struct crypto_aead *rx_tfm[2];
	struct crypto_aead *tag_tfm;
	struct quic_cipher *cipher;
	u32 cipher_type;

	u8 tx_secret[QUIC_SECRET_LEN];
	u8 rx_secret[QUIC_SECRET_LEN];
	u8 tx_iv[2][QUIC_IV_LEN];
	u8 rx_iv[2][QUIC_IV_LEN];

	u32 key_update_send_time;
	u32 key_update_time;
	u32 version;

	u8 ticket_ready:1;
	u8 key_pending:1;
	u8 send_ready:1;
	u8 recv_ready:1;
	u8 key_phase:1;

	u64 send_offset;
	u64 recv_offset;
};

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt,
			   u32 version, u8 flag);
int quic_crypto_get_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt);
int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb);
int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb);
int quic_crypto_key_update(struct quic_crypto *crypto);

int quic_crypto_initial_keys_install(struct quic_crypto *crypto, struct quic_conn_id *conn_id,
				     u32 version, bool is_serv);
int quic_crypto_generate_session_ticket_key(struct quic_crypto *crypto, void *data,
					    u32 len, u8 *key, u32 key_len);
int quic_crypto_generate_stateless_reset_token(struct quic_crypto *crypto, void *data,
					       u32 len, u8 *key, u32 key_len);

int quic_crypto_generate_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			       struct quic_conn_id *conn_id, u8 *token, u32 *tlen);
int quic_crypto_get_retry_tag(struct quic_crypto *crypto, struct sk_buff *skb,
			      struct quic_conn_id *odcid, u32 version, u8 *tag);
int quic_crypto_verify_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			     struct quic_conn_id *conn_id, u8 *token, u32 len);

void quic_crypto_free(struct quic_crypto *crypto);
void quic_crypto_init(void);
