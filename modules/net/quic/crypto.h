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
	u32 secretlen;			/* Length of the traffic secret */
	u32 keylen;			/* Length of the AEAD key */

	char *shash;			/* Name of hash algorithm used for key derivation */
	char *aead;			/* Name of AEAD algorithm used for payload en/decryption */
	char *skc;			/* Name of cipher algorithm used for header protection */
};

struct quic_crypto {
	struct crypto_skcipher *tx_hp_tfm;	/* Transform for TX header protection */
	struct crypto_skcipher *rx_hp_tfm;	/* Transform for RX header protection */
	struct crypto_shash *secret_tfm;	/* Transform for key derivation (HKDF) */
	struct crypto_aead *tx_tfm[2];		/* AEAD transform for TX (key phase 0 and 1) */
	struct crypto_aead *rx_tfm[2];		/* AEAD transform for RX (key phase 0 and 1) */
	struct crypto_aead *tag_tfm;		/* AEAD transform used for Retry token validation */
	struct quic_cipher *cipher;		/* Cipher information (selected cipher suite) */
	u32 cipher_type;			/* Cipher suite (e.g., AES_GCM_128, etc.) */

	u8 tx_secret[QUIC_SECRET_LEN];		/* TX secret derived or provided by user space */
	u8 rx_secret[QUIC_SECRET_LEN];		/* RX secret derived or provided by user space */
	u8 tx_iv[2][QUIC_IV_LEN];		/* IVs for TX (key phase 0 and 1) */
	u8 rx_iv[2][QUIC_IV_LEN];		/* IVs for RX (key phase 0 and 1) */

	u32 key_update_send_time;		/* Time when 1st packet was sent after key update */
	u32 key_update_time;			/* Time to retain old keys after key update */
	u32 version;				/* QUIC version in use */

	u8 ticket_ready:1;			/* True if  a session ticket is ready to read */
	u8 key_pending:1;			/* A key update is in progress */
	u8 send_ready:1;			/* TX encryption context is initialized */
	u8 recv_ready:1;			/* RX decryption context is initialized */
	u8 key_phase:1;				/* Current key phase being used (0 or 1) */

	u64 send_offset;	/* Number of handshake bytes sent by user at this level */
	u64 recv_offset;	/* Number of handshake bytes read by user at this level */
};

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt,
			   u32 version, u8 flag);
int quic_crypto_get_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt);
int quic_crypto_set_cipher(struct quic_crypto *crypto, u32 type, u8 flag);
int quic_crypto_key_update(struct quic_crypto *crypto);

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb);
int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb);

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
