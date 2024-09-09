/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <linux/crypto.h>

struct quic_crypto_cb {
	union {
		void (*crypto_done)(struct sk_buff *skb, int err);
		struct sk_buff *last;
	};
	s64 number_max;
	s64 number;
	u16 errcode;
	u16 length;

	u16 udph_offset;
	u8 number_offset;
	u8 number_len;
	u8 level;

	u8 key_update:1;
	u8 key_phase:1;
	u8 path_alt:2;
	u8 backlog:1;
	u8 resume:1;
	u8 ecn:2;
};

#define QUIC_CRYPTO_CB(__skb)      ((struct quic_crypto_cb *)&((__skb)->cb[0]))

#define QUIC_TAG_LEN	16
#define QUIC_IV_LEN	12
#define QUIC_SECRET_LEN	48

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
	u64 send_offset;
	u64 recv_offset;
	u32 version;

	u8 key_pending:1;
	u8 send_ready:1;
	u8 recv_ready:1;
	u8 key_phase:1;
};

static inline u32 quic_crypto_cipher_type(struct quic_crypto *crypto)
{
	return crypto->cipher_type;
}

static inline void quic_crypto_set_cipher_type(struct quic_crypto *crypto, u32 type)
{
	crypto->cipher_type = type;
}

static inline u64 quic_crypto_recv_offset(struct quic_crypto *crypto)
{
	return crypto->recv_offset;
}

static inline void quic_crypto_inc_recv_offset(struct quic_crypto *crypto, u64 offset)
{
	crypto->recv_offset += offset;
}

static inline u64 quic_crypto_send_offset(struct quic_crypto *crypto)
{
	return crypto->send_offset;
}

static inline void quic_crypto_inc_send_offset(struct quic_crypto *crypto, u64 offset)
{
	crypto->send_offset += offset;
}

static inline u8 quic_crypto_recv_ready(struct quic_crypto *crypto)
{
	return crypto->recv_ready;
}

static inline u8 quic_crypto_send_ready(struct quic_crypto *crypto)
{
	return crypto->send_ready;
}

static inline void quic_crypto_set_key_pending(struct quic_crypto *crypto, u8 pending)
{
	crypto->key_pending = pending;
}

static inline void quic_crypto_set_key_update_send_time(struct quic_crypto *crypto, u32 send_time)
{
	crypto->key_update_send_time = send_time;
}

static inline void quic_crypto_set_key_update_time(struct quic_crypto *crypto, u32 key_update_time)
{
	crypto->key_update_time = key_update_time;
}

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt,
			   u32 version, u8 flag);
int quic_crypto_get_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt);
int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb);
int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb);
int quic_crypto_key_update(struct quic_crypto *crypto);
void quic_crypto_destroy(struct quic_crypto *crypto);

int quic_crypto_initial_keys_install(struct quic_crypto *crypto, struct quic_conn_id *conn_id,
				     u32 version, bool is_serv);
int quic_crypto_generate_session_ticket_key(struct quic_crypto *crypto, void *data,
					    u32 len, u8 *key, u32 key_len);
int quic_crypto_generate_stateless_reset_token(struct quic_crypto *crypto, void *data,
					       u32 len, u8 *key, u32 key_len);

int quic_crypto_generate_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			       struct quic_conn_id *conn_id, u8 *token, u32 *tokenlen);
int quic_crypto_get_retry_tag(struct quic_crypto *crypto, struct sk_buff *skb,
			      struct quic_conn_id *odcid, u32 version, u8 *tag);
int quic_crypto_verify_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			     struct quic_conn_id *conn_id, u8 *token, u32 len);
