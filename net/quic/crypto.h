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

struct quic_packet_info {
	s64 number;
	s64 number_max;
	u32 number_len;
	u32 number_offset;
	u64 length;
	u8 key_phase:1;
	u8 key_update:1;
	u8 ack_eliciting:1;
	u8 ack_immediate:1;
	u8 non_probing:1;
	u8 resume:1;
	void *crypto_done;
};

#define QUIC_KEY_LEN	32
#define QUIC_TAG_LEN	16
#define QUIC_IV_LEN	12
#define QUIC_SECRET_LEN	48

struct quic_cipher {
	u32 secretlen;
	u32 keylen;
	char *aead;
	char *skc;
	char *shash;
};

struct quic_crypto {
	struct crypto_shash *secret_tfm;
	u8 tx_secret[QUIC_SECRET_LEN];
	u8 rx_secret[QUIC_SECRET_LEN];

	struct crypto_aead *aead_tfm;
	struct quic_cipher *cipher;
	u32 cipher_type;
	u8 tx_key[2][QUIC_KEY_LEN];
	u8 tx_iv[2][QUIC_IV_LEN];
	u8 rx_key[2][QUIC_KEY_LEN];
	u8 rx_iv[2][QUIC_IV_LEN];

	struct crypto_skcipher *skc_tfm;
	u8 tx_hp_key[QUIC_KEY_LEN];
	u8 rx_hp_key[QUIC_KEY_LEN];
	u32 send_offset;
	u32 recv_offset;
	u32 version;

	u32 key_update_ts;
	u32 key_update_send_ts;

	u8 key_phase:1;
	u8 key_pending:1;
	u8 send_ready:1;
	u8 recv_ready:1;
};

int quic_crypto_initial_keys_install(struct quic_crypto *crypto, struct quic_connection_id *conn_id,
				     u32 version, bool is_serv);
int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki);
int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki);
int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt, u32 version);
int quic_crypto_get_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt);
void quic_crypto_destroy(struct quic_crypto *crypto);
int quic_crypto_key_update(struct quic_crypto *crypto);
void quic_crypto_set_key_update_ts(struct quic_crypto *crypto, u32 key_update_ts);
int quic_crypto_get_retry_tag(struct quic_crypto *crypto, struct sk_buff *skb,
			      struct quic_connection_id *odcid, u32 version, u8 *tag);
int quic_crypto_set_tfms(struct quic_crypto *crypto, u32 type);
int quic_crypto_generate_token(struct quic_crypto *crypto, void *data, char *label,
			       u8 *token, u32 len);
int quic_crypto_generate_session_ticket_key(struct quic_crypto *crypto, void *data,
					    u8 *key, u32 len);
