/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_packet_info {
	s64 number;
	s64 number_max;
	u32 number_len;
	u32 number_offset;
	u8 key_phase:1;
	u8 key_update:1;
	u8 ack_eliciting:1;
	u8 ack_immediate:1;
	u8 non_probing:1;
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

	u32 key_update_ts;
	u32 key_update_send_ts;

	u8 key_phase:1,
	   key_pending:1;
};

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki);
int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki);
int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *send,
			   struct quic_crypto_secret *recv);
int quic_crypto_get_secret(struct quic_crypto *crypto, struct quic_crypto_secret *send,
			   struct quic_crypto_secret *recv);
int quic_crypto_set_cipher(struct quic_crypto *crypto, u32 *cipher, u32 len);
int quic_crypto_get_cipher(struct quic_crypto *crypto, int len,
			   char __user *optval, int __user *optlen);
void quic_crypto_destroy(struct quic_crypto *crypto);
int quic_crypto_key_update(struct quic_crypto *crypto, u8 *key, unsigned int len);
void quic_crypto_set_key_update_ts(struct quic_crypto *crypto, u32 key_update_ts);
