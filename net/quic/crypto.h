/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

struct quic_packet_info {
	u32 number;
	u32 number_len;
	u32 number_offset;
};

#define QUIC_KEY_LEN	16
#define QUIC_TAG_LEN	16
#define QUIC_IV_LEN	12
#define QUIC_SECRET_LEN	32

struct quic_crypto {
	struct crypto_shash *secret_tfm;
	u8 tx_secret[QUIC_SECRET_LEN];
	u8 rx_secret[QUIC_SECRET_LEN];

	struct crypto_aead *aead_tfm;
	u8 tx_key[2][QUIC_KEY_LEN];
	u8 tx_iv[2][QUIC_IV_LEN];
	u8 rx_key[2][QUIC_KEY_LEN];
	u8 rx_iv[2][QUIC_IV_LEN];

	struct crypto_skcipher *skc_tfm;
	u8 tx_hp_key[QUIC_KEY_LEN];
	u8 rx_hp_key[QUIC_KEY_LEN];

	u8 key_phase:1,
	   key_pending:1;
};

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki);
int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki);
int quic_crypto_set_secret(struct quic_crypto *crypto, void *key, u8 len, bool send);
int quic_crypto_get_secret(struct quic_crypto *crypto, int len, char __user *optval,
			   int __user *optlen, bool send);
void quic_crypto_destroy(struct quic_crypto *crypto);
