// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <uapi/linux/quic.h>
#include <crypto/skcipher.h>
#include <net/netns/hash.h>
#include <net/udp_tunnel.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include "connection.h"
#include "hashtable.h"
#include <net/tls.h>
#include "protocol.h"
#include "crypto.h"
#include "number.h"

struct tls_vec {
	u8 *data;
	u32  len;
};

static struct tls_vec *tls_vec(struct tls_vec *vec, u8 *data, u32 len)
{
	vec->data = data;
	vec->len  = len;
	return vec;
}

static int tls_crypto_hkdf_extract(struct crypto_shash *tfm, struct tls_vec *srt,
				   struct tls_vec *hash, struct tls_vec *key)
{
	int err;

	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;

	return crypto_shash_tfm_digest(tfm, hash->data, hash->len, key->data);
}

static int tls_crypto_hkdf_expand(struct crypto_shash *tfm, struct tls_vec *srt,
				  struct tls_vec *label, struct tls_vec *hash, struct tls_vec *key)
{
	u8 cnt = 1, info[256], *p = info, *prev = NULL;
	u8 LABEL[] = "tls13 ", tmp[48];
	SHASH_DESC_ON_STACK(desc, tfm);
	int err, i, infolen;

	*p++ = (u8)(key->len / 256);
	*p++ = (u8)(key->len % 256);
	*p++ = (u8)(sizeof(LABEL) - 1 + label->len);
	memcpy(p, LABEL, sizeof(LABEL) - 1);
	p += sizeof(LABEL) - 1;
	memcpy(p, label->data, label->len);
	p += label->len;
	if (hash) {
		*p++ = hash->len;
		memcpy(p, hash->data, hash->len);
		p += hash->len;
	} else {
		*p++ = 0;
	}
	infolen = (int)(p - info);

	desc->tfm = tfm;
	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;
	for (i = 0; i < key->len; i += srt->len) {
		err = crypto_shash_init(desc);
		if (err)
			goto out;
		if (prev) {
			err = crypto_shash_update(desc, prev, srt->len);
			if (err)
				goto out;
		}
		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;
		BUILD_BUG_ON(sizeof(cnt) != 1);
		if (key->len - i < srt->len) {
			err = crypto_shash_finup(desc, &cnt, 1, tmp);
			if (err)
				goto out;
			memcpy(&key->data[i], tmp, key->len - i);
			memzero_explicit(tmp, sizeof(tmp));
		} else {
			err = crypto_shash_finup(desc, &cnt, 1, &key->data[i]);
			if (err)
				goto out;
		}
		cnt++;
		prev = &key->data[i];
	}
out:
	shash_desc_zero(desc);
	return err;
}

#define KEY_LABEL_V1		"quic key"
#define IV_LABEL_V1		"quic iv"
#define HP_KEY_LABEL_V1		"quic hp"

#define KEY_LABEL_V2		"quicv2 key"
#define IV_LABEL_V2		"quicv2 iv"
#define HP_KEY_LABEL_V2		"quicv2 hp"

static int quic_crypto_keys_derive(struct crypto_shash *tfm, struct tls_vec *s, struct tls_vec *k,
				   struct tls_vec *i, struct tls_vec *hp_k, u32 version)
{
	struct tls_vec hp_k_l = {HP_KEY_LABEL_V1, 7}, k_l = {KEY_LABEL_V1, 8};
	struct tls_vec i_l = {IV_LABEL_V1, 7};
	struct tls_vec z = {NULL, 0};
	int err;

	if (version == QUIC_VERSION_V2) {
		tls_vec(&hp_k_l, HP_KEY_LABEL_V2, 9);
		tls_vec(&k_l, KEY_LABEL_V2, 10);
		tls_vec(&i_l, IV_LABEL_V2, 9);
	}

	err = tls_crypto_hkdf_expand(tfm, s, &k_l, &z, k);
	if (err)
		return err;
	err = tls_crypto_hkdf_expand(tfm, s, &i_l, &z, i);
	if (err)
		return err;
	/* Don't change hp key for key update */
	if (!hp_k)
		return 0;

	return tls_crypto_hkdf_expand(tfm, s, &hp_k_l, &z, hp_k);
}

static int quic_crypto_tx_keys_derive_and_install(struct quic_crypto *crypto)
{
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k = {}, *hp;
	u32 keylen, ivlen = QUIC_IV_LEN;
	int err;

	keylen = crypto->cipher->keylen;
	tls_vec(&srt, crypto->tx_secret, crypto->cipher->secretlen);
	tls_vec(&k, crypto->tx_key[crypto->key_phase], keylen);
	tls_vec(&iv, crypto->tx_iv[crypto->key_phase], ivlen);
	hp = crypto->key_pending ? NULL : tls_vec(&hp_k, crypto->tx_hp_key, keylen);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp, crypto->version);
	if (err)
		return err;
	pr_debug("[QUIC] tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

static int quic_crypto_rx_keys_derive_and_install(struct quic_crypto *crypto)
{
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k = {}, *hp;
	u32 keylen, ivlen = QUIC_IV_LEN;
	int err;

	keylen = crypto->cipher->keylen;
	tls_vec(&srt, crypto->rx_secret, crypto->cipher->secretlen);
	tls_vec(&k, crypto->rx_key[crypto->key_phase], keylen);
	tls_vec(&iv, crypto->rx_iv[crypto->key_phase], ivlen);
	hp = crypto->key_pending ? NULL : tls_vec(&hp_k, crypto->rx_hp_key, keylen);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp, crypto->version);
	if (err)
		return err;
	pr_debug("[QUIC] rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

static void *quic_crypto_skcipher_mem_alloc(struct crypto_skcipher *tfm, u32 mask_size,
					    u8 **iv, struct skcipher_request **req)
{
	unsigned int iv_size, req_size;
	unsigned int len;
	u8 *mem;

	iv_size = crypto_skcipher_ivsize(tfm);
	req_size = sizeof(**req) + crypto_skcipher_reqsize(tfm);

	len = mask_size;
	len += iv_size;
	len += crypto_skcipher_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;

	mem = kzalloc(len, GFP_ATOMIC);
	if (!mem)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(mem + mask_size, crypto_skcipher_alignmask(tfm) + 1);
	*req = (struct skcipher_request *)PTR_ALIGN(*iv + iv_size,
			crypto_tfm_ctx_alignment());

	return (void *)mem;
}

static int quic_crypto_header_encrypt(struct crypto_skcipher *tfm, struct sk_buff *skb,
				      struct quic_packet_info *pki, u8 *tx_hp_key, u32 keylen,
				      bool chacha)
{
	struct skcipher_request *req;
	u8 *mask, *iv, *p;
	struct scatterlist sg;
	int err, i;

	err = crypto_skcipher_setkey(tfm, tx_hp_key, keylen);
	if (err)
		return err;
	mask = quic_crypto_skcipher_mem_alloc(tfm, 16, &iv, &req);
	if (!mask)
		return -ENOMEM;

	memcpy((chacha ? iv : mask), skb->data + pki->number_offset + 4, 16);
	sg_init_one(&sg, mask, 16);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, 16, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = skb->data;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	p = skb->data + pki->number_offset;
	for (i = 1; i <= pki->number_len; i++)
		*p++ ^= mask[i];
err:
	kfree(mask);
	return err;
}

static void *quic_crypto_aead_mem_alloc(struct crypto_aead *tfm, u32 ctx_size,
					u8 **iv, struct aead_request **req,
					struct scatterlist **sg, int nsg)
{
	unsigned int iv_size, req_size;
	unsigned int len;
	u8 *mem;

	iv_size = crypto_aead_ivsize(tfm);
	req_size = sizeof(**req) + crypto_aead_reqsize(tfm);

	len = ctx_size;
	len += iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += nsg * sizeof(**sg);

	mem = kzalloc(len, GFP_ATOMIC);
	if (!mem)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(mem + ctx_size, crypto_aead_alignmask(tfm) + 1);
	*req = (struct aead_request *)PTR_ALIGN(*iv + iv_size,
			crypto_tfm_ctx_alignment());
	*sg = (struct scatterlist *)PTR_ALIGN((u8 *)*req + req_size,
			__alignof__(struct scatterlist));

	return (void *)mem;
}

static int quic_crypto_payload_encrypt(struct crypto_aead *tfm, struct sk_buff *skb,
				       struct quic_packet_info *pki, u8 *tx_key, u32 keylen,
				       u8 *tx_iv, u32 ivlen, bool ccm)
{
	struct quichdr *hdr = quic_hdr(skb);
	u8 *iv, i, nonce[QUIC_IV_LEN];
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, err, hlen, len;
	struct scatterlist *sg;
	void *ctx;
	__be64 n;

	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, tx_key, keylen);
	if (err)
		return err;

	len = skb->len;
	nsg = skb_cow_data(skb, QUIC_TAG_LEN, &trailer);
	if (nsg < 0)
		return nsg;
	pskb_put(skb, trailer, QUIC_TAG_LEN);
	hdr->key = pki->key_phase;

	ctx = quic_crypto_aead_mem_alloc(tfm, 0, &iv, &req, &sg, nsg);
	if (!ctx)
		return -ENOMEM;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, skb->len);
	if (err < 0)
		goto err;

	hlen = pki->number_offset + pki->number_len;
	memcpy(nonce, tx_iv, ivlen);
	n = cpu_to_be64(pki->number);
	for (i = 0; i < 8; i++)
		nonce[ivlen - 8 + i] ^= ((u8 *)&n)[i];

	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[ccm], nonce, ivlen);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	err = crypto_aead_encrypt(req);

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_payload_decrypt(struct crypto_aead *tfm, struct sk_buff *skb,
				       struct quic_packet_info *pki, u8 *rx_key, u32 keylen,
				       u8 *rx_iv, u32 ivlen, bool ccm)
{
	u8 *iv, i, nonce[QUIC_IV_LEN];
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, hlen, len, err;
	struct scatterlist *sg;
	void *ctx;
	__be64 n;

	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, rx_key, keylen);
	if (err)
		return err;

	len = pki->length + pki->number_offset;
	hlen = pki->number_offset + pki->number_len;
	if (len - hlen < QUIC_TAG_LEN)
		return -EINVAL;
	nsg = skb_cow_data(skb, 0, &trailer);
	if (nsg < 0)
		return nsg;
	ctx = quic_crypto_aead_mem_alloc(tfm, 0, &iv, &req, &sg, nsg);
	if (!ctx)
		return -ENOMEM;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, len);
	if (err < 0)
		goto err;

	memcpy(nonce, rx_iv, ivlen);
	n = cpu_to_be64(pki->number);
	for (i = 0; i < 8; i++)
		nonce[ivlen - 8 + i] ^= ((u8 *)&n)[i];

	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[ccm], nonce, ivlen);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	err = crypto_aead_decrypt(req);

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_header_decrypt(struct crypto_skcipher *tfm, struct sk_buff *skb,
				      struct quic_packet_info *pki, u8 *rx_hp_key, u32 keylen,
				      bool chacha)
{
	struct quichdr *hdr = quic_hdr(skb);
	struct skcipher_request *req;
	u8 *mask, *iv, *p;
	struct scatterlist sg;
	int err, i;

	err = crypto_skcipher_setkey(tfm, rx_hp_key, keylen);
	if (err)
		return err;
	mask = quic_crypto_skcipher_mem_alloc(tfm, 16, &iv, &req);
	if (!mask)
		return -ENOMEM;

	if (pki->length + pki->number_offset < pki->number_offset + 4 + 16) {
		err = -EINVAL;
		goto err;
	}
	p = (u8 *)hdr + pki->number_offset;
	memcpy((chacha ? iv : mask), p + 4, 16);
	sg_init_one(&sg, mask, 16);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, 16, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	pki->number_len = (*p & 0x03) + 1;
	if (pki->length + pki->number_offset < pki->number_offset + pki->number_len) {
		err = -EINVAL;
		goto err;
	}
	p += pki->number_offset;
	for (i = 0; i < pki->number_len; ++i)
		*(p + i) = *((u8 *)hdr + pki->number_offset + i) ^ mask[i + 1];

	pki->number = quic_get_int(&p, pki->number_len);
	pki->number = quic_get_num(pki->number_max, pki->number, pki->number_len);
	pki->key_phase = hdr->key;

err:
	kfree(mask);
	return err;
}

#define QUIC_CIPHER_MIN TLS_CIPHER_AES_GCM_128
#define QUIC_CIPHER_MAX TLS_CIPHER_CHACHA20_POLY1305

#define TLS_CIPHER_AES_GCM_128_SECRET_SIZE		32
#define TLS_CIPHER_AES_GCM_256_SECRET_SIZE		48
#define TLS_CIPHER_AES_CCM_128_SECRET_SIZE		32
#define TLS_CIPHER_CHACHA20_POLY1305_SECRET_SIZE	32

#define CIPHER_DESC(type,aead_name,skc_name,sha_name) [type - QUIC_CIPHER_MIN] = { \
	.secretlen = type ## _SECRET_SIZE, \
	.keylen = type ## _KEY_SIZE, \
	.aead = aead_name, \
	.skc = skc_name, \
	.shash = sha_name, \
}

static struct quic_cipher ciphers[QUIC_CIPHER_MAX + 1 - QUIC_CIPHER_MIN] = {
	CIPHER_DESC(TLS_CIPHER_AES_GCM_128, "gcm(aes)", "ecb(aes)", "hmac(sha256)"),
	CIPHER_DESC(TLS_CIPHER_AES_GCM_256, "gcm(aes)", "ecb(aes)", "hmac(sha384)"),
	CIPHER_DESC(TLS_CIPHER_AES_CCM_128, "ccm(aes)", "ecb(aes)", "hmac(sha256)"),
	CIPHER_DESC(TLS_CIPHER_CHACHA20_POLY1305,
			  "rfc7539(chacha20,poly1305)", "chacha20", "hmac(sha256)"),
};

static bool quic_crypto_is_cipher_ccm(struct quic_crypto *crypto)
{
	return crypto->cipher_type == TLS_CIPHER_AES_CCM_128;
}

static bool quic_crypto_is_cipher_chacha(struct quic_crypto *crypto)
{
	return crypto->cipher_type == TLS_CIPHER_CHACHA20_POLY1305;
}

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki)
{
	u32 keylen, ivlen = QUIC_IV_LEN;
	u8 *key, *iv, *hp_key;
	int err;

	pki->key_phase = crypto->key_phase;
	key = crypto->tx_key[crypto->key_phase];
	iv = crypto->tx_iv[crypto->key_phase];
	hp_key = crypto->tx_hp_key;

	if (crypto->key_pending && !crypto->key_update_send_ts)
		crypto->key_update_send_ts = jiffies_to_usecs(jiffies);

	keylen = crypto->cipher->keylen;
	err = quic_crypto_payload_encrypt(crypto->aead_tfm, skb, pki, key, keylen, iv, ivlen,
					  quic_crypto_is_cipher_ccm(crypto));
	if (err)
		return err;

	return quic_crypto_header_encrypt(crypto->skc_tfm, skb, pki, hp_key, keylen,
					  quic_crypto_is_cipher_chacha(crypto));
}

int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki)
{
	u32 keylen, ivlen = QUIC_IV_LEN;
	u8 *key, *iv, *hp_key;
	int err;

	hp_key = crypto->rx_hp_key;
	keylen = crypto->cipher->keylen;
	err = quic_crypto_header_decrypt(crypto->skc_tfm, skb, pki, hp_key, keylen,
					 quic_crypto_is_cipher_chacha(crypto));
	if (err) {
		pr_warn("[QUIC] hd decrypt err %d\n", err);
		return err;
	}

	if (pki->key_phase != crypto->key_phase && !crypto->key_pending) {
		err = quic_crypto_key_update(crypto, NULL, 0);
		if (err)
			return err;
	}

	key = crypto->rx_key[pki->key_phase];
	iv = crypto->rx_iv[pki->key_phase];

	err = quic_crypto_payload_decrypt(crypto->aead_tfm, skb, pki, key, keylen, iv, ivlen,
					  quic_crypto_is_cipher_ccm(crypto));
	if (err)
		return err;

	/* An endpoint MUST retain old keys until it has successfully unprotected a
	 * packet sent using the new keys. An endpoint SHOULD retain old keys for
	 * some time after unprotecting a packet sent using the new keys.
	 */
	if (pki->key_phase == crypto->key_phase &&
	    crypto->key_pending && crypto->key_update_send_ts &&
	    jiffies_to_usecs(jiffies) - crypto->key_update_send_ts >= crypto->key_update_ts) {
		pki->key_update = 1;
		crypto->key_pending = 0;
		crypto->key_update_send_ts = 0;
	}
	return 0;
}

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt, u32 version)
{
	struct quic_cipher *cipher;
	void *tfm;
	int err;

	if (srt->type < QUIC_CIPHER_MIN || srt->type > QUIC_CIPHER_MAX)
		return -EINVAL;

	cipher = &ciphers[srt->type - QUIC_CIPHER_MIN];
	if (!crypto->cipher) {
		crypto->version = version;
		tfm = crypto_alloc_shash(cipher->shash, 0, 0);
		if (IS_ERR(tfm))
			return PTR_ERR(tfm);
		crypto->secret_tfm = tfm;

		tfm = crypto_alloc_skcipher(cipher->skc, 0, 0);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			goto err;
		}
		crypto->skc_tfm = tfm;

		tfm = crypto_alloc_aead(cipher->aead, 0, 0);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			goto err;
		}
		crypto->aead_tfm = tfm;
		crypto->cipher = cipher;
		crypto->cipher_type = srt->type;
	}

	if (!srt->send) {
		memcpy(crypto->rx_secret, srt->secret, cipher->secretlen);
		err = quic_crypto_rx_keys_derive_and_install(crypto);
		if (err)
			goto err;
		crypto->recv_ready = 1;
		return 0;
	}

	memcpy(crypto->tx_secret, srt->secret, cipher->secretlen);
	err = quic_crypto_tx_keys_derive_and_install(crypto);
	if (err)
		goto err;
	crypto->send_ready = 1;
	return 0;
err:
	quic_crypto_destroy(crypto);
	return err;
}

int quic_crypto_get_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt)
{
	u8 *secret;

	if (!crypto->cipher)
		return -EINVAL;
	srt->type = crypto->cipher_type;
	secret = srt->send ? crypto->tx_secret : crypto->rx_secret;
	memcpy(srt->secret, secret, crypto->cipher->secretlen);
	return 0;
}

#define LABEL_V1	"quic ku"
#define LABEL_V2	"quicv2 ku"

int quic_crypto_key_update(struct quic_crypto *crypto, u8 *key, unsigned int len)
{
	u8 tx_secret[QUIC_SECRET_LEN], rx_secret[QUIC_SECRET_LEN];
	struct tls_vec l = {LABEL_V1, 7}, z = {NULL, 0}, k, srt;
	int err, secret_len;

	if (crypto->key_pending || !crypto->recv_ready)
		return -EINVAL;

	secret_len = crypto->cipher->secretlen;
	if (crypto->version == QUIC_VERSION_V2)
		tls_vec(&l, LABEL_V2, 9);

	crypto->key_pending = 1;
	memcpy(tx_secret, crypto->tx_secret, secret_len);
	memcpy(rx_secret, crypto->rx_secret, secret_len);
	crypto->key_phase = !crypto->key_phase;

	tls_vec(&srt, tx_secret, secret_len);
	tls_vec(&k, crypto->tx_secret, secret_len);
	err = tls_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &z, &k);
	if (err)
		goto err;
	err = quic_crypto_tx_keys_derive_and_install(crypto);
	if (err)
		goto err;

	tls_vec(&srt, rx_secret, secret_len);
	tls_vec(&k, crypto->rx_secret, secret_len);
	err = tls_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &z, &k);
	if (err)
		goto err;
	err = quic_crypto_rx_keys_derive_and_install(crypto);
	if (err)
		goto err;
	return 0;
err:
	crypto->key_pending = 0;
	memcpy(crypto->tx_secret, tx_secret, secret_len);
	memcpy(crypto->rx_secret, rx_secret, secret_len);
	crypto->key_phase = !crypto->key_phase;
	return err;
}

void quic_crypto_set_key_update_ts(struct quic_crypto *crypto, u32 key_update_ts)
{
	crypto->key_update_ts = key_update_ts;
}

void quic_crypto_destroy(struct quic_crypto *crypto)
{
	crypto_free_shash(crypto->secret_tfm);
	crypto_free_skcipher(crypto->skc_tfm);
	crypto_free_aead(crypto->aead_tfm);

	crypto->cipher = NULL;
	crypto->secret_tfm = NULL;
	crypto->skc_tfm = NULL;
	crypto->aead_tfm = NULL;

	crypto->send_ready = 0;
	crypto->recv_ready = 0;
}

#define QUIC_INITIAL_SALT_V1    \
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"
#define QUIC_INITIAL_SALT_V2    \
	"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9"

int quic_crypto_initial_keys_install(struct quic_crypto *crypto, struct quic_connection_id *conn_id,
				     u32 version, bool is_serv)
{
	struct tls_vec salt, s, k, l, dcid, z = {NULL, 0};
	struct quic_crypto_secret srt = {};
	struct crypto_shash *tfm;
	char *tl, *rl, *sal;
	u8 secret[32];
	int err;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	if (is_serv) {
		rl = "client in";
		tl = "server in";
	} else {
		tl = "client in";
		rl = "server in";
	}
	crypto->version = version;
	sal = QUIC_INITIAL_SALT_V1;
	if (version == QUIC_VERSION_V2)
		sal = QUIC_INITIAL_SALT_V2;
	tls_vec(&salt, sal, 20);
	tls_vec(&dcid, conn_id->data, conn_id->len);
	tls_vec(&s, secret, 32);
	err = tls_crypto_hkdf_extract(tfm, &salt, &dcid, &s);
	if (err)
		goto out;

	crypto->cipher = NULL;
	tls_vec(&l, tl, 9);
	tls_vec(&k, srt.secret, 32);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 1;
	err = tls_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version);
	if (err)
		goto out;

	tls_vec(&l, rl, 9);
	tls_vec(&k, srt.secret, 32);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 0;
	err = tls_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version);
out:
	crypto_free_shash(tfm);
	return err;
}

#define QUIC_RETRY_KEY_V1 "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"
#define QUIC_RETRY_KEY_V2 "\x8f\xb4\xb0\x1b\x56\xac\x48\xe2\x60\xfb\xcb\xce\xad\x7c\xcc\x92"

#define QUIC_RETRY_NONCE_V1 "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"
#define QUIC_RETRY_NONCE_V2 "\xd8\x69\x69\xbc\x2d\x7c\x6d\x99\x90\xef\xb0\x4a"

int quic_crypto_get_retry_tag(struct sk_buff *skb, struct quic_connection_id *odcid,
			      u32 version, u8 *tag)
{
	u8 *pseudo_retry, *p, *iv, *key;
	struct aead_request *req;
	struct crypto_aead *tfm;
	struct scatterlist *sg;
	int err, plen;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		goto err;
	key = QUIC_RETRY_KEY_V1;
	if (version == QUIC_VERSION_V2)
		key = QUIC_RETRY_KEY_V2;
	err = crypto_aead_setkey(tfm, key, 16);
	if (err)
		goto err;

	pseudo_retry = quic_crypto_aead_mem_alloc(tfm, 128, &iv, &req, &sg, 1);
	if (!pseudo_retry) {
		err = -ENOMEM;
		goto err;
	}

	p = pseudo_retry;
	p = quic_put_int(p, odcid->len, 1);
	p = quic_put_data(p, odcid->data, odcid->len);
	p = quic_put_data(p, skb->data, skb->len - 16);
	plen = p - pseudo_retry;
	sg_init_one(sg, pseudo_retry, plen + 16);

	memcpy(iv, QUIC_RETRY_NONCE_V1, 12);
	if (version == QUIC_VERSION_V2)
		memcpy(iv, QUIC_RETRY_NONCE_V2, 12);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, plen);
	aead_request_set_crypt(req, sg, sg, 0, iv);
	err = crypto_aead_encrypt(req);

	memcpy(tag, pseudo_retry + plen, 16);
	kfree(pseudo_retry);
err:
	crypto_free_aead(tfm);
	return  err;
}

int quic_crypto_listen_init(struct quic_crypto *crypto)
{
	struct crypto_shash *tfm;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	crypto->secret_tfm = tfm;
	return 0;
}

int quic_crypto_generate_token(struct quic_crypto *crypto, void *data, char *label,
			       u8 *token, u32 len)
{
	struct tls_vec salt, s, l, k, z = {NULL, 0};
	struct crypto_shash *tfm = crypto->secret_tfm;
	u8 secret[32];
	int err;

	if (!tfm)
		return -EINVAL;

	tls_vec(&salt, data, 16);
	tls_vec(&k, random_data, 16);
	tls_vec(&s, secret, 32);
	err = tls_crypto_hkdf_extract(tfm, &salt, &k, &s);
	if (err)
		goto out;
	tls_vec(&l, label, strlen(label));
	tls_vec(&k, token, len);
	err = tls_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
out:
	return err;
}

int quic_crypto_generate_session_ticket_key(struct quic_crypto *crypto, void *data,
					    u8 *key, u32 len)
{
	return quic_crypto_generate_token(crypto, data, "session_ticket", key, len);
}
