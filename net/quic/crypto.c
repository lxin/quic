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
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include "hashtable.h"
#include <net/tls.h>
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

static int quic_crypto_keys_derive(struct crypto_shash *tfm, struct tls_vec *s, struct tls_vec *k,
				   struct tls_vec *i, struct tls_vec *hp_k)
{
	struct tls_vec hp_k_l = {"quic hp", 7}, k_l = {"quic key", 8}, i_l = {"quic iv", 7};
	struct tls_vec z = {NULL, 0};
	int err;

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
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp);
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
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp);
	if (err)
		return err;
	pr_debug("[QUIC] rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

static int quic_crypto_header_encrypt(struct crypto_skcipher *tfm, struct sk_buff *skb,
				      struct quic_packet_info *pki, u8 *tx_hp_key, u32 keylen,
				      bool chacha)
{
	struct skcipher_request *req;
	u8 mask[2][16] = {}, *p;
	struct scatterlist sg;
	int err, i;

	err = crypto_skcipher_setkey(tfm, tx_hp_key, keylen);
	if (err)
		return err;
	req = skcipher_request_alloc(tfm, 0);
	if (!req)
		return -ENOMEM;

	memcpy(mask[chacha], skb->data + pki->number_offset + 4, 16);
	sg_init_one(&sg, mask[0], 16);
	skcipher_request_set_crypt(req, &sg, &sg, 16, mask[1]);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = skb->data;
	*p = (u8)(*p ^ (mask[0][0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	p = skb->data + pki->number_offset;
	for (i = 1; i <= pki->number_len; i++)
		*p++ ^= mask[0][i];
err:
	skcipher_request_free(req);
	return err;
}

static void *quic_crypto_aead_mem_alloc(struct crypto_aead *tfm, u8 **iv,
					struct aead_request **req,
					struct scatterlist **sg, int nsg)
{
	unsigned int iv_size, req_size;
	unsigned int len;
	u8 *mem;

	iv_size = crypto_aead_ivsize(tfm);
	req_size = sizeof(**req) + crypto_aead_reqsize(tfm);

	len = iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += nsg * sizeof(**sg);

	mem = kzalloc(len, GFP_ATOMIC);
	if (!mem)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(mem, crypto_aead_alignmask(tfm) + 1);
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
		goto err;
	pskb_put(skb, trailer, QUIC_TAG_LEN);
	hdr->key = pki->key_phase;

	ctx = quic_crypto_aead_mem_alloc(tfm, &iv, &req, &sg, nsg);
	if (!ctx)
		return err;

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
		return err;
	ctx = quic_crypto_aead_mem_alloc(tfm, &iv, &req, &sg, nsg);
	if (!ctx)
		return err;

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
	u8 mask[2][16] = {}, *p;
	struct scatterlist sg;
	int err, i;

	err = crypto_skcipher_setkey(tfm, rx_hp_key, keylen);
	if (err)
		return err;
	req = skcipher_request_alloc(tfm, 0);
	if (!req)
		return -ENOMEM;

	if (pki->length + pki->number_offset < pki->number_offset + 4 + 16) {
		err = -EINVAL;
		goto err;
	}
	p = (u8 *)hdr + pki->number_offset;
	memcpy(mask[chacha], p + 4, 16);
	sg_init_one(&sg, mask[0], 16);
	skcipher_request_set_crypt(req, &sg, &sg, 16, mask[1]);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (mask[0][0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	pki->number_len = (*p & 0x03) + 1;
	if (pki->length + pki->number_offset < pki->number_offset + pki->number_len) {
		err = -EINVAL;
		goto err;
	}
	p += pki->number_offset;
	for (i = 0; i < pki->number_len; ++i)
		*(p + i) = *((u8 *)hdr + pki->number_offset + i) ^ mask[0][i + 1];

	pki->number = quic_get_int(&p, pki->number_len);
	pki->number = quic_get_num(pki->number_max, pki->number, pki->number_len);
	pki->key_phase = hdr->key;

err:
	skcipher_request_free(req);
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

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt)
{
	struct quic_cipher *cipher;
	void *tfm;
	int err;

	if (srt->type < QUIC_CIPHER_MIN || srt->type > QUIC_CIPHER_MAX)
		return -EINVAL;

	cipher = &ciphers[srt->type - QUIC_CIPHER_MIN];
	if (!srt->send) {
		if (!crypto->cipher)
			return -EINVAL;
		memcpy(crypto->rx_secret, srt->secret, cipher->secretlen);
		err = quic_crypto_rx_keys_derive_and_install(crypto);
		if (err)
			goto err;
		return 0;
	}

	if (crypto->cipher)
		return -EINVAL;

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

	memcpy(crypto->tx_secret, srt->secret, cipher->secretlen);
	err = quic_crypto_tx_keys_derive_and_install(crypto);
	if (err)
		goto err;
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

int quic_crypto_key_update(struct quic_crypto *crypto, u8 *key, unsigned int len)
{
	u8 tx_secret[QUIC_SECRET_LEN], rx_secret[QUIC_SECRET_LEN];
	struct tls_vec l = {"quic ku", 7}, z = {NULL, 0}, k, srt;
	int err, secret_len = crypto->cipher->secretlen;

	if (crypto->key_pending)
		return -EINVAL;

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

int quic_crypto_set_cipher(struct quic_crypto *crypto, u32 *cipher, u32 len)
{
	if (len < sizeof(*cipher))
		return -EINVAL;

	if (*cipher < QUIC_CIPHER_MIN || *cipher > QUIC_CIPHER_MAX)
		return -EINVAL;

	crypto->cipher_type = *cipher;
	return 0;
}

int quic_crypto_get_cipher(struct quic_crypto *crypto, int len,
			   char __user *optval, int __user *optlen)
{
	if (len < sizeof(crypto->cipher_type))
		return -EINVAL;
	len = sizeof(crypto->cipher_type);
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &crypto->cipher_type, len))
		return -EFAULT;
	return 0;
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
}

#define QUIC_INITIAL_SALT_V1    \
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"

int quic_crypto_initial_keys_install(struct quic_crypto *crypto,
				     struct quic_connection_id *conn_id, bool is_serv)
{
	struct tls_vec salt, s, k, l, dcid, z = {NULL, 0};
	struct quic_crypto_secret srt = {};
	struct crypto_shash *tfm;
	u8 secret[32];
	char *tl, *rl;
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
	tls_vec(&salt, QUIC_INITIAL_SALT_V1, sizeof(QUIC_INITIAL_SALT_V1) - 1);
	tls_vec(&dcid, conn_id->data, conn_id->len);
	tls_vec(&s, secret, 32);
	err = tls_crypto_hkdf_extract(tfm, &salt, &dcid, &s);
	if (err)
		goto out;

	tls_vec(&l, tl, 9);
	tls_vec(&k, srt.secret, 32);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 1;
	err = tls_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt);
	if (err)
		goto out;

	tls_vec(&l, rl, 9);
	tls_vec(&k, srt.secret, 32);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 0;
	err = tls_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt);
out:
	crypto_free_shash(tfm);
	return err;
}
