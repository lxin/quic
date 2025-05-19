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

#include <crypto/skcipher.h>
#include <linux/skbuff.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/quic.h>
#include <net/tls.h>

#include "common.h"
#include "crypto.h"

#define QUIC_RANDOM_DATA_LEN	32

static u8 quic_random_data[QUIC_RANDOM_DATA_LEN] __read_mostly;

static int quic_crypto_hkdf_extract(struct crypto_shash *tfm, struct quic_data *srt,
				    struct quic_data *hash, struct quic_data *key)
{
	int err;

	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;

	return crypto_shash_tfm_digest(tfm, hash->data, hash->len, key->data);
}

#define QUIC_MAX_INFO_LEN	256

static int quic_crypto_hkdf_expand(struct crypto_shash *tfm, struct quic_data *srt,
				   struct quic_data *label, struct quic_data *hash,
				   struct quic_data *key)
{
	u8 cnt = 1, info[QUIC_MAX_INFO_LEN], *p = info, *prev = NULL;
	u8 LABEL[] = "tls13 ", tmp[QUIC_SECRET_LEN];
	SHASH_DESC_ON_STACK(desc, tfm);
	u32 i, infolen;
	int err;

	*p++ = (u8)(key->len / QUIC_MAX_INFO_LEN);
	*p++ = (u8)(key->len % QUIC_MAX_INFO_LEN);
	*p++ = (u8)(sizeof(LABEL) - 1 + label->len);
	p = quic_put_data(p, LABEL, sizeof(LABEL) - 1);
	p = quic_put_data(p, label->data, label->len);
	if (hash) {
		*p++ = (u8)hash->len;
		p = quic_put_data(p, hash->data, hash->len);
	} else {
		*p++ = 0;
	}
	infolen = (u32)(p - info);

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

static int quic_crypto_keys_derive(struct crypto_shash *tfm, struct quic_data *s,
				   struct quic_data *k, struct quic_data *i,
				   struct quic_data *hp_k, u32 version)
{
	struct quic_data hp_k_l = {HP_KEY_LABEL_V1, strlen(HP_KEY_LABEL_V1)};
	struct quic_data k_l = {KEY_LABEL_V1, strlen(KEY_LABEL_V1)};
	struct quic_data i_l = {IV_LABEL_V1, strlen(IV_LABEL_V1)};
	struct quic_data z = {};
	int err;

	if (version == QUIC_VERSION_V2) {
		quic_data(&hp_k_l, HP_KEY_LABEL_V2, strlen(HP_KEY_LABEL_V2));
		quic_data(&k_l, KEY_LABEL_V2, strlen(KEY_LABEL_V2));
		quic_data(&i_l, IV_LABEL_V2, strlen(IV_LABEL_V2));
	}

	err = quic_crypto_hkdf_expand(tfm, s, &k_l, &z, k);
	if (err)
		return err;
	err = quic_crypto_hkdf_expand(tfm, s, &i_l, &z, i);
	if (err)
		return err;
	/* Don't change hp key for key update */
	if (!hp_k)
		return 0;

	return quic_crypto_hkdf_expand(tfm, s, &hp_k_l, &z, hp_k);
}

static int quic_crypto_tx_keys_derive_and_install(struct quic_crypto *crypto)
{
	struct quic_data srt = {}, k, iv, hp_k = {}, *hp = NULL;
	u8 tx_key[QUIC_KEY_LEN], tx_hp_key[QUIC_KEY_LEN];
	int err, phase = crypto->key_phase;
	u32 keylen, ivlen = QUIC_IV_LEN;

	keylen = crypto->cipher->keylen;
	quic_data(&srt, crypto->tx_secret, crypto->cipher->secretlen);
	quic_data(&k, tx_key, keylen);
	quic_data(&iv, crypto->tx_iv[phase], ivlen);
	if (!crypto->key_pending)
		hp = quic_data(&hp_k, tx_hp_key, keylen);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp, crypto->version);
	if (err)
		return err;
	err = crypto_aead_setauthsize(crypto->tx_tfm[phase], QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(crypto->tx_tfm[phase], tx_key, keylen);
	if (err)
		return err;
	if (hp) {
		err = crypto_skcipher_setkey(crypto->tx_hp_tfm, tx_hp_key, keylen);
		if (err)
			return err;
	}
	pr_debug("%s: k: %16phN, iv: %12phN, hp_k:%16phN\n", __func__, k.data, iv.data, hp_k.data);
	return 0;
}

static int quic_crypto_rx_keys_derive_and_install(struct quic_crypto *crypto)
{
	struct quic_data srt = {}, k, iv, hp_k = {}, *hp = NULL;
	u8 rx_key[QUIC_KEY_LEN], rx_hp_key[QUIC_KEY_LEN];
	int err, phase = crypto->key_phase;
	u32 keylen, ivlen = QUIC_IV_LEN;

	keylen = crypto->cipher->keylen;
	quic_data(&srt, crypto->rx_secret, crypto->cipher->secretlen);
	quic_data(&k, rx_key, keylen);
	quic_data(&iv, crypto->rx_iv[phase], ivlen);
	if (!crypto->key_pending)
		hp = quic_data(&hp_k, rx_hp_key, keylen);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp, crypto->version);
	if (err)
		return err;
	err = crypto_aead_setauthsize(crypto->rx_tfm[phase], QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(crypto->rx_tfm[phase], rx_key, keylen);
	if (err)
		return err;
	if (hp) {
		err = crypto_skcipher_setkey(crypto->rx_hp_tfm, rx_hp_key, keylen);
		if (err)
			return err;
	}
	pr_debug("%s: k: %16phN, iv: %12phN, hp_k:%16phN\n", __func__, k.data, iv.data, hp_k.data);
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

#define QUIC_SAMPLE_LEN		16
#define QUIC_MAX_PN_LEN		4

#define QUIC_HEADER_FORM_BIT	0x80
#define QUIC_LONG_HEADER_MASK	0x0f
#define QUIC_SHORT_HEADER_MASK	0x1f

static int quic_crypto_header_encrypt(struct crypto_skcipher *tfm, struct sk_buff *skb, bool chacha)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 *mask, *iv, *p;
	int err, i;

	mask = quic_crypto_skcipher_mem_alloc(tfm, QUIC_SAMPLE_LEN, &iv, &req);
	if (!mask)
		return -ENOMEM;

	memcpy((chacha ? iv : mask), skb->data + cb->number_offset + QUIC_MAX_PN_LEN,
	       QUIC_SAMPLE_LEN);
	sg_init_one(&sg, mask, QUIC_SAMPLE_LEN);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_SAMPLE_LEN, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = skb->data;
	*p = (u8)(*p ^ (mask[0] & (((*p & QUIC_HEADER_FORM_BIT) == QUIC_HEADER_FORM_BIT) ?
				   QUIC_LONG_HEADER_MASK : QUIC_SHORT_HEADER_MASK)));
	p = skb->data + cb->number_offset;
	for (i = 1; i <= cb->number_len; i++)
		*p++ ^= mask[i];
err:
	kfree(mask);
	return err;
}

static void *quic_crypto_aead_mem_alloc(struct crypto_aead *tfm, u32 ctx_size,
					u8 **iv, struct aead_request **req,
					struct scatterlist **sg, u32 nsg)
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

static void quic_crypto_destruct_skb(struct sk_buff *skb)
{
	kfree(skb_shinfo(skb)->destructor_arg);
	sock_efree(skb);
}

static void quic_crypto_done(void *data, int err)
{
	struct crypto_async_request *base = data;
	struct sk_buff *skb = data;

	if (base->flags == CRYPTO_TFM_REQ_MAY_BACKLOG)
		skb = base->data;

	QUIC_SKB_CB(skb)->crypto_done(skb, err);
}

static int quic_crypto_payload_encrypt(struct crypto_aead *tfm, struct sk_buff *skb,
				       u8 *tx_iv, bool ccm)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quichdr *hdr = quic_hdr(skb);
	u8 *iv, i, nonce[QUIC_IV_LEN];
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	u32 nsg, hlen, len;
	void *ctx;
	__be64 n;
	int err;

	len = skb->len;
	err = skb_cow_data(skb, QUIC_TAG_LEN, &trailer);
	if (err < 0)
		return err;
	nsg = (u32)err;
	pskb_put(skb, trailer, QUIC_TAG_LEN);
	hdr->key = cb->key_phase;

	ctx = quic_crypto_aead_mem_alloc(tfm, 0, &iv, &req, &sg, nsg);
	if (!ctx)
		return -ENOMEM;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, (int)skb->len);
	if (err < 0)
		goto err;

	hlen = cb->number_offset + cb->number_len;
	memcpy(nonce, tx_iv, QUIC_IV_LEN);
	n = cpu_to_be64(cb->number);
	for (i = 0; i < sizeof(n); i++)
		nonce[QUIC_IV_LEN - sizeof(n) + i] ^= ((u8 *)&n)[i];

	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[ccm], nonce, QUIC_IV_LEN);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, (void *)quic_crypto_done, skb);

	err = crypto_aead_encrypt(req);
	if (err == -EINPROGRESS) {
		skb->destructor = quic_crypto_destruct_skb;
		skb_shinfo(skb)->destructor_arg = ctx;
		return err;
	}

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_payload_decrypt(struct crypto_aead *tfm, struct sk_buff *skb,
				       u8 *rx_iv, bool ccm)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 *iv, i, nonce[QUIC_IV_LEN];
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, hlen, len, err;
	struct scatterlist *sg;
	void *ctx;
	__be64 n;

	len = cb->length + cb->number_offset;
	hlen = cb->number_offset + cb->number_len;
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
	skb_dst_force(skb);

	memcpy(nonce, rx_iv, QUIC_IV_LEN);
	n = cpu_to_be64(cb->number);
	for (i = 0; i < sizeof(n); i++)
		nonce[QUIC_IV_LEN - sizeof(n) + i] ^= ((u8 *)&n)[i];

	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[ccm], nonce, QUIC_IV_LEN);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, (void *)quic_crypto_done, skb);

	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS) {
		skb->destructor = quic_crypto_destruct_skb;
		skb_shinfo(skb)->destructor_arg = ctx;
		return err;
	}
err:
	kfree(ctx);
	return err;
}

static void quic_crypto_get_header(struct sk_buff *skb)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quichdr *hdr = quic_hdr(skb);
	u32 len = QUIC_MAX_PN_LEN;
	u8 *p = (u8 *)hdr;

	p += cb->number_offset;
	cb->key_phase = hdr->key;
	cb->number_len = hdr->pnl + 1;
	quic_get_int(&p, &len, &cb->number, cb->number_len);
	cb->number = quic_get_num(cb->number_max, cb->number, cb->number_len);

	if (cb->number > cb->number_max)
		cb->number_max = cb->number;
}

#define QUIC_PN_LEN_BITS_MASK	0x03

static int quic_crypto_header_decrypt(struct crypto_skcipher *tfm, struct sk_buff *skb, bool chacha)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quichdr *hdr = quic_hdr(skb);
	int err, i, len = cb->length;
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 *mask, *iv, *p;

	mask = quic_crypto_skcipher_mem_alloc(tfm, QUIC_SAMPLE_LEN, &iv, &req);
	if (!mask)
		return -ENOMEM;

	if (len < QUIC_MAX_PN_LEN + QUIC_SAMPLE_LEN) {
		err = -EINVAL;
		goto err;
	}
	p = (u8 *)hdr + cb->number_offset;
	memcpy((chacha ? iv : mask), p + QUIC_MAX_PN_LEN, QUIC_SAMPLE_LEN);
	sg_init_one(&sg, mask, QUIC_SAMPLE_LEN);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_SAMPLE_LEN, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (mask[0] & (((*p & QUIC_HEADER_FORM_BIT) == QUIC_HEADER_FORM_BIT) ?
				   QUIC_LONG_HEADER_MASK : QUIC_SHORT_HEADER_MASK)));
	cb->number_len = (*p & QUIC_PN_LEN_BITS_MASK) + 1;
	p += cb->number_offset;
	for (i = 0; i < cb->number_len; ++i)
		*(p + i) = *((u8 *)hdr + cb->number_offset + i) ^ mask[i + 1];
	quic_crypto_get_header(skb);

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

#define CIPHER_DESC(type, aead_name, skc_name, sha_name)[type - QUIC_CIPHER_MIN] = { \
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

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb)
{
	u8 *iv, cha, ccm, phase = crypto->key_phase;
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	int err;

	cb->key_phase = phase;
	iv = crypto->tx_iv[phase];
	if (cb->resume)
		goto out;

	if (crypto->key_pending && !crypto->key_update_send_time)
		crypto->key_update_send_time = jiffies_to_usecs(jiffies);

	ccm = quic_crypto_is_cipher_ccm(crypto);
	err = quic_crypto_payload_encrypt(crypto->tx_tfm[phase], skb, iv, ccm);
	if (err)
		return err;
out:
	cha = quic_crypto_is_cipher_chacha(crypto);
	return quic_crypto_header_encrypt(crypto->tx_hp_tfm, skb, cha);
}
EXPORT_SYMBOL_GPL(quic_crypto_encrypt);

int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 *iv, cha, ccm, phase;
	int err = 0;
	u32 time;

	if (cb->resume) {
		quic_crypto_get_header(skb);
		goto out;
	}

	cha = quic_crypto_is_cipher_chacha(crypto);
	err = quic_crypto_header_decrypt(crypto->rx_hp_tfm, skb, cha);
	if (err) {
		pr_debug("%s: hd decrypt err %d\n", __func__, err);
		return err;
	}

	if (cb->key_phase != crypto->key_phase && !crypto->key_pending) {
		if (!crypto->send_ready) /* not ready for key update */
			return -EINVAL;
		err = quic_crypto_key_update(crypto);
		if (err) {
			cb->errcode = QUIC_TRANSPORT_ERROR_KEY_UPDATE;
			return err;
		}
		cb->key_update = 1;
	}

	phase = cb->key_phase;
	iv = crypto->rx_iv[phase];
	ccm = quic_crypto_is_cipher_ccm(crypto);
	err = quic_crypto_payload_decrypt(crypto->rx_tfm[phase], skb, iv, ccm);
	if (err) {
		if (err == -EINPROGRESS)
			return err;
		/* When using the old keys can not decrypt the packets, the peer might
		 * start another key_update. Thus, clear the last key_pending so that
		 * next packets will trigger the new key-update.
		 */
		if (crypto->key_pending && cb->key_phase != crypto->key_phase) {
			crypto->key_pending = 0;
			crypto->key_update_time = 0;
		}
		return err;
	}

out:
	/* An endpoint MUST retain old keys until it has successfully unprotected a
	 * packet sent using the new keys. An endpoint SHOULD retain old keys for
	 * some time after unprotecting a packet sent using the new keys.
	 */
	if (crypto->key_pending && cb->key_phase == crypto->key_phase) {
		time = crypto->key_update_send_time;
		if (time && jiffies_to_usecs(jiffies) - time >= crypto->key_update_time) {
			crypto->key_pending = 0;
			crypto->key_update_time = 0;
		}
	}
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_decrypt);

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt,
			   u32 version, u8 flag)
{
	struct quic_cipher *cipher;
	int err = -EINVAL;
	u32 secretlen;
	void *tfm;

	if (!crypto->cipher) {
		crypto->version = version;
		if (srt->type < QUIC_CIPHER_MIN || srt->type > QUIC_CIPHER_MAX)
			return -EINVAL;

		cipher = &ciphers[srt->type - QUIC_CIPHER_MIN];
		tfm = crypto_alloc_shash(cipher->shash, 0, 0);
		if (IS_ERR(tfm))
			return PTR_ERR(tfm);
		crypto->secret_tfm = tfm;

		tfm = crypto_alloc_aead(cipher->aead, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			goto err;
		}
		crypto->tag_tfm = tfm;
		crypto->cipher = cipher;
		crypto->cipher_type = srt->type;
	}

	cipher = crypto->cipher;
	secretlen = cipher->secretlen;
	if (!srt->send) {
		if (crypto->recv_ready)
			goto err;
		memcpy(crypto->rx_secret, srt->secret, secretlen);
		tfm = crypto_alloc_aead(cipher->aead, 0, flag);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			goto err;
		}
		crypto->rx_tfm[0] = tfm;
		tfm = crypto_alloc_aead(cipher->aead, 0, flag);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			goto err;
		}
		crypto->rx_tfm[1] = tfm;
		tfm = crypto_alloc_sync_skcipher(cipher->skc, 0, 0);
		if (IS_ERR(tfm)) {
			err = PTR_ERR(tfm);
			goto err;
		}
		crypto->rx_hp_tfm = tfm;

		err = quic_crypto_rx_keys_derive_and_install(crypto);
		if (err)
			goto err;
		crypto->recv_ready = 1;
		return 0;
	}

	if (crypto->send_ready)
		goto err;
	memcpy(crypto->tx_secret, srt->secret, secretlen);
	tfm = crypto_alloc_aead(cipher->aead, 0, flag);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->tx_tfm[0] = tfm;
	tfm = crypto_alloc_aead(cipher->aead, 0, flag);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->tx_tfm[1] = tfm;
	tfm = crypto_alloc_sync_skcipher(cipher->skc, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->tx_hp_tfm = tfm;
	err = quic_crypto_tx_keys_derive_and_install(crypto);
	if (err)
		goto err;
	crypto->send_ready = 1;
	return 0;
err:
	quic_crypto_free(crypto);
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_set_secret);

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

int quic_crypto_key_update(struct quic_crypto *crypto)
{
	u8 tx_secret[QUIC_SECRET_LEN], rx_secret[QUIC_SECRET_LEN];
	struct quic_data l = {LABEL_V1, strlen(LABEL_V1)};
	struct quic_data z = {}, k, srt;
	u32 secret_len;
	int err;

	if (crypto->key_pending || !crypto->recv_ready)
		return -EINVAL;

	secret_len = crypto->cipher->secretlen;
	if (crypto->version == QUIC_VERSION_V2)
		quic_data(&l, LABEL_V2, strlen(LABEL_V2));

	crypto->key_pending = 1;
	memcpy(tx_secret, crypto->tx_secret, secret_len);
	memcpy(rx_secret, crypto->rx_secret, secret_len);
	crypto->key_phase = !crypto->key_phase;

	quic_data(&srt, tx_secret, secret_len);
	quic_data(&k, crypto->tx_secret, secret_len);
	err = quic_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &z, &k);
	if (err)
		goto err;
	err = quic_crypto_tx_keys_derive_and_install(crypto);
	if (err)
		goto err;

	quic_data(&srt, rx_secret, secret_len);
	quic_data(&k, crypto->rx_secret, secret_len);
	err = quic_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &z, &k);
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
EXPORT_SYMBOL_GPL(quic_crypto_key_update);

void quic_crypto_free(struct quic_crypto *crypto)
{
	if (crypto->tag_tfm)
		crypto_free_aead(crypto->tag_tfm);
	if (crypto->rx_tfm[0])
		crypto_free_aead(crypto->rx_tfm[0]);
	if (crypto->rx_tfm[1])
		crypto_free_aead(crypto->rx_tfm[1]);
	if (crypto->tx_tfm[0])
		crypto_free_aead(crypto->tx_tfm[0]);
	if (crypto->tx_tfm[1])
		crypto_free_aead(crypto->tx_tfm[1]);
	if (crypto->secret_tfm)
		crypto_free_shash(crypto->secret_tfm);
	if (crypto->rx_hp_tfm)
		crypto_free_skcipher(crypto->rx_hp_tfm);
	if (crypto->tx_hp_tfm)
		crypto_free_skcipher(crypto->tx_hp_tfm);

	memset(crypto, 0, offsetof(struct quic_crypto, send_offset));
}
EXPORT_SYMBOL_GPL(quic_crypto_free);

#define QUIC_INITIAL_SALT_V1    \
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"
#define QUIC_INITIAL_SALT_V2    \
	"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9"

#define QUIC_INITIAL_SALT_LEN	20

int quic_crypto_initial_keys_install(struct quic_crypto *crypto, struct quic_conn_id *conn_id,
				     u32 version, bool is_serv)
{
	u8 secret[TLS_CIPHER_AES_GCM_128_SECRET_SIZE];
	struct quic_data salt, s, k, l, dcid, z = {};
	struct quic_crypto_secret srt = {};
	struct crypto_shash *tfm;
	char *tl, *rl, *sal;
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
	quic_data(&salt, sal, QUIC_INITIAL_SALT_LEN);
	quic_data(&dcid, conn_id->data, conn_id->len);
	quic_data(&s, secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	err = quic_crypto_hkdf_extract(tfm, &salt, &dcid, &s);
	if (err)
		goto out;

	quic_data(&l, tl, strlen(tl));
	quic_data(&k, srt.secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 1;
	err = quic_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version, CRYPTO_ALG_ASYNC);
	if (err)
		goto out;

	quic_data(&l, rl, strlen(rl));
	quic_data(&k, srt.secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 0;
	err = quic_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version, CRYPTO_ALG_ASYNC);
out:
	crypto_free_shash(tfm);
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_initial_keys_install);

#define QUIC_RETRY_KEY_V1 "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"
#define QUIC_RETRY_KEY_V2 "\x8f\xb4\xb0\x1b\x56\xac\x48\xe2\x60\xfb\xcb\xce\xad\x7c\xcc\x92"

#define QUIC_RETRY_NONCE_V1 "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"
#define QUIC_RETRY_NONCE_V2 "\xd8\x69\x69\xbc\x2d\x7c\x6d\x99\x90\xef\xb0\x4a"

int quic_crypto_get_retry_tag(struct quic_crypto *crypto, struct sk_buff *skb,
			      struct quic_conn_id *odcid, u32 version, u8 *tag)
{
	struct crypto_aead *tfm = crypto->tag_tfm;
	u8 *pseudo_retry, *p, *iv, *key;
	struct aead_request *req;
	struct scatterlist *sg;
	u32 plen;
	int err;

	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	key = QUIC_RETRY_KEY_V1;
	if (version == QUIC_VERSION_V2)
		key = QUIC_RETRY_KEY_V2;
	err = crypto_aead_setkey(tfm, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (err)
		return err;

	plen = 1 + odcid->len + skb->len - QUIC_TAG_LEN;
	pseudo_retry = quic_crypto_aead_mem_alloc(tfm, plen + QUIC_TAG_LEN, &iv, &req, &sg, 1);
	if (!pseudo_retry)
		return -ENOMEM;

	p = pseudo_retry;
	p = quic_put_int(p, odcid->len, 1);
	p = quic_put_data(p, odcid->data, odcid->len);
	p = quic_put_data(p, skb->data, skb->len - QUIC_TAG_LEN);
	sg_init_one(sg, pseudo_retry, plen + QUIC_TAG_LEN);

	memcpy(iv, QUIC_RETRY_NONCE_V1, QUIC_IV_LEN);
	if (version == QUIC_VERSION_V2)
		memcpy(iv, QUIC_RETRY_NONCE_V2, QUIC_IV_LEN);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, plen);
	aead_request_set_crypt(req, sg, sg, 0, iv);
	err = crypto_aead_encrypt(req);
	if (!err)
		memcpy(tag, p, QUIC_TAG_LEN);
	kfree(pseudo_retry);
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_get_retry_tag);

int quic_crypto_generate_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			       struct quic_conn_id *conn_id, u8 *token, u32 *tlen)
{
	u8 key[TLS_CIPHER_AES_GCM_128_KEY_SIZE], iv[QUIC_IV_LEN], *retry_token, *tx_iv, *p;
	struct crypto_aead *tfm = crypto->tag_tfm;
	u32 ts = jiffies_to_usecs(jiffies), len;
	struct quic_data srt = {}, k, i;
	struct aead_request *req;
	struct scatterlist *sg;
	int err;

	quic_data(&srt, quic_random_data, QUIC_RANDOM_DATA_LEN);
	quic_data(&k, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	quic_data(&i, iv, QUIC_IV_LEN);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &i, NULL, QUIC_VERSION_V1);
	if (err)
		return err;
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (err)
		return err;
	token++;
	len = addrlen + sizeof(ts) + conn_id->len + QUIC_TAG_LEN;
	retry_token = quic_crypto_aead_mem_alloc(tfm, len, &tx_iv, &req, &sg, 1);
	if (!retry_token)
		return -ENOMEM;

	p = retry_token;
	p = quic_put_data(p, addr, addrlen);
	p = quic_put_int(p, ts, sizeof(ts));
	quic_put_data(p, conn_id->data, conn_id->len);
	sg_init_one(sg, retry_token, len);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, addrlen);
	aead_request_set_crypt(req, sg, sg, len - addrlen - QUIC_TAG_LEN, iv);
	err = crypto_aead_encrypt(req);
	if (!err) {
		memcpy(token, retry_token, len);
		*tlen = len + 1;
	}
	kfree(retry_token);
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_generate_token);

int quic_crypto_verify_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			     struct quic_conn_id *conn_id, u8 *token, u32 len)
{
	u32 ts = jiffies_to_usecs(jiffies), timeout = QUIC_TOKEN_TIMEOUT_RETRY;
	u8 key[TLS_CIPHER_AES_GCM_128_KEY_SIZE], iv[QUIC_IV_LEN];
	u8 *retry_token, *rx_iv, *p, flag = *token;
	struct crypto_aead *tfm = crypto->tag_tfm;
	struct quic_data srt = {}, k, i;
	struct aead_request *req;
	struct scatterlist *sg;
	int err;
	u64 t;

	quic_data(&srt, quic_random_data, QUIC_RANDOM_DATA_LEN);
	quic_data(&k, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	quic_data(&i, iv, QUIC_IV_LEN);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &i, NULL, QUIC_VERSION_V1);
	if (err)
		return err;
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (err)
		return err;
	len--;
	token++;
	retry_token = quic_crypto_aead_mem_alloc(tfm, len, &rx_iv, &req, &sg, 1);
	if (!retry_token)
		return -ENOMEM;

	memcpy(retry_token, token, len);
	sg_init_one(sg, retry_token, len);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, addrlen);
	aead_request_set_crypt(req, sg, sg, len - addrlen, iv);
	err = crypto_aead_decrypt(req);
	if (err)
		goto out;

	err = -EINVAL;
	p = retry_token;
	if (memcmp(p, addr, addrlen))
		goto out;
	p += addrlen;
	len -= addrlen;
	if (flag == QUIC_TOKEN_FLAG_REGULAR)
		timeout = QUIC_TOKEN_TIMEOUT_REGULAR;
	if (!quic_get_int(&p, &len, &t, sizeof(ts)) || t + timeout < ts)
		goto out;
	len -= QUIC_TAG_LEN;
	if (len > QUIC_CONN_ID_MAX_LEN)
		goto out;

	if (flag == QUIC_TOKEN_FLAG_RETRY)
		quic_conn_id_update(conn_id, p, len);
	err = 0;
out:
	kfree(retry_token);
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_verify_token);

static int quic_crypto_generate_key(struct quic_crypto *crypto, void *data, u32 len,
				    char *label, u8 *token, u32 key_len)
{
	struct crypto_shash *tfm = crypto->secret_tfm;
	u8 secret[TLS_CIPHER_AES_GCM_128_SECRET_SIZE];
	struct quic_data salt, s, l, k, z = {};
	int err;

	quic_data(&salt, data, len);
	quic_data(&k, quic_random_data, QUIC_RANDOM_DATA_LEN);
	quic_data(&s, secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	err = quic_crypto_hkdf_extract(tfm, &salt, &k, &s);
	if (err)
		return err;

	quic_data(&l, label, strlen(label));
	quic_data(&k, token, key_len);
	return quic_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
}

int quic_crypto_generate_stateless_reset_token(struct quic_crypto *crypto, void *data,
					       u32 len, u8 *key, u32 key_len)
{
	return quic_crypto_generate_key(crypto, data, len, "stateless_reset", key, key_len);
}
EXPORT_SYMBOL_GPL(quic_crypto_generate_stateless_reset_token);

int quic_crypto_generate_session_ticket_key(struct quic_crypto *crypto, void *data,
					    u32 len, u8 *key, u32 key_len)
{
	return quic_crypto_generate_key(crypto, data, len, "session_ticket", key, key_len);
}
EXPORT_SYMBOL_GPL(quic_crypto_generate_session_ticket_key);

void quic_crypto_init(void)
{
	get_random_bytes(quic_random_data, QUIC_RANDOM_DATA_LEN);
}
