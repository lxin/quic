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
#include "stream.h"
#include "frame.h"

static int quic_crypto_hkdf_extract(struct crypto_shash *tfm, struct quic_data *srt,
				    struct quic_data *hash, struct quic_data *key)
{
	int err;

	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;

	return crypto_shash_tfm_digest(tfm, hash->data, hash->len, key->data);
}

static int quic_crypto_hkdf_expand(struct crypto_shash *tfm, struct quic_data *srt,
				   struct quic_data *label, struct quic_data *hash,
				   struct quic_data *key)
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

static int quic_crypto_keys_derive(struct crypto_shash *tfm, struct quic_data *s,
				   struct quic_data *k, struct quic_data *i,
				   struct quic_data *hp_k, u32 version)
{
	struct quic_data hp_k_l = {HP_KEY_LABEL_V1, 7}, k_l = {KEY_LABEL_V1, 8};
	struct quic_data i_l = {IV_LABEL_V1, 7};
	struct quic_data z = {};
	int err;

	if (version == QUIC_VERSION_V2) {
		quic_data(&hp_k_l, HP_KEY_LABEL_V2, 9);
		quic_data(&k_l, KEY_LABEL_V2, 10);
		quic_data(&i_l, IV_LABEL_V2, 9);
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
	int err, phase = crypto->key_phase;
	u32 keylen, ivlen = QUIC_IV_LEN;
	u8 tx_key[32], tx_hp_key[32];

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
	pr_debug("[QUIC] tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

static int quic_crypto_rx_keys_derive_and_install(struct quic_crypto *crypto)
{
	struct quic_data srt = {}, k, iv, hp_k = {}, *hp = NULL;
	int err, phase = crypto->key_phase;
	u32 keylen, ivlen = QUIC_IV_LEN;
	u8 rx_key[32], rx_hp_key[32];

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
				      struct quic_crypto_info *ci, bool chacha)
{
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 *mask, *iv, *p;
	int err, i;

	mask = quic_crypto_skcipher_mem_alloc(tfm, 16, &iv, &req);
	if (!mask)
		return -ENOMEM;

	memcpy((chacha ? iv : mask), skb->data + ci->number_offset + 4, 16);
	sg_init_one(&sg, mask, 16);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, 16, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = skb->data;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	p = skb->data + ci->number_offset;
	for (i = 1; i <= ci->number_len; i++)
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

static void quic_crypto_destruct_skb(struct sk_buff *skb)
{
	kfree(skb_shinfo(skb)->destructor_arg);
	sock_efree(skb);
}

static int quic_crypto_payload_encrypt(struct crypto_aead *tfm, struct sk_buff *skb,
				       struct quic_crypto_info *ci, u8 *tx_iv, bool ccm)
{
	struct quichdr *hdr = quic_hdr(skb);
	u8 *iv, i, nonce[QUIC_IV_LEN];
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, err, hlen, len;
	struct scatterlist *sg;
	void *ctx;
	__be64 n;

	len = skb->len;
	nsg = skb_cow_data(skb, QUIC_TAG_LEN, &trailer);
	if (nsg < 0)
		return nsg;
	pskb_put(skb, trailer, QUIC_TAG_LEN);
	hdr->key = ci->key_phase;

	ctx = quic_crypto_aead_mem_alloc(tfm, 0, &iv, &req, &sg, nsg);
	if (!ctx)
		return -ENOMEM;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, 0, skb->len);
	if (err < 0)
		goto err;

	hlen = ci->number_offset + ci->number_len;
	memcpy(nonce, tx_iv, QUIC_IV_LEN);
	n = cpu_to_be64(ci->number);
	for (i = 0; i < 8; i++)
		nonce[QUIC_IV_LEN - 8 + i] ^= ((u8 *)&n)[i];

	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[ccm], nonce, QUIC_IV_LEN);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, ci->crypto_done, skb);

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
				       struct quic_crypto_info *ci, u8 *rx_iv, bool ccm)
{
	u8 *iv, i, nonce[QUIC_IV_LEN];
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, hlen, len, err;
	struct scatterlist *sg;
	void *ctx;
	__be64 n;

	len = ci->length + ci->number_offset;
	hlen = ci->number_offset + ci->number_len;
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

	memcpy(nonce, rx_iv, QUIC_IV_LEN);
	n = cpu_to_be64(ci->number);
	for (i = 0; i < 8; i++)
		nonce[QUIC_IV_LEN - 8 + i] ^= ((u8 *)&n)[i];

	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[ccm], nonce, QUIC_IV_LEN);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, ci->crypto_done, skb);

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

static void quic_crypto_get_num(u8 *p, struct quic_crypto_info *ci)
{
	u32 len = ci->number_len;

	quic_get_int(&p, &len, &ci->number, ci->number_len);
	ci->number = quic_get_num(ci->number_max, ci->number, ci->number_len);
}

static int quic_crypto_header_decrypt(struct crypto_skcipher *tfm, struct sk_buff *skb,
				      struct quic_crypto_info *ci, bool chacha)
{
	struct quichdr *hdr = quic_hdr(skb);
	int err, i, len = ci->length;
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 *mask, *iv, *p;

	mask = quic_crypto_skcipher_mem_alloc(tfm, 16, &iv, &req);
	if (!mask)
		return -ENOMEM;

	if (len < 4 + 16) {
		err = -EINVAL;
		goto err;
	}
	p = (u8 *)hdr + ci->number_offset;
	memcpy((chacha ? iv : mask), p + 4, 16);
	sg_init_one(&sg, mask, 16);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, 16, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	ci->number_len = (*p & 0x03) + 1;
	p += ci->number_offset;
	for (i = 0; i < ci->number_len; ++i)
		*(p + i) = *((u8 *)hdr + ci->number_offset + i) ^ mask[i + 1];
	ci->key_phase = hdr->key;
	quic_crypto_get_num(p, ci);

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

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_crypto_info *ci)
{
	int err, phase = crypto->key_phase;
	u8 *iv, cha, ccm;

	ci->key_phase = phase;
	iv = crypto->tx_iv[phase];
	if (ci->resume)
		goto out;

	if (crypto->key_pending && !crypto->key_update_send_ts)
		crypto->key_update_send_ts = jiffies_to_usecs(jiffies);

	ccm = quic_crypto_is_cipher_ccm(crypto);
	err = quic_crypto_payload_encrypt(crypto->tx_tfm[phase], skb, ci, iv, ccm);
	if (err)
		return err;
out:
	cha = quic_crypto_is_cipher_chacha(crypto);
	return quic_crypto_header_encrypt(crypto->tx_hp_tfm, skb, ci, cha);
}
EXPORT_SYMBOL_GPL(quic_crypto_encrypt);

int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_crypto_info *ci)
{
	struct quichdr *hdr = quic_hdr(skb);
	int err = 0, phase;
	u8 *iv, cha, ccm;

	if (ci->resume) {
		ci->key_phase = hdr->key;
		ci->number_len = hdr->pnl + 1;
		quic_crypto_get_num((u8 *)hdr + ci->number_offset, ci);
		goto out;
	}

	cha = quic_crypto_is_cipher_chacha(crypto);
	err = quic_crypto_header_decrypt(crypto->rx_hp_tfm, skb, ci, cha);
	if (err) {
		pr_warn("[QUIC] hd decrypt err %d\n", err);
		return err;
	}

	if (ci->key_phase != crypto->key_phase && !crypto->key_pending) {
		err = quic_crypto_key_update(crypto);
		if (err) {
			ci->errcode = QUIC_TRANSPORT_ERROR_KEY_UPDATE;
			return err;
		}
	}

	phase = ci->key_phase;
	iv = crypto->rx_iv[phase];
	ccm = quic_crypto_is_cipher_ccm(crypto);
	err = quic_crypto_payload_decrypt(crypto->rx_tfm[phase], skb, ci, iv, ccm);
	if (err)
		return err;

out:
	/* An endpoint MUST retain old keys until it has successfully unprotected a
	 * packet sent using the new keys. An endpoint SHOULD retain old keys for
	 * some time after unprotecting a packet sent using the new keys.
	 */
	if (ci->key_phase == crypto->key_phase &&
	    crypto->key_pending && crypto->key_update_send_ts &&
	    jiffies_to_usecs(jiffies) - crypto->key_update_send_ts >= crypto->key_update_ts)
		ci->key_update = 1;
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_decrypt);

int quic_crypto_set_secret(struct quic_crypto *crypto, struct quic_crypto_secret *srt,
			   u32 version, u8 flag)
{
	struct quic_cipher *cipher;
	int err, secretlen;
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
	quic_crypto_destroy(crypto);
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
	struct quic_data l = {LABEL_V1, 7}, z = {}, k, srt;
	int err, secret_len;

	if (crypto->key_pending || !crypto->recv_ready)
		return -EINVAL;

	secret_len = crypto->cipher->secretlen;
	if (crypto->version == QUIC_VERSION_V2)
		quic_data(&l, LABEL_V2, 9);

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

void quic_crypto_set_key_update_ts(struct quic_crypto *crypto, u32 key_update_ts)
{
	crypto->key_update_ts = key_update_ts;
}

void quic_crypto_destroy(struct quic_crypto *crypto)
{
	crypto_free_aead(crypto->tag_tfm);
	crypto_free_aead(crypto->rx_tfm[0]);
	crypto_free_aead(crypto->rx_tfm[1]);
	crypto_free_aead(crypto->tx_tfm[0]);
	crypto_free_aead(crypto->tx_tfm[1]);
	crypto_free_shash(crypto->secret_tfm);
	crypto_free_skcipher(crypto->rx_hp_tfm);
	crypto_free_skcipher(crypto->tx_hp_tfm);

	memset(crypto, 0, sizeof(*crypto));
}
EXPORT_SYMBOL_GPL(quic_crypto_destroy);

#define QUIC_INITIAL_SALT_V1    \
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"
#define QUIC_INITIAL_SALT_V2    \
	"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9"

int quic_crypto_initial_keys_install(struct quic_crypto *crypto, struct quic_connection_id *conn_id,
				     u32 version, u8 flag, bool is_serv)
{
	struct quic_data salt, s, k, l, dcid, z = {};
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
	quic_data(&salt, sal, 20);
	quic_data(&dcid, conn_id->data, conn_id->len);
	quic_data(&s, secret, 32);
	err = quic_crypto_hkdf_extract(tfm, &salt, &dcid, &s);
	if (err)
		goto out;

	quic_data(&l, tl, 9);
	quic_data(&k, srt.secret, 32);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 1;
	err = quic_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version, flag);
	if (err)
		goto out;

	quic_data(&l, rl, 9);
	quic_data(&k, srt.secret, 32);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 0;
	err = quic_crypto_hkdf_expand(tfm, &s, &l, &z, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version, flag);
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
			      struct quic_connection_id *odcid, u32 version, u8 *tag)
{
	struct crypto_aead *tfm = crypto->tag_tfm;
	u8 *pseudo_retry, *p, *iv, *key;
	struct aead_request *req;
	struct scatterlist *sg;
	int err, plen;

	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	key = QUIC_RETRY_KEY_V1;
	if (version == QUIC_VERSION_V2)
		key = QUIC_RETRY_KEY_V2;
	err = crypto_aead_setkey(tfm, key, 16);
	if (err)
		return err;

	pseudo_retry = quic_crypto_aead_mem_alloc(tfm, 128, &iv, &req, &sg, 1);
	if (!pseudo_retry)
		return -ENOMEM;

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
	return 0;
}
EXPORT_SYMBOL_GPL(quic_crypto_get_retry_tag);

int quic_crypto_generate_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			       struct quic_connection_id *conn_id, u8 *token, u32 *tokenlen)
{
	u8 key[16], iv[12], *retry_token, *tx_iv, *p;
	struct crypto_aead *tfm = crypto->tag_tfm;
	u32 ts = jiffies_to_usecs(jiffies);
	struct quic_data srt = {}, k, i;
	struct aead_request *req;
	struct scatterlist *sg;
	int err, len;

	quic_data(&srt, random_data, 32);
	quic_data(&k, key, 16);
	quic_data(&i, iv, 12);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &i, NULL, QUIC_VERSION_V1);
	if (err)
		return err;
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, key, 16);
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
	p = quic_put_data(p, conn_id->data, conn_id->len);
	sg_init_one(sg, retry_token, len);
	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, addrlen);
	aead_request_set_crypt(req, sg, sg, len - addrlen - QUIC_TAG_LEN, iv);
	err = crypto_aead_encrypt(req);

	memcpy(token, retry_token, len);
	*tokenlen = len + 1;
	kfree(retry_token);
	return err;
}
EXPORT_SYMBOL_GPL(quic_crypto_generate_token);

int quic_crypto_verify_token(struct quic_crypto *crypto, void *addr, u32 addrlen,
			     struct quic_connection_id *conn_id, u8 *token, u32 len)
{
	u8 key[16], iv[12], *retry_token, *rx_iv, *p, retry = *token;
	u32 ts = jiffies_to_usecs(jiffies), timeout = 3000000;
	struct crypto_aead *tfm = crypto->tag_tfm;
	struct quic_data srt = {}, k, i;
	struct aead_request *req;
	struct scatterlist *sg;
	int err;
	u64 t;

	quic_data(&srt, random_data, 32);
	quic_data(&k, key, 16);
	quic_data(&i, iv, 12);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &i, NULL, QUIC_VERSION_V1);
	if (err)
		return err;
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, key, 16);
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
	if (!retry)
		timeout = 36000000;
	if (!quic_get_int(&p, &len, &t, 4) || t + timeout < ts)
		goto out;
	len -= QUIC_TAG_LEN;
	if (len > QUIC_CONNECTION_ID_MAX_LEN)
		goto out;

	if (retry)
		quic_connection_id_update(conn_id, p, len);
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
	struct quic_data salt, s, l, k, z = {};
	u8 secret[32];
	int err;

	quic_data(&salt, data, len);
	quic_data(&k, random_data, 32);
	quic_data(&s, secret, 32);
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
