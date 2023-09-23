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
#include <net/netns/hash.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include "hashtable.h"
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

static int tls_crypto_hkdf_expand(struct crypto_shash *tfm, struct tls_vec *srt,
				  struct tls_vec *label, struct tls_vec *hash, struct tls_vec *key)
{
	u8 cnt = 1, info[256], *p = info, *prev = NULL;
	u8 LABEL[] = "tls13 ", tmp[32];
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
	for (i = 0; i < key->len; i += 32) {
		err = crypto_shash_init(desc);
		if (err)
			goto out;
		if (prev) {
			err = crypto_shash_update(desc, prev, 32);
			if (err)
				goto out;
		}
		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;
		BUILD_BUG_ON(sizeof(cnt) != 1);
		if (key->len - i < 32) {
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
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k, *hp;
	int err;

	tls_vec(&srt, crypto->tx_secret, QUIC_SECRET_LEN);
	tls_vec(&k, crypto->tx_key[crypto->key_phase], QUIC_KEY_LEN);
	tls_vec(&iv, crypto->tx_iv[crypto->key_phase], QUIC_IV_LEN);
	hp = crypto->key_pending ? NULL : tls_vec(&hp_k, crypto->tx_hp_key, QUIC_KEY_LEN);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp);
	if (err)
		return err;
	pr_debug("[QUIC] ap tx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

static int quic_crypto_rx_keys_derive_and_install(struct quic_crypto *crypto)
{
	struct tls_vec srt = {NULL, 0}, k, iv, hp_k, *hp;
	int err;

	tls_vec(&srt, crypto->rx_secret, QUIC_SECRET_LEN);
	tls_vec(&k, crypto->rx_key[crypto->key_phase], QUIC_KEY_LEN);
	tls_vec(&iv, crypto->rx_iv[crypto->key_phase], QUIC_IV_LEN);
	hp = crypto->key_pending ? NULL : tls_vec(&hp_k, crypto->rx_hp_key, QUIC_KEY_LEN);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp);
	if (err)
		return err;
	pr_debug("[QUIC] ap rx keys: %16phN, %12phN, %16phN\n", k.data, iv.data, hp_k.data);
	return 0;
}

static int quic_crypto_header_encrypt(struct crypto_skcipher *tfm, struct sk_buff *skb,
				      struct quic_packet_info *pki, u8 *tx_hp_key)
{
	struct skcipher_request *req;
	u8 mask[QUIC_KEY_LEN], *p;
	struct scatterlist sg;
	int err, i;

	err = crypto_skcipher_setkey(tfm, tx_hp_key, QUIC_KEY_LEN);
	if (err)
		return err;
	req = skcipher_request_alloc(tfm, 0);
	if (!req)
		return -ENOMEM;

	memcpy(mask, skb->data + pki->number_offset + 4, QUIC_KEY_LEN);
	sg_init_one(&sg, mask, QUIC_KEY_LEN);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_KEY_LEN, NULL);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = skb->data;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	p = skb->data + pki->number_offset;
	for (i = 1; i <= pki->number_len; i++)
		*p++ ^= mask[i];
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

	mem = kmalloc(len, GFP_ATOMIC);
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
				       struct quic_packet_info *pki, u8 *tx_key, u8 *tx_iv)
{
	struct quichdr *hdr = quic_hdr(skb);
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, err, hlen, len;
	struct scatterlist *sg;
	void *ctx;
	u8 *iv, i;
	__be64 n;

	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, tx_key, QUIC_KEY_LEN);
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
	memcpy(iv, tx_iv, QUIC_IV_LEN);
	n = cpu_to_be64(pki->number);
	for (i = 0; i < 8; i++)
		iv[QUIC_IV_LEN - 8 + i] ^= ((u8 *)&n)[i];

	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	err = crypto_aead_encrypt(req);

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_payload_decrypt(struct crypto_aead *tfm, struct sk_buff *skb,
				       struct quic_packet_info *pki, u8 *rx_key, u8 *rx_iv)
{
	struct aead_request *req;
	struct sk_buff *trailer;
	int nsg, hlen, len, err;
	struct scatterlist *sg;
	void *ctx;
	u8 *iv, i;
	__be64 n;

	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		return err;
	err = crypto_aead_setkey(tfm, rx_key, QUIC_KEY_LEN);
	if (err)
		return err;

	len = skb->len;
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

	memcpy(iv, rx_iv, QUIC_IV_LEN);
	n = cpu_to_be64(pki->number);
	for (i = 0; i < 8; i++)
		iv[QUIC_IV_LEN - 8 + i] ^= ((u8 *)&n)[i];

	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - hlen, iv);
	err = crypto_aead_decrypt(req);

err:
	kfree(ctx);
	return err;
}

static int quic_crypto_header_decrypt(struct crypto_skcipher *tfm, struct sk_buff *skb,
				      struct quic_packet_info *pki, u8 *rx_hp_key)
{
	struct quichdr *hdr = quic_hdr(skb);
	struct skcipher_request *req;
	u8 mask[QUIC_KEY_LEN], *p;
	struct scatterlist sg;
	int err, i;

	err = crypto_skcipher_setkey(tfm, rx_hp_key, QUIC_KEY_LEN);
	if (err)
		return err;
	req = skcipher_request_alloc(tfm, 0);
	if (!req)
		return -ENOMEM;

	if (skb->len < pki->number_offset + 4 + QUIC_KEY_LEN) {
		err = -EINVAL;
		goto err;
	}
	p = (u8 *)hdr + pki->number_offset;
	memcpy(mask, p + 4, QUIC_KEY_LEN);
	sg_init_one(&sg, mask, QUIC_KEY_LEN);
	skcipher_request_set_crypt(req, &sg, &sg, QUIC_KEY_LEN, NULL);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p = (u8 *)hdr;
	*p = (u8)(*p ^ (mask[0] & (((*p & 0x80) == 0x80) ? 0x0f : 0x1f)));
	pki->number_len = (*p & 0x03) + 1;
	if (skb->len < pki->number_offset + pki->number_len) {
		err = -EINVAL;
		goto err;
	}
	p += pki->number_offset;
	for (i = 0; i < pki->number_len; ++i)
		*(p + i) = *((u8 *)hdr + pki->number_offset + i) ^ mask[i + 1];

	pki->number = quic_get_int(&p, pki->number_len);
	pki->key_phase = hdr->key;

err:
	skcipher_request_free(req);
	return err;
}

int quic_crypto_encrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki)
{
	u8 *key, *iv, *hp_key;
	int err;

	pki->key_phase = crypto->key_phase;
	key = crypto->tx_key[crypto->key_phase];
	iv = crypto->tx_iv[crypto->key_phase];
	hp_key = crypto->tx_hp_key;

	if (crypto->key_pending && !crypto->key_update_send_ts)
		crypto->key_update_send_ts = jiffies_to_usecs(jiffies);

	err = quic_crypto_payload_encrypt(crypto->aead_tfm, skb, pki, key, iv);
	if (err)
		return err;

	return quic_crypto_header_encrypt(crypto->skc_tfm, skb, pki, hp_key);
}

int quic_crypto_decrypt(struct quic_crypto *crypto, struct sk_buff *skb,
			struct quic_packet_info *pki)
{
	u8 *key, *iv, *hp_key;
	int err;

	hp_key = crypto->rx_hp_key;

	err = quic_crypto_header_decrypt(crypto->skc_tfm, skb, pki, hp_key);
	if (err) {
		pr_warn("[QUIC] hd decrypt err %d\n", err);
		return err;
	}

	if (pki->key_phase != crypto->key_phase && !crypto->key_pending) {
		err = quic_crypto_key_update(crypto, NULL, 0);
		if (err)
			return err;
	}

	/* Make sure the packets with old key have got processed */
	if (crypto->key_pending && crypto->key_update_send_ts &&
	    jiffies_to_usecs(jiffies) - crypto->key_update_send_ts >= crypto->key_update_ts) {
		crypto->key_pending = 0;
		crypto->key_update_send_ts = 0;
	}

	key = crypto->rx_key[pki->key_phase];
	iv = crypto->rx_iv[pki->key_phase];

	return quic_crypto_payload_decrypt(crypto->aead_tfm, skb, pki, key, iv);
}

int quic_crypto_set_secret(struct quic_crypto *crypto, u8 *key, bool send)
{
	u8 len = QUIC_SECRET_LEN;
	void *tfm;

	tfm = crypto->secret_tfm;
	if (!tfm) {
		tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
		if (IS_ERR(tfm))
			return PTR_ERR(tfm);
		crypto->secret_tfm = tfm;
	}
	tfm = crypto->skc_tfm;
	if (!tfm) {
		tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
		if (IS_ERR(tfm))
			return PTR_ERR(tfm);
		crypto->skc_tfm = tfm;
	}
	tfm = crypto->aead_tfm;
	if (!tfm) {
		tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(tfm))
			return PTR_ERR(tfm);
		crypto->aead_tfm = tfm;
	}

	if (send) {
		memcpy(crypto->tx_secret, key, len);
		return quic_crypto_tx_keys_derive_and_install(crypto);
	}
	memcpy(crypto->rx_secret, key, len);
	return quic_crypto_rx_keys_derive_and_install(crypto);
}

int quic_crypto_get_secret(struct quic_crypto *crypto, u8 *key, bool send)
{
	u8 *secret = send ? crypto->tx_secret : crypto->rx_secret;

	memcpy(key, secret, QUIC_SECRET_LEN);
	return 0;
}

int quic_crypto_key_update(struct quic_crypto *crypto, u8 *key, unsigned int len)
{
	u8 tx_secret[QUIC_SECRET_LEN], rx_secret[QUIC_SECRET_LEN];
	struct tls_vec l = {"quic ku", 7}, z = {NULL, 0}, k, srt;
	int err;

	if (crypto->key_pending)
		return -EINVAL;

	crypto->key_pending = 1;
	memcpy(tx_secret, crypto->tx_secret, QUIC_SECRET_LEN);
	memcpy(rx_secret, crypto->rx_secret, QUIC_SECRET_LEN);
	crypto->key_phase = !crypto->key_phase;

	tls_vec(&srt, tx_secret, QUIC_SECRET_LEN);
	tls_vec(&k, crypto->tx_secret, QUIC_SECRET_LEN);
	err = tls_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &z, &k);
	if (err)
		goto err;
	err = quic_crypto_tx_keys_derive_and_install(crypto);
	if (err)
		goto err;

	tls_vec(&srt, rx_secret, QUIC_SECRET_LEN);
	tls_vec(&k, crypto->rx_secret, QUIC_SECRET_LEN);
	err = tls_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &z, &k);
	if (err)
		goto err;
	err = quic_crypto_rx_keys_derive_and_install(crypto);
	if (err)
		goto err;
	return 0;
err:
	crypto->key_pending = 0;
	memcpy(crypto->tx_secret, tx_secret, QUIC_SECRET_LEN);
	memcpy(crypto->rx_secret, rx_secret, QUIC_SECRET_LEN);
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
}
