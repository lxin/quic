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

#include <net/protocol.h>
#include <net/gso.h>

#include "offload.h"

struct sk_buff *quic_gso_segment_list(struct sk_buff *skb, int hlen)
{
	unsigned int truesize = 0, len = 0;
	struct sk_buff *nskb, *tail = NULL;
	int err;

	err = skb_unclone(skb, GFP_ATOMIC);
	if (err)
		return ERR_PTR(err);

	skb_gso_reset(skb);
	for (nskb = skb_shinfo(skb)->frag_list; nskb; nskb = nskb->next) {
		truesize += nskb->truesize;
		len += nskb->len;

		skb_copy_header(nskb, skb);
		skb_copy_from_linear_data_offset(skb, -hlen, nskb->data - hlen, hlen);

		if (tail)
			tail->next = nskb;
		else
			skb->next = nskb;
		tail = nskb;
	}

	skb_shinfo(skb)->frag_list = NULL;
	skb->truesize -= truesize;
	skb->data_len -= len;
	skb->len -= len;

	skb->encapsulation = 0;
	skb->prev = tail;

	return skb_get(skb);
}

static struct sk_buff *quic_gso_segment(struct sk_buff *skb, netdev_features_t features)
{
	return quic_gso_segment_list(skb, skb_tnl_header_len(skb));
}

static const struct net_offload quic_offload = {
	.callbacks = {
		.gso_segment = quic_gso_segment,
	},
};

static const struct net_offload quic6_offload = {
	.callbacks = {
		.gso_segment = quic_gso_segment,
	},
};

int quic_offload_init(void)
{
	int ret;

	ret = inet_add_offload(&quic_offload, IPPROTO_QUIC_GSO);
	if (ret)
		goto out;

	ret = inet6_add_offload(&quic6_offload, IPPROTO_QUIC_GSO);
	if (ret)
		goto ipv4;

	return ret;

ipv4:
	inet_del_offload(&quic_offload, IPPROTO_QUIC_GSO);
out:
	return ret;
}

void quic_offload_exit(void)
{
	inet_del_offload(&quic_offload, IPPROTO_QUIC_GSO);
	inet6_del_offload(&quic6_offload, IPPROTO_QUIC_GSO);
}
