/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

/* Internal QUIC GSO ID (IPPROTO_QUIC=261 doesn’t fit in u8
 * skb->inner_ipproto), reused from unused ST-II.
 */
#define IPPROTO_QUIC_GSO	5

int quic_offload_init(void);
void quic_offload_exit(void);

struct sk_buff *quic_gso_segment_list(struct sk_buff *skb, int hlen);
