/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#define QUIC_PN_MAX_GABS	16

struct quic_pnmap {
	unsigned long *pn_map;
	u16 len;

	u32 base_pn;
	u32 cumulative_pn_ack_point;
	u32 max_pn_seen;

	u32 last_ts;
	u32 last_max_pn;

	u8 is_serv;
};

struct quic_gap_ack_block {
	u16 start;
	u16 end;
};

struct quic_pnmap *quic_pnmap_init(struct quic_pnmap *map);
u32 quic_pnmap_get_cpn(const struct quic_pnmap *map);
u32 quic_pnmap_get_max_pn_seen(const struct quic_pnmap *map);
int quic_pnmap_check(const struct quic_pnmap *map, u32 pn);
int quic_pnmap_mark(struct quic_pnmap *map, u32 pn);
void quic_pnmap_free(struct quic_pnmap *map);
u16 quic_pnmap_num_gabs(struct quic_pnmap *map, struct quic_gap_ack_block *gabs);
u32 quic_pnmap_get_base_pn(const struct quic_pnmap *map);
