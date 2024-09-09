// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is kernel test of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <uapi/linux/quic.h>
#include <uapi/linux/tls.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <kunit/test.h>
#include <net/sock.h>

#include "../pnspace.h"
#include "../connid.h"
#include "../crypto.h"
#include "../cong.h"

static void quic_pnspace_test1(struct kunit *test)
{
	struct quic_pnspace _space = {}, *space = &_space;
	struct quic_gap_ack_block *gabs;
	int i;

	KUNIT_ASSERT_EQ(test, 0, quic_pnspace_init(space));
	quic_pnspace_set_base_pn(space, 1);
	quic_pnspace_set_max_time_limit(space, 30000);
	gabs = quic_pnspace_gabs(space);

	KUNIT_EXPECT_EQ(test, space->base_pn, 1);
	KUNIT_EXPECT_EQ(test, space->min_pn_seen, 0);
	KUNIT_EXPECT_EQ(test, space->pn_map_len, QUIC_PN_MAP_INITIAL);

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, -1));
	KUNIT_EXPECT_EQ(test, -ENOMEM, quic_pnspace_mark(space, QUIC_PN_MAP_SIZE + 1));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 0));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 1));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 2));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3));
	KUNIT_EXPECT_EQ(test, 4, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 3, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 4));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 6));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 9));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 13));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 18));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 24));
	KUNIT_EXPECT_EQ(test, 5, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 24, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 5, quic_pnspace_num_gabs(space));
	KUNIT_EXPECT_EQ(test, 6, gabs[0].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 6, gabs[0].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 8, gabs[1].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 9, gabs[1].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 11, gabs[2].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 13, gabs[2].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 15, gabs[3].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 18, gabs[3].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 20, gabs[4].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 24, gabs[4].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 4, gabs[0].start - 1 + quic_pnspace_base_pn(space) -
				 (quic_pnspace_min_pn_seen(space) + 1));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 7));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 8));
	KUNIT_EXPECT_EQ(test, 5, space->base_pn);
	KUNIT_EXPECT_EQ(test, 4, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 5));
	KUNIT_EXPECT_EQ(test, 10, space->base_pn);
	KUNIT_EXPECT_EQ(test, 3, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 15));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 16));
	KUNIT_EXPECT_EQ(test, 10, space->base_pn);
	KUNIT_EXPECT_EQ(test, 4, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 14));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 17));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 10));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 11));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 12));
	KUNIT_EXPECT_EQ(test, 19, space->base_pn);
	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 128));
	KUNIT_EXPECT_EQ(test, 19, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 128, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 128 + QUIC_PN_MAP_INITIAL, space->pn_map_len);
	KUNIT_EXPECT_EQ(test, 2, quic_pnspace_num_gabs(space));

	/* ! space->max_pn_seen <= space->mid_pn_seen + QUIC_PN_MAP_LIMIT */
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3073));
	KUNIT_EXPECT_EQ(test, 19, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 3073, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 3073, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 3136, space->pn_map_len);
	KUNIT_EXPECT_EQ(test, 3, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3074));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3075));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3090));
	KUNIT_EXPECT_EQ(test, 19, space->base_pn);
	KUNIT_EXPECT_EQ(test, 3090, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 3073, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 3136, space->pn_map_len);
	KUNIT_EXPECT_EQ(test, 4, quic_pnspace_num_gabs(space));

	/* ! space->max_pn_seen <= space->base_pn + QUIC_PN_MAP_LIMIT */
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3190));
	KUNIT_EXPECT_EQ(test, 3076, space->base_pn);
	KUNIT_EXPECT_EQ(test, 3190, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 3190, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 3264, space->pn_map_len);
	KUNIT_EXPECT_EQ(test, 2, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3290));
	KUNIT_EXPECT_EQ(test, 3076, space->base_pn);
	KUNIT_EXPECT_EQ(test, 3290, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 3190, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 3264, space->pn_map_len);
	KUNIT_EXPECT_EQ(test, 3, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3289));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3288));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3192));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3191));
	KUNIT_EXPECT_EQ(test, 3076, space->base_pn);
	KUNIT_EXPECT_EQ(test, 3290, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 3190, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 3264, space->pn_map_len);
	KUNIT_EXPECT_EQ(test, 3, quic_pnspace_num_gabs(space));

	for (i = 1; i <= 128; i++)
		KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 256 * i));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, QUIC_PN_MAP_SIZE + 1));
	KUNIT_EXPECT_EQ(test, -ENOMEM,
			quic_pnspace_mark(space, space->base_pn + QUIC_PN_MAP_SIZE + 1));

	quic_pnspace_free(space);
	KUNIT_EXPECT_EQ(test, space->pn_map_len, 0);
}

static void quic_pnspace_test2(struct kunit *test)
{
	struct quic_pnspace _space = {}, *space = &_space;
	struct quic_gap_ack_block *gabs;

	KUNIT_ASSERT_EQ(test, 0, quic_pnspace_init(space));
	quic_pnspace_set_base_pn(space, 1);
	quic_pnspace_set_max_time_limit(space, 30000);
	gabs = quic_pnspace_gabs(space);

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 2));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 3));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 5));
	KUNIT_EXPECT_EQ(test, 1, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 5, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnspace_num_gabs(space));
	KUNIT_EXPECT_EQ(test, 2, gabs[0].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 2, gabs[0].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 5, gabs[1].start + space->base_pn);
	KUNIT_EXPECT_EQ(test, 5, gabs[1].end + space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, gabs[0].start - 1 + quic_pnspace_base_pn(space) -
				 (quic_pnspace_min_pn_seen(space) + 1));

	msleep(50);
	/* ! space->max_pn_time - space->mid_pn_time < space->max_time_limit */
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 4));
	KUNIT_EXPECT_EQ(test, 1, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 1));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 6));
	KUNIT_EXPECT_EQ(test, 7, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 8));
	KUNIT_EXPECT_EQ(test, 7, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 7));
	KUNIT_EXPECT_EQ(test, 9, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 11));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 10));
	KUNIT_EXPECT_EQ(test, 9, space->base_pn);
	KUNIT_EXPECT_EQ(test, 0, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 11, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_num_gabs(space));

	msleep(50);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 18));
	KUNIT_EXPECT_EQ(test, 9, space->base_pn);
	KUNIT_EXPECT_EQ(test, 6, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 9));
	KUNIT_EXPECT_EQ(test, 12, space->base_pn);
	KUNIT_EXPECT_EQ(test, 6, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_num_gabs(space));

	msleep(50);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 17));
	KUNIT_EXPECT_EQ(test, 12, space->base_pn);
	KUNIT_EXPECT_EQ(test, 6, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 19));
	KUNIT_EXPECT_EQ(test, 20, space->base_pn);
	KUNIT_EXPECT_EQ(test, 19, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 19, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 25));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 26));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 29));
	KUNIT_EXPECT_EQ(test, 20, space->base_pn);
	KUNIT_EXPECT_EQ(test, 29, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 19, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnspace_num_gabs(space));

	msleep(50);
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_mark(space, 30));
	KUNIT_EXPECT_EQ(test, 20, space->base_pn);
	KUNIT_EXPECT_EQ(test, 30, space->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 19, space->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 30, space->mid_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnspace_num_gabs(space));

	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_check(space, 29));
	KUNIT_EXPECT_EQ(test, 1, quic_pnspace_check(space, 19));
	KUNIT_EXPECT_EQ(test, 0, quic_pnspace_check(space, 35));
	KUNIT_EXPECT_EQ(test, -1, quic_pnspace_check(space, space->base_pn + QUIC_PN_MAP_SIZE));

	quic_pnspace_free(space);
	KUNIT_EXPECT_EQ(test, space->pn_map_len, 0);
}

static u8 secret[48] = {
	0x55, 0xe7, 0x18, 0x93, 0x73, 0x08, 0x09, 0xf6, 0xbf, 0xa1, 0xab, 0x66, 0xe8, 0xfc, 0x02,
	0xde, 0x17, 0xfa, 0xbe, 0xc5, 0x4a, 0xe7, 0xe4, 0xb8, 0x25, 0x48, 0xff, 0xe9, 0xd6, 0x7d,
	0x8e, 0x0e};

static u8 data[296] = {
	0x03, 0x65, 0x85, 0x3b, 0xf1, 0xe4, 0xf4, 0x22, 0x8d, 0x45, 0x48, 0xcb, 0xb8, 0x2e, 0x7e,
	0x05, 0x09, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01, 0x10, 0xad, 0x35, 0x67, 0x29, 0xe2,
	0xa6, 0x99, 0x99, 0x17, 0xf4, 0xe5, 0xdc, 0x10, 0xbf, 0x4c, 0xee, 0xd5, 0x75, 0xa0, 0x77,
	0xd0, 0x1d, 0x49, 0x78, 0x5d, 0xaa, 0xa9, 0x74, 0x70, 0x72, 0x19, 0x91, 0x18, 0x02, 0x01,
	0x10, 0x3c, 0xdc, 0x40, 0x33, 0xe6, 0xe9, 0x35, 0xa6, 0xa9, 0x80, 0xb6, 0xe9, 0x39, 0x84,
	0xea, 0xb7, 0xe9, 0xc2, 0x86, 0xfb, 0x84, 0x34, 0x0a, 0x26, 0x69, 0xa5, 0x9f, 0xbb, 0x02,
	0x7c, 0xd2, 0xd4, 0x18, 0x03, 0x01, 0x10, 0x14, 0x6a, 0xa5, 0x7e, 0x82, 0x8d, 0xc0, 0xb3,
	0x5e, 0x23, 0x1a, 0x4d, 0xd1, 0x68, 0xbf, 0x29, 0x62, 0x01, 0xda, 0x70, 0xad, 0x88, 0x8c,
	0x7c, 0x70, 0xb1, 0xb5, 0xdf, 0xce, 0x66, 0x00, 0xfe, 0x18, 0x04, 0x01, 0x10, 0x25, 0x83,
	0x2f, 0x08, 0x97, 0x1a, 0x99, 0xe8, 0x68, 0xad, 0x4a, 0x2c, 0xbb, 0xc9, 0x27, 0x94, 0xd4,
	0x5d, 0x2e, 0xe6, 0xe5, 0x50, 0x47, 0xa7, 0x72, 0x6f, 0x44, 0x49, 0x9b, 0x87, 0x21, 0xec,
	0x18, 0x05, 0x01, 0x10, 0xcf, 0xb4, 0x62, 0xdd, 0x34, 0xb7, 0x6b, 0x92, 0xd8, 0x2d, 0x6c,
	0xd6, 0x17, 0x75, 0xdc, 0x33, 0x8c, 0x49, 0xf3, 0xd5, 0xc0, 0xf2, 0x8e, 0xc4, 0xb6, 0x97,
	0x99, 0xe3, 0x3c, 0x97, 0x7e, 0xa5, 0x18, 0x06, 0x01, 0x10, 0x29, 0xc6, 0x70, 0x43, 0xbe,
	0x94, 0x18, 0x8e, 0x22, 0xf7, 0xe1, 0x02, 0xc6, 0x71, 0xc9, 0xc5, 0xb1, 0x69, 0x14, 0xb5,
	0x62, 0x59, 0x13, 0xe5, 0xff, 0xcd, 0xc7, 0xfc, 0xfc, 0x8e, 0x46, 0x1d, 0x18, 0x07, 0x01,
	0x10, 0x38, 0x67, 0x2b, 0x1a, 0xeb, 0x2f, 0x79, 0xdc, 0x3b, 0xc0, 0x70, 0x60, 0x21, 0xce,
	0x35, 0x80, 0x42, 0x52, 0x4d, 0x28, 0x1f, 0x25, 0xaa, 0x59, 0x57, 0x64, 0xc3, 0xec, 0xa1,
	0xe3, 0x3c, 0x4a, 0x19, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00};

static u8 encrypted_data[296] = {
	0x03, 0x65, 0x85, 0x3b, 0xf1, 0xe4, 0xf4, 0x22, 0x8d, 0x45, 0x48, 0xcb, 0xb8, 0x2e, 0x7e,
	0x05, 0x09, 0x26, 0x0c, 0xae, 0xc2, 0x36, 0x54, 0xd1, 0xe4, 0x34, 0xdf, 0x42, 0xf7, 0xe6,
	0x66, 0xc5, 0x4b, 0x80, 0x04, 0x3f, 0x77, 0x9e, 0x26, 0xdb, 0x5a, 0x5c, 0xd9, 0x48, 0xc7,
	0x21, 0xb1, 0x01, 0xaf, 0xa4, 0x4f, 0x4d, 0x46, 0xc8, 0xb6, 0x8b, 0xde, 0xdb, 0x3b, 0x23,
	0xee, 0x0c, 0x8b, 0x57, 0xba, 0x5a, 0x5a, 0x5e, 0xa8, 0xac, 0x12, 0x48, 0x16, 0x81, 0x12,
	0xfb, 0xa1, 0x76, 0x1a, 0x41, 0x89, 0x46, 0xb1, 0xe3, 0xa7, 0x7b, 0x38, 0x0c, 0x75, 0x4d,
	0x49, 0xc7, 0x77, 0x13, 0x40, 0x18, 0xf0, 0x24, 0xb9, 0x4c, 0xe4, 0xff, 0xea, 0x9c, 0xb4,
	0xfe, 0x46, 0xcf, 0xe0, 0x2e, 0x15, 0xb5, 0xe9, 0x9b, 0xe7, 0x42, 0x3b, 0x3b, 0xdf, 0x55,
	0xd2, 0x1e, 0xa0, 0x00, 0xdb, 0xb9, 0x1b, 0x77, 0xb7, 0x06, 0x31, 0xc8, 0x67, 0xd8, 0x61,
	0x45, 0xcc, 0x1a, 0x3f, 0x01, 0xf8, 0xd8, 0x06, 0xd2, 0xcb, 0x76, 0xf5, 0xd2, 0x9d, 0x2c,
	0x79, 0xd5, 0x7d, 0xe6, 0x06, 0x98, 0x8c, 0x17, 0xe5, 0xc5, 0x11, 0xec, 0x39, 0x68, 0x32,
	0x8b, 0x66, 0x25, 0xd4, 0xf3, 0xb2, 0x4b, 0x88, 0xdf, 0x82, 0x9f, 0x17, 0x87, 0xb3, 0x44,
	0xdf, 0x9c, 0x1a, 0xd0, 0x13, 0x3a, 0xfc, 0xa9, 0x39, 0xe6, 0xa0, 0xf3, 0x82, 0x78, 0x26,
	0x3e, 0x79, 0xe3, 0xfa, 0x5c, 0x43, 0x55, 0xa0, 0x5b, 0x24, 0x4c, 0x63, 0x43, 0x80, 0x69,
	0x5e, 0x0c, 0x38, 0xcf, 0x82, 0x13, 0xb5, 0xbc, 0xaa, 0x40, 0x1d, 0x4d, 0x33, 0x1a, 0xfd,
	0x91, 0x6f, 0x4f, 0xc0, 0x71, 0x1d, 0xa1, 0x55, 0xf0, 0xa5, 0x64, 0x68, 0x08, 0x43, 0xda,
	0xa6, 0xd2, 0x23, 0xad, 0x41, 0xf5, 0xd9, 0xa8, 0x81, 0x1d, 0xd7, 0x92, 0xa5, 0xb4, 0x08,
	0x64, 0x96, 0x23, 0xac, 0xe3, 0xbf, 0x7d, 0x1c, 0x8f, 0x9f, 0x47, 0xc7, 0x71, 0xc2, 0x48,
	0x28, 0x5c, 0x47, 0x74, 0x8c, 0xbb, 0x8c, 0xde, 0xc3, 0xcd, 0x0e, 0x62, 0x9f, 0xbe, 0x9d,
	0xb5, 0x61, 0xfb, 0x2f, 0x72, 0x92, 0x62, 0x74, 0x2a, 0xda, 0x12};

static struct quic_crypto crypto;

static void quic_encrypt_done(struct sk_buff *skb, int err)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);

	WARN_ON(!skb_set_owner_sk_safe(skb, skb->sk));

	cb->number_len = 4;
	cb->number = 0;
	cb->number_offset = 17;
	cb->crypto_done = quic_encrypt_done;
	cb->resume = 1;
	quic_crypto_encrypt(&crypto, skb);
}

static void quic_decrypt_done(struct sk_buff *skb, int err)
{
	struct quic_crypto_cb *cb = QUIC_CRYPTO_CB(skb);

	WARN_ON(!skb_set_owner_sk_safe(skb, skb->sk));

	cb->number_len = 4;
	cb->number = 0;
	cb->number_offset = 17;
	cb->crypto_done = quic_decrypt_done;
	cb->resume = 1;
	quic_crypto_decrypt(&crypto, skb);
}

static void quic_crypto_test1(struct kunit *test)
{
	struct quic_conn_id conn_id, tmpid = {};
	struct quic_crypto_secret srt = {};
	struct sockaddr_in addr = {};
	struct sk_buff *skb;
	int ret, tokenlen;
	u8 token[72];

	srt.send = 1;
	memcpy(srt.secret, secret, 48);

	srt.type = 100;
	ret = quic_crypto_set_secret(&crypto, &srt, QUIC_VERSION_V1, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	srt.type = 0;
	ret = quic_crypto_set_secret(&crypto, &srt, QUIC_VERSION_V1, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	srt.type = TLS_CIPHER_AES_GCM_128;
	ret = quic_crypto_set_secret(&crypto, &srt, QUIC_VERSION_V1, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);

	srt.send = 0;
	srt.type = TLS_CIPHER_AES_GCM_128;
	ret = quic_crypto_set_secret(&crypto, &srt, QUIC_VERSION_V1, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = quic_crypto_key_update(&crypto);
	KUNIT_EXPECT_EQ(test, ret, 0);

	quic_conn_id_generate(&conn_id);
	quic_crypto_destroy(&crypto);
	ret = quic_crypto_initial_keys_install(&crypto, &conn_id, QUIC_VERSION_V1, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);

	quic_crypto_destroy(&crypto);
	ret = quic_crypto_initial_keys_install(&crypto, &conn_id, QUIC_VERSION_V2, 1);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = quic_crypto_generate_stateless_reset_token(&crypto, conn_id.data,
							 conn_id.len, token, 16);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = quic_crypto_generate_session_ticket_key(&crypto, conn_id.data,
						      conn_id.len, token, 16);
	KUNIT_EXPECT_EQ(test, ret, 0);

	addr.sin_port = htons(1234);
	token[0] = 1;
	ret = quic_crypto_generate_token(&crypto, &addr, sizeof(addr),
					 &conn_id, token, &tokenlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tokenlen, 1 + sizeof(addr) + 4 + conn_id.len + QUIC_TAG_LEN);

	ret = quic_crypto_verify_token(&crypto, &addr, sizeof(addr), &tmpid, token, tokenlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tmpid.len, conn_id.len);
	KUNIT_EXPECT_EQ(test, memcmp(tmpid.data, conn_id.data, tmpid.len), 0);

	skb = alloc_skb(296, GFP_ATOMIC);
	if (!skb)
		goto out;
	skb_put_data(skb, data, 280);

	ret = quic_crypto_get_retry_tag(&crypto, skb, &conn_id, QUIC_VERSION_V1, token);
	KUNIT_EXPECT_EQ(test, ret, 0);
	kfree_skb(skb);
out:
	quic_crypto_destroy(&crypto);
}

static void quic_crypto_test2(struct kunit *test)
{
	struct quic_crypto_secret srt = {};
	struct quic_crypto_cb *cb;
	struct socket *sock;
	struct sk_buff *skb;
	int err;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err)
		return;

	srt.send = 1;
	srt.level = 0;
	srt.type = TLS_CIPHER_AES_GCM_128;
	memcpy(srt.secret, secret, 48);
	if (quic_crypto_set_secret(&crypto, &srt, QUIC_VERSION_V1, 0))
		return;

	skb = alloc_skb(296, GFP_ATOMIC);
	if (!skb)
		goto out;
	WARN_ON(!skb_set_owner_sk_safe(skb, sock->sk));
	skb_reset_transport_header(skb);

	skb_put_data(skb, data, 280);
	cb = QUIC_CRYPTO_CB(skb);
	cb->number_len = 4;
	cb->number = 0;
	cb->number_offset = 17;
	cb->crypto_done = quic_encrypt_done;
	cb->resume = 0;
	err = quic_crypto_encrypt(&crypto, skb);
	if (err) {
		if (err != -EINPROGRESS)
			goto out;
		msleep(50);
	}

	KUNIT_EXPECT_EQ(test, memcmp(encrypted_data, skb->data, skb->len), 0);
	quic_crypto_destroy(&crypto);

	srt.send = 0;
	srt.level = 0;
	srt.type = TLS_CIPHER_AES_GCM_128;
	memcpy(srt.secret, secret, 48);
	if (quic_crypto_set_secret(&crypto, &srt, QUIC_VERSION_V1, 0))
		goto out;

	WARN_ON(!skb_set_owner_sk_safe(skb, sock->sk));
	cb->number_len = 4; /* unknown yet */
	cb->number = 0; /* unknown yet */
	cb->number_offset = 17;
	cb->crypto_done = quic_decrypt_done;
	cb->resume = 0;
	cb->length = skb->len - cb->number_offset;
	err = quic_crypto_decrypt(&crypto, skb);
	if (err) {
		if (err != -EINPROGRESS)
			goto out;
		msleep(50);
	}

	KUNIT_EXPECT_EQ(test, memcmp(data, skb->data, 280), 0);

out:
	kfree_skb(skb);
	quic_crypto_destroy(&crypto);
	sock_release(sock);
}

static void quic_cong_test1(struct kunit *test)
{
	struct quic_transport_param p = {};
	struct quic_cong cong = {};
	struct quic_config c = {};
	u32 time, ack_delay;

	p.max_ack_delay = 25000;
	p.ack_delay_exponent = 3;
	quic_cong_set_param(&cong, &p);

	c.initial_smoothed_rtt = 333000;
	quic_cong_set_config(&cong, &c);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 166500);
	KUNIT_EXPECT_EQ(test, cong.rto, 499500);

	quic_cong_set_time(&cong, jiffies_to_usecs(jiffies));
	time = quic_cong_time(&cong) - 30000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	/* (smoothed_rtt * 7 + adjusted_rtt) / 8 */
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 295125);
	/* (rttvar * 3 + rttvar_sample) / 4 */
	KUNIT_EXPECT_EQ(test, cong.rttvar, 191156);
	/* smoothed_rtt + rttvar */
	KUNIT_EXPECT_EQ(test, cong.rto, 486281);

	time = quic_cong_time(&cong) - 30000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 261984);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 201363);
	KUNIT_EXPECT_EQ(test, cong.rto, 463347);

	time = quic_cong_time(&cong) - 30000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 232986);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 201768);
	KUNIT_EXPECT_EQ(test, cong.rto, 434754);

	time = quic_cong_time(&cong) - 3000;
	ack_delay = 250;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 204237);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 201635);
	KUNIT_EXPECT_EQ(test, cong.rto, 405872);

	time = quic_cong_time(&cong) - 3000;
	ack_delay = 250;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 179082);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 195246);
	KUNIT_EXPECT_EQ(test, cong.rto, 374328);

	time = quic_cong_time(&cong) - 300;
	ack_delay = 25;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 300);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 300);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 156734);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 185543);
	KUNIT_EXPECT_EQ(test, cong.rto, 342277);

	time = quic_cong_time(&cong) - 30;
	ack_delay = 2;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 30);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 137146);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 173436);
	KUNIT_EXPECT_EQ(test, cong.rto, 310582);

	time = quic_cong_time(&cong) - 3;
	ack_delay = 0;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 120003);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 160077);
	KUNIT_EXPECT_EQ(test, cong.rto, 280080);

	time = quic_cong_time(&cong) - 1;
	ack_delay = 0;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 1);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 1);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 105002);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 146308);
	KUNIT_EXPECT_EQ(test, cong.rto, 251310);

	time = quic_cong_time(&cong) - 0;
	ack_delay = 0;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 0);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 0);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 91876);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 132700);
	KUNIT_EXPECT_EQ(test, cong.rto, 224576);

	time = quic_cong_time(&cong) - 3;
	ack_delay = 0;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 80391);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 119622);
	KUNIT_EXPECT_EQ(test, cong.rto, 200013);

	time = quic_cong_time(&cong) - 300;
	ack_delay = 25;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 300);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 70354);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 107280);
	KUNIT_EXPECT_EQ(test, cong.rto, 177634);

	time = quic_cong_time(&cong) - 300;
	ack_delay = 25;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 300);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 61572);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 95828);
	KUNIT_EXPECT_EQ(test, cong.rto, 157400);

	time = quic_cong_time(&cong) - 3000;
	ack_delay = 250;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 3);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 54000);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 85121);
	KUNIT_EXPECT_EQ(test, cong.rto, 139121);

	time = quic_cong_time(&cong) - 0;
	ack_delay = 0;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 0);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 0);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 47250);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 75653);
	KUNIT_EXPECT_EQ(test, cong.rto, 122903);

	time = quic_cong_time(&cong) - 0;
	ack_delay = 0;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 0);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 0);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 41343);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 67075);
	KUNIT_EXPECT_EQ(test, cong.rto, 108418);

	time = quic_cong_time(&cong) - 30000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 39925);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 52787);
	KUNIT_EXPECT_EQ(test, cong.rto, 100000);

	time = quic_cong_time(&cong) - 30000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 38684);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 41761);
	KUNIT_EXPECT_EQ(test, cong.rto, 100000);

	time = quic_cong_time(&cong) - 3000000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3000000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 406348);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 674733);
	KUNIT_EXPECT_EQ(test, cong.rto, 1081081);

	time = quic_cong_time(&cong) - 3000000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3000000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 728054);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 1069036);
	KUNIT_EXPECT_EQ(test, cong.rto, 1797090);

	time = quic_cong_time(&cong) - 3000000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 3000000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 1009547);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 1294390);
	KUNIT_EXPECT_EQ(test, cong.rto, 2303937);

	time = quic_cong_time(&cong) - 6000000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 6000000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 1630853);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 2058079);
	KUNIT_EXPECT_EQ(test, cong.rto, 3688932);

	time = quic_cong_time(&cong) - 10000000;
	ack_delay = 2500;
	quic_cong_rtt_update(&cong, time, ack_delay);
	KUNIT_EXPECT_EQ(test, cong.latest_rtt, 10000000);
	KUNIT_EXPECT_EQ(test, cong.min_rtt, 30000);
	KUNIT_EXPECT_EQ(test, cong.smoothed_rtt, 2674496);
	KUNIT_EXPECT_EQ(test, cong.rttvar, 3369935);
	KUNIT_EXPECT_EQ(test, cong.rto, 6000000);
}

static void quic_cong_test2(struct kunit *test)
{
	struct quic_transport_param p = {};
	struct quic_cong cong = {};
	struct quic_config c = {};
	u32 time, bytes;

	p.max_data = 106496;
	p.max_ack_delay = 25000;
	p.ack_delay_exponent = 3;
	quic_cong_set_param(&cong, &p);

	quic_cong_set_mss(&cong, 1400);
	quic_cong_set_window(&cong, 14720);

	c.congestion_control_algo = QUIC_CONG_ALG_RENO;
	c.initial_smoothed_rtt = 333000;
	quic_cong_set_config(&cong, &c);

	KUNIT_EXPECT_EQ(test, cong.mss, 1400);
	KUNIT_EXPECT_EQ(test, cong.window, 14720);
	KUNIT_EXPECT_EQ(test, cong.max_window, 106496);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, U32_MAX);

	quic_cong_set_time(&cong, jiffies_to_usecs(jiffies));
	/* slow_start:  cwnd increases by bytes after SACK */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 16120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 7000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 23120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 14000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 37120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 28000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 65120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 56000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 106496);

	/* slow_start -> recovery: go to recovery after one loss */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 53248);
	KUNIT_EXPECT_EQ(test, cong.window, 53248);

	/* recovery: no cwnd update after more loss */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 53248);
	KUNIT_EXPECT_EQ(test, cong.window, 53248);

	/* recovery -> cong_avoid: go to cong_avoid after SACK if recovery_time < time */
	msleep(20);
	quic_cong_set_time(&cong, jiffies_to_usecs(jiffies));
	time = quic_cong_time(&cong);
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);

	/* cong_avoid: cwnd increase by 'mss * bytes / cwnd' after SACK */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 53284);

	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 53320);

	/* cong_avoid -> recovery: go back to recovery after one loss */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 26660);
	KUNIT_EXPECT_EQ(test, cong.window, 26660);

	/* recovery: no update after SACK if recovery_time >= time */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.window, 26660);

	/* recovery -> slow_start: go back to start if in persistent congestion */
	time = quic_cong_time(&cong) - 5000000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 26660);
	KUNIT_EXPECT_EQ(test, cong.window, 2800);

	time = quic_cong_time(&cong) - 300000;
	bytes = 20000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 22800);

	/* slow_start -> recovery: go to recovery after ECN */
	quic_cong_on_process_ecn(&cong);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 11400);
	KUNIT_EXPECT_EQ(test, cong.window, 11400);

	/* recovery: no update after ECN */
	quic_cong_on_process_ecn(&cong);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.window, 11400);

	/* recovery -> cong_avoid: go to cong_avoid after SACK if recovery_time < time */
	time = quic_cong_time(&cong) + 20;
	quic_cong_set_time(&cong, time);
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);

	/* cong_avoid -> slow_start: go back to start if in persistent congestion */
	time = quic_cong_time(&cong) - 5000000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 11400);
	KUNIT_EXPECT_EQ(test, cong.window, 2800);

	/* slow_start -> cong_avoid: go to cong_void after SACK if cwnd > ssthresh */
	time = quic_cong_time(&cong) - 300000;
	bytes = 10532;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 13332);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 11400);

	/* cong_avoid -> recovery: go back to recovery after ECN */
	quic_cong_on_process_ecn(&cong);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.window, 6666);
}

static void quic_cong_test3(struct kunit *test)
{
	struct quic_transport_param p = {};
	struct quic_cong cong = {};
	struct quic_config c = {};
	u32 time, bytes;
	u64 number;

	p.max_data = 106496;
	p.max_ack_delay = 25000;
	p.ack_delay_exponent = 3;
	quic_cong_set_param(&cong, &p);

	quic_cong_set_mss(&cong, 1400);
	quic_cong_set_window(&cong, 14720);

	c.congestion_control_algo = QUIC_CONG_ALG_CUBIC;
	c.initial_smoothed_rtt = 333000;
	quic_cong_set_config(&cong, &c);

	KUNIT_EXPECT_EQ(test, cong.mss, 1400);
	KUNIT_EXPECT_EQ(test, cong.window, 14720);
	KUNIT_EXPECT_EQ(test, cong.max_window, 106496);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, U32_MAX);

	quic_cong_set_time(&cong, jiffies_to_usecs(jiffies));
	/* slow_start:  cwnd increases by bytes after SACK */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 16120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 7000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 23120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 14000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 37120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 28000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 65120);

	time = quic_cong_time(&cong) - 300000;
	bytes = 56000;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.window, 106496);

	/* slow_start -> recovery: go to recovery after one loss */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 74547);
	KUNIT_EXPECT_EQ(test, cong.window, 74547);

	/* recovery: no cwnd update after more loss */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 74547);
	KUNIT_EXPECT_EQ(test, cong.window, 74547);

	/* recovery -> cong_avoid: go to cong_avoid after SACK if recovery_time < time */
	time = quic_cong_time(&cong) + 20;
	quic_cong_set_time(&cong, time);
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);

	/* cong_avoid: cwnd increase in Reno-friendly after SACK */
	time = quic_cong_time(&cong) + 100000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74547 + 2);

	time = quic_cong_time(&cong) + 100000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74547 + 2 + 5);

	time = quic_cong_time(&cong) + 100000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74547 + 2 + 5 + 8);

	time = quic_cong_time(&cong) + 100000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74547 + 2 + 5 + 8 + 11);

	time = quic_cong_time(&cong) + 100000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74547 + 2 + 5 + 8 + 11 + 14); /* 74587 */

	/* cong_avoid: cwnd increase in concave/Convex after SACK */
	time = quic_cong_time(&cong) + 100000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74587 + 126);

	time = quic_cong_time(&cong) + 5000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74587 + 126 + 136);

	time = quic_cong_time(&cong) + 5000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74587 + 126 + 136 + 142);

	time = quic_cong_time(&cong) + 5000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74587 + 126 + 136 + 142 + 149);

	time = quic_cong_time(&cong) + 5000;
	quic_cong_set_time(&cong, time);
	bytes = 8400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 74587 + 126 + 136 + 142 + 149 + 156); /* 75296 */

	/* cong_avoid -> recovery: go back to recovery after one loss */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 52707);
	KUNIT_EXPECT_EQ(test, cong.window, 52707);

	/* recovery: no update after SACK if recovery_time >= time */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	quic_cong_on_packet_acked(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.window, 52707);

	/* recovery -> slow_start: go back to start if in persistent congestion */
	time = quic_cong_time(&cong) - 5000000;
	bytes = 1400;
	quic_cong_on_packet_lost(&cong, time, bytes, 0);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.ssthresh, 52707);
	KUNIT_EXPECT_EQ(test, cong.window, 2800);

	/* test hystart++ */
	time = quic_cong_time(&cong) - 300000;
	bytes = 1400;
	number = 100;
	quic_cong_on_packet_sent(&cong, time, bytes, number);
	/*
	 * cubic->window_end = 100;
	 * cubic->last_round_min_rtt = U32_MAX;
	 * cubic->rtt_sample_count = 0;
	 */
	quic_cong_rtt_update(&cong, time, 0);
	/*
	 * cubic->current_round_min_rtt = 300000
	 * cubic->css_baseline_min_rtt = U32_MAX;
	 * cubic->css_rounds = 0;
	 * cubic->rtt_sample_count = 1;
	 */
	time = quic_cong_time(&cong) - 300000;
	bytes = 14000;
	number = 100;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 16800);

	/* new round */
	time = quic_cong_time(&cong) - 500000;
	bytes = 1400;
	number = 110;
	quic_cong_on_packet_sent(&cong, time, bytes, number);
	/*
	 * cubic->window_end = 110;
	 * cubic->last_round_min_rtt = cubic->current_round_min_rtt;
	 * cubic->rtt_sample_count = 0;
	 */
	quic_cong_rtt_update(&cong, time, 0);
	/*
	 * cubic->current_round_min_rtt = 500000
	 * cubic->css_baseline_min_rtt = U32_MAX;
	 * cubic->css_rounds = 0;
	 * cubic->rtt_sample_count = 1;
	 */
	time = quic_cong_time(&cong) - 500000;
	bytes = 14000;
	number = 101;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 30800);

	/* in CSS */
	quic_cong_rtt_update(&cong, time, 0);
	quic_cong_rtt_update(&cong, time, 0);
	quic_cong_rtt_update(&cong, time, 0);
	quic_cong_rtt_update(&cong, time, 0);
	quic_cong_rtt_update(&cong, time, 0);
	quic_cong_rtt_update(&cong, time, 0);
	quic_cong_rtt_update(&cong, time, 0);
	/* cubic->rtt_sample_count = 8, and enter CSS */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 102;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 35600);
	/* cubic->css_baseline_min_rtt = 500000 */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 103;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 36800);
	/* cubic->rtt_sample_count = 1 */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 104;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 38000);
	/* cubic->rtt_sample_count = 2 */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 104;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 39200);
	/* cubic->rtt_sample_count = 3 */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 105;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 40400);
	/* cubic->rtt_sample_count = 4 */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 106;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_SLOW_START);
	KUNIT_EXPECT_EQ(test, cong.window, 41600);
	/* cubic->rtt_sample_count = 5 */

	 /* slow_start -> cong_avoid: go to cong_void after SACK if cwnd > ssthresh */
	time = quic_cong_time(&cong) - 500000;
	bytes = 4800;
	number = 107;
	quic_cong_on_packet_acked(&cong, time, bytes, number);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, cong.window, 42800);
	/* cubic->rtt_sample_count = 6 */

	/* cong_avoid -> recovery: go back to recovery after ECN */
	quic_cong_on_process_ecn(&cong);
	KUNIT_EXPECT_EQ(test, cong.state, QUIC_CONG_RECOVERY_PERIOD);
	KUNIT_EXPECT_EQ(test, cong.window, 29960);
}

static struct kunit_case quic_test_cases[] = {
	KUNIT_CASE(quic_pnspace_test1),
	KUNIT_CASE(quic_pnspace_test2),
	KUNIT_CASE(quic_crypto_test1),
	KUNIT_CASE(quic_crypto_test2),
	KUNIT_CASE(quic_cong_test1),
	KUNIT_CASE(quic_cong_test2),
	KUNIT_CASE(quic_cong_test3),
	{}
};

static struct kunit_suite quic_test_suite = {
	.name = "quic",
	.test_cases = quic_test_cases,
};

kunit_test_suite(quic_test_suite);

MODULE_DESCRIPTION("Test QUIC Kernel API functions");
MODULE_LICENSE("GPL");
