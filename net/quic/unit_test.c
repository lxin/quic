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

#include <linux/delay.h>
#include <kunit/test.h>
#include "pnmap.h"

static void quic_pnmap_test1(struct kunit *test)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	struct quic_pnmap _map = {}, *map = &_map;
	int i;

	KUNIT_ASSERT_EQ(test, 0, quic_pnmap_init(map));
	quic_pnmap_set_max_record_ts(map, 30000);

	KUNIT_EXPECT_EQ(test, map->base_pn, QUIC_PN_MAP_BASE_PN);
	KUNIT_EXPECT_EQ(test, map->min_pn_seen, map->base_pn + QUIC_PN_MAP_SIZE);
	KUNIT_EXPECT_EQ(test, map->len, QUIC_PN_MAP_INITIAL);

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, -1));
	KUNIT_EXPECT_EQ(test, -ENOMEM, quic_pnmap_mark(map, QUIC_PN_MAP_SIZE + 1));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 0));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 1));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 2));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 3));
	KUNIT_EXPECT_EQ(test, 4, map->base_pn);
	KUNIT_EXPECT_EQ(test, 3, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 0, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 3, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 4));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 6));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 9));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 13));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 18));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 24));
	KUNIT_EXPECT_EQ(test, 5, map->base_pn);
	KUNIT_EXPECT_EQ(test, 4, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 0, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 24, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 5, quic_pnmap_num_gabs(map, gabs));
	KUNIT_EXPECT_EQ(test, 6, gabs[0].start + map->base_pn);
	KUNIT_EXPECT_EQ(test, 6, gabs[0].end + map->base_pn);
	KUNIT_EXPECT_EQ(test, 8, gabs[1].start + map->base_pn);
	KUNIT_EXPECT_EQ(test, 9, gabs[1].end + map->base_pn);
	KUNIT_EXPECT_EQ(test, 11, gabs[2].start + map->base_pn);
	KUNIT_EXPECT_EQ(test, 13, gabs[2].end + map->base_pn);
	KUNIT_EXPECT_EQ(test, 15, gabs[3].start + map->base_pn);
	KUNIT_EXPECT_EQ(test, 18, gabs[3].end + map->base_pn);
	KUNIT_EXPECT_EQ(test, 20, gabs[4].start + map->base_pn);
	KUNIT_EXPECT_EQ(test, 24, gabs[4].end + map->base_pn);

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 7));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 8));
	KUNIT_EXPECT_EQ(test, 5, map->base_pn);
	KUNIT_EXPECT_EQ(test, 4, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 4, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 5));
	KUNIT_EXPECT_EQ(test, 10, map->base_pn);
	KUNIT_EXPECT_EQ(test, 9, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 3, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 15));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 16));
	KUNIT_EXPECT_EQ(test, 10, map->base_pn);
	KUNIT_EXPECT_EQ(test, 9, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 4, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 14));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 17));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 10));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 11));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 12));
	KUNIT_EXPECT_EQ(test, 19, map->base_pn);
	KUNIT_EXPECT_EQ(test, 18, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 128));
	KUNIT_EXPECT_EQ(test, 19, map->base_pn);
	KUNIT_EXPECT_EQ(test, 18, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 0, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 128, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 128 + QUIC_PN_MAP_INITIAL, map->len);
	KUNIT_EXPECT_EQ(test, 2, quic_pnmap_num_gabs(map, gabs));

	/* ! map->max_pn_seen <= map->last_max_pn_seen + QUIC_PN_MAP_SIZE / 2 */
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 610));
	KUNIT_EXPECT_EQ(test, 19, map->base_pn);
	KUNIT_EXPECT_EQ(test, 18, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 0, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 610, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 610, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 640 + QUIC_PN_MAP_INITIAL, map->len);
	KUNIT_EXPECT_EQ(test, 3, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 611));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 612));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 650));
	KUNIT_EXPECT_EQ(test, 19, map->base_pn);
	KUNIT_EXPECT_EQ(test, 18, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 650, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 610, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 640 + QUIC_PN_MAP_INITIAL, map->len);
	KUNIT_EXPECT_EQ(test, 4, quic_pnmap_num_gabs(map, gabs));

	/* ! map->max_pn_seen <= map->base_pn + QUIC_PN_MAP_SIZE * 3 / 4 */
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 810));
	KUNIT_EXPECT_EQ(test, 613, map->base_pn);
	KUNIT_EXPECT_EQ(test, 612, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 810, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 810, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 832 + QUIC_PN_MAP_INITIAL, map->len);
	KUNIT_EXPECT_EQ(test, 2, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 825));
	KUNIT_EXPECT_EQ(test, 613, map->base_pn);
	KUNIT_EXPECT_EQ(test, 612, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 825, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 810, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 832 + QUIC_PN_MAP_INITIAL, map->len);
	KUNIT_EXPECT_EQ(test, 3, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 824));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 823));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 812));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 811));
	KUNIT_EXPECT_EQ(test, 613, map->base_pn);
	KUNIT_EXPECT_EQ(test, 612, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 825, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 810, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 832 + QUIC_PN_MAP_INITIAL, map->len);
	KUNIT_EXPECT_EQ(test, 3, quic_pnmap_num_gabs(map, gabs));

	for (i = 1; i <= 128; i++)
		KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 256 * i));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, QUIC_PN_MAP_SIZE + 1));
	KUNIT_EXPECT_EQ(test, -ENOMEM, quic_pnmap_mark(map, map->base_pn + QUIC_PN_MAP_SIZE + 1));

	quic_pnmap_free(map);
	KUNIT_EXPECT_EQ(test, map->len, 0);
}

static void quic_pnmap_test2(struct kunit *test)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAX_GABS];
	struct quic_pnmap _map = {}, *map = &_map;

	KUNIT_ASSERT_EQ(test, 0, quic_pnmap_init(map));
	quic_pnmap_set_max_record_ts(map, 30000);

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 3));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 4));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 6));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 2));
	KUNIT_EXPECT_EQ(test, 0, map->base_pn);
	KUNIT_EXPECT_EQ(test, -1, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 2, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_num_gabs(map, gabs));

	msleep(50);
	/* ! current_ts - map->last_max_pn_ts < map->max_record_ts */
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 5));
	KUNIT_EXPECT_EQ(test, 7, map->base_pn);
	KUNIT_EXPECT_EQ(test, 2, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 6, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 8));
	KUNIT_EXPECT_EQ(test, 7, map->base_pn);
	KUNIT_EXPECT_EQ(test, 2, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 6, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 6, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 7));
	KUNIT_EXPECT_EQ(test, 9, map->base_pn);
	KUNIT_EXPECT_EQ(test, 2, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 6, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 11));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 10));
	KUNIT_EXPECT_EQ(test, 9, map->base_pn);
	KUNIT_EXPECT_EQ(test, 2, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 6, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 11, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_num_gabs(map, gabs));

	msleep(50);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 18));
	KUNIT_EXPECT_EQ(test, 9, map->base_pn);
	KUNIT_EXPECT_EQ(test, 6, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 8, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 18, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 9));
	KUNIT_EXPECT_EQ(test, 12, map->base_pn);
	KUNIT_EXPECT_EQ(test, 6, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 11, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 18, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_num_gabs(map, gabs));

	msleep(50);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 17));
	KUNIT_EXPECT_EQ(test, 19, map->base_pn);
	KUNIT_EXPECT_EQ(test, 18, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 18, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 19));
	KUNIT_EXPECT_EQ(test, 20, map->base_pn);
	KUNIT_EXPECT_EQ(test, 19, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 19, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 25));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 26));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 30));
	KUNIT_EXPECT_EQ(test, 20, map->base_pn);
	KUNIT_EXPECT_EQ(test, 19, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 30, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnmap_num_gabs(map, gabs));

	msleep(50);
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_mark(map, 29));
	KUNIT_EXPECT_EQ(test, 20, map->base_pn);
	KUNIT_EXPECT_EQ(test, 19, map->cum_ack_point);
	KUNIT_EXPECT_EQ(test, 30, map->max_pn_seen);
	KUNIT_EXPECT_EQ(test, 18, map->min_pn_seen);
	KUNIT_EXPECT_EQ(test, 30, map->last_max_pn_seen);
	KUNIT_EXPECT_EQ(test, 2, quic_pnmap_num_gabs(map, gabs));

	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_check(map, 29));
	KUNIT_EXPECT_EQ(test, 1, quic_pnmap_check(map, 19));
	KUNIT_EXPECT_EQ(test, 0, quic_pnmap_check(map, 35));
	KUNIT_EXPECT_EQ(test, -1, quic_pnmap_check(map, map->base_pn + QUIC_PN_MAP_SIZE));

	quic_pnmap_free(map);
	KUNIT_EXPECT_EQ(test, map->len, 0);
}

static struct kunit_case quic_test_cases[] = {
	KUNIT_CASE(quic_pnmap_test1),
	KUNIT_CASE(quic_pnmap_test2),
	{}
};

static struct kunit_suite quic_test_suite = {
	.name = "quic",
	.test_cases = quic_test_cases,
};

kunit_test_suite(quic_test_suite);

MODULE_DESCRIPTION("Test QUIC Kernel API functions");
MODULE_LICENSE("GPL");
