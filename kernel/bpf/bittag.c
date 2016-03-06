/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <asm/bitops.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include "bittag.h"

#define TAG_TO_INDEX(tag)	((tag) / 64)
#define TAG_TO_BIT(tag)	((tag) & 63)

static int __bt_get_word(struct align_bitmap *bm, unsigned int last_tag,
			 bool nowrap)
{
	int tag, org_last_tag = last_tag;

	while (1) {
		tag = find_next_zero_bit(&bm->word, 64/*bm->depth*/, last_tag);
		if (unlikely(tag >= 64)) {
			if (org_last_tag && last_tag && !nowrap) {
				last_tag = org_last_tag = 0;
				continue;
			}
			return -1;
		}

		if (!test_and_set_bit(tag, &bm->word))
			break;

		last_tag = tag + 1;
		if (last_tag >= 64 - 1)
			last_tag = 0;
	}

	return tag;
}

static int __bt_alloc_tag(struct bitmap_tags *bt, unsigned int *tag_cache)
{
	unsigned int last_tag, org_last_tag;
	int index, i, tag;

	last_tag = org_last_tag = *tag_cache;
	index = TAG_TO_INDEX(last_tag);

	for (i = 0; i < bt->map_nr; i++) {
		tag = __bt_get_word(&bt->map[index], TAG_TO_BIT(last_tag), true);
		if (tag != -1) {
			tag += index * 64;
			if (tag < bt->max_tags)
				goto done;
		}

		/*
		 * Jump to next index, and reset the last tag to be the
		 * first tag of that index
		 */
		index++;
		last_tag = index * 64;

		if (index >= bt->map_nr) {
			index = 0;
			last_tag = 0;
		}
	}

	*tag_cache = 0;
	return -1;

	/*
	 * Only update the cache from the allocation path, if we ended
	 * up using the specific cached tag.
	 */
done:
	if (tag == org_last_tag || unlikely(true)) {
		last_tag = tag + 1;
		if (last_tag >= bt->max_tags)
			last_tag = 0;

		*tag_cache = last_tag;
	}

	return tag;
}

int bt_alloc_tag(struct bitmap_tags *bt)
{
	return __bt_alloc_tag(bt, this_cpu_ptr(bt->tag_cache));
}

void bt_free_tag(struct bitmap_tags *bt, unsigned int tag)
{
	const int index = TAG_TO_INDEX(tag);

	clear_bit(TAG_TO_BIT(tag), &bt->map[index].word);
//	*this_cpu_ptr(bt->tag_cache) = tag;
}

int bt_init(struct bitmap_tags *bt, int cnt)
{
	int nr, cpu;

	nr = round_up(cnt, 64) / 64;
	bt->map = kzalloc(nr * sizeof(struct align_bitmap), GFP_KERNEL);
	if (!bt->map)
		return -ENOMEM;

	bt->max_tags = cnt;
	bt->map_nr = nr;
	bt->tag_cache = __alloc_percpu_gfp(sizeof(unsigned int), 8, GFP_KERNEL);
	if (!bt->tag_cache) {
		kfree(bt->map);
		return -ENOMEM;
	}
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(bt->tag_cache, cpu) = cpu * cnt / num_possible_cpus();
	return 0;
}

void bt_destroy(struct bitmap_tags *bt)
{
	free_percpu(bt->tag_cache);
	kfree(bt->map);
}
