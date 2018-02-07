// SPDX-License-Identifier: GPL-2.0
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>

#include <linux/bitops.h>

#include "bpfilter_mod.h"

unsigned int __sw_hweight32(unsigned int w)
{
	w -= (w >> 1) & 0x55555555;
	w =  (w & 0x33333333) + ((w >> 2) & 0x33333333);
	w =  (w + (w >> 4)) & 0x0f0f0f0f;
	return (w * 0x01010101) >> 24;
}

struct bpfilter_table_info *bpfilter_ipv4_table_alloc(struct bpfilter_table *tbl,
						      __u32 size_ents)
{
	unsigned int num_hooks = hweight32(tbl->valid_hooks);
	struct bpfilter_table_info *info;
	unsigned int size, alloc_size;

	size  = sizeof(struct bpfilter_ipt_standard) * num_hooks;
	size += sizeof(struct bpfilter_ipt_error);
	size += size_ents;

	alloc_size = size + sizeof(struct bpfilter_table_info);

	info = malloc(alloc_size);
	if (info) {
		memset(info, 0, alloc_size);
		info->size = size;
	}
	return info;
}

struct bpfilter_table_info *bpfilter_ipv4_table_finalize(struct bpfilter_table *tbl,
							 struct bpfilter_table_info *info,
							 __u32 size_ents, __u32 num_ents)
{
	unsigned int num_hooks = hweight32(tbl->valid_hooks);
	struct bpfilter_ipt_standard *tgts;
	struct bpfilter_ipt_error *term;
	struct bpfilter_ipt_entry *ent;
	unsigned int mask, offset, h, i;

	info->num_entries = num_ents + num_hooks + 1;

	ent  = (struct bpfilter_ipt_entry *)(info + 1);
	tgts = (struct bpfilter_ipt_standard *)((u8 *)ent + size_ents);
	term = (struct bpfilter_ipt_error *)(tgts + num_hooks);

	mask = tbl->valid_hooks;
	offset = 0;
	h = 0;
	i = 0;
	while (mask) {
		struct bpfilter_ipt_standard *t;

		if (!(mask & 1))
			goto next;

		info->hook_entry[h] = offset;
		info->underflow[h] = offset;
		t = &tgts[i++];
		*t = (struct bpfilter_ipt_standard)
			BPFILTER_IPT_STANDARD_INIT(BPFILTER_NF_ACCEPT);
		t->target.target.u.kernel.target =
			bpfilter_target_get_by_name(t->target.target.u.user.name);
		if (!t->target.target.u.kernel.target)
			goto out_fail;

		offset += sizeof(struct bpfilter_ipt_standard);
	next:
		mask >>= 1;
		h++;
	}
	*term = (struct bpfilter_ipt_error) BPFILTER_IPT_ERROR_INIT;
	term->target.target.u.kernel.target =
		bpfilter_target_get_by_name(term->target.target.u.user.name);
	if (!term->target.target.u.kernel.target) {
out_fail:
		free(info);
		return NULL;
	}
	return info;
}
