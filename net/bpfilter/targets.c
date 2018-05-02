// SPDX-License-Identifier: GPL-2.0
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include "bpfilter_mod.h"

//DEFINE_MUTEX(bpfilter_target_mutex);
static LIST_HEAD(bpfilter_targets);

struct bpfilter_target *bpfilter_target_get_by_name(const char *name)
{
	struct bpfilter_target *tgt;

//	mutex_lock(&bpfilter_target_mutex);
	list_for_each_entry(tgt, &bpfilter_targets, all_target_list) {
		if (!strcmp(tgt->name, name)) {
			tgt->hold++;
			goto out;
		}
	}
	tgt = NULL;
out:
//	mutex_unlock(&bpfilter_target_mutex);
	return tgt;
}

void bpfilter_target_put(struct bpfilter_target *tgt)
{
//	mutex_lock(&bpfilter_target_mutex);
	tgt->hold--;
//	mutex_unlock(&bpfilter_target_mutex);
}

int bpfilter_target_add(struct bpfilter_target *tgt)
{
	struct bpfilter_target *srch;

//	mutex_lock(&bpfilter_target_mutex);
	list_for_each_entry(srch, &bpfilter_targets, all_target_list) {
		if (!strcmp(srch->name, tgt->name))
			goto exists;
	}
	list_add_tail(&tgt->all_target_list, &bpfilter_targets);
//	mutex_unlock(&bpfilter_target_mutex);
	return 0;

exists:
//	mutex_unlock(&bpfilter_target_mutex);
	return -EEXIST;
}

