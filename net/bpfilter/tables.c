// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <string.h>

#include <sys/socket.h>

#include <linux/hashtable.h>

#include "bpfilter_mod.h"

static unsigned int full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned int hash = 0;
	int i;

	for (i = 0; i < len; i++)
		hash ^= *(name + i);
	return hash;
}

DEFINE_HASHTABLE(bpfilter_tables, 4);
//DEFINE_MUTEX(bpfilter_table_mutex);

struct bpfilter_table *bpfilter_table_get_by_name(const char *name, int name_len)
{
	unsigned int hval = full_name_hash(NULL, name, name_len);
	struct bpfilter_table *tbl;

//	mutex_lock(&bpfilter_table_mutex);
	hash_for_each_possible(bpfilter_tables, tbl, hash, hval) {
		if (!strcmp(name, tbl->name)) {
			tbl->hold++;
			goto out;
		}
	}
	tbl = NULL;
out:
//	mutex_unlock(&bpfilter_table_mutex);
	return tbl;
}

void bpfilter_table_put(struct bpfilter_table *tbl)
{
//	mutex_lock(&bpfilter_table_mutex);
	tbl->hold--;
//	mutex_unlock(&bpfilter_table_mutex);
}

int bpfilter_table_add(struct bpfilter_table *tbl)
{
	unsigned int hval = full_name_hash(NULL, tbl->name, strlen(tbl->name));
	struct bpfilter_table *srch;

//	mutex_lock(&bpfilter_table_mutex);
	hash_for_each_possible(bpfilter_tables, srch, hash, hval) {
		if (!strcmp(srch->name, tbl->name))
			goto exists;
	}
	hash_add(bpfilter_tables, &tbl->hash, hval);
//	mutex_unlock(&bpfilter_table_mutex);

	return 0;

exists:
//	mutex_unlock(&bpfilter_table_mutex);
	return -EEXIST;
}

void bpfilter_tables_init(void)
{
	hash_init(bpfilter_tables);
}

