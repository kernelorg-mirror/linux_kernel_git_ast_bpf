/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPFILTER_INTERNAL_H
#define _LINUX_BPFILTER_INTERNAL_H

#include "include/uapi/linux/bpfilter.h"
#include <linux/list.h>

struct bpfilter_table {
	struct hlist_node	hash;
	u32			valid_hooks;
	struct			bpfilter_table_info *info;
	int			hold;
	u8			family;
	int			priority;
	const char		name[BPFILTER_XT_TABLE_MAXNAMELEN];
};

struct bpfilter_table_info {
	unsigned int		size;
	u32			num_entries;
	unsigned int		initial_entries;
	unsigned int		hook_entry[BPFILTER_INET_HOOK_MAX];
	unsigned int		underflow[BPFILTER_INET_HOOK_MAX];
	unsigned int		stacksize;
	void			***jumpstack;
	unsigned char		entries[0] __aligned(8);
};

struct bpfilter_table *bpfilter_table_get_by_name(const char *name, int name_len);
void bpfilter_table_put(struct bpfilter_table *tbl);
int bpfilter_table_add(struct bpfilter_table *tbl);

struct bpfilter_ipt_standard {
	struct bpfilter_ipt_entry	entry;
	struct bpfilter_standard_target	target;
};

struct bpfilter_ipt_error {
	struct bpfilter_ipt_entry	entry;
	struct bpfilter_error_target	target;
};

#define BPFILTER_IPT_ENTRY_INIT(__sz) 				\
{								\
	.target_offset = sizeof(struct bpfilter_ipt_entry),	\
	.next_offset = (__sz),					\
}

#define BPFILTER_IPT_STANDARD_INIT(__verdict) 					\
{										\
	.entry = BPFILTER_IPT_ENTRY_INIT(sizeof(struct bpfilter_ipt_standard)),	\
	.target = BPFILTER_TARGET_INIT(BPFILTER_STANDARD_TARGET,		\
				       sizeof(struct bpfilter_standard_target)),\
	.target.verdict = -(__verdict) - 1,					\
}

#define BPFILTER_IPT_ERROR_INIT							\
{										\
	.entry = BPFILTER_IPT_ENTRY_INIT(sizeof(struct bpfilter_ipt_error)),	\
	.target = BPFILTER_TARGET_INIT(BPFILTER_ERROR_TARGET,			\
				       sizeof(struct bpfilter_error_target)),	\
	.target.error_name = "ERROR",						\
}

struct bpfilter_target {
	struct list_head	all_target_list;
	const char		name[BPFILTER_EXTENSION_MAXNAMELEN];
	unsigned int		size;
	int			hold;
	u16			family;
	u8			rev;
};

struct bpfilter_target *bpfilter_target_get_by_name(const char *name);
void bpfilter_target_put(struct bpfilter_target *tgt);
int bpfilter_target_add(struct bpfilter_target *tgt);

struct bpfilter_table_info *bpfilter_ipv4_table_ctor(struct bpfilter_table *tbl);
int bpfilter_ipv4_register_targets(void);
void bpfilter_tables_init(void);
int bpfilter_get_info(void *addr, int len);
int bpfilter_get_entries(void *cmd, int len);
int bpfilter_ipv4_init(void);

int copy_from_user(void *dst, void *addr, int len);
int copy_to_user(void *addr, const void *src, int len);
#define put_user(x, ptr) \
({ \
	__typeof__(*(ptr)) __x = (x); \
	copy_to_user(ptr, &__x, sizeof(*(ptr))); \
})
extern int pid;
extern int debug_fd;
#define ENOTSUPP        524

#endif
