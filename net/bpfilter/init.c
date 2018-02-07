// SPDX-License-Identifier: GPL-2.0
#include <errno.h>

#include <sys/socket.h>

#include "bpfilter_mod.h"

static struct bpfilter_table filter_table_ipv4 = {
	.name		= "filter",
	.valid_hooks	= ((1<<BPFILTER_INET_HOOK_LOCAL_IN) |
			   (1<<BPFILTER_INET_HOOK_FORWARD) |
			   (1<<BPFILTER_INET_HOOK_LOCAL_OUT)),
	.family		= BPFILTER_PROTO_IPV4,
	.priority	= BPFILTER_IP_PRI_FILTER,
};

int bpfilter_ipv4_init(void)
{
	struct bpfilter_table *t = &filter_table_ipv4;
	struct bpfilter_table_info *info;
	int err;

	err = bpfilter_ipv4_register_targets();
	if (err)
		return err;

	info = bpfilter_ipv4_table_alloc(t, 0);
	if (!info)
		return -ENOMEM;
	info = bpfilter_ipv4_table_finalize(t, info, 0, 0);
	if (!info)
		return -ENOMEM;
	t->info = info;
	return bpfilter_table_add(&filter_table_ipv4);
}

