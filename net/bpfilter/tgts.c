// SPDX-License-Identifier: GPL-2.0
#include <sys/socket.h>
#include "bpfilter_mod.h"

struct bpfilter_target std_tgt = {
	.name = BPFILTER_STANDARD_TARGET,
	.family = BPFILTER_PROTO_IPV4,
	.size = sizeof(int),
};

struct bpfilter_target err_tgt = {
	.name = BPFILTER_ERROR_TARGET,
	.family = BPFILTER_PROTO_IPV4,
	.size = BPFILTER_FUNCTION_MAXNAMELEN,
};

int bpfilter_ipv4_register_targets(void)
{
	int err = bpfilter_target_add(&std_tgt);

	if (err)
		return err;
	return bpfilter_target_add(&err_tgt);
}

