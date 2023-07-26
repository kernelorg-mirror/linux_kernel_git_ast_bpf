// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>

#include "ptr32.skel.h"

static void test_ptr32_basic(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);
	struct ptr32 *skel;
	int ret;

	skel = ptr32__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rbtree__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.ptr32_basic), &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");

	ptr32__destroy(skel);
}

void test_ptr32_success(void)
{
	if (test__start_subtest("ptr32_basic"))
		test_ptr32_basic();
}

