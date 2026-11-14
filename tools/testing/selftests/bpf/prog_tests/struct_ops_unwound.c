// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "struct_ops_unwound.skel.h"

static int call_test_1(struct struct_ops_unwound *skel, __u64 arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts, .ctx_in = &arg, .ctx_size_in = sizeof(arg));

	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.call_test_1), &opts), "run");
	return opts.retval;
}

void test_struct_ops_unwound(void)
{
	struct struct_ops_unwound *skel;
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	skel = struct_ops_unwound__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (!ASSERT_OK(bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.st_ops_map), &info, &len),
		       "info"))
		goto out;
	skel->bss->st_ops_id = info.id;
	if (!ASSERT_OK(struct_ops_unwound__attach(skel), "attach"))
		goto out;

	ASSERT_EQ(call_test_1(skel, 0), 7, "returns");
	ASSERT_EQ(call_test_1(skel, 1), 1 << 16 | 5, "bpf_throw");
out:
	struct_ops_unwound__destroy(skel);
}
