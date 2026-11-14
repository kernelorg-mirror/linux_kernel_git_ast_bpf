// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

int st_ops_id;

/* The pad that ends the invocation tells the struct_ops. The cookie waits in the stack. */
SEC("struct_ops")
int BPF_PROG(test_1, struct st_ops_args *args)
{
	if (args->a)
		bpf_throw(5);
	return 7;
}

/* What test_1(ctx) returns, and in the upper half how many calls of ->unwound() that made */
SEC("syscall")
int call_test_1(__u64 *ctx)
{
	struct st_ops_args args = { .a = *ctx };
	int cnt = bpf_kfunc_multi_st_ops_unwound_cnt();
	int ret = bpf_kfunc_multi_st_ops_test_1(&args, st_ops_id);

	return (bpf_kfunc_multi_st_ops_unwound_cnt() - cnt) << 16 | ret;
}

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_map = {
	.test_1 = (void *)test_1,
};
