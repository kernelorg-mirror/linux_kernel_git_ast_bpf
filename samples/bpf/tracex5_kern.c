/* Copyright (c) 2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct pair {
	u64 val;
	u64 ip;
};

struct bpf_map_def SEC("maps") progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 4,
};

SEC("kprobe/sys_write")
int bpf_prog1(struct pt_regs *ctx)
{
	if (ctx->dx == 512)
		bpf_tail_call(ctx, &progs, 0);
	return 0;
}

SEC("kprobe/sys_read")
int bpf_prog2(struct pt_regs *ctx)
{
	if (ctx->dx == 1024)
		bpf_tail_call(ctx, &progs, 1);
	return 0;
}

SEC("kprobe/0")
int bpf_prog3(struct pt_regs *ctx)
{
	char fmt[] = "write512\n";
	bpf_trace_printk(fmt, sizeof(fmt));
	return 0;
}

SEC("kprobe/1")
int bpf_prog4(struct pt_regs *ctx)
{
	char fmt[] = "read1024\n";
	bpf_trace_printk(fmt, sizeof(fmt));
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
