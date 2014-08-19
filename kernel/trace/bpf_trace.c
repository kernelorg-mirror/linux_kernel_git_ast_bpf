/* Copyright (c) 2011-2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/uaccess.h>
#include <trace/bpf_trace.h>
#include "trace.h"

unsigned int trace_call_bpf(struct bpf_prog *prog, void *ctx)
{
	unsigned int ret;

	if (in_nmi()) /* not supported yet */
		return 1;

	rcu_read_lock();
	ret = BPF_PROG_RUN(prog, ctx);
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(trace_call_bpf);

static u64 bpf_fetch_ptr(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	void *unsafe_ptr = (void *) (long) r1;
	void *ptr = NULL;

	probe_kernel_read(&ptr, unsafe_ptr, sizeof(ptr));
	return (u64) (unsigned long) ptr;
}

#define FETCH(SIZE) \
static u64 bpf_fetch_##SIZE(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)	\
{									\
	void *unsafe_ptr = (void *) (long) r1;				\
	SIZE val = 0;							\
									\
	probe_kernel_read(&val, unsafe_ptr, sizeof(val));		\
	return (u64) (SIZE) val;					\
}
FETCH(u64)
FETCH(u32)
FETCH(u16)
FETCH(u8)
#undef FETCH

static u64 bpf_probe_memcmp(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	void *unsafe_ptr = (void *) (long) r1;
	void *safe_ptr = (void *) (long) r2;
	u32 size = (u32) r3;
	char buf[64];
	int err;

	if (size < 64) {
		err = probe_kernel_read(buf, unsafe_ptr, size);
		if (err)
			return err;
		return memcmp(buf, safe_ptr, size);
	}
	return -1;
}

static u64 bpf_ktime_get_ns(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return ktime_get_ns();
}

static struct bpf_func_proto tp_prog_funcs[] = {
#define FETCH(SIZE)				\
	[BPF_FUNC_fetch_##SIZE] = {		\
		.func = bpf_fetch_##SIZE,	\
		.gpl_only = true,		\
		.ret_type = RET_INTEGER,	\
	},
	FETCH(ptr)
	FETCH(u64)
	FETCH(u32)
	FETCH(u16)
	FETCH(u8)
#undef FETCH
	[BPF_FUNC_probe_memcmp] = {
		.func = bpf_probe_memcmp,
		.gpl_only = false,
		.ret_type = RET_INTEGER,
		.arg1_type = ARG_ANYTHING,
		.arg2_type = ARG_PTR_TO_STACK,
		.arg3_type = ARG_CONST_STACK_SIZE,
	},
	[BPF_FUNC_ktime_get_ns] = {
		.func = bpf_ktime_get_ns,
		.gpl_only = true,
		.ret_type = RET_INTEGER,
	},
};

static const struct bpf_func_proto *tp_prog_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	default:
		if (func_id < 0 || func_id >= ARRAY_SIZE(tp_prog_funcs))
			return NULL;
		return &tp_prog_funcs[func_id];
	}
}

/* check access to argN fields of 'struct bpf_context' from program */
static bool tp_prog_is_valid_access(int off, int size,
				    enum bpf_access_type type)
{
	/* check bounds */
	if (off < 0 || off >= sizeof(struct bpf_context))
		return false;

	/* only read is allowed */
	if (type != BPF_READ)
		return false;

	/* disallow misaligned access */
	if (off % size != 0)
		return false;

	return true;
}

static struct bpf_verifier_ops tp_prog_ops = {
	.get_func_proto = tp_prog_func_proto,
	.is_valid_access = tp_prog_is_valid_access,
};

static struct bpf_prog_type_list tl = {
	.ops = &tp_prog_ops,
	.type = BPF_PROG_TYPE_TRACEPOINT,
};

static int __init register_tp_prog_ops(void)
{
	bpf_register_prog_type(&tl);
	return 0;
}
late_initcall(register_tp_prog_ops);
