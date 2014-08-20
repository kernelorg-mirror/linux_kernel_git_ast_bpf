/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
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

static u64 bpf_memcmp(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
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

static u64 bpf_dump_stack(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	trace_dump_stack(0);
	return 0;
}

/* limited printk()
 * only %d %u %x %ld %lu %lx %lld %llu %llx %p conversion specifiers allowed
 */
static u64 bpf_printk(u64 r1, u64 fmt_size, u64 r3, u64 r4, u64 r5)
{
	char *fmt = (char *) (long) r1;
	int fmt_cnt = 0;
	bool mod_l[3] = {};
	int i;

	/* bpf_check() guarantees that fmt points to bpf program stack and
	 * fmt_size bytes of it were initialized by bpf program
	 */
	if (fmt[fmt_size - 1] != 0)
		return -EINVAL;

	/* check format string for allowed specifiers */
	for (i = 0; i < fmt_size; i++)
		if (fmt[i] == '%') {
			if (fmt_cnt >= 3)
				return -EINVAL;
			i++;
			if (i >= fmt_size)
				return -EINVAL;

			if (fmt[i] == 'l') {
				mod_l[fmt_cnt] = true;
				i++;
				if (i >= fmt_size)
					return -EINVAL;
			} else if (fmt[i] == 'p') {
				mod_l[fmt_cnt] = true;
				fmt_cnt++;
				continue;
			}

			if (fmt[i] == 'l') {
				mod_l[fmt_cnt] = true;
				i++;
				if (i >= fmt_size)
					return -EINVAL;
			}

			if (fmt[i] != 'd' && fmt[i] != 'u' && fmt[i] != 'x')
				return -EINVAL;
			fmt_cnt++;
		}

	return __trace_printk((unsigned long) __builtin_return_address(3), fmt,
			      mod_l[0] ? r3 : (u32) r3,
			      mod_l[1] ? r4 : (u32) r4,
			      mod_l[2] ? r5 : (u32) r5);
}

static struct bpf_func_proto tracing_filter_funcs[] = {
#define FETCH(SIZE)				\
	[BPF_FUNC_fetch_##SIZE] = {		\
		.func = bpf_fetch_##SIZE,	\
		.gpl_only = false,		\
		.ret_type = RET_INTEGER,	\
	},
	FETCH(ptr)
	FETCH(u64)
	FETCH(u32)
	FETCH(u16)
	FETCH(u8)
#undef FETCH
	[BPF_FUNC_memcmp] = {
		.func = bpf_memcmp,
		.gpl_only = false,
		.ret_type = RET_INTEGER,
		.arg1_type = ARG_ANYTHING,
		.arg2_type = ARG_PTR_TO_STACK,
		.arg3_type = ARG_CONST_STACK_SIZE,
	},
	[BPF_FUNC_dump_stack] = {
		.func = bpf_dump_stack,
		.gpl_only = false,
		.ret_type = RET_VOID,
	},
	[BPF_FUNC_printk] = {
		.func = bpf_printk,
		.gpl_only = true,
		.ret_type = RET_INTEGER,
		.arg1_type = ARG_PTR_TO_STACK,
		.arg2_type = ARG_CONST_STACK_SIZE,
	},
};

static const struct bpf_func_proto *tracing_filter_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	default:
		if (func_id < 0 || func_id >= ARRAY_SIZE(tracing_filter_funcs))
			return NULL;
		return &tracing_filter_funcs[func_id];
	}
}

static const struct bpf_context_access {
	int size;
	enum bpf_access_type type;
} tracing_filter_ctx_access[] = {
	[offsetof(struct bpf_context, arg1)] = {
		FIELD_SIZEOF(struct bpf_context, arg1),
		BPF_READ
	},
	[offsetof(struct bpf_context, arg2)] = {
		FIELD_SIZEOF(struct bpf_context, arg2),
		BPF_READ
	},
	[offsetof(struct bpf_context, arg3)] = {
		FIELD_SIZEOF(struct bpf_context, arg3),
		BPF_READ
	},
	[offsetof(struct bpf_context, arg4)] = {
		FIELD_SIZEOF(struct bpf_context, arg4),
		BPF_READ
	},
	[offsetof(struct bpf_context, arg5)] = {
		FIELD_SIZEOF(struct bpf_context, arg5),
		BPF_READ
	},
	[offsetof(struct bpf_context, arg6)] = {
		FIELD_SIZEOF(struct bpf_context, arg6),
		BPF_READ
	},
	[offsetof(struct bpf_context, ret)] = {
		FIELD_SIZEOF(struct bpf_context, ret),
		BPF_READ
	},
};

static bool tracing_filter_is_valid_access(int off, int size, enum bpf_access_type type)
{
	const struct bpf_context_access *access;

	if (off < 0 || off >= ARRAY_SIZE(tracing_filter_ctx_access))
		return false;

	access = &tracing_filter_ctx_access[off];
	if (access->size == size && (access->type & type))
		return true;

	return false;
}

static struct bpf_verifier_ops tracing_filter_ops = {
	.get_func_proto = tracing_filter_func_proto,
	.is_valid_access = tracing_filter_is_valid_access,
};

static struct bpf_prog_type_list tl = {
	.ops = &tracing_filter_ops,
	.type = BPF_PROG_TYPE_TRACING_FILTER,
};

static int __init register_tracing_filter_ops(void)
{
	bpf_register_prog_type(&tl);
	return 0;
}
late_initcall(register_tracing_filter_ops);
