// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *) &(x)) = (val))
#endif

#define __uptr __attribute__((address_space(1))) __attribute__((btf_type_tag("uptr")))
//#define __uptr __attribute__((btf_type_tag("uptr")))

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1u << 20);
	__type(key, __u64);
	__type(value, __u64);
} arena SEC(".maps");

void __uptr* bpf_uptr_alloc_pages(void *map, __u32 page_cnt) __ksym;
void bpf_uptr_free_pages(void *map, void __uptr *ptr, __u32 page_cnt) __ksym;

#include "uptr_htab.h"

static volatile int zero = 0;

void __uptr *htab_for_user;

SEC("syscall")
int uptr_basic(void *ctx)
{
	struct htab __uptr *htab;
	__u64 i;

	htab = bpf_alloc(sizeof(*htab));
	bpf_cast_as(htab, 1);
	htab_init(htab);
	htab_for_user = htab;

	/* first run. No old elems in the table */
	bpf_for(i, 0, 1000) {
		zero = i;
		htab_update_elem(htab, zero, zero);
	}
	/* should replace all elems with new ones */
	bpf_for(i, 0, 1000) {
		zero = i;
		htab_update_elem(htab, zero, zero);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
