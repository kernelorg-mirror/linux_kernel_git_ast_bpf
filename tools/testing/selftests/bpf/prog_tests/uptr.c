// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <sys/mman.h>
#include <network_helpers.h>

#include "uptr.skel.h"

#undef offsetof
#define offsetof(type, member)  ((unsigned long)&((type *)0)->member)

/* redefined container_of() to ensure we use the above offsetof() macro */
#undef container_of
#define container_of(ptr, type, member)				\
	({							\
		void *__mptr = (void *)(ptr);			\
		((type *)(__mptr - offsetof(type, member)));	\
	})

#define __uptr
#define PAGE_SIZE 4096

char arena[1];
void __uptr* bpf_uptr_alloc_pages(void *map, __u32 page_cnt) { return 0; }
void bpf_uptr_free_pages(void *map, void __uptr *ptr, __u32 page_cnt) { }

#define bpf_cast_as(var, addr_space) /* nop for user space */

#include "uptr_htab.h"

struct args {
	__u64 log_buf;
	__u32 log_size;
	int max_entries;
	int map_fd;
	int prog_fd;
	int btf_fd;
};

static void test_uptr_basic(void)
{
        static char verifier_log[8192];
        struct args ctx = {
                .max_entries = 1024,
                .log_buf = (uintptr_t) verifier_log,
                .log_size = sizeof(verifier_log),
        };
        LIBBPF_OPTS(bpf_test_run_opts, opts,
                .ctx_in = &ctx,
                .ctx_size_in = sizeof(ctx),
        );
	struct uptr *skel;
	size_t arena_sz;
	void *area;
	int ret, i;
	struct htab *htab, *htab2;

	skel = uptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rbtree__open_and_load"))
		return;

	area = bpf_map__initial_value(skel->maps.arena, &arena_sz);
	/* fault-in a page with pgoff == 0 as sanity check */
	*(volatile int*)area = 0x55aa;

	/* bpf prog will allocate more pages */
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.uptr_basic), &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");

	/* hack1: internal detail of bpf_alloc() from uptr_htab.h */
	htab = area + 4096 * 2 - sizeof(*htab) - 8;
	/* hack2: the verifier doesn't set _yet_ upper 32-bit of uptr when prog stores it into bss */
	htab2 = (void *)(((__u64)area) & ~(__u64)~0U) + (__u32)(long)skel->bss->htab_for_user;
	ASSERT_EQ(htab, htab2, "two ways to compute htab pointer");
	printf("htab_for_user %p\n", skel->bss->htab_for_user);
	printf("htab %p buckets %p n_buckets %d\n", htab, htab->buckets, htab->n_buckets);
	for (i = 0; htab->buckets && i < 16; i++) {
		/*
		 * Walk htab buckets and link lists since all pointers are correct,
		 * though they were written by bpf program.
		 */
		int val = htab_lookup_elem(htab, i);

		ASSERT_EQ(i, val, "key == value");
	}
	uptr__destroy(skel);
}

void test_uptr_success(void)
{
	if (test__start_subtest("uptr_basic"))
		test_uptr_basic();
}

