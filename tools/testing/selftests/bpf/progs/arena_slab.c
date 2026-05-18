// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 256); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

void __arena *bpf_arena_alloc(void *map, __u32 size) __ksym __weak;
void bpf_arena_free(void *map, void __arena *ptr) __ksym __weak;
void bpf_local_irq_save(unsigned long *flags) __ksym;
void bpf_local_irq_restore(unsigned long *flags) __ksym;

#define N 64
#define CORRUPT_N 8
#define LEAK_N 16

int alloc_failed;
int free_done;
int corrupt_alloc_failed;
int corrupt_done;
int leak_alloc_failed;
int leak_done;

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
static __u8 __arena *objs[N];
static __u64 __arena *corrupt_objs[CORRUPT_N];
#endif

SEC("syscall")
int arena_slab_alloc(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	int i;

	for (i = 0; i < N; i++) {
		__u32 size = 8U << (i & 7); /* 8, 16, 32, ... 1024 */
		__u8 __arena *p = bpf_arena_alloc(&arena, size);

		if (!p) {
			alloc_failed = i + 1;
			return 0;
		}
		/* Write a sentinel that depends on the slot — proves the object
		 * is real arena memory and not aliased with another slot.
		 */
		p[0] = (__u8)(i + 1);
		p[size - 1] = (__u8)(i + 1);
		objs[i] = p;
	}
#endif
	return 0;
}

SEC("syscall")
int arena_slab_free(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	int i;

	for (i = 0; i < N; i++) {
		if (!objs[i])
			continue;
		bpf_arena_free(&arena, objs[i]);
		objs[i] = NULL;
	}
	free_done = 1;
#endif
	return 0;
}

SEC("syscall")
int arena_slab_defer_corrupt(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	unsigned long flags;
	int i;

	for (i = 0; i < CORRUPT_N; i++) {
		corrupt_objs[i] = bpf_arena_alloc(&arena, 4096);
		if (!corrupt_objs[i]) {
			corrupt_alloc_failed = i + 1;
			return 0;
		}
	}

	/*
	 * IRQs off so the irq_work IPI raised by defer_free() is deferred
	 * until after the loop; otherwise it would fire between iterations
	 * and drain the single-entry llist before the next free + poison
	 * could chain onto it.
	 */
	bpf_local_irq_save(&flags);
	for (i = 0; i < CORRUPT_N; i++) {
		bpf_arena_free(&arena, corrupt_objs[i]);
		/*
		 * For non-debug/non-ctor/non-RCU caches slub places the
		 * freepointer at ALIGN_DOWN(object_size / 2, sizeof(void *))
		 * inside the object (see calculate_sizes() in mm/slub.c).
		 * For the 4096-byte arena bucket that is 2048. Scribble
		 * 0xdead... there to poison defer_free()'s llist next
		 * pointer in the unfixed kernel.
		 */
		corrupt_objs[i][2048 / sizeof(__u64)] = 0xdeadbeefdeadbeefULL;
	}
	bpf_local_irq_restore(&flags);

	corrupt_done = 1;
#endif
	return 0;
}

/*
 * Intentional leak: allocate LEAK_N objects across a mix of buckets and
 * never free them.
 */
SEC("syscall")
int arena_slab_leak(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	int i;

	for (i = 0; i < LEAK_N; i++) {
		/*
		 * Mix of sizes spanning small (16) up to PAGE_SIZE so we
		 * leak across multiple bucket caches.
		 */
		__u32 size = 16U << (i & 7); /* 16, 32, ..., 2048 */
		__u8 __arena *p = bpf_arena_alloc(&arena, size);

		if (!p) {
			leak_alloc_failed = i + 1;
			return 0;
		}
		p[0] = (__u8)(i + 1);
	}
	leak_done = 1;
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
