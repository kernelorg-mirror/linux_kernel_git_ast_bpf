// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 10); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} htab SEC(".maps");

void __arena *htab_for_user;
bool skip = false;

int zero = 0;

#define MAX_CNT 8
int __arena cnt[MAX_CNT];
struct bpf_lock __arena locks[MAX_CNT];
int other_cnt;
int busy;
struct bpf_lock __arena other_lock;

SEC("fentry/bpf_get_numa_node_id")
int fentry(void *ctx)
{
	struct bpf_lock_kern *klock;

	if (!busy)
		return 0;
	bpf_guard_preempt();
	klock = bpf_lock_acquire(&other_lock);
	if (klock) {
		other_cnt++;
		bpf_lock_release(&other_lock, klock);
	} else {
		busy++;
	}
	return 0;
}


struct bpf_lock __arena lockAA;
int AAlock_cnt;

SEC("syscall")
int arena_AA_lock(void *ctx)
{
	struct bpf_lock_kern *klock, *klock2;

	bpf_guard_preempt();
	klock = bpf_lock_acquire(&lockAA);
	if (klock) {
		klock2 = bpf_lock_acquire(&lockAA);
		if (klock2)
			bpf_lock_release(&lockAA, klock2);
		AAlock_cnt++;
		bpf_lock_release(&lockAA, klock);
	}
	return 0;
}

int ABBAlock_cnt;
struct bpf_lock __arena lockAB;

SEC("fentry/alloc_htab_elem")
int alloc_htab_elem(void *ctx)
{
	int cpu = bpf_get_smp_processor_id();
	struct bpf_lock_kern *klock;

	if (cpu & 1) {
		bpf_guard_preempt();
		klock = bpf_lock_acquire(&lockAB);
		if (!klock) {
			busy++;
		} else {
			ABBAlock_cnt++;
			bpf_lock_release(&lockAB, klock);
		}
	}

	return 0;
}

static void map_update(void)
{
	__u32 key = 0, value = 1;

	bpf_map_delete_elem(&htab, &key);
	bpf_map_update_elem(&htab, &key, &value, 0);
}

SEC("syscall")
int arena_ABBA_lock(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	int cpu = bpf_get_smp_processor_id();
	struct bpf_lock_kern *klock;
	__u64 i;

	for (i = zero; i < 100; i++, cond_break) {
		if (cpu & 1)
			map_update();
		bpf_guard_preempt();
		klock = bpf_lock_acquire(&lockAB);
		if (!klock) {
			busy++;
			continue;
		}
		ABBAlock_cnt++;
		if (! (cpu & 1))
			map_update();
		bpf_lock_release(&lockAB, klock);
	}
#else
	skip = true;
#endif
	return 0;
}

SEC("syscall")
int arena_lock(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	struct bpf_lock_kern *klock;
	__u64 i, j;

	for (j = zero; j < 1000; j++, cond_break) {
		for (i = zero; i < MAX_CNT; i++) {
			cond_break;
			bpf_guard_preempt();
			klock = bpf_lock_acquire(&locks[i]);
			cnt[i]++;
			if (0)
			bpf_get_numa_node_id();
			if (!klock) {
				busy++;
				continue;
			}
			bpf_lock_release(&locks[i], klock);
		}
	}
#else
	skip = true;
#endif
	return 0;
}

struct glock {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CNT);
	__type(key, uint32_t);
	__type(value, struct glock);
} lock_arr SEC(".maps");

SEC("syscall")
int old_spin_lock(void *ctx)
{
	struct glock *lock;
	__u64 i, j;

	for (j = zero; j < 1000; j++, cond_break) {
		for (i = zero; i < MAX_CNT; i++) {
			cond_break;
			lock = bpf_map_lookup_elem(&lock_arr, &i);
			if (!lock) {
				busy++;
				continue;
			}
			bpf_spin_lock(&lock->lock);
			cnt[i]++;
			bpf_spin_unlock(&lock->lock);
		}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
