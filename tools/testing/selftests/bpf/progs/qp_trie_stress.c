// SPDX-License-Identifier: GPL-2.0
/* BPF stress test for QP-trie map - concurrent operations from BPF programs */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NR_KEYS 64

struct {
	__uint(type, BPF_MAP_TYPE_QP_TRIE);
	__uint(key_size, 8);
	__uint(value_size, 8);
	__uint(max_entries, NR_KEYS * 2);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} stress_map SEC(".maps");

__u64 keys[NR_KEYS];
long update_cnt;
long delete_cnt;
long lookup_cnt;

static int update_cb(__u32 index, void *ctx)
{
	__u64 value;

	if (index >= NR_KEYS)
		return 1;
	value = index;
	bpf_map_update_elem(&stress_map, &keys[index], &value, BPF_ANY);
	return 0;
}

static int delete_cb(__u32 index, void *ctx)
{
	if (index >= NR_KEYS)
		return 1;
	bpf_map_delete_elem(&stress_map, &keys[index]);
	return 0;
}

static int lookup_cb(__u32 index, void *ctx)
{
	if (index >= NR_KEYS)
		return 1;
	bpf_map_lookup_elem(&stress_map, &keys[index]);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int stress_update(void *ctx)
{
	bpf_loop(NR_KEYS, update_cb, NULL, 0);
	__sync_fetch_and_add(&update_cnt, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getppid")
int stress_delete(void *ctx)
{
	bpf_loop(NR_KEYS, delete_cb, NULL, 0);
	__sync_fetch_and_add(&delete_cnt, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getuid")
int stress_lookup(void *ctx)
{
	bpf_loop(NR_KEYS, lookup_cb, NULL, 0);
	__sync_fetch_and_add(&lookup_cnt, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
