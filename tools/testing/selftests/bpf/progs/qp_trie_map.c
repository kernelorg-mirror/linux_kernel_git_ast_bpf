// SPDX-License-Identifier: GPL-2.0
/* BPF program exercising QP-trie map from BPF context */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_QP_TRIE);
	__uint(key_size, 8);
	__uint(value_size, 8);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} qp_trie_map SEC(".maps");

int test_done;
int update_ret;
int delete_ret;
int lookup_after_delete;
__u64 lookup_val;

SEC("tp/syscalls/sys_enter_getpid")
int test_qp_trie_ops(void *ctx)
{
	__u64 key, value, *val_ptr;

	/* Insert a key */
	key = 0x0102030405060708ULL;
	value = 42;
	update_ret = bpf_map_update_elem(&qp_trie_map, &key, &value, BPF_ANY);

	/* Lookup the key */
	val_ptr = bpf_map_lookup_elem(&qp_trie_map, &key);
	if (val_ptr)
		lookup_val = *val_ptr;

	/* Delete the key */
	delete_ret = bpf_map_delete_elem(&qp_trie_map, &key);

	/* Lookup after delete should fail */
	val_ptr = bpf_map_lookup_elem(&qp_trie_map, &key);
	lookup_after_delete = val_ptr ? 1 : 0;

	test_done = 1;
	return 0;
}

char _license[] SEC("license") = "GPL";
