// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */
#include <linux/bpf.h>
#include <linux/magic.h>
#include "bpf_helpers.h"
#include "test_file_open_common.h"

struct bpf_map_def SEC("maps") local_storage = {
	.type = BPF_MAP_TYPE_CGROUP_STORAGE,
	.key_size = sizeof(struct bpf_cgroup_storage_key),
	.value_size = sizeof(struct test_file_open_config),
};

SEC("cgroup/file_open")
int bpf_file_filter(struct bpf_file_info *f)
{
	char fmt1[] = "magic 0x%x mnt %d inode %ld\n";
	char fmt2[] = "dev 0x%x link %d file %s\n";
	char fmt3[] = "mode %o flags %o /etc mnt_id %d\n";
	char path[400];
	struct test_file_open_config *cfg;

	cfg = bpf_get_local_storage(&local_storage, 0);

	/* debugging prints */
	bpf_get_file_path(f, path, sizeof(path));
	bpf_trace_printk(fmt1, sizeof(fmt1), f->fs_magic, f->mnt_id, f->inode);
	bpf_trace_printk(fmt2, sizeof(fmt2), (f->dev_major << 8) | f->dev_minor,
			 f->nlink, path);
	bpf_trace_printk(fmt3, sizeof(fmt3), f->mode, f->flags, cfg->mnt_id);

	/* disallow access to cgroupv2 */
	if (f->fs_magic == CGROUP2_SUPER_MAGIC)
		return 0;

	/* disallow access to given mount */
	if (f->mnt_id == cfg->mnt_id)
		return 0;

	/* disallow access to a given file */
	if (f->dev_major == cfg->dev_major &&
	    f->dev_minor == cfg->dev_minor &&
	    f->inode == cfg->inode)
		return 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
