// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/kdev_t.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cgroup_helpers.h"
#include "bpf_rlimit.h"
#include "test_file_open_common.h"

#define CGROUP_PROG "./test_file_open_kern.o"

#define TEST_CGROUP "/test-bpf-based-device-cgroup/"

int main(int argc, char **argv)
{
	struct bpf_cgroup_storage_key key;
	struct file_handle fhp[1] = {};
	struct test_file_open_config cfg = {};
	struct bpf_object *obj;
	int error = EXIT_FAILURE;
	int prog_fd, cgroup_fd;
	struct bpf_map *map;
	__u32 prog_cnt;
	struct stat st;
	int map_fd;

	if (bpf_prog_load(CGROUP_PROG, BPF_PROG_TYPE_FILE_FILTER,
			  &obj, &prog_fd)) {
		printf("Failed to load FILE_FILTER program\n");
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, "local_storage");
	if (!map) {
		printf("Failed to find cgroup local storage map");
		goto err;
	}
	map_fd = bpf_map__fd(map);

	if (setup_cgroup_environment()) {
		printf("Failed to load FILE_FILTER program\n");
		goto err;
	}

	/* Create a cgroup, get fd, and join it */
	cgroup_fd = create_and_get_cgroup(TEST_CGROUP);
	if (!cgroup_fd) {
		printf("Failed to create test cgroup\n");
		goto err;
	}

	if (join_cgroup(TEST_CGROUP)) {
		printf("Failed to join cgroup\n");
		goto err;
	}

	/* few sanity checks before bpf prog is attached */
	assert(system("cat /mnt/cgroup-test-work-dir" TEST_CGROUP "cgroup.procs >& /dev/null") == 0);
	assert(system("cat /etc/hosts >& /dev/null") == 0);

	/* Attach bpf program */
	if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_FILE_OPEN, 0)) {
		perror("Failed to attach CGROUP_FILE_OPEN program");
		goto err;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key)) {
		printf("Failed to get key in cgroup storage\n");
		goto err;
	}

	if (bpf_prog_query(cgroup_fd, BPF_CGROUP_FILE_OPEN, 0, NULL, NULL,
			   &prog_cnt)) {
		perror("Failed to query attached programs");
		goto err;
	}
	assert(prog_cnt == 1);

	/* check that this process cannot make any further changes to cgroup */
	assert(system("cat /mnt/cgroup-test-work-dir" TEST_CGROUP "cgroup.procs >& /dev/null") != 0);

	/* figure out the mnt_id of /etc */
	if (name_to_handle_at(-1, "/etc", fhp, &cfg.mnt_id, 0) != -1 ||
	    errno != EOVERFLOW) {
		perror("name_to_handle_at failed");
		goto err;
	}

	/* let bpf prog know /etc's mnt_id via cgroup local storage */
	if (bpf_map_update_elem(map_fd, &key, &cfg, 0)) {
		printf("Failed to update cgroup local storage\n");
		goto err;
	}

	/* check that this process cannot read /etc any more */
	assert(system("cat /etc/hosts >& /dev/null") != 0);
	assert(system("cat /etc/hostname >& /dev/null") != 0);

	/* set mnt_id back to zero */
	cfg.mnt_id = 0;
	if (bpf_map_update_elem(map_fd, &key, &cfg, 0)) {
		printf("Failed to update cgroup local storage\n");
		goto err;
	}
	/* access to /etc should work again */
	assert(system("cat /etc/hosts >& /dev/null") == 0);

	/* figure out inode of /etc/hosts */
	if (stat("/etc/hosts", &st)) {
		perror("stat failed");
		goto err;
	}
	cfg.inode = st.st_ino;
	cfg.dev_major = MAJOR(st.st_dev);
	cfg.dev_minor = MINOR(st.st_dev);
	if (bpf_map_update_elem(map_fd, &key, &cfg, 0)) {
		printf("Failed to update cgroup local storage\n");
		goto err;
	}
	/* check that this process cannot read /etc/hosts any more */
	assert(system("cat /etc/hosts >& /dev/null") != 0);
	/* but /etc/hostname is still ok */
	assert(system("cat /etc/hostname >& /dev/null") == 0);

	/*
	 * detach from cgroup. Otherwise our own bpf prog will prevent us
	 * from cleaning up the cgroup environment
	 */
	if (bpf_prog_detach(cgroup_fd, BPF_CGROUP_FILE_OPEN)) {
		perror("Failed to detach");
		goto err;
	}

	error = 0;
	printf("test_file_open:PASS\n");

err:
	cleanup_cgroup_environment();

out:
	return error;
}
