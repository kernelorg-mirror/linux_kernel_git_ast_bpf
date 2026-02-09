// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for BPF_MAP_TYPE_QP_TRIE
 */

#include <assert.h>
#include <errno.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <test_maps.h>

#include "bpf_util.h"

static int qp_trie_create(unsigned int key_size, unsigned int value_size,
			   unsigned int max_entries)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	int fd;

	opts.map_flags = BPF_F_NO_PREALLOC;
	fd = bpf_map_create(BPF_MAP_TYPE_QP_TRIE, "qp_trie", key_size,
			    value_size, max_entries, &opts);
	CHECK(fd < 0, "bpf_map_create", "error %d\n", errno);

	return fd;
}

/* Test basic insert, lookup, delete with 4-byte keys */
static void test_qp_trie_basic(void)
{
	__u32 key, value, got;
	int fd, err;

	fd = qp_trie_create(sizeof(key), sizeof(value), 100);

	/* Insert */
	key = 0x01020304;
	value = 100;
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	CHECK(err, "insert", "error %d\n", err);

	/* Lookup */
	got = 0;
	err = bpf_map_lookup_elem(fd, &key, &got);
	CHECK(err, "lookup", "error %d\n", err);
	CHECK(got != 100, "value", "got %u exp 100\n", got);

	/* Update */
	value = 200;
	err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
	CHECK(err, "update", "error %d\n", err);

	got = 0;
	err = bpf_map_lookup_elem(fd, &key, &got);
	CHECK(err, "lookup after update", "error %d\n", err);
	CHECK(got != 200, "value", "got %u exp 200\n", got);

	/* Delete */
	err = bpf_map_delete_elem(fd, &key);
	CHECK(err, "delete", "error %d\n", err);

	err = bpf_map_lookup_elem(fd, &key, &got);
	CHECK(err != -ENOENT, "lookup after delete", "error %d\n", err);

	/* Delete non-existent */
	err = bpf_map_delete_elem(fd, &key);
	CHECK(err != -ENOENT, "delete non-existent", "error %d\n", err);

	close(fd);
}

/* Test BPF_NOEXIST / BPF_EXIST / BPF_ANY semantics */
static void test_qp_trie_update_flags(void)
{
	__u32 key, value, got;
	int fd, err;

	fd = qp_trie_create(sizeof(key), sizeof(value), 10);

	key = 1;
	value = 10;

	/* BPF_EXIST on empty trie: ENOENT */
	err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
	CHECK(err != -ENOENT, "exist on empty", "error %d\n", err);

	/* BPF_NOEXIST: success */
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	CHECK(err, "noexist insert", "error %d\n", err);

	/* BPF_NOEXIST again: EEXIST */
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	CHECK(err != -EEXIST, "noexist dup", "error %d\n", err);

	/* BPF_EXIST: success */
	value = 20;
	err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
	CHECK(err, "exist update", "error %d\n", err);

	got = 0;
	err = bpf_map_lookup_elem(fd, &key, &got);
	CHECK(err, "lookup", "error %d\n", err);
	CHECK(got != 20, "value", "got %u exp 20\n", got);

	/* BPF_ANY: success (overwrite) */
	value = 30;
	err = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
	CHECK(err, "any update", "error %d\n", err);

	got = 0;
	err = bpf_map_lookup_elem(fd, &key, &got);
	CHECK(err, "lookup", "error %d\n", err);
	CHECK(got != 30, "value", "got %u exp 30\n", got);

	/* BPF_ANY on new key: success (insert) */
	key = 2;
	value = 40;
	err = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
	CHECK(err, "any insert", "error %d\n", err);

	/* Invalid flags */
	err = bpf_map_update_elem(fd, &key, &value, BPF_F_LOCK);
	CHECK(err != -EINVAL, "invalid flags", "error %d\n", err);

	close(fd);
}

/* Test max_entries enforcement */
static void test_qp_trie_max_entries(void)
{
	__u32 key, value;
	int fd, err, i;

	fd = qp_trie_create(sizeof(key), sizeof(value), 3);

	for (i = 0; i < 3; i++) {
		key = i;
		value = i * 10;
		err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		CHECK(err, "insert", "#%d error %d\n", i, err);
	}

	/* 4th insert should fail */
	key = 3;
	value = 30;
	err = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
	CHECK(err != -ENOSPC, "full trie", "error %d\n", err);

	/* Overwrite existing should succeed even when full */
	key = 1;
	value = 100;
	err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
	CHECK(err, "overwrite when full", "error %d\n", err);

	/* Delete one, then insert should work */
	key = 0;
	err = bpf_map_delete_elem(fd, &key);
	CHECK(err, "delete", "error %d\n", err);

	key = 3;
	value = 30;
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	CHECK(err, "insert after delete", "error %d\n", err);

	close(fd);
}

/* Test various key sizes */
static void test_qp_trie_key_sizes(void)
{
	int key_sizes[] = {1, 2, 4, 8, 16, 32, 64, 128};
	int fd, err, i, j;

	for (i = 0; i < (int)(sizeof(key_sizes) / sizeof(key_sizes[0])); i++) {
		int ks = key_sizes[i];
		__u32 value, got;
		__u8 *key;

		key = calloc(1, ks);
		assert(key);

		fd = qp_trie_create(ks, sizeof(value), 256);

		/* Insert several entries */
		for (j = 0; j < 64; j++) {
			memset(key, 0, ks);
			key[0] = j;
			if (ks > 1)
				key[1] = j * 3;
			value = j;
			err = bpf_map_update_elem(fd, key, &value, BPF_ANY);
			CHECK(err, "insert", "ks=%d #%d error %d\n",
			      ks, j, err);
		}

		/* Lookup each */
		for (j = 0; j < 64; j++) {
			memset(key, 0, ks);
			key[0] = j;
			if (ks > 1)
				key[1] = j * 3;
			got = 0;
			err = bpf_map_lookup_elem(fd, key, &got);
			CHECK(err, "lookup", "ks=%d #%d error %d\n",
			      ks, j, err);
			CHECK(got != (__u32)j, "value", "ks=%d #%d got %u\n",
			      ks, j, got);
		}

		/* Delete half */
		for (j = 0; j < 32; j++) {
			memset(key, 0, ks);
			key[0] = j;
			if (ks > 1)
				key[1] = j * 3;
			err = bpf_map_delete_elem(fd, key);
			CHECK(err, "delete", "ks=%d #%d error %d\n",
			      ks, j, err);
		}

		/* Verify remaining */
		for (j = 32; j < 64; j++) {
			memset(key, 0, ks);
			key[0] = j;
			if (ks > 1)
				key[1] = j * 3;
			got = 0;
			err = bpf_map_lookup_elem(fd, key, &got);
			CHECK(err, "lookup", "ks=%d #%d error %d\n",
			      ks, j, err);
			CHECK(got != (__u32)j, "value", "ks=%d #%d got %u\n",
			      ks, j, got);
		}

		free(key);
		close(fd);
	}
}

/* Test get_next_key returns keys in lexicographic order */
static void test_qp_trie_get_next_key(void)
{
	__u32 keys_insert[] = {50, 10, 30, 20, 40};
	__u32 keys_sorted[] = {10, 20, 30, 40, 50};
	__u32 key, next_key, value;
	int fd, err, i;

	fd = qp_trie_create(sizeof(key), sizeof(value), 100);

	/* Insert in random order */
	for (i = 0; i < 5; i++) {
		key = htobe32(keys_insert[i]);
		value = keys_insert[i];
		err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		CHECK(err, "insert", "#%d error %d\n", i, err);
	}

	/* NULL key should return first */
	err = bpf_map_get_next_key(fd, NULL, &next_key);
	CHECK(err, "first key", "error %d\n", err);
	CHECK(be32toh(next_key) != keys_sorted[0], "first key value",
	      "got %u exp %u\n", be32toh(next_key), keys_sorted[0]);

	/* Iterate and verify order */
	key = next_key;
	for (i = 1; i < 5; i++) {
		err = bpf_map_get_next_key(fd, &key, &next_key);
		CHECK(err, "next key", "#%d error %d\n", i, err);
		CHECK(be32toh(next_key) != keys_sorted[i], "key order",
		      "#%d got %u exp %u\n", i, be32toh(next_key),
		      keys_sorted[i]);
		key = next_key;
	}

	/* Past last key: ENOENT */
	err = bpf_map_get_next_key(fd, &key, &next_key);
	CHECK(err != -ENOENT, "past last", "error %d\n", err);

	/* Empty trie */
	close(fd);
	fd = qp_trie_create(sizeof(key), sizeof(value), 100);
	err = bpf_map_get_next_key(fd, NULL, &next_key);
	CHECK(err != -ENOENT, "empty trie", "error %d\n", err);

	close(fd);
}

/* Test get_next_key with multi-byte keys for lexicographic order */
static void test_qp_trie_iterate_bytes(void)
{
	struct {
		__u8 key[4];
		__u32 val;
	} entries[] = {
		{{0x00, 0x00, 0x00, 0x01}, 1},
		{{0x00, 0x00, 0x00, 0x02}, 2},
		{{0x00, 0x01, 0x00, 0x00}, 3},
		{{0x01, 0x00, 0x00, 0x00}, 4},
		{{0xff, 0xff, 0xff, 0xff}, 5},
	};
	__u8 key[4], next_key[4];
	__u32 value;
	int fd, err, i;

	fd = qp_trie_create(4, sizeof(value), 100);

	/* Insert in reverse order */
	for (i = 4; i >= 0; i--) {
		err = bpf_map_update_elem(fd, entries[i].key, &entries[i].val,
					  BPF_NOEXIST);
		CHECK(err, "insert", "#%d error %d\n", i, err);
	}

	/* Iterate and verify lexicographic order */
	err = bpf_map_get_next_key(fd, NULL, next_key);
	CHECK(err, "first key", "error %d\n", err);
	CHECK(memcmp(next_key, entries[0].key, 4), "first key",
	      "unexpected first key\n");

	memcpy(key, next_key, 4);
	for (i = 1; i < 5; i++) {
		err = bpf_map_get_next_key(fd, key, next_key);
		CHECK(err, "next key", "#%d error %d\n", i, err);
		CHECK(memcmp(next_key, entries[i].key, 4), "key order",
		      "#%d unexpected key\n", i);
		memcpy(key, next_key, 4);
	}

	err = bpf_map_get_next_key(fd, key, next_key);
	CHECK(err != -ENOENT, "past last", "error %d\n", err);

	close(fd);
}

/* Randomized insert/lookup/delete consistency test */
static void test_qp_trie_randomized(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
	int n_entries = 1024;
	__u64 *keys, value, got;
	__u8 *present;
	int fd, err, i, j;

	keys = calloc(n_entries, sizeof(*keys));
	present = calloc(n_entries, sizeof(*present));
	assert(keys && present);

	fd = bpf_map_create(BPF_MAP_TYPE_QP_TRIE, "qp_trie",
			    sizeof(__u64), sizeof(__u64),
			    n_entries, &opts);
	assert(fd >= 0);

	srand(42);

	/* Insert all */
	for (i = 0; i < n_entries; i++) {
		keys[i] = ((__u64)rand() << 32) | rand();
		value = i;
		err = bpf_map_update_elem(fd, &keys[i], &value, BPF_ANY);
		CHECK(err, "insert", "#%d error %d\n", i, err);
		present[i] = 1;
	}

	/* Lookup all */
	for (i = 0; i < n_entries; i++) {
		err = bpf_map_lookup_elem(fd, &keys[i], &got);
		CHECK(err, "lookup", "#%d error %d\n", i, err);
	}

	/* Delete random half and verify */
	for (i = 0; i < n_entries; i++) {
		if (rand() % 2) {
			err = bpf_map_delete_elem(fd, &keys[i]);
			/* May fail if duplicate key from rand() */
			if (!err)
				present[i] = 0;
		}
	}

	/* Verify consistency */
	for (i = 0; i < n_entries; i++) {
		err = bpf_map_lookup_elem(fd, &keys[i], &got);
		if (present[i]) {
			/* May not be present if there was a duplicate key */
			if (err)
				present[i] = 0;
		}
	}

	/* Re-insert deleted ones */
	for (i = 0; i < n_entries; i++) {
		if (!present[i]) {
			value = i + n_entries;
			err = bpf_map_update_elem(fd, &keys[i], &value,
						  BPF_ANY);
			if (!err)
				present[i] = 1;
		}
	}

	/* Final lookup */
	for (j = 0; j < n_entries; j++) {
		if (!present[j])
			continue;
		err = bpf_map_lookup_elem(fd, &keys[j], &got);
		CHECK(err, "final lookup", "#%d error %d\n", j, err);
	}

	free(keys);
	free(present);
	close(fd);
}

/* Concurrent stress test with 4 threads */
#define MT_KEYS		16
#define MT_ITERS	2000

struct qp_mt_info {
	int cmd;	/* 0: update, 1: delete, 2: lookup, 3: get_next_key */
	int map_fd;
	__u64 keys[MT_KEYS];
};

static void *qp_mt_worker(void *arg)
{
	struct qp_mt_info *info = arg;
	__u64 value, next_key;
	int i, j, ret, iter;

	for (iter = 0; iter < MT_ITERS; iter++) {
		for (i = 0; i < MT_KEYS; i++) {
			j = (iter < MT_ITERS / 2) ? i : MT_KEYS - i - 1;

			if (info->cmd == 0) {
				value = j;
				assert(bpf_map_update_elem(info->map_fd,
					&info->keys[j], &value, 0) == 0);
			} else if (info->cmd == 1) {
				ret = bpf_map_delete_elem(info->map_fd,
							  &info->keys[j]);
				assert(ret == 0 || errno == ENOENT);
			} else if (info->cmd == 2) {
				ret = bpf_map_lookup_elem(info->map_fd,
							  &info->keys[j],
							  &value);
				assert(ret == 0 || errno == ENOENT);
			} else {
				ret = bpf_map_get_next_key(info->map_fd,
							   &info->keys[j],
							   &next_key);
				assert(ret == 0 || errno == ENOENT ||
				       errno == ENOMEM);
			}
		}
	}

	pthread_exit((void *)info);
}

static void test_qp_trie_multi_thread(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
	struct qp_mt_info info[4];
	pthread_t threads[4];
	void *ret;
	int fd, i;

	fd = bpf_map_create(BPF_MAP_TYPE_QP_TRIE, "qp_trie",
			    sizeof(__u64), sizeof(__u64), 256, &opts);
	assert(fd >= 0);

	/* Initialize keys */
	for (i = 0; i < MT_KEYS; i++)
		info[0].keys[i] = htobe64(i * 1000 + 1);

	for (i = 0; i < 4; i++) {
		if (i != 0)
			memcpy(&info[i], &info[0], sizeof(info[i]));
		info[i].cmd = i;
		info[i].map_fd = fd;
		assert(pthread_create(&threads[i], NULL, &qp_mt_worker,
				      &info[i]) == 0);
	}

	for (i = 0; i < 4; i++)
		assert(pthread_join(threads[i], &ret) == 0 &&
		       ret == (void *)&info[i]);

	close(fd);
}

void test_qp_trie_map_basic_ops(void)
{
	srand(0xf00ba1);

	test_qp_trie_basic();
	test_qp_trie_update_flags();
	test_qp_trie_max_entries();
	test_qp_trie_key_sizes();
	test_qp_trie_get_next_key();
	test_qp_trie_iterate_bytes();
	test_qp_trie_randomized();
	test_qp_trie_multi_thread();

	printf("%s: PASS\n", __func__);
}
