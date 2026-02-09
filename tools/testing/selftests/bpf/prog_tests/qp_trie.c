// SPDX-License-Identifier: GPL-2.0
/* Test QP-trie map from BPF program and userspace */

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <test_progs.h>
#include "qp_trie_map.skel.h"
#include "qp_trie_stress.skel.h"

static void test_qp_trie_bpf_ops(void)
{
	struct qp_trie_map *skel;
	int err;

	skel = qp_trie_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = qp_trie_map__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;

	/* Trigger the BPF program */
	syscall(__NR_getpid);

	ASSERT_EQ(skel->bss->test_done, 1, "test_done");
	ASSERT_EQ(skel->bss->update_ret, 0, "update_ret");
	ASSERT_EQ(skel->bss->lookup_val, 42, "lookup_val");
	ASSERT_EQ(skel->bss->delete_ret, 0, "delete_ret");
	ASSERT_EQ(skel->bss->lookup_after_delete, 0, "lookup_after_delete");

	/* Userspace operations on the same map */
	{
		int map_fd = bpf_map__fd(skel->maps.qp_trie_map);
		__u64 key, value;

		/* Insert from userspace */
		key = 0xAABBCCDDEEFF0011ULL;
		value = 99;
		err = bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST);
		ASSERT_OK(err, "userspace insert");

		/* Lookup */
		value = 0;
		err = bpf_map_lookup_elem(map_fd, &key, &value);
		ASSERT_OK(err, "userspace lookup");
		ASSERT_EQ(value, 99, "userspace value");

		/* Delete */
		err = bpf_map_delete_elem(map_fd, &key);
		ASSERT_OK(err, "userspace delete");

		/* Verify deleted */
		err = bpf_map_lookup_elem(map_fd, &key, &value);
		ASSERT_ERR(err, "userspace lookup after delete");

		/* get_next_key on empty map */
		err = bpf_map_get_next_key(map_fd, NULL, &key);
		ASSERT_ERR(err, "get_next_key empty");

		/* Insert several and iterate */
		for (int i = 0; i < 5; i++) {
			key = htobe64(i + 1);
			value = i + 100;
			err = bpf_map_update_elem(map_fd, &key, &value,
						  BPF_ANY);
			ASSERT_OK(err, "insert for iteration");
		}

		/* Iterate with get_next_key */
		err = bpf_map_get_next_key(map_fd, NULL, &key);
		ASSERT_OK(err, "first key");
		ASSERT_EQ(be64toh(key), 1, "first key value");

		for (int i = 1; i < 5; i++) {
			__u64 prev = key;

			err = bpf_map_get_next_key(map_fd, &prev, &key);
			ASSERT_OK(err, "next key");
			ASSERT_EQ(be64toh(key), (unsigned long)(i + 1),
				  "key order");
		}

		/* Past last */
		{
			__u64 prev = key;

			err = bpf_map_get_next_key(map_fd, &prev, &key);
			ASSERT_ERR(err, "past last key");
		}
	}

cleanup:
	qp_trie_map__destroy(skel);
}

/* --- BPF-driven parallel stress test --- */

#define STRESS_NR_KEYS		64
#define STRESS_LOOPS		2000
#define STRESS_NR_UPDATE	2
#define STRESS_NR_DELETE	2
#define STRESS_NR_LOOKUP	2
#define STRESS_NR_THREADS	(STRESS_NR_UPDATE + STRESS_NR_DELETE + \
				 STRESS_NR_LOOKUP)

struct trigger_ctx {
	int nr;
	int syscall_nr;
	volatile bool *stop;
};

static void *trigger_fn(void *arg)
{
	struct trigger_ctx *ctx = arg;
	int i;

	for (i = 0; i < ctx->nr && !*ctx->stop; i++)
		syscall(ctx->syscall_nr);

	return NULL;
}

static void test_qp_trie_stress(void)
{
	pthread_t tids[STRESS_NR_THREADS] = {};
	struct trigger_ctx tctx[STRESS_NR_THREADS];
	struct qp_trie_stress *skel;
	volatile bool stop = false;
	unsigned int t = 0;
	int map_fd, i, err;

	skel = qp_trie_stress__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/* Initialize keys in BPF BSS */
	for (i = 0; i < STRESS_NR_KEYS; i++)
		skel->bss->keys[i] = htobe64(i * 1000 + 1);

	/* Seed the map so delete/lookup have something to work with */
	map_fd = bpf_map__fd(skel->maps.stress_map);
	for (i = 0; i < STRESS_NR_KEYS; i++) {
		__u64 value = i;

		err = bpf_map_update_elem(map_fd, &skel->bss->keys[i],
					  &value, BPF_ANY);
		if (!ASSERT_OK(err, "seed map"))
			goto cleanup;
	}

	err = qp_trie_stress__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;

	/*
	 * Launch threads that trigger BPF programs via syscalls.
	 * Each syscall invocation fires the attached BPF program which
	 * performs NR_KEYS map operations via bpf_loop().
	 */
	for (i = 0; i < STRESS_NR_UPDATE; i++, t++) {
		tctx[t].nr = STRESS_LOOPS;
		tctx[t].syscall_nr = __NR_getpgid;
		tctx[t].stop = &stop;
		err = pthread_create(&tids[t], NULL, trigger_fn, &tctx[t]);
		if (!ASSERT_OK(err, "create update trigger")) {
			stop = true;
			goto reap;
		}
	}
	for (i = 0; i < STRESS_NR_DELETE; i++, t++) {
		tctx[t].nr = STRESS_LOOPS;
		tctx[t].syscall_nr = __NR_getppid;
		tctx[t].stop = &stop;
		err = pthread_create(&tids[t], NULL, trigger_fn, &tctx[t]);
		if (!ASSERT_OK(err, "create delete trigger")) {
			stop = true;
			goto reap;
		}
	}
	for (i = 0; i < STRESS_NR_LOOKUP; i++, t++) {
		tctx[t].nr = STRESS_LOOPS;
		tctx[t].syscall_nr = __NR_getuid;
		tctx[t].stop = &stop;
		err = pthread_create(&tids[t], NULL, trigger_fn, &tctx[t]);
		if (!ASSERT_OK(err, "create lookup trigger")) {
			stop = true;
			goto reap;
		}
	}

reap:
	for (i = 0; i < STRESS_NR_THREADS; i++) {
		if (!tids[i])
			continue;
		pthread_join(tids[i], NULL);
	}

	/* Detach BPF programs before post-stress verification */
	qp_trie_stress__detach(skel);

	/* After stress, verify map is still functional */
	{
		__u64 key = htobe64(99999), value = 1;

		err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
		ASSERT_OK(err, "post-stress insert");

		value = 0;
		err = bpf_map_lookup_elem(map_fd, &key, &value);
		ASSERT_OK(err, "post-stress lookup");
		ASSERT_EQ(value, 1, "post-stress value");

		err = bpf_map_delete_elem(map_fd, &key);
		ASSERT_OK(err, "post-stress delete");
	}

cleanup:
	qp_trie_stress__destroy(skel);
}

void test_qp_trie(void)
{
	if (test__start_subtest("bpf_ops"))
		test_qp_trie_bpf_ops();
	if (test__start_subtest("stress"))
		test_qp_trie_stress();
}
