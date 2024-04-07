// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <regex.h>
#include <test_progs.h>
#include <network_helpers.h>

struct bpf_lock {
	__u32 lock_id;
};

#include "arena_lock.skel.h"

#define NUM_THREADS 32

int repeat = 1;

static void *lock_thread(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int ret = 0, prog_fd = *(u32 *) arg, i;

	for (i = 0; i < repeat; i++)
		ret |= bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "ret");
	ASSERT_OK(opts.retval, "retval");
	pthread_exit(arg);
}

static int run_threads(struct arena_lock *skel, int prog_fd)
{
	pthread_t thread_id[NUM_THREADS];
	int i, err;

	for (i = 0; i < NUM_THREADS; i++) {
		err = pthread_create(&thread_id[i], NULL, &lock_thread, &prog_fd);
		if (!ASSERT_OK(err, "pthread_create"))
			goto out;
	}

	for (i = 0; i < NUM_THREADS; i++) {
		void *ret;

		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join"))
			goto out;
		if (!ASSERT_EQ(ret, &prog_fd, "ret == prog_fd"))
			goto out;
	}
	if (skel->bss->skip) {
		printf("%s:SKIP:compiler doesn't support arena_cast\n", __func__);
		test__skip();
		err = 0;
		goto out;
	}
out:
	return err;
}

static void test_basic_lock(void)
{
	struct arena_lock *skel;
	int prog_fd, err, i;

	skel = arena_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_lock__open_and_load"))
		return;
	err = arena_lock__attach(skel);
	ASSERT_OK(err, "arena_lock__attach");
	prog_fd = bpf_program__fd(skel->progs.arena_lock);
	if (run_threads(skel, prog_fd))
		goto out;
	for (i = 0; i < 8; i++) {
		ASSERT_EQ(skel->arena->cnt[i], NUM_THREADS * 1000 * repeat, "cnt");
		ASSERT_EQ(skel->arena->locks[i].lock_id, 0, "lock_id");
	}
//	ASSERT_EQ(skel->bss->other_cnt, NUM_THREADS * 1000 * 8, "other_cnt");
	ASSERT_EQ(skel->bss->busy, 0, "busy");
out:
	arena_lock__destroy(skel);
}

static void test_old_spin_lock(void)
{
	struct arena_lock *skel;
	int prog_fd, err, i;

	skel = arena_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_lock__open_and_load"))
		return;
	err = arena_lock__attach(skel);
	ASSERT_OK(err, "arena_lock__attach");
	prog_fd = bpf_program__fd(skel->progs.old_spin_lock);
	if (run_threads(skel, prog_fd))
		goto out;
	for (i = 0; i < 8; i++) {
		ASSERT_EQ(skel->arena->cnt[i], NUM_THREADS * 1000 * repeat, "cnt");
	}
	ASSERT_EQ(skel->bss->busy, 0, "busy");
out:
	arena_lock__destroy(skel);
}

static void test_AA_lock(void)
{
	struct arena_lock *skel;
	int prog_fd, err;

	skel = arena_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_lock__open_and_load"))
		return;
	err = arena_lock__attach(skel);
	ASSERT_OK(err, "arena_lock__attach");
	prog_fd = bpf_program__fd(skel->progs.arena_AA_lock);
	if (run_threads(skel, prog_fd))
		goto out;
	ASSERT_GT(skel->bss->AAlock_cnt, 0, "AAlock");
out:
	arena_lock__destroy(skel);
}

static void test_ABBA_lock(void)
{
	struct arena_lock *skel;
	int prog_fd, err;

	skel = arena_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_lock__open_and_load"))
		return;
	err = arena_lock__attach(skel);
	ASSERT_OK(err, "arena_lock__attach");
	prog_fd = bpf_program__fd(skel->progs.arena_ABBA_lock);
	if (run_threads(skel, prog_fd))
		goto out;
	ASSERT_GT(skel->bss->ABBAlock_cnt, 0, "ABBAlock");
out:
	arena_lock__destroy(skel);
}

void test_arena_lock(void)
{
	if (test__start_subtest("basic_lock"))
		test_basic_lock();
	if (test__start_subtest("old_spin_lock"))
		test_old_spin_lock();
	if (test__start_subtest("AA_lock"))
		test_AA_lock();
	if (test__start_subtest("ABBA_lock"))
		test_ABBA_lock();
}
