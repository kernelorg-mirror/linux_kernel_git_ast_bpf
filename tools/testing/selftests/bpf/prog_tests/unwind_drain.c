// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "verifier_unwind_cb.skel.h"

/* The callback unwinds on its sample with 5. The sample is consumed and the busy bit dropped. */
void test_unwind_drain(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = &pkt_v4, .data_size_in = sizeof(pkt_v4));
	struct user_ring_buffer *rb = NULL;
	struct verifier_unwind_cb *skel;
	struct bpf_program *prog;
	void *sample;
	int fd;

	skel = verifier_unwind_cb__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, prog == skel->progs.drain_cb_unwinds);
	if (verifier_unwind_cb__load(skel)) {
		test__skip();
		goto out;
	}
	fd = bpf_program__fd(skel->progs.drain_cb_unwinds);
	rb = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf), NULL);
	sample = rb ? user_ring_buffer__reserve(rb, 8) : NULL;
	if (!ASSERT_OK_PTR(sample, "reserve"))
		goto out;
	user_ring_buffer__submit(rb, sample);
	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "run");
	ASSERT_EQ(opts.retval, 47, "unwinds");
	ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "run again");
	ASSERT_EQ(opts.retval, 0, "consumed");
out:
	user_ring_buffer__free(rb);
	verifier_unwind_cb__destroy(skel);
}
