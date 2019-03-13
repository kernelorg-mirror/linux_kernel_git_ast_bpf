// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

void test_bpf_verif_scale(void)
{
	const char *file = "./test_verif_scale.o";
	struct bpf_object *obj;
	int err, prog_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	printf("test_verif_scale:OK\n");
	bpf_object__close(obj);
}
