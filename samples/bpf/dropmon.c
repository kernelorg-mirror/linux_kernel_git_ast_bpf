/* simple packet drop monitor:
 * - in-kernel eBPF program attaches to kfree_skb() event and records number
 *   of packet drops at given location
 * - userspace iterates over the map every second and prints stats
 */
#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <errno.h>
#include <linux/unistd.h>
#include <string.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include "libbpf.h"

#define TRACEPOINT "/sys/kernel/debug/tracing/events/skb/kfree_skb/id"

static int dropmon(void)
{
	long long key, next_key, value = 0;
	int prog_fd, map_fd, i, event_fd, efd, err;
	char buf[32];

	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), 1024);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	/* the following eBPF program is equivalent to C:
	 * int filter(struct bpf_context *ctx)
	 * {
	 *   long loc = ctx->arg2;
	 *   long init_val = 1;
	 *   long *value;
	 *
	 *   value = bpf_map_lookup_elem(MAP_ID, &loc);
	 *   if (value) {
	 *      __sync_fetch_and_add(value, 1);
	 *   } else {
	 *      bpf_map_update_elem(MAP_ID, &loc, &init_val, BPF_ANY);
	 *   }
	 *   return 0;
	 * }
	 */
	struct bpf_insn prog[] = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 8), /* r2 = *(u64 *)(r1 + 8) */
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -8), /* *(u64 *)(fp - 8) = r2 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), /* r2 = fp - 8 */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),
		BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
		BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 1), /* *(u64 *)(fp - 16) = 1 */
		BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16), /* r3 = fp - 16 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), /* r2 = fp - 8 */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, prog,
				sizeof(prog), "GPL");
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n%s",
		       strerror(errno), bpf_log_buf);
		return -1;
	}


	event_fd = open(TRACEPOINT, O_RDONLY, 0);
	if (event_fd < 0) {
		printf("failed to open event %s\n", TRACEPOINT);
		return -1;
	}

	err = read(event_fd, buf, sizeof(buf));
	if (err < 0 || err >= sizeof(buf)) {
		printf("read from '%s' failed '%s'\n",
		       TRACEPOINT, strerror(errno));
		return -1;
	}

	close(event_fd);

	buf[err] = 0;

	struct perf_event_attr attr = {.type = PERF_TYPE_TRACEPOINT};
	attr.config = atoi(buf);

	efd = perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	if (efd < 0) {
		printf("event %lld fd %d err %s\n",
		       attr.config, efd, strerror(errno));
		return -1;
	}
	ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(efd, PERF_EVENT_IOC_SET_BPF, prog_fd);

	for (i = 0; i < 10; i++) {
		key = 0;
		while (bpf_get_next_key(map_fd, &key, &next_key) == 0) {
			bpf_lookup_elem(map_fd, &next_key, &value);
			printf("location 0x%llx count %lld\n", next_key, value);
			key = next_key;
		}
		if (key)
			printf("\n");
		sleep(1);
	}

cleanup:
	/* maps, programs, tracepoint filters will auto cleanup on process exit */

	return 0;
}

int main(void)
{
	FILE *f;

	/* start ping in the background to get some kfree_skb events */
	f = popen("ping -c5 localhost", "r");
	(void) f;

	dropmon();
	return 0;
}
