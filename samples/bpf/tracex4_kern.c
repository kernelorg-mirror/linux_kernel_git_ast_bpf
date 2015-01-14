#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <trace/bpf_trace.h>
#include "bpf_helpers.h"

static unsigned int log2l(unsigned long long n)
{
#define S(k) if (n >= (1ull << k)) { i += k; n >>= k; }
	int i = -(n == 0);
	S(32); S(16); S(8); S(4); S(2); S(1);
	return i;
#undef S
}

struct bpf_map_def SEC("maps") my_hist_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 64,
};

SEC("events/kprobes/sys_write")
int bpf_prog4(struct pt_regs *regs)
{
	long write_size = regs->dx; /* $rdx contains 3rd argument to a function */
	long init_val = 1;
	void *value;
	u32 index = log2l(write_size);

	value = bpf_map_lookup_elem(&my_hist_map, &index);
	if (value)
		__sync_fetch_and_add((long *)value, 1);
	return 0;
}
char _license[] SEC("license") = "GPL";
