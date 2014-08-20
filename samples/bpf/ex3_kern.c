#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <trace/bpf_trace.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = sizeof(u64),
	.max_entries = 4096,
};

/* alternative events:
 * SEC("events/syscalls/sys_enter_write")
 * SEC("events/net/net_dev_start_xmit")
 */
SEC("events/block/block_rq_issue")
int bpf_prog1(struct bpf_context *ctx)
{
	long rq = ctx->arg2; /* long rq = bpf_get_current(); */
	u64 val = bpf_ktime_get_ns();

	bpf_map_update_elem(&my_map, &rq, &val, BPF_ANY);
	return 0;
}

struct globals {
	u64 lat_ave;
	u64 lat_sum;
	u64 missed;
	u64 max_lat;
	int num_samples;
};

struct bpf_map_def SEC("maps") global_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct globals),
	.max_entries = 1,
};

#define MAX_SLOT 32

struct bpf_map_def SEC("maps") lat_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u64),
	.max_entries = MAX_SLOT,
};

/* alternative evenets:
 * SEC("events/syscalls/sys_exit_write")
 * SEC("events/net/net_dev_xmit")
 */
SEC("events/block/block_rq_complete")
int bpf_prog2(struct bpf_context *ctx)
{
	long rq = ctx->arg2;
	void *value;

	value = bpf_map_lookup_elem(&my_map, &rq);
	if (!value)
		return 0;

	u64 cur_time = bpf_ktime_get_ns();
	u64 delta = (cur_time - *(u64 *)value) / 1000;

	bpf_map_delete_elem(&my_map, &rq);

	int ind = 0;
	struct globals *g = bpf_map_lookup_elem(&global_map, &ind);
	if (!g)
		return 0;
	if (g->lat_ave == 0) {
		g->num_samples++;
		g->lat_sum += delta;
		if (g->num_samples >= 100) {
			g->lat_ave = g->lat_sum / g->num_samples;
			if (0/* debug */) {
				char fmt[] = "after %d samples average latency %ld usec\n";
				bpf_printk(fmt, sizeof(fmt), g->num_samples,
					   g->lat_ave);
			}
		}
	} else {
		u64 max_lat = g->lat_ave * 2;
		if (delta > max_lat) {
			g->missed++;
			if (delta > g->max_lat)
				g->max_lat = delta;
			return 0;
		}

		ind = delta * MAX_SLOT / max_lat;
		value = bpf_map_lookup_elem(&lat_map, &ind);
		if (!value)
			return 0;
		(*(u64 *)value) ++;
	}

	return 0;
}
char _license[] SEC("license") = "GPL";
