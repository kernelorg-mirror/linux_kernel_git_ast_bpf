#include <stdio.h>
#include <linux/bpf.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"

static char *get_str(void *entry, __u32 arrloc)
{
	int off = arrloc & 0xffff;
	return entry + off;
}

static void print_netif_receive_skb(void *data, int size)
{
	struct ftrace_raw_netif_receive_skb {
		struct trace_entry t;
		void *skb;
		__u32 len;
		__u32 name;
	} *e = data;

	printf("pid %d skb %p len %d dev %s\n",
	       e->t.pid, e->skb, e->len, get_str(e, e->name));
}

int main(int ac, char **argv)
{
	FILE *f;
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	if (perf_event_mmap(event_fd[0]) < 0)
		return 1;

	f = popen("taskset 1 ping -c5 localhost", "r");
	(void) f;

	for (;;) {
		perf_event_poll(event_fd[0]);
		perf_event_read(print_netif_receive_skb);
	}

	return 0;
}
