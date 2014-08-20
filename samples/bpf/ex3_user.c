#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct globals {
	__u64 lat_ave;
	__u64 lat_sum;
	__u64 missed;
	__u64 max_lat;
	int num_samples;
};

static void clear_stats(int fd)
{
	int key;
	__u64 value = 0;
	for (key = 0; key < 32; key++)
		bpf_update_elem(fd, &key, &value, BPF_ANY);
}

const char *color[] = {
	"\033[48;5;255m",
	"\033[48;5;252m",
	"\033[48;5;250m",
	"\033[48;5;248m",
	"\033[48;5;246m",
	"\033[48;5;244m",
	"\033[48;5;242m",
	"\033[48;5;240m",
	"\033[48;5;238m",
	"\033[48;5;236m",
	"\033[48;5;234m",
	"\033[48;5;232m",
};
const int num_colors = ARRAY_SIZE(color);

const char nocolor[] = "\033[00m";

static void print_banner(__u64 max_lat)
{
	printf("0 usec     ...          %lld usec\n", max_lat);
}

static void print_hist(int fd)
{
	int key;
	__u64 value;
	__u64 cnt[32];
	__u64 max_cnt = 0;
	__u64 total_events = 0;
	int max_bucket = 0;

	for (key = 0; key < 32; key++) {
		value = 0;
		bpf_lookup_elem(fd, &key, &value);
		if (value > 0)
			max_bucket = key;
		cnt[key] = value;
		total_events += value;
		if (value > max_cnt)
			max_cnt = value;
	}
	clear_stats(fd);
	for (key = 0; key < 32; key++) {
		int c = num_colors * cnt[key] / (max_cnt + 1);
		printf("%s %s", color[c], nocolor);
	}
	printf(" captured=%lld", total_events);

	key = 0;
	struct globals g = {};
	bpf_lookup_elem(map_fd[1], &key, &g);

	printf(" missed=%lld max_lat=%lld usec\n",
	       g.missed, g.max_lat);

	if (g.missed > 10 && g.missed > total_events / 10) {
		printf("adjusting range UP...\n");
		g.lat_ave = g.max_lat / 2;
		print_banner(g.lat_ave * 2);
	} else if (max_bucket < 4 && total_events > 100) {
		printf("adjusting range DOWN...\n");
		g.lat_ave = g.lat_ave / 4;
		print_banner(g.lat_ave * 2);
	}
	/* clear some globals */
	g.missed = 0;
	g.max_lat = 0;
	bpf_update_elem(map_fd[1], &key, &g, BPF_ANY);
}

static void int_exit(int sig)
{
	print_hist(map_fd[2]);
	exit(0);
}

int main(int ac, char **argv)
{
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	clear_stats(map_fd[2]);

	signal(SIGINT, int_exit);

	if (fork() == 0) {
		read_trace_pipe();
	} else {
		struct globals g;

		printf("waiting for events to determine average latency...\n");
		for (;;) {
			int key = 0;
			bpf_lookup_elem(map_fd[1], &key, &g);
			if (g.lat_ave)
				break;
			sleep(1);
		}

		printf("  IO latency in usec\n"
		       "  %s %s - many events with this latency\n"
		       "  %s %s - few events\n",
		       color[num_colors - 1], nocolor,
		       color[0], nocolor);
		print_banner(g.lat_ave * 2);
		for (;;) {
			print_hist(map_fd[2]);
			sleep(2);
		}
	}

	return 0;
}
