/* eBPF example program:
 * - creates a hashtable in kernel with key 4 bytes and value 8 bytes
 *
 * - populates map[6] = 0; map[17] = 0;  // 6 - tcp_proto, 17 - udp_proto
 *
 * - loads eBPF program:
 *   r0 = skb[14 + 9]; // load one byte of ip->proto
 *   *(u32*)(fp - 4) = r0;
 *   value = bpf_map_lookup_elem(map_id, fp - 4);
 *   if (value)
 *        (*(u64*)value) += 1;
 *
 * - attaches this program to eth0 raw socket
 *
 * - every second user space reads map[6] and map[17] to see how many
 *   TCP and UDP packets were seen on eth0
 */
#include <stdio.h>
#include <unistd.h>
#include <asm-generic/socket.h>
#include <linux/netlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/bpf.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/unistd.h>
#include <string.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "libbpf.h"

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	struct packet_mreq mr;
	struct ifreq ifr;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot open socket!\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy((char *)ifr.ifr_name, name, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		printf("ioctl: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		printf("set_promisc: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

static int test_sock(void)
{
	int sock = -1, map_fd, prog_fd, i, key;
	long long value = 0, tcp_cnt, udp_cnt;

	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), 2);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		/* must have been left from previous aborted run, delete it */
		goto cleanup;
	}

	key = 6; /* tcp */
	if (bpf_update_elem(map_fd, &key, &value) < 0) {
		printf("update err key=%d\n", key);
		goto cleanup;
	}

	key = 17; /* udp */
	if (bpf_update_elem(map_fd, &key, &value) < 0) {
		printf("update err key=%d\n", key);
		goto cleanup;
	}

	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_LD_ABS(BPF_B, 14 + 9 /* R0 = ip->proto */),
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
		BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */
		BPF_MOV64_IMM(BPF_REG_0, 0), /* r0 = 0 */
		BPF_EXIT_INSN(),
	};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog),
				"GPL");
	if (prog_fd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		goto cleanup;
	}

	sock = open_raw_sock("lo");

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER_EBPF, &prog_fd, sizeof(prog_fd)) < 0) {
		printf("setsockopt %d\n", errno);
		goto cleanup;
	}

	for (i = 0; i < 10; i++) {
		key = 6;
		if (bpf_lookup_elem(map_fd, &key, &tcp_cnt) < 0) {
			printf("lookup err\n");
			break;
		}
		key = 17;
		if (bpf_lookup_elem(map_fd, &key, &udp_cnt) < 0) {
			printf("lookup err\n");
			break;
		}
		printf("TCP %lld UDP %lld packets\n", tcp_cnt, udp_cnt);
		sleep(1);
	}

cleanup:
	/* maps, programs, raw sockets will auto cleanup on process exit */

	return 0;
}

int main(void)
{
	test_sock();
	return 0;
}
