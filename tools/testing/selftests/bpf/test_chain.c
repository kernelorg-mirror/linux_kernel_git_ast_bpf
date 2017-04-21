/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include "bpf_helpers.h"

#define htons __builtin_bswap16
#define ntohs __builtin_bswap16
int _version SEC("version") = 1;

struct md {
	__u8 proto;
	__u8 is_ipv6;
};

struct bpf_map_def SEC("maps") pcpu = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct md),
	.max_entries = 1,
};

static __always_inline int handle_ipv4(struct xdp_md *xdp, struct md *md)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct iphdr *iph = data + sizeof(struct ethhdr);

	md->is_ipv6 = false;
	if (iph + 1 > data_end)
		return XDP_DROP;
	md->proto = iph->protocol;
	bpf_tail_call_next(xdp);
	return XDP_DROP;
}

static __always_inline int handle_ipv6(struct xdp_md *xdp, struct md *md)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

	md->is_ipv6 = true;
	if (ip6h + 1 > data_end)
		return XDP_DROP;
	md->proto = ip6h->nexthdr;
	bpf_tail_call_next(xdp);
	return XDP_DROP;
}

SEC("xdp_prog1")
int _xdp_prog1(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	struct md *md;
	__u32 key = 0;
	__u16 h_proto;

	if (eth + 1 > data_end)
		return XDP_DROP;
	h_proto = eth->h_proto;

	md = bpf_map_lookup_elem(&pcpu, &key);
	if (!md)
		return XDP_DROP;

	if (h_proto == htons(ETH_P_IP))
		return handle_ipv4(xdp, md);
	else if (h_proto == htons(ETH_P_IPV6))
		return handle_ipv6(xdp, md);
	else
		return XDP_DROP;
}

SEC("xdp_prog2")
int _xdp_prog2(struct xdp_md *xdp)
{
	struct md *md;
	__u32 key = 0;

	md = bpf_map_lookup_elem(&pcpu, &key);
	if (!md)
		return XDP_DROP;
	if (md->is_ipv6 && md->proto == 6)
		return XDP_PASS;
	bpf_tail_call_next(xdp);
	return XDP_ABORTED;
}

SEC("xdp_prog3")
int _xdp_prog3(struct xdp_md *xdp)
{
	struct md *md;
	__u32 key = 0;

	md = bpf_map_lookup_elem(&pcpu, &key);
	if (!md)
		return XDP_DROP;
	if (!md->is_ipv6 && md->proto == 6)
		return XDP_TX;
	bpf_tail_call_next(xdp);
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
