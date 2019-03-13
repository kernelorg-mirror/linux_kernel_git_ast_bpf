// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "test_iptunnel_common.h"
#include "bpf_endian.h"

int _version SEC("version") = 1;

static __attribute__((always_inline)) __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

/* copy paste of jhash from kernel sources to make sure llvm
 * can compile it into valid sequence of bpf instructions
 */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

#define JHASH_INITVAL		0xdeadbeef

typedef unsigned int u32;

static __attribute__((noinline))
//static __attribute__((always_inline))
u32 jhash(const void *key, u32 length, u32 initval)
{
	u32 a, b, c;
	const unsigned char *k = key;

	a = b = c = JHASH_INITVAL + length + initval;

	while (length > 12) {
		a += *(volatile u32 *)(k);
		b += *(volatile u32 *)(k + 4);
		c += *(volatile u32 *)(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	switch (length) {
	case 12: c += (u32)k[11]<<24;
	case 11: c += (u32)k[10]<<16;
	case 10: c += (u32)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (u32)k[7]<<24;
	case 7:  b += (u32)k[6]<<16;
	case 6:  b += (u32)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (u32)k[3]<<24;
	case 3:  a += (u32)k[2]<<16;
	case 2:  a += (u32)k[1]<<8;
	case 1:  a += k[0];
		 c ^= a;
		 __jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

SEC("l4lb-demo")
int balancer_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *ptr;
	int ret = 0, nh_off, i = 0;

	nh_off = sizeof(struct ethhdr);

	/* pragma unroll doesn't work on large loops */

#define C do { \
	ptr = data + i; \
	if (ptr + nh_off > data_end) \
		break; \
	ctx->tc_index = jhash(ptr, nh_off, ctx->cb[0] + i++); \
	} while (0);
#define C30 C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;C;
#define C10 C30;C30;C30;C30;C30;C30;C30;C30;C30;C30;
	C30;C30;C30; /* 300 calls */
//	C10;
	return 0;
}
char _license[] SEC("license") = "GPL";
