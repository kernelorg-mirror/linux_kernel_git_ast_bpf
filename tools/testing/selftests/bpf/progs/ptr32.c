// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

#define _32 __attribute__((address_space(271))) __attribute__((btf_type_tag("ptr32")))

struct list_node {
	struct list_node _32* next;
	struct list_node _32* _32* pprev;
	int sz;
};

void _32* bpf_alloc32(__u32 size) __ksym;

void set(struct list_node _32* node)
{
	node->next = bpf_alloc32(sizeof(*node));
	node->sz = sizeof(*node);
	*node->pprev = node;
	node += 1ull<<20;
	node->sz = sizeof(*node);
}

SEC("tc")
int ptr32_basic(void *ctx)
{
	set(bpf_alloc32(128));
	return 0;
}

char _license[] SEC("license") = "GPL";
