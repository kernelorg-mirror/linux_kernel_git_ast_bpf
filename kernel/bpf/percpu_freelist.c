/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "percpu_freelist.h"

int pcpu_freelist_init(struct pcpu_freelist *s)
{
	int cpu;

	s->freelist = alloc_percpu(struct pcpu_freelist_head);
	if (!s->freelist)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct pcpu_freelist_head *head = per_cpu_ptr(s->freelist, cpu);

		raw_spin_lock_init(&head->lock);
		head->first = NULL;
	}
	return 0;
}

void pcpu_freelist_destroy(struct pcpu_freelist *s)
{
	free_percpu(s->freelist);
}

static inline void __pcpu_freelist_push(struct pcpu_freelist_head *head,
					struct pcpu_freelist_node *node)
{
	raw_spin_lock(&head->lock);
	node->next = head->first;
	head->first = node;
	raw_spin_unlock(&head->lock);
}

void pcpu_freelist_push(struct pcpu_freelist *s,
			struct pcpu_freelist_node *node)
{
	struct pcpu_freelist_head *head = this_cpu_ptr(s->freelist);

	__pcpu_freelist_push(head, node);
}

void pcpu_freelist_push_cpu(struct pcpu_freelist *s,
			    struct pcpu_freelist_node *node, int cpu)
{
	struct pcpu_freelist_head *head = per_cpu_ptr(s->freelist, cpu);

	__pcpu_freelist_push(head, node);
}

struct pcpu_freelist_node *pcpu_freelist_pop(struct pcpu_freelist *s)
{
	struct pcpu_freelist_head *head;
	struct pcpu_freelist_node *node;
	int orig_cpu, cpu;
	
	orig_cpu = cpu = raw_smp_processor_id();
retry:
	head = per_cpu_ptr(s->freelist, cpu);
	raw_spin_lock(&head->lock);
	node = head->first;
	if (node) {
		head->first = node->next;
		raw_spin_unlock(&head->lock);
		return node;
	} else {
		raw_spin_unlock(&head->lock);
		cpu = cpumask_next(cpu, cpu_possible_mask);
		if (cpu >= nr_cpu_ids)
			cpu = 0;
		if (cpu == orig_cpu)
			return NULL;
		goto retry;
	}
}
