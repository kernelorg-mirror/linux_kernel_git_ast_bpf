// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

struct uptr_list_node;

typedef struct uptr_list_node __uptr uptr_list_node_t;

struct uptr_list_node {
	uptr_list_node_t *next;
	uptr_list_node_t * __uptr *pprev;
};

struct uptr_list_head {
	struct uptr_list_node __uptr *first;
};
typedef struct uptr_list_head __uptr uptr_list_head_t;

struct htab_bucket {
	struct uptr_list_head head;
};
typedef struct htab_bucket __uptr htab_bucket_t;

struct htab {
	htab_bucket_t *buckets;
	int n_buckets;
	int pad;
};
typedef struct htab __uptr htab_t;

static inline htab_bucket_t *__select_bucket(htab_t *htab, __u32 hash)
{
	return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static inline uptr_list_head_t *select_bucket(htab_t *htab, __u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

struct hashtab_elem {
	struct uptr_list_node hash_node;
	int hash;
	int key;
	int value;
	int pad;
};
typedef struct hashtab_elem __uptr hashtab_elem_t;

#define ulist_entry(ptr, type, member) container_of(ptr,type,member)

#define ulist_entry_safe(ptr, type, member) \
	({ typeof(*ptr) * ___ptr = (ptr); \
	 ___ptr ? ulist_entry(___ptr, type, member) : NULL; \
	 })

#define ulist_for_each_entry(pos, head, member)                         \
	for (__i = 0, pos = ulist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos && __i < 10;                                                     \
	     pos = ulist_entry_safe((pos)->member.next, typeof(*(pos)), member), __i++)

static inline void ulist_add_head(uptr_list_node_t *n, uptr_list_head_t *h)
{
	uptr_list_node_t *first = h->first;
	WRITE_ONCE(n->next, first);
	if (first)
		WRITE_ONCE(first->pprev, &n->next);
	WRITE_ONCE(h->first, n);
	WRITE_ONCE(n->pprev, &h->first);
}

static inline void __ulist_del(uptr_list_node_t *n)
{
	uptr_list_node_t *next = n->next;
	uptr_list_node_t * __uptr *pprev = n->pprev;

	WRITE_ONCE(*pprev, next);
	if (next)
		WRITE_ONCE(next->pprev, pprev);
}

#define POISON_POINTER_DELTA 0

#define LIST_POISON1  ((void __uptr *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void __uptr *) 0x122 + POISON_POINTER_DELTA)

static inline void ulist_del(uptr_list_node_t *n)
{
	__ulist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

static hashtab_elem_t *lookup_elem_raw(uptr_list_head_t *head, __u32 hash, int key)
{
	hashtab_elem_t *l;
	int __i;

	ulist_for_each_entry(l, head, hash_node)
		if (l->hash == hash && l->key == key)
			return l;

	return NULL;
}

static int htab_hash(int key)
{
	return key;
}

void __uptr *cur_page;
int cur_offset;

/* Simple page_frag allocator */
static void __uptr* bpf_alloc(int size)
{
	__u64 __uptr *obj_cnt;
	void __uptr *page = cur_page;
	int offset;
	int retry = 0;

	bpf_cast_as(page, 1);
	if (!page) {
refill:
		page = bpf_uptr_alloc_pages(&arena, 1);
		bpf_cast_as(page, 1);
		cur_page = page;
		cur_offset = PAGE_SIZE - 8;
		obj_cnt = page + PAGE_SIZE - 8;
		*obj_cnt = 0;
	} else {
		obj_cnt = page + PAGE_SIZE - 8;
	}

	offset = cur_offset - size;
	if (offset < 0 && retry++ < 3)
		goto refill;

	(*obj_cnt)++;
	cur_offset = offset;
	return page + offset;
}

static void bpf_free(void __uptr *addr)
{
	__u64 __uptr *obj_cnt;

	addr = (void __uptr *)(((long)addr) & ~(PAGE_SIZE - 1));
	obj_cnt = addr + PAGE_SIZE - 8;
	if (--(*obj_cnt) == 0)
		bpf_uptr_free_pages(&arena, addr, 1);
}

__weak int htab_lookup_elem(htab_t *htab, int key)
{
	hashtab_elem_t *l_old;
	uptr_list_head_t *head;

	head = select_bucket(htab, key);
	l_old = lookup_elem_raw(head, htab_hash(key), key);
	if (l_old)
		return l_old->value;
	return 0;
}

__weak int htab_update_elem(struct htab __uptr *htab, int key, int value)
{
	hashtab_elem_t *l_new = NULL, *l_old;
	uptr_list_head_t *head;

	head = select_bucket(htab, key);
	l_old = lookup_elem_raw(head, htab_hash(key), key);

	l_new = bpf_alloc(sizeof(*l_new));
	l_new->key = key;
	l_new->hash = htab_hash(key);
	l_new->value = value;

	ulist_add_head(&l_new->hash_node, head);
	if (l_old) {
		ulist_del(&l_old->hash_node);
		bpf_free(l_old);
	}
	return 0;
}

void htab_init(htab_t *htab)
{
	void __uptr *buckets = bpf_uptr_alloc_pages(&arena, 2);

	bpf_cast_as(buckets, 1);
	htab->buckets = buckets;
	htab->n_buckets = 2 * PAGE_SIZE / sizeof(struct htab_bucket);
}
