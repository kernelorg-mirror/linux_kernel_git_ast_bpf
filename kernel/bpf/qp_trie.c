// SPDX-License-Identifier: GPL-2.0-only
/*
 * QP-Trie (Quadbit Popcount Patricia Trie) BPF map
 *
 * Provides exact-match key-value lookup with ordered iteration.
 * Branches on 4-bit nibbles using a 16-bit bitmap + popcount
 * to compress sparse child arrays.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <uapi/linux/btf.h>
#include <linux/btf_ids.h>
#include <asm/rqspinlock.h>
#include <linux/bpf_mem_alloc.h>

#define QP_TRIE_KEY_SIZE_MAX	256
#define QP_TRIE_KEY_SIZE_MIN	1
#define QP_TRIE_VAL_SIZE_MIN	1

#define QP_TRIE_CREATE_FLAG_MASK (BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | \
				  BPF_F_ACCESS_MASK)

/*
 * Tagged pointer: bit 0 = 1 for leaf, bit 0 = 0 for branch.
 * All allocations are >= 8-byte aligned so bottom 3 bits are free.
 */
#define QP_LEAF_TAG	1UL

struct qp_trie_leaf {
	DECLARE_FLEX_ARRAY(u8, data);	/* key[key_size] followed by value[value_size] */
};

struct qp_trie_branch {
	u32 offset;		/* nibble position (0 .. key_size*2 - 1) */
	u16 bitmap;		/* which nibble values 0..15 have children */
	u16 pad;
	unsigned long children[];  /* popcount(bitmap) tagged child pointers */
};

struct qp_trie {
	struct bpf_map		map;
	unsigned long		root;		/* tagged pointer */
	struct bpf_mem_alloc	leaf_ma;	/* fixed-size for leaves */
	struct bpf_mem_alloc	branch_ma;	/* variable-size for branches */
	size_t			n_entries;
	u32			max_nibbles;	/* key_size * 2 */
	rqspinlock_t		lock;
};

/* --- Tagged pointer helpers --- */

static inline bool qp_is_leaf(unsigned long ptr)
{
	return ptr & QP_LEAF_TAG;
}

static inline struct qp_trie_leaf *qp_to_leaf(unsigned long ptr)
{
	return (struct qp_trie_leaf *)(ptr & ~QP_LEAF_TAG);
}

static inline struct qp_trie_branch *qp_to_branch(unsigned long ptr)
{
	return (struct qp_trie_branch *)ptr;
}

static inline unsigned long qp_mk_leaf(struct qp_trie_leaf *leaf)
{
	return (unsigned long)leaf | QP_LEAF_TAG;
}

static inline unsigned long qp_mk_branch(struct qp_trie_branch *branch)
{
	return (unsigned long)branch;
}

/* --- Nibble extraction --- */

static inline u8 qp_nibble(const u8 *key, u32 pos)
{
	return (pos & 1) ? (key[pos >> 1] & 0xf) : (key[pos >> 1] >> 4);
}

/* --- Branch sizing --- */

static inline size_t qp_branch_size(int n_children)
{
	return sizeof(struct qp_trie_branch) +
	       n_children * sizeof(unsigned long);
}

/* --- RCU accessors for tagged pointers stored as unsigned long --- */

static inline unsigned long qp_deref(unsigned long *p)
{
	return (unsigned long)rcu_dereference_check(
		*(void *__rcu __force *)p, rcu_read_lock_bh_held());
}

static inline unsigned long qp_deref_locked(unsigned long *p)
{
	return (unsigned long)rcu_dereference_protected(
		*(void *__rcu __force *)p, true);
}

static inline void qp_publish(unsigned long *p, unsigned long val)
{
	rcu_assign_pointer(*(void *__rcu __force *)p, (void *)val);
}

/* --- Find first differing nibble position --- */

static u32 qp_find_diff_nibble(const u8 *key1, const u8 *key2, u32 key_size)
{
	u32 i;

	for (i = 0; i < key_size; i++) {
		if (key1[i] != key2[i]) {
			if ((key1[i] >> 4) != (key2[i] >> 4))
				return i * 2;
			else
				return i * 2 + 1;
		}
	}
	/* Should never be called when keys are equal */
	return key_size * 2;
}

/* --- Lookup (lock-free under RCU) --- */

static void *qp_trie_lookup_elem(struct bpf_map *map, void *_key)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct qp_trie_branch *branch;
	struct qp_trie_leaf *leaf;
	const u8 *key = _key;
	unsigned long ptr;
	u16 bit;
	u8 nib;
	int idx;

	ptr = qp_deref(&trie->root);

	while (ptr && !qp_is_leaf(ptr)) {
		branch = qp_to_branch(ptr);
		nib = qp_nibble(key, branch->offset);
		bit = 1u << nib;

		if (!(branch->bitmap & bit))
			return NULL;

		idx = hweight16(branch->bitmap & (bit - 1));
		ptr = qp_deref(&branch->children[idx]);
	}

	if (ptr) {
		leaf = qp_to_leaf(ptr);
		if (memcmp(leaf->data, key, map->key_size) == 0)
			return leaf->data + map->key_size;
	}

	return NULL;
}

/* --- Update (under rqspinlock) --- */

static long qp_trie_update_elem(struct bpf_map *map,
				 void *_key, void *value, u64 flags)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct qp_trie_branch *branch, *new_branch = NULL;
	struct qp_trie_leaf *new_leaf, *old_leaf;
	unsigned long *slot, ptr, walk_ptr, irq_flags;
	u32 diff_offset;
	u8 nib, old_nib, new_nib;
	u16 bit;
	int idx, n;
	int ret = 0;

	if (unlikely(flags > BPF_EXIST))
		return -EINVAL;

	/* Pre-allocate new leaf outside lock */
	new_leaf = bpf_mem_cache_alloc(&trie->leaf_ma);
	if (!new_leaf)
		return -ENOMEM;
	memcpy(new_leaf->data, _key, map->key_size);
	memcpy(new_leaf->data + map->key_size, value, map->value_size);

	ret = raw_res_spin_lock_irqsave(&trie->lock, irq_flags);
	if (ret)
		goto out_free_leaf;

	slot = &trie->root;
	ptr = qp_deref_locked(slot);

	/* Empty trie */
	if (!ptr) {
		if (flags == BPF_EXIST) {
			ret = -ENOENT;
			goto out_unlock;
		}
		if (trie->n_entries >= map->max_entries) {
			ret = -ENOSPC;
			goto out_unlock;
		}
		trie->n_entries++;
		qp_publish(slot, qp_mk_leaf(new_leaf));
		new_leaf = NULL;
		goto out_unlock;
	}

	/*
	 * Step 1: Walk to a leaf.  Follow the new key's nibbles through
	 * branches where the nibble is present.  When a nibble is missing,
	 * follow the first available child to reach any leaf for comparison.
	 * This avoids prematurely growing a branch before knowing where
	 * the new key actually diverges from existing keys.
	 */
	walk_ptr = ptr;
	while (walk_ptr && !qp_is_leaf(walk_ptr)) {
		branch = qp_to_branch(walk_ptr);
		nib = qp_nibble((const u8 *)_key, branch->offset);
		bit = 1u << nib;

		if (branch->bitmap & bit)
			idx = hweight16(branch->bitmap & (bit - 1));
		else
			idx = 0; /* follow first child */

		walk_ptr = qp_deref_locked(&branch->children[idx]);
	}

	old_leaf = qp_to_leaf(walk_ptr);

	/* Step 2: Exact match — replace leaf */
	if (memcmp(old_leaf->data, _key, map->key_size) == 0) {
		if (flags == BPF_NOEXIST) {
			ret = -EEXIST;
			goto out_unlock;
		}

		/* Re-walk to find the slot pointing to this leaf */
		slot = &trie->root;
		ptr = qp_deref_locked(slot);
		while (ptr && !qp_is_leaf(ptr)) {
			branch = qp_to_branch(ptr);
			nib = qp_nibble((const u8 *)_key, branch->offset);
			idx = hweight16(branch->bitmap & ((1u << nib) - 1));
			slot = &branch->children[idx];
			ptr = qp_deref_locked(slot);
		}

		qp_publish(slot, qp_mk_leaf(new_leaf));
		new_leaf = NULL;

		raw_res_spin_unlock_irqrestore(&trie->lock, irq_flags);
		bpf_mem_cache_free_rcu(&trie->leaf_ma, old_leaf);
		return 0;
	}

	/* Step 3: Keys differ — find where */
	if (flags == BPF_EXIST) {
		ret = -ENOENT;
		goto out_unlock;
	}
	if (trie->n_entries >= map->max_entries) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	diff_offset = qp_find_diff_nibble(old_leaf->data,
					   (const u8 *)_key, map->key_size);
	old_nib = qp_nibble(old_leaf->data, diff_offset);
	new_nib = qp_nibble((const u8 *)_key, diff_offset);

	/*
	 * Step 4: Re-walk from root to find the insertion point.
	 *
	 * At branches with offset < diff_offset the new key and the found
	 * leaf agree, so the key's nibble is always in the bitmap — safe
	 * to descend.  Stop at the first branch with offset >= diff_offset.
	 */
	slot = &trie->root;
	ptr = qp_deref_locked(slot);

	while (ptr && !qp_is_leaf(ptr)) {
		branch = qp_to_branch(ptr);
		if (branch->offset >= diff_offset)
			break;
		nib = qp_nibble((const u8 *)_key, branch->offset);
		idx = hweight16(branch->bitmap & ((1u << nib) - 1));
		slot = &branch->children[idx];
		ptr = qp_deref_locked(slot);
	}

	if (ptr && !qp_is_leaf(ptr) &&
	    qp_to_branch(ptr)->offset == diff_offset) {
		/*
		 * A branch already exists at the exact nibble position
		 * where the keys diverge.  Grow it by adding new_nib.
		 */
		branch = qp_to_branch(ptr);
		bit = 1u << new_nib;
		n = hweight16(branch->bitmap);
		idx = hweight16(branch->bitmap & (bit - 1));

		new_branch = bpf_mem_alloc(&trie->branch_ma,
					   qp_branch_size(n + 1));
		if (!new_branch) {
			ret = -ENOMEM;
			goto out_unlock;
		}

		new_branch->offset = branch->offset;
		new_branch->bitmap = branch->bitmap | bit;
		new_branch->pad = 0;

		memcpy(new_branch->children, branch->children,
		       idx * sizeof(unsigned long));
		new_branch->children[idx] = qp_mk_leaf(new_leaf);
		memcpy(&new_branch->children[idx + 1],
		       &branch->children[idx],
		       (n - idx) * sizeof(unsigned long));

		qp_publish(slot, qp_mk_branch(new_branch));
		trie->n_entries++;
		new_leaf = NULL;

		raw_res_spin_unlock_irqrestore(&trie->lock, irq_flags);
		bpf_mem_free_rcu(&trie->branch_ma, branch);
		return 0;
	}

	/*
	 * No branch exists at diff_offset (either ptr is a leaf,
	 * or it is a branch with offset > diff_offset).
	 * Insert a new 2-child branch here.
	 */
	new_branch = bpf_mem_alloc(&trie->branch_ma, qp_branch_size(2));
	if (!new_branch) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	new_branch->offset = diff_offset;
	new_branch->bitmap = (1u << old_nib) | (1u << new_nib);
	new_branch->pad = 0;

	if (new_nib < old_nib) {
		new_branch->children[0] = qp_mk_leaf(new_leaf);
		new_branch->children[1] = ptr;
	} else {
		new_branch->children[0] = ptr;
		new_branch->children[1] = qp_mk_leaf(new_leaf);
	}

	qp_publish(slot, qp_mk_branch(new_branch));
	trie->n_entries++;
	new_leaf = NULL;

out_unlock:
	raw_res_spin_unlock_irqrestore(&trie->lock, irq_flags);
out_free_leaf:
	if (new_leaf)
		bpf_mem_cache_free(&trie->leaf_ma, new_leaf);
	return ret;
}

/* --- Delete (under rqspinlock) --- */

static long qp_trie_delete_elem(struct bpf_map *map, void *_key)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct qp_trie_branch *parent, *new_branch;
	struct qp_trie_leaf *leaf;
	unsigned long *slot, *parent_slot, ptr, parent_ptr, remaining;
	unsigned long irq_flags;
	u8 nib;
	u16 bit;
	int idx, other_idx, n;
	int ret;

	ret = raw_res_spin_lock_irqsave(&trie->lock, irq_flags);
	if (ret)
		return ret;

	slot = &trie->root;
	ptr = qp_deref_locked(slot);
	parent_slot = NULL;
	parent_ptr = 0;

	/* Walk to the leaf */
	while (ptr && !qp_is_leaf(ptr)) {
		struct qp_trie_branch *branch = qp_to_branch(ptr);

		nib = qp_nibble((const u8 *)_key, branch->offset);
		bit = 1u << nib;

		if (!(branch->bitmap & bit)) {
			ret = -ENOENT;
			goto out;
		}

		idx = hweight16(branch->bitmap & (bit - 1));
		parent_slot = slot;
		parent_ptr = ptr;
		slot = &branch->children[idx];
		ptr = qp_deref_locked(slot);
	}

	if (!ptr || !qp_is_leaf(ptr)) {
		ret = -ENOENT;
		goto out;
	}

	leaf = qp_to_leaf(ptr);
	if (memcmp(leaf->data, _key, map->key_size) != 0) {
		ret = -ENOENT;
		goto out;
	}

	trie->n_entries--;

	if (!parent_slot) {
		/* Leaf is root */
		qp_publish(&trie->root, 0);
		raw_res_spin_unlock_irqrestore(&trie->lock, irq_flags);
		bpf_mem_cache_free_rcu(&trie->leaf_ma, leaf);
		return 0;
	}

	parent = qp_to_branch(parent_ptr);
	n = hweight16(parent->bitmap);
	nib = qp_nibble((const u8 *)_key, parent->offset);
	bit = 1u << nib;
	idx = hweight16(parent->bitmap & (bit - 1));

	if (n > 2) {
		/* Shrink branch (n-1 children) */
		new_branch = bpf_mem_alloc(&trie->branch_ma,
					   qp_branch_size(n - 1));
		if (!new_branch) {
			trie->n_entries++;
			ret = -ENOMEM;
			goto out;
		}

		new_branch->offset = parent->offset;
		new_branch->bitmap = parent->bitmap & ~bit;
		new_branch->pad = 0;

		memcpy(new_branch->children, parent->children,
		       idx * sizeof(unsigned long));
		memcpy(&new_branch->children[idx],
		       &parent->children[idx + 1],
		       (n - 1 - idx) * sizeof(unsigned long));

		qp_publish(parent_slot, qp_mk_branch(new_branch));
	} else {
		/* n == 2: collapse — replace parent with remaining child */
		other_idx = 1 - idx;
		remaining = parent->children[other_idx];
		qp_publish(parent_slot, remaining);
	}

	raw_res_spin_unlock_irqrestore(&trie->lock, irq_flags);
	bpf_mem_cache_free_rcu(&trie->leaf_ma, leaf);
	bpf_mem_free_rcu(&trie->branch_ma, parent);
	return 0;

out:
	raw_res_spin_unlock_irqrestore(&trie->lock, irq_flags);
	return ret;
}

/* --- get_next_key (lock-free under RCU) --- */

struct qp_path_entry {
	struct qp_trie_branch *branch;
	int child_idx;
};

static int qp_trie_get_next_key(struct bpf_map *map, void *_key,
				 void *_next_key)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct qp_trie_branch *branch;
	struct qp_path_entry *stack = NULL;
	struct qp_trie_leaf *leaf;
	unsigned long ptr;
	int stack_ptr = -1;
	u16 bit;
	u8 nib;
	int idx, n;
	int ret;

	ptr = qp_deref(&trie->root);
	if (!ptr)
		return -ENOENT;

	/* NULL key: return first (leftmost) key */
	if (!_key)
		goto descend;

	stack = kmalloc_array(trie->max_nibbles + 1, sizeof(*stack),
			      GFP_ATOMIC | __GFP_NOWARN);
	if (!stack)
		return -ENOMEM;

	/* Walk trie following _key */
	while (ptr && !qp_is_leaf(ptr)) {
		branch = qp_to_branch(ptr);
		nib = qp_nibble((const u8 *)_key, branch->offset);
		bit = 1u << nib;

		if (!(branch->bitmap & bit))
			goto find_first;

		idx = hweight16(branch->bitmap & (bit - 1));
		stack[++stack_ptr].branch = branch;
		stack[stack_ptr].child_idx = idx;
		ptr = qp_deref(&branch->children[idx]);
	}

	/* Check if we found the exact key */
	if (!ptr || !qp_is_leaf(ptr))
		goto find_first;

	leaf = qp_to_leaf(ptr);
	if (memcmp(leaf->data, _key, map->key_size) != 0)
		goto find_first;

	/* Found key. Backtrack to find next key in order. */
	while (stack_ptr >= 0) {
		branch = stack[stack_ptr].branch;
		idx = stack[stack_ptr].child_idx;
		n = hweight16(branch->bitmap);

		if (idx + 1 < n) {
			ptr = qp_deref(&branch->children[idx + 1]);
			goto descend;
		}
		stack_ptr--;
	}

	/* No next key */
	ret = -ENOENT;
	goto out;

find_first:
	/* Key not found — return first key in trie */
	ptr = qp_deref(&trie->root);

descend:
	/* Descend to leftmost leaf from ptr */
	while (ptr && !qp_is_leaf(ptr)) {
		branch = qp_to_branch(ptr);
		ptr = qp_deref(&branch->children[0]);
	}

	if (ptr && qp_is_leaf(ptr)) {
		leaf = qp_to_leaf(ptr);
		memcpy(_next_key, leaf->data, map->key_size);
		ret = 0;
	} else {
		ret = -ENOENT;
	}

out:
	kfree(stack);
	return ret;
}

/* --- Alloc / Free --- */

static struct bpf_map *qp_trie_alloc(union bpf_attr *attr)
{
	struct qp_trie *trie;
	size_t leaf_size;
	int err;

	if (attr->max_entries == 0 ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->map_flags & ~QP_TRIE_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags) ||
	    attr->key_size < QP_TRIE_KEY_SIZE_MIN ||
	    attr->key_size > QP_TRIE_KEY_SIZE_MAX ||
	    attr->value_size < QP_TRIE_VAL_SIZE_MIN)
		return ERR_PTR(-EINVAL);

	trie = bpf_map_area_alloc(sizeof(*trie), NUMA_NO_NODE);
	if (!trie)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&trie->map, attr);
	trie->max_nibbles = attr->key_size * 2;
	trie->root = 0;
	trie->n_entries = 0;

	raw_res_spin_lock_init(&trie->lock);

	/* Fixed-size allocator for leaves */
	leaf_size = sizeof(struct qp_trie_leaf) + attr->key_size +
		    attr->value_size;
	err = bpf_mem_alloc_init(&trie->leaf_ma, leaf_size, false);
	if (err)
		goto free_trie;

	/* Variable-size allocator for branches */
	err = bpf_mem_alloc_init(&trie->branch_ma, 0, false);
	if (err)
		goto free_leaf_ma;

	return &trie->map;

free_leaf_ma:
	bpf_mem_alloc_destroy(&trie->leaf_ma);
free_trie:
	bpf_map_area_free(trie);
	return ERR_PTR(err);
}

static void qp_trie_free(struct bpf_map *map)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct qp_trie_branch *branch;
	unsigned long *slot, ptr, child;
	int i, n;

	/* Repeatedly walk from root to a leaf, free it, and null out the
	 * parent's child pointer. Branches with all-NULL children are freed
	 * when encountered. No locking needed — exclusive access.
	 */
	for (;;) {
		slot = &trie->root;
		ptr = *slot;

		if (!ptr)
			break;

		while (ptr && !qp_is_leaf(ptr)) {
			branch = qp_to_branch(ptr);
			n = hweight16(branch->bitmap);
			child = 0;

			for (i = 0; i < n; i++) {
				if (branch->children[i]) {
					child = branch->children[i];
					slot = &branch->children[i];
					break;
				}
			}

			if (!child) {
				bpf_mem_cache_raw_free(branch);
				*slot = 0;
				ptr = 0;
				break;
			}
			ptr = child;
		}

		if (ptr && qp_is_leaf(ptr)) {
			bpf_mem_cache_raw_free(qp_to_leaf(ptr));
			*slot = 0;
		}
	}

	bpf_mem_alloc_destroy(&trie->leaf_ma);
	bpf_mem_alloc_destroy(&trie->branch_ma);
	bpf_map_area_free(trie);
}

static u64 qp_trie_mem_usage(const struct bpf_map *map)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	u64 leaf_size;

	leaf_size = sizeof(struct qp_trie_leaf) + map->key_size +
		    map->value_size;
	return leaf_size * READ_ONCE(trie->n_entries);
}

BTF_ID_LIST_SINGLE(qp_trie_map_btf_ids, struct, qp_trie)
const struct bpf_map_ops qp_trie_map_ops = {
	.map_meta_equal		= bpf_map_meta_equal,
	.map_alloc		= qp_trie_alloc,
	.map_free		= qp_trie_free,
	.map_lookup_elem	= qp_trie_lookup_elem,
	.map_update_elem	= qp_trie_update_elem,
	.map_delete_elem	= qp_trie_delete_elem,
	.map_get_next_key	= qp_trie_get_next_key,
	.map_lookup_batch	= generic_map_lookup_batch,
	.map_update_batch	= generic_map_update_batch,
	.map_delete_batch	= generic_map_delete_batch,
	.map_mem_usage		= qp_trie_mem_usage,
	.map_btf_id		= &qp_trie_map_btf_ids[0],
};
