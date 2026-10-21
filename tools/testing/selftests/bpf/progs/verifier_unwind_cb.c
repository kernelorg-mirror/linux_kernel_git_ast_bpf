// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/* The insns of verifier_unwind.c as raw words: vmlinux.h leaves no BPF_RAW_INSN() */
#define unwind_goto(off) ".8byte (" #off " << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
#define unwind_exit ".8byte 0x1095;"				/* BPF_JMP | BPF_EXIT */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} rhash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

struct node_data {
	long key;
	struct bpf_rb_node node;
	struct bpf_refcount ref;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, node);

/* How many times the callback ran */
__u64 runs;

#define count_run()				\
	"r1 = %[runs] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/* Unwinds with r0 = 5 on its first run */
__naked __noinline __used
static unsigned long cb_unwinds(void)
{
	asm volatile (
		count_run()
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(runs)
	);
}

/* The pad after the call of the helper: the number of runs + what the callback unwound with + 41 */
#define PAD					\
	"r1 = %[runs] ll;"			\
	"r1 = *(u64 *)(r1 + 0);"		\
	"r0 += r1;"				\
	"r0 += 41;"				\
	"exit;"

/* For C code: a helper or a kfunc with a pad after the call, which returns r0 + 42 */
#define WITH_PAD(name, func, args)		\
__naked __noinline __used			\
static int name(void *a, void *b, void *c)	\
{						\
	asm volatile (				\
		args				\
		"call %[" #func "];"		\
		unwind_goto(1)			\
		"exit;"				\
		"r0 += 42;"			\
		"exit;"				\
		:				\
		: __imm(func)			\
		: __clobber_all			\
	);					\
}

WITH_PAD(for_each_with_pad, bpf_for_each_map_elem, "r3 = 0; r4 = 0;")
WITH_PAD(drain_with_pad, bpf_user_ringbuf_drain, "r3 = 0; r4 = 0;")
WITH_PAD(find_vma_with_pad, bpf_find_vma, "r4 = 0; r5 = 0;")
WITH_PAD(rbtree_add_with_pad, bpf_rbtree_add, "")
WITH_PAD(rbtree_add_impl_with_pad, bpf_rbtree_add_impl, "r4 = 0; r5 = 0;")

/* The loop is inlined, and so is its pad, which brings back r6-r8: the loop counts in them */
SEC("tc")
__description("unwind cb: the callback of bpf_loop unwinds on its first run")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(54)
__xlated("unwind_goto pc+7")
__naked int loop_cb_unwinds(void)
{
	asm volatile (
		"r6 = 1;"
		"r7 = 2;"
		"r8 = 4;"
		"r1 = 10;"
		"r2 = %[cb_unwinds] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r0 += r6;"
		"r0 += r7;"
		"r0 += r8;"
		PAD
		:
		: __imm_addr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_all
	);
}

/* One call for three maps goes through the helper, which has a pad as well as the maps have */
SEC("tc")
__description("unwind cb: the callback of bpf_for_each_map_elem over an array, a hash, an rhash unwinds")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(144)
int for_each_cb_unwinds(void *ctx)
{
	int key = 1, ret;

	bpf_map_update_elem(&hash, &key, &key, 0);
	bpf_map_update_elem(&rhash, &key, &key, 0);
	ret = for_each_with_pad(&array, cb_unwinds, NULL);
	ret += for_each_with_pad(&hash, cb_unwinds, NULL);
	return ret + for_each_with_pad(&rhash, cb_unwinds, NULL) + runs;
}

/* Nothing is in the ring buffer here. prog_tests/unwind_drain.c runs it with a sample. */
SEC("tc")
__description("unwind cb: the callback of bpf_user_ringbuf_drain unwinds")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(0)
int drain_cb_unwinds(void *ctx)
{
	return drain_with_pad(&user_ringbuf, cb_unwinds, NULL);
}

/* The vma of the stack of the current task. The helper drops the mmap lock on its way out. */
SEC("tc")
__description("unwind cb: the callback of bpf_find_vma unwinds")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(48)
int find_vma_cb_unwinds(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return find_vma_with_pad(task, (void *)task->mm->start_stack, cb_unwinds) + runs;
}

static bool less_returns(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	return true;
}

/* Not naked: the branch keeps the return reachable. Unwinds with r0 = 5. */
static bool less_unwinds(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	runs++;
	if (a)
		asm volatile ("r0 = 5;" unwind_exit ::: "r0");
	return false;
}

/* The second node meets the first one, the comparator unwinds, the kfunc drops the node */
static __always_inline int rbtree_cb_unwinds_via(bool impl)
{
	struct node_data *n, *m;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}

	bpf_spin_lock(&glock);
	if (impl) {
		bpf_rbtree_add_impl(&groot, &n->node, less_returns, NULL, 0);
		ret = rbtree_add_impl_with_pad(&groot, &m->node, (void *)less_unwinds);
	} else {
		bpf_rbtree_add(&groot, &n->node, less_returns);
		ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	}
	bpf_spin_unlock(&glock);
	return ret + runs;
}

SEC("tc")
__description("unwind cb: the comparator of bpf_rbtree_add and of bpf_rbtree_add_impl unwinds")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(97)
int rbtree_cb_unwinds(void *ctx)
{
	return rbtree_cb_unwinds_via(false) + rbtree_cb_unwinds_via(true);
}

char _license[] SEC("license") = "GPL";
