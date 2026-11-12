// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

/* The insns of verifier_unwind.c as raw words: vmlinux.h leaves no BPF_RAW_INSN() */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
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

/* A kptr whose destructor is not for NMI context */
struct node_task {
	long key;
	struct bpf_rb_node node;
	struct task_struct __kptr *task;
};

private(C) struct bpf_spin_lock tlock;
private(C) struct bpf_rb_root troot __contains(node_task, node);

/* How many times the callback ran */
__u64 runs;

/* What the verifier doesn't know: bpf_loop() is not inlined, a loop doesn't end */
volatile __u64 no_flags, forever = 1;

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
__xlated("unwind_goto pc-15")
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

/* Nothing is in the map. What follows the loop counts on its exit. */
static long cb_waits(u32 i, long *sum)
{
	int key = 0, *val;

	bpf_rcu_read_lock();
	do {
		val = bpf_map_lookup_elem(&hash, &key);
	} while (!val);
	*sum += *val;
	bpf_rcu_read_unlock();
	return 0;
}

/* The callback leaves its RCU section and unwinds, bpf_loop() leaves, the caller turns preemption on */
SEC("tc")
__description("unwind cb: a loop in the callback of bpf_loop is out of time")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(0)
int loop_in_cb(void *ctx)
{
	long sum = 7;

	bpf_preempt_disable();
	bpf_loop(2, cb_waits, &sum, no_flags);
	bpf_preempt_enable();
	return sum;
}

/* Unwinds with a pointer into its own stack */
__naked __noinline __used
static unsigned long cb_unwinds_with_fp(void)
{
	asm volatile (
		"r0 = r10;"
		"r0 += -8;"
		unwind_exit
	);
}

SEC("tc")
__description("unwind cb: the callback unwinds with a pointer into its stack")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("cannot return stack pointer to the caller")
__naked int loop_cb_unwinds_with_fp(void)
{
	asm volatile (
		"r1 = 10;"
		"r2 = %[cb_unwinds_with_fp];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_with_fp),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Unwinds with the key, which is in the frame of bpf_for_each_array_elem() */
__naked __noinline __used
static unsigned long cb_unwinds_with_key(void)
{
	asm volatile (
		"r0 = r2;"
		unwind_exit
	);
}

SEC("tc")
__description("unwind cb: the callback unwinds with a pointer into the frame of the helper")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("R0 invalid mem access 'scalar'")
__naked int for_each_cb_unwinds_with_key(void)
{
	asm volatile (
		"r1 = %[array] ll;"
		"r2 = %[cb_unwinds_with_key];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_for_each_map_elem];"
		unwind_goto(1)
		"exit;"
		"r0 = *(u32 *)(r0 + 0);"
		"exit;"
		:
		: __imm_addr(array),
		  __imm_ptr(cb_unwinds_with_key),
		  __imm(bpf_for_each_map_elem)
		: __clobber_common
	);
}

/* Its prototype returns two registers, but it unwinds with r0 alone */
__naked __noinline __used
static unsigned __int128 cb_unwinds_pair(void)
{
	asm volatile (
		"r0 = 5;"
		"r2 = 0;"
		unwind_exit
	);
}

/* The pad reads the slot through r0: 5 of the callback, not 0 of the caller. r2 stays the caller's. */
SEC("tc")
__description("unwind cb: the pad knows what the callback unwound with")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(9)
__naked int loop_cb_r0_known(void)
{
	asm volatile (
		"r0 = 0;"
		"r1 = 9;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = 10;"
		"r2 = %[cb_unwinds_pair];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = r10;"
		"r1 += r0;"
		"r0 = *(u8 *)(r1 - 13);"
		"exit;"
		:
		: __imm_ptr(cb_unwinds_pair),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* The helper in the pad starts its rounds afresh, so its callback is checked */
SEC("tc")
__description("unwind cb: a helper in the pad starts its rounds afresh")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(0)
__naked int loop_cb_unwinds_then_loops(void)
{
	asm volatile (
		"r1 = 2;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(1)
		"exit;"
		"r1 = 1;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* The inlined loop jumps back to the pad. 'll': the compiler puts nothing in front of the asm. */
SEC("tc")
__description("unwind cb: the pad before the call of the inlined bpf_loop")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(47)
__xlated("unwind_goto pc-15")
__naked int loop_cb_pad_before_call(void)
{
	asm volatile (
		"goto 1f;"
		PAD
	"1:"
		"r1 = 10;"
		"r2 = %[cb_unwinds] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		unwind_goto(-13)
		"exit;"
		:
		: __imm_addr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_loop)
		: __clobber_common
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

static bool less_waits(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	while (forever)
		;
	return false;
}

/* The kfunc drops the node. The pad that the verifier adds releases the lock and nothing else. */
SEC("tc")
__description("unwind cb: a loop in the comparator of bpf_rbtree_add is out of time")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(0)
int loop_in_comparator(void *ctx)
{
	struct node_data *n;
	int i;

	for (i = 0; i < 2; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return 1;
		bpf_spin_lock(&glock);
		bpf_rbtree_add(&groot, &n->node, less_waits);
		bpf_spin_unlock(&glock);
	}
	return 2;
}

struct node_tree {
	struct bpf_rb_node node;
	struct bpf_spin_lock lock;
	struct bpf_rb_root root __contains(node_data, node);
};

private(D) struct bpf_spin_lock nlock;
private(D) struct bpf_rb_root nroot __contains(node_tree, node);

/* The kfunc would drop the node under the lock of the tree, and to free it takes the lock in it */
SEC("tc")
__description("unwind cb: a loop in the comparator, the node has a lock and a tree of its own")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the JIT or the helper that calls the function cannot unwind it")
int loop_in_comparator_node_with_tree(void *ctx)
{
	struct node_tree *n = bpf_obj_new(typeof(*n));

	if (!n)
		return 0;
	bpf_spin_lock(&nlock);
	bpf_rbtree_add(&nroot, &n->node, less_waits);
	bpf_spin_unlock(&nlock);
	return 0;
}

/* It is one function for both trees, and it has unwound out of the first one */
SEC("tc")
__description("unwind cb: one comparator with a loop for two trees, one of them has such nodes")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("callback cannot unwind at insn {{[0-9]+}}: less_waits() does")
int loop_in_comparator_of_two_trees(void *ctx)
{
	struct node_data *d = bpf_obj_new(typeof(*d));
	struct node_tree *n;

	if (!d)
		return 0;
	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &d->node, less_waits);
	bpf_spin_unlock(&glock);
	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&nlock);
	bpf_rbtree_add(&nroot, &n->node, less_waits);
	bpf_spin_unlock(&nlock);
	return 0;
}

static __noinline int first_goes_in_again(void)
{
	struct bpf_rb_node *m = bpf_rbtree_first(&groot);

	m = m ? bpf_rbtree_remove(&groot, m) : NULL;
	return m ? rbtree_add_with_pad(&groot, m, (void *)less_unwinds) : 0;
}

/* The kfunc dropped f. The function is verified on its own: its caller is not in that state. */
SEC("tc")
__description("unwind cb: what the caller holds of the tree is gone when the comparator unwinds")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("invalid mem access")
int rbtree_cb_unwinds_first_gone(void *ctx)
{
	struct bpf_rb_node *f;
	long key = 0;

	bpf_spin_lock(&glock);
	f = bpf_rbtree_first(&groot);
	first_goes_in_again();
	if (f)
		key = ((struct node_data *)((void *)f - offsetof(struct node_data, node)))->key;
	bpf_spin_unlock(&glock);
	return key;
}

/* Another reference keeps the node that the kfunc dropped. It goes in again: it was left unlinked. */
SEC("tc")
__description("unwind cb: the node the comparator unwound on can be added again")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__success __retval(48)
int rbtree_cb_unwinds_node_readded(void *ctx)
{
	struct node_data *n, *m, *m2;
	int ret, again;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 1;
	m = bpf_obj_new(typeof(*m));
	if (!m) {
		bpf_obj_drop(n);
		return 2;
	}
	m2 = bpf_refcount_acquire(m);
	if (!m2) {
		bpf_obj_drop(n);
		bpf_obj_drop(m);
		return 3;
	}

	bpf_spin_lock(&glock);
	bpf_rbtree_add(&groot, &n->node, less_returns);
	ret = rbtree_add_with_pad(&groot, &m->node, (void *)less_unwinds);
	again = bpf_rbtree_add(&groot, &m2->node, less_returns);
	bpf_spin_unlock(&glock);
	return ret + again + runs;
}

/* The pad of the kfunc drops the node, which is a bpf_obj_drop() */
SEC("tp_btf/task_newtask")
__description("unwind cb: the comparator unwinds in a tracing program on a type with NMI unsafe fields")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("bpf_rbtree_add with a comparator that unwinds cannot be used in tracing programs on types with NMI unsafe fields")
int BPF_PROG(rbtree_cb_unwinds_nmi_unsafe, struct task_struct *task, u64 clone_flags)
{
	struct node_task *n;
	int ret;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&tlock);
	ret = rbtree_add_with_pad(&troot, &n->node, (void *)less_unwinds);
	bpf_spin_unlock(&tlock);
	return ret;
}

/* So the verifier doesn't let a comparator unwind there */
SEC("tp_btf/task_newtask")
__description("unwind cb: a loop in the comparator, tracing program, type with NMI unsafe fields")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("landing pad of may_goto at {{[0-9]+}}: conflict: the JIT or the helper that calls the function cannot unwind it")
int BPF_PROG(loop_in_comparator_nmi_unsafe, struct task_struct *task, u64 clone_flags)
{
	struct node_task *n;

	n = bpf_obj_new(typeof(*n));
	if (!n)
		return 0;
	bpf_spin_lock(&tlock);
	bpf_rbtree_add(&troot, &n->node, less_waits);
	bpf_spin_unlock(&tlock);
	return 0;
}

char _license[] SEC("license") = "GPL";
