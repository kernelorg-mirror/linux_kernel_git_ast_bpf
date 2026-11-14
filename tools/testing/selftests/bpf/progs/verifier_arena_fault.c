// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

/*
 * An access to the arena that no page backs ends the prog: it unwinds like one whose time slice is
 * over. Where no landing pad will do the access is skipped: each prog returns 7 then.
 */
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

/* See verifier_unwind_cb.c */
#define unwind_goto(off) ".8byte ((" #off " & 0xffff) << 16) | 0x10e5;"	/* BPF_JMP | BPF_JCOND */
/* rN = addr_space_cast(rN, 0x0, 0x1), which the assembler of GCC doesn't know */
#define to_arena(n) ".8byte 0x1000100bf | (0x11 * " #n ") << 8;"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;

/* r8 = an address of the arena, no page is there */
#define NO_PAGE						\
		"r1 = %[arena] ll;"			\
		"r8 = 0x1000;"				\
		to_arena(8)

/* @reg = a task, which has to be released */
#define ACQUIRE_TASK(reg)				\
		"r1 = 1;"				\
		"call %[bpf_task_from_pid];"		\
		"if r0 != 0 goto +1;"			\
		"exit;"					\
		#reg " = r0;"
#define RELEASE_TASK(reg) "r1 = " #reg ";" "call %[bpf_task_release];"
#define TASK_IMM __imm_addr(arena), __imm(bpf_task_from_pid), __imm(bpf_task_release)

#define ENTER_9 ".rept 9;" "call %[bpf_rcu_read_lock];" ".endr;"
#define LEAVE_9 ".rept 9;" "call %[bpf_rcu_read_unlock];" ".endr;"
#define RCU_IMM __imm_addr(arena), __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(bpf_task_from_pid(0));
}

/* Nothing is held: no insn is added at the access. All such accesses of a function share a pad. */
SEC("socket")
__description("fault: a load in the main prog ends it")
__success __retval(0)
__xlated("4: r2 = *(u32 *)(r8 +0)")
__xlated("5: r0 = 7")
__xlated("6: exit")
__xlated("7: r0 = 0")
__xlated("8: exit")
__naked void load_in_main(void)
{
	asm volatile (
	NO_PAGE
		"r2 = *(u32 *)(r8 + 0);"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(arena) : __clobber_all);
}

#define FAULT(sec, val, name, insns)						\
SEC(sec)									\
__description("fault: " #name)							\
__success __retval(val)								\
__naked void name(void)								\
{										\
	asm volatile (NO_PAGE insns "r0 = 7; exit;" :: TASK_IMM : __clobber_all); \
}

FAULT("socket", 0, store, "*(u32 *)(r8 + 0) = 1;")
/* On x86-64 two native insns of it can fault */
FAULT("socket", 0, fetch_or, "r3 = 1; r3 = atomic_fetch_or((u64 *)(r8 + 0), r3);")
/* 'w0 = w0' is added after the insn. The mark of the shared pad stays on the insn. */
FAULT("socket", 0, cmpxchg32, "r0 = 1; r1 = 2; w0 = cmpxchg32_32(r8 + 0, w0, w1); r9 = r0;")
/* .. and it comes after unwind_goto, not in front of it */
FAULT("tc", 2, cmpxchg32_task, ACQUIRE_TASK(r6)
      "w0 = 0; w2 = 1; w0 = cmpxchg32_32(r8 + 0, w0, w2); r9 = r0;" RELEASE_TASK(r6))
/* R0-R5 are as before the access: they are places */
FAULT("tc", 2, task_in_r0, ACQUIRE_TASK(r0) "r2 = *(u32 *)(r8 + 0);" RELEASE_TASK(r0))
/* The register that the insn would load is the place of the task: the pad gets it as it was */
FAULT("tc", 2, xchg_of_the_task, ACQUIRE_TASK(r6)
      "r7 = r6; r6 = xchg_64(r8 + 0, r6);" RELEASE_TASK(r7))
/* The frame is in the private stack, r9 on x86-64: the landing pad finds the task there */
FAULT("raw_tp", 0, private_stack, "r1 = 42; *(u64 *)(r10 - 512) = r1;" ACQUIRE_TASK(r6)
      "*(u64 *)(r10 - 8) = r6; r6 = 0; r2 = *(u32 *)(r8 + 0); r6 = *(u64 *)(r10 - 8);"
      RELEASE_TASK(r6))

/* unwind_goto is an entry in the exception table: the native code has nothing after the load */
SEC("tc")
__description("fault: a task is held")
__success __retval(2)
__xlated("...")
__xlated("r2 = *(u32 *)(r8 +0)")
__xlated("unwind_goto pc+4")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 7")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__arch_x86_64
__jited("	movl	(%r14,%r12), %esi")
__jited("	movq	%rbx, %rdi")
__arch_arm64
__naked void task_in_main(void)
{
	asm volatile (
	NO_PAGE
	ACQUIRE_TASK(r6)
		"r2 = *(u32 *)(r8 + 0);"
	RELEASE_TASK(r6)
		"r0 = 7;"
		"exit;"
		:: TASK_IMM : __clobber_all);
}

struct bpf_spin_lock lock_a SEC(".data.lock_a") __hidden;
struct bpf_spin_lock lock_b SEC(".data.lock_b") __hidden;

/* One insn takes one of two locks. What the prog keeps for its own unlock tells which. */
SEC("tc")
__description("fault: one of two locks in global variables is held")
__success __retval(2)
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call {{.*}}")
__xlated("r0 = 2")
__naked void one_of_two_locks(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r6 = %[lock_a] ll;"
		"if r9 == 0 goto +2;"
		"r6 = %[lock_b] ll;"
		"r1 = r6;"
		"call %[bpf_spin_lock];"
		"r2 = *(u32 *)(r8 + 0);"
		"r1 = r6;"
		"call %[bpf_spin_unlock];"
		"r0 = 7;"
		"exit;"
		:: __imm_addr(arena), __imm_addr(zero), __imm_addr(lock_a), __imm_addr(lock_b),
		   __imm(bpf_spin_lock), __imm(bpf_spin_unlock)
		: __clobber_all);
}

/*
 * States that hold nothing go by without a look at the plan. When one comes that holds the task all
 * is done again, so that the plan sees r6 == 0 too.
 */
SEC("tc")
__description("fault: a task is held on some paths, the pointer is NULL on the others")
__success __retval(2)
__xlated("...")
__xlated("r2 = *(u32 *)(r8 +0)")
__xlated("unwind_goto pc+")
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__naked void task_or_null(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[one] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r6 = 0;"
		"if r9 == 0 goto 1f;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
	"1:"
		"r2 = *(u32 *)(r8 + 0);"
		"if r6 == 0 goto 2f;"
	RELEASE_TASK(r6)
	"2:"
		"r0 = 7;"
		"exit;"
		:: TASK_IMM, __imm_addr(one) : __clobber_all);
}

/*
 * The state that holds the task is first at the load, and it has compared r6 with NULL. Only the
 * visit of the state that holds nothing brings the test.
 */
SEC("tc")
__description("fault: a task is held on some paths, the state that holds it comes first")
__success __retval(2)
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("if r1 == 0x0 goto pc+1")
__xlated("call kernel-function")
__xlated("r0 = 2")
__naked void task_first_or_null(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[zero] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r6 = 0;"
		"if r9 != 0 goto 3f;"
		"r7 = 1;"
		"goto 1f;"
	"3:"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r6 = r0;"
		"if r6 == 0 goto 2f;"
	"1:"
		"r2 = *(u32 *)(r8 + 0);"
		"if r6 == 0 goto 2f;"
	RELEASE_TASK(r6)
	"2:"
		"r0 = 7;"
		"exit;"
		:: TASK_IMM, __imm_addr(zero) : __clobber_all);
}

/* No test of a pointer tells whether the prog is in the section. A fault gets no hidden slots. */
SEC("socket")
__description("fault: an RCU section on some paths, the access is skipped")
__success __retval(7)
__naked void section_on_some_paths(void)
{
	asm volatile (
	NO_PAGE
		"r9 = %[one] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"if r9 == 0 goto +1;"
		"call %[bpf_rcu_read_lock];"
		"r2 = *(u32 *)(r8 + 0);"
		"if r9 == 0 goto +1;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 7;"
		"exit;"
		:: RCU_IMM, __imm_addr(one) : __clobber_all);
}

__naked __noinline __used
static unsigned long loads(void)
{
	asm volatile (
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u32 *)(r8 + 0);"
		"r0 += 5;"
		"exit;"
		::: __clobber_all);
}

SEC("tc")
__description("fault: a load in a subprog, the caller holds a task")
__success __retval(2)
__xlated("...")
__xlated("call pc+")
__xlated("unwind_goto pc+4")
__xlated("...")
__xlated("exit")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = 2")
__xlated("exit")
__xlated("...")
__xlated("exit")
__xlated("r0 = 2")
__xlated("unwind_exit")
__naked void load_in_subprog(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
	ACQUIRE_TASK(r6)
		"call loads;"
	RELEASE_TASK(r6)
		"r0 = 7;"
		"exit;"
		:: TASK_IMM : __clobber_all);
}

/*
 * The call has only faults below it and no pad: the load is skipped, the subprog goes on. Then the
 * main prog holds nothing: each function has a pad of its own for such accesses.
 */
SEC("socket")
__description("fault: a load in a subprog, the caller holds too much")
__success __retval(0)
__naked void load_in_subprog_skipped(void)
{
	asm volatile (
	NO_PAGE
	ENTER_9
		"call loads;"
		"r6 = r0;"
	LEAVE_9
		"r0 = 7;"
		"if r6 != 5 goto +1;"
		"r2 = *(u32 *)(r8 + 0);"
		"exit;"
		:: RCU_IMM : __clobber_all);
}

/*
 * r6 is the task that is held, or current: never NULL. Only a hidden slot could tell, and that is a
 * store on the normal path. A call with nothing but faults below it gets none: the load is skipped.
 */
SEC("tc")
__description("fault: a load in a subprog, the caller would need a hidden slot")
__success __retval(7)
__naked void load_in_subprog_no_slot(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r9 = %[one] ll;"
		"r9 = *(u64 *)(r9 + 0);"
		"r7 = 0;"
		"if r9 == 0 goto 1f;"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r7 = 1;"
		"if r0 != 0 goto 2f;"
		"r7 = 0;"
	"1:"
		"call %[bpf_get_current_task_btf];"
	"2:"
		"r6 = r0;"
		"call loads;"
		"if r7 == 0 goto 3f;"
	RELEASE_TASK(r6)
	"3:"
		"r0 = 7;"
		"exit;"
		:: TASK_IMM, __imm_addr(one), __imm(bpf_get_current_task_btf) : __clobber_all);
}

/*
 * One unwound state per stretch of accesses goes to the caller. A store to the stack of the caller,
 * a call and a join end the stretch. The pad of the prog is in bounds if fp-8 is 0 or [4, 7].
 */
#define PAD_READS_STACK(name, callee)						\
SEC("socket")									\
__description("fault: " #callee)						\
__failure __msg("invalid access to map value, value_size=")			\
__naked void name(void)								\
{										\
	asm volatile (								\
		"r1 = %[arena] ll;"						\
		"r1 = 0;"							\
		"*(u64 *)(r10 - 8) = r1;"					\
		"*(u64 *)(r10 - 16) = r1;"					\
		"r1 = r10;"							\
		"r1 += -16;"							\
		"call " #callee ";"						\
		unwind_goto(2)							\
		"r0 = 7;"							\
		"exit;"								\
		"r1 = *(u64 *)(r10 - 8);"					\
		"r1 &= 7;"							\
		"r3 = r1;"							\
		"r3 >>= 2;"							\
		"r3 ^= 1;"							\
		"r1 *= r3;"							\
		"r1 *= 1000;"							\
		"r2 = %[zero] ll;"						\
		"r2 += r1;"							\
		"r0 = *(u64 *)(r2 + 0);"					\
		"r2 = *(u64 *)(r10 - 16);"					\
		"if r2 == 0 goto +1;"						\
		"r0 = 1;"							\
		"exit;"								\
		:: __imm_addr(arena), __imm_addr(zero) : __clobber_all);	\
}

__naked __noinline __used
static unsigned long stores_between_loads(void)
{
	asm volatile (
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
		"*(u64 *)(r1 + 8) = 2;"
		"r0 = *(u64 *)(r8 + 8);"
		"*(u64 *)(r1 + 8) = 0;"
		"exit;"
		::: __clobber_all);
}
PAD_READS_STACK(pad_after_store, stores_between_loads)

/* The helper writes to fp-8 of the caller */
__naked __noinline __used
static unsigned long calls_between_loads(void)
{
	asm volatile (
		"r1 += 8;"
		"r6 = r1;"
		"r8 = 0x1000;"
		to_arena(8)
		"r0 = *(u64 *)(r8 + 0);"
		"r2 = 8;"
		"r3 = 0;"
		"call %[bpf_probe_read_kernel];"
		"r0 = *(u64 *)(r8 + 8);"
		"*(u64 *)(r6 + 0) = 0;"
		"exit;"
		:: __imm(bpf_probe_read_kernel) : __clobber_all);
}
PAD_READS_STACK(pad_after_call, calls_between_loads)

/*
 * fp-8 = 0 and [4, 7], each with a load, are joined: [0, 7]. The path with 2 and no load is within
 * that and is dropped. fp-16 = 0 and [1, U64_MAX], which the pad tests, keeps them apart up there.
 */
__naked __noinline __used
static unsigned long joins_between_loads(void)
{
	asm volatile (
		"r8 = 0x1000;"
		to_arena(8)
		"r4 = %[zero] ll;"
		"r3 = *(u64 *)(r4 + 0);"
		"r5 = *(u64 *)(r4 + 0);"
		"if r3 == 1 goto 1f;"
		"if r5 != 0 goto 2f;"
		"*(u64 *)(r1 + 8) = 2;"
		"goto 3f;"
	"1:"
		"r0 = *(u64 *)(r8 + 0);"
		"goto 3f;"
	"2:"
		"*(u64 *)(r1 + 0) = r5;"
		"r3 &= 3;"
		"r3 += 4;"
		"*(u64 *)(r1 + 8) = r3;"
		"r0 = *(u64 *)(r8 + 8);"
	"3:"
		"r0 = *(u64 *)(r8 + 16);"
		"exit;"
		:: __imm_addr(zero) : __clobber_all);
}
PAD_READS_STACK(pad_after_join, joins_between_loads)

/* In C a pointer to arena takes a compiler that has address spaces */
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST

struct foo {
	int data;
};

void *arena_ptr;

/* An address the arena has no page for: an access to it faults. */
static __always_inline int __arena *unmapped_arena_addr(void)
{
	arena_ptr = &arena;
	return (int __arena *)0xdeadbee0;
}

/* Keep the access to @addr behind everything before it, so that the fault is not hoisted. */
#define access_barrier(addr) asm volatile("" : "+r"(addr) : : "memory")

__noinline int global_fault(void)
{
	int __arena *addr = unmapped_arena_addr();

	access_barrier(addr);
	return *addr;
}

SEC("tc")
__description("fault: a load in a global subprog, the caller holds an object")
__success __retval(2)
int cancel_arena_global(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	ret = global_fault();
	bpf_obj_drop(f);
	return ret + 7;
}

int __arena consumed;

static __noinline long try_consume(struct task_struct *t)
{
	while (*(volatile unsigned long *)&zero == 2)
		;
	if (zero)
		return 0;
	bpf_task_release(t);
	consumed = 1;
	return 1;
}

/*
 * The loop unwinds while the caller holds the task, the store when it is gone. A call with a loop
 * below it has to have a pad.
 */
SEC("syscall")
__description("fault: a subprog with a loop releases the task of its caller, then a store")
__failure __msg("landing pad of call at {{[0-9]+}}: conflict: a resource is held on some paths only")
int store_after_release_for_caller(void *ctx)
{
	struct task_struct *t = bpf_task_from_pid(1);

	if (!t)
		return 3;
	if (!try_consume(t))
		bpf_task_release(t);
	return 7;
}

#endif /* __BPF_FEATURE_ADDR_SPACE_CAST */

#else

SEC("socket")
__description("fault: unwinding is not supported, use a dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
