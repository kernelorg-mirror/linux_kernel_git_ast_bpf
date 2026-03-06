// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, long long);
} map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} array_map_8b SEC(".maps");

SEC("socket")
__log_level(2)
__naked void simple_read_simple_write(void)
{
	asm volatile (
	"r1 = *(u64 *)(r10 - 8);"
	"r2 = *(u64 *)(r10 - 24);"
	"*(u64 *)(r10 - 8) = r1;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__log_level(2)
__naked void read_write_join(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"if r0 > 42 goto 1f;"
	"r0 = *(u64 *)(r10 - 8);"
	"*(u64 *)(r10 - 32) = r0;"
	"*(u64 *)(r10 - 40) = r0;"
	"exit;"
"1:"
	"r0 = *(u64 *)(r10 - 16);"
	"*(u64 *)(r10 - 32) = r0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
__msg("2: (25) if r0 > 0x2a goto pc+1")
__msg("7: (95) exit")
__naked void must_write_not_same_slot(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = -8;"
	"if r0 > 42 goto 1f;"
	"r1 = -16;"
"1:"
	"r2 = r10;"
	"r2 += r1;"
	"*(u64 *)(r2 + 0) = r0;"
	"exit;"
	:: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
__naked void must_write_not_same_type(void)
{
	asm volatile (
	"*(u64*)(r10 - 8) = 0;"
	"r2 = r10;"
	"r2 += -8;"
	"r1 = %[map] ll;"
	"call %[bpf_map_lookup_elem];"
	"if r0 != 0 goto 1f;"
	"r0 = r10;"
	"r0 += -16;"
"1:"
	"*(u64 *)(r0 + 0) = 42;"
	"exit;"
	:
        : __imm(bpf_get_prandom_u32),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(map)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
__naked void caller_stack_write(void)
{
	asm volatile (
	"r1 = r10;"
	"r1 += -8;"
	"call write_first_param;"
	"exit;"
	::: __clobber_all);
}

static __used __naked void write_first_param(void)
{
	asm volatile (
	"*(u64 *)(r1 + 0) = 7;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__log_level(2)
/* caller_stack_read() function */
__msg("2: .12345.... {{.*}}(85) call pc+4")
__msg("5: .12345.... {{.*}}(85) call pc+1")
__msg("6: 0......... {{.*}}(95) exit")
/* read_first_param() function */
__msg("7: .1........ {{.*}}(79) r0 = *(u64 *)(r1 +0)")
__msg("8: 0......... {{.*}}(95) exit")
__naked void caller_stack_read(void)
{
	asm volatile (
	"r1 = r10;"
	"r1 += -8;"
	"call read_first_param;"
	"r1 = r10;"
	"r1 += -16;"
	"call read_first_param;"
	"exit;"
	::: __clobber_all);
}

static __used __naked void read_first_param(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__log_level(2)
/* read_first_param2() function */
__msg(" 9: .1........ {{.*}}(79) r0 = *(u64 *)(r1 +0)")
__msg("10: .......... {{.*}}(b7) r0 = 0")
__msg("11: 0......... {{.*}}(05) goto pc+0")
__msg("12: 0......... {{.*}}(95) exit")
__naked void caller_stack_pruning(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"if r0 == 42 goto 1f;"
	"r0 = %[map] ll;"
"1:"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = r10;"
	"r1 += -8;"
	/*
	 * fp[0]-8 is either pointer to map or a scalar,
	 * preventing state pruning at checkpoint created for call.
	 */
	"call read_first_param2;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_addr(map)
	: __clobber_all);
}

static __used __naked void read_first_param2(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"
	"r0 = 0;"
	/*
	 * Checkpoint at goto +0 should fire,
	 * as caller stack fp[0]-8 is not alive at this point.
	 */
	"goto +0;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__failure
__msg("R1 type=scalar expected=map_ptr")
__naked void caller_stack_pruning_callback(void)
{
	asm volatile (
	"r0 = %[map] ll;"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = 2;"
	"r2 = loop_cb ll;"
	"r3 = r10;"
	"r3 += -8;"
	"r4 = 0;"
	/*
	 * fp[0]-8 is either pointer to map or a scalar,
	 * preventing state pruning at checkpoint created for call.
	 */
	"call %[bpf_loop];"
	"r0 = 42;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_loop),
	  __imm_addr(map)
	: __clobber_all);
}

static __used __naked void loop_cb(void)
{
	asm volatile (
	/*
	 * Checkpoint at function entry should not fire, as caller
	 * stack fp[0]-8 is alive at this point.
	 */
	"r6 = r2;"
	"r1 = *(u64 *)(r6 + 0);"
	"*(u64*)(r10 - 8) = 7;"
	"r2 = r10;"
	"r2 += -8;"
	"call %[bpf_map_lookup_elem];"
	/*
	 * This should stop verifier on a second loop iteration,
	 * but only if verifier correctly maintains that fp[0]-8
	 * is still alive.
	 */
	"*(u64 *)(r6 + 0) = 0;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Because of a bug in verifier.c:compute_postorder()
 * the program below overflowed traversal queue in that function.
 */
SEC("socket")
__naked void syzbot_postorder_bug1(void)
{
	asm volatile (
	"r0 = 0;"
	"if r0 != 0 goto -1;"
	"exit;"
	::: __clobber_all);
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u32);
} map_array SEC(".maps");

SEC("socket")
__failure __msg("invalid read from stack R2 off=-1024 size=8")
__flag(BPF_F_TEST_STATE_FREQ)
__naked unsigned long caller_stack_write_tail_call(void)
{
        asm volatile (
	"r6 = r1;"
	"*(u64 *)(r10 - 8) = -8;"
        "call %[bpf_get_prandom_u32];"
        "if r0 != 42 goto 1f;"
        "goto 2f;"
  "1:"
        "*(u64 *)(r10 - 8) = -1024;"
  "2:"
        "r1 = r6;"
        "r2 = r10;"
        "r2 += -8;"
        "call write_tail_call;"
        "r1 = *(u64 *)(r10 - 8);"
        "r2 = r10;"
        "r2 += r1;"
        "r0 = *(u64 *)(r2 + 0);"
        "exit;"
        :: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

static __used __naked unsigned long write_tail_call(void)
{
        asm volatile (
        "r6 = r2;"
        "r2 = %[map_array] ll;"
        "r3 = 0;"
        "call %[bpf_tail_call];"
        "*(u64 *)(r6 + 0) = -16;"
        "r0 = 0;"
        "exit;"
	:
	: __imm(bpf_tail_call),
          __imm_addr(map_array)
        : __clobber_all);
}

/* Test precise subprog stack access analysis.
 * Caller passes fp-32 (SPI 3) to callee that only accesses arg+0 and arg+8
 * (SPIs 3 and 2). Slots 0 and 1 should NOT be live at the call site.
 *
 * Insn layout:
 *   0: *(u64*)(r10 - 8) = 0      write SPI 0
 *   1: *(u64*)(r10 - 16) = 0     write SPI 1
 *   2: *(u64*)(r10 - 24) = 0     write SPI 2
 *   3: *(u64*)(r10 - 32) = 0     write SPI 3
 *   4: r1 = r10
 *   5: r1 += -32
 *   6: call precise_read_two      passes fp-32 (SPI 3)
 *   7: r0 = 0
 *   8: exit
 *
 * At insn 6 only SPIs 2,3 should be live (slots 4-7, 0xf0).
 * SPIs 0,1 are written but never read → dead.
 */
SEC("socket")
__log_level(2)
__msg("6: .12345.... 0000000000000000:00000000000000f0 (85) call pc+2")
__naked void subprog_precise_stack_access(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = 0;"
	"*(u64 *)(r10 - 16) = 0;"
	"*(u64 *)(r10 - 24) = 0;"
	"*(u64 *)(r10 - 32) = 0;"
	"r1 = r10;"
	"r1 += -32;"
	"call precise_read_two;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* Callee reads only at arg+0 (SPI 3) and arg+8 (SPI 2) */
static __used __naked void precise_read_two(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"
	"r2 = *(u64 *)(r1 + 8);"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* Test that multi-level subprog calls (callee passes arg-derived ptr
 * to another BPF subprog) are analyzed precisely.
 *
 * Caller passes fp-32 (SPI 3). The callee forwards it to inner_callee.
 * inner_callee only reads at offset 0 from the pointer.
 * The analysis recurses into forward_to_inner -> inner_callee and
 * determines only SPI 3 is accessed (slots 6-7, 0xc0), not all of SPIs 0-3.
 *
 * Insn layout:
 *   0: *(u64*)(r10 - 8) = 0      write SPI 0
 *   1: *(u64*)(r10 - 16) = 0     write SPI 1
 *   2: *(u64*)(r10 - 24) = 0     write SPI 2
 *   3: *(u64*)(r10 - 32) = 0     write SPI 3
 *   4: r1 = r10
 *   5: r1 += -32
 *   6: call forward_to_inner      passes fp-32 (SPI 3)
 *   7: r0 = 0
 *   8: exit
 */
SEC("socket")
__log_level(2)
__msg("6: .12345.... 0000000000000000:00000000000000c0 (85) call pc+2")
__naked void subprog_multilevel_conservative(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = 0;"
	"*(u64 *)(r10 - 16) = 0;"
	"*(u64 *)(r10 - 24) = 0;"
	"*(u64 *)(r10 - 32) = 0;"
	"r1 = r10;"
	"r1 += -32;"
	"call forward_to_inner;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* Forwards arg to another subprog */
static __used __naked void forward_to_inner(void)
{
	asm volatile (
	"call inner_callee;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

static __used __naked void inner_callee(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* Test multi-frame precision loss: callee consumes caller stack early,
 * but static liveness keeps it live at pruning points inside callee.
 *
 * Caller stores map_ptr or scalar(42) at fp-8, then calls
 * consume_and_call_inner. The callee reads fp[0]-8 at entry (consuming
 * the slot), then calls do_nothing2. After do_nothing2 returns (a
 * pruning point), fp-8 should be dead -- the read already happened.
 * But because the call instruction's stack_use includes SPI 0, the
 * static live_stack_before at insn 7 is 0x1, keeping fp-8 live inside
 * the callee and preventing state pruning between the two paths.
 *
 * Insn layout:
 *   0: call bpf_get_prandom_u32
 *   1: if r0 == 42 goto pc+2    -> insn 4
 *   2: r0 = map ll (ldimm64 part1)
 *   3: (ldimm64 part2)
 *   4: *(u64)(r10 - 8) = r0     fp-8 = map_ptr OR scalar(42)
 *   5: r1 = r10
 *   6: r1 += -8
 *   7: call consume_and_call_inner
 *   8: r0 = 0
 *   9: exit
 *
 * At insn 7, live_stack_before = 0x3 (slots 0-1 live due to stack_use).
 * At insn 8, live_stack_before = 0x0 (SPI 0 dead, caller doesn't need it).
 */
SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__log_level(2)
__success
__msg(" 7: {{.*}} 0000000000000000:0000000000000003 (85) call pc+")
__msg(" 8: {{.*}} 0000000000000000:0000000000000000 (b7)")
__naked void callee_consumed_caller_stack(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"if r0 == 42 goto 1f;"
	"r0 = %[map] ll;"
"1:"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = r10;"
	"r1 += -8;"
	"call consume_and_call_inner;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_addr(map)
	: __clobber_all);
}

static __used __naked void consume_and_call_inner(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"	/* read fp[0]-8 into caller-saved r0 */
	"call do_nothing2;"		/* inner call clobbers r0 */
	"r0 = 0;"
	"goto +0;"			/* checkpoint */
	"r0 = 0;"
	"goto +0;"			/* checkpoint */
	"r0 = 0;"
	"goto +0;"			/* checkpoint */
	"r0 = 0;"
	"goto +0;"			/* checkpoint */
	"exit;"
	::: __clobber_all);
}

static __used __naked void do_nothing2(void)
{
	asm volatile (
	"r0 = 0;"
	"r0 = 0;"
	"r0 = 0;"
	"r0 = 0;"
	"r0 = 0;"
	"r0 = 0;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/*
 * Reproducer for unsound pruning when clean_verifier_state() promotes
 * live STACK_ZERO bytes to STACK_MISC.
 *
 * Program shape:
 * - Build key at fp-4:
 *   - path A keeps key byte as STACK_ZERO;
 *   - path B writes unknown byte making it STACK_MISC.
 * - Branches merge at a prune point before map_lookup.
 * - map_lookup on ARRAY map is value-sensitive to constant zero key:
 *   - path A: const key 0 => PTR_TO_MAP_VALUE (non-NULL);
 *   - path B: non-const key => PTR_TO_MAP_VALUE_OR_NULL.
 * - Dereference lookup result without null check.
 *
 * Note this behavior won't trigger at fp-8, since the verifier will
 * track 32-bit scalar spill differently as spilled_ptr.
 *
 * Correct verifier behavior: reject (path B unsafe).
 * With blanket STACK_ZERO->STACK_MISC promotion on live slots, cached path A
 * state can be generalized and incorrectly prune path B, making program load.
 */
SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__failure __msg("R0 invalid mem access 'map_value_or_null'")
__naked void stack_zero_to_misc_unsound_array_lookup(void)
{
	asm volatile (
	/* key at fp-4: all bytes STACK_ZERO */
	"*(u32 *)(r10 - 4) = 0;"
	"call %[bpf_get_prandom_u32];"
	/* fall-through (path A) explored first */
	"if r0 != 0 goto l_nonconst%=;"
	/* path A: keep key constant zero */
	"goto l_lookup%=;"
"l_nonconst%=:"
	/* path B: key byte turns to STACK_MISC, key no longer const */
	"*(u8 *)(r10 - 4) = r0;"
"l_lookup%=:"
	/* value-sensitive lookup */
	"r2 = r10;"
	"r2 += -4;"
	"r1 = %[array_map_8b] ll;"
	"call %[bpf_map_lookup_elem];"
	/* unsafe when lookup result is map_value_or_null */
	"r0 = *(u64 *)(r0 + 0);"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(array_map_8b)
	: __clobber_all);
}

/* BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root(void)
{
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
}

/* Test that open-coded iterator kfunc arguments get precise stack
 * liveness tracking. struct bpf_iter_num is 8 bytes (1 SPI).
 *
 * Insn layout:
 *   0: *(u64*)(r10 - 8) = 0      write SPI 0 (dead)
 *   1: *(u64*)(r10 - 16) = 0     write SPI 1 (dead)
 *   2: r1 = r10
 *   3: r1 += -24                 iter state at fp-24 (SPI 2)
 *   4: r2 = 0
 *   5: r3 = 10
 *   6: call bpf_iter_num_new     defines SPI 2 (KF_ITER_NEW) → 0x0
 *   7-8: r1 = fp-24
 *   9: call bpf_iter_num_next    uses SPI 2 → 0x30
 *  10: if r0 == 0 goto 2f
 *  11: goto 1b
 *  12-13: r1 = fp-24
 *  14: call bpf_iter_num_destroy uses SPI 2 → 0x30
 *  15: r0 = 0
 *  16: exit
 *
 * At insn 6, SPI 2 is defined (KF_ITER_NEW initializes, doesn't read),
 * so it kills liveness from successors. live_stack_before = 0x0.
 * At insns 9 and 14, SPI 2 is used (iter_next/destroy read the state),
 * so live_stack_before = 0x30.
 */
SEC("socket")
__success __log_level(2)
__msg("6: .123...... 0000000000000000:0000000000000000 (85) call bpf_iter_num_new")
__msg("9: .1........ 0000000000000000:0000000000000030 (85) call bpf_iter_num_next")
__msg("14: .1........ 0000000000000000:0000000000000030 (85) call bpf_iter_num_destroy")
__naked void kfunc_iter_stack_liveness(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = 0;"	/* SPI 0 - dead */
	"*(u64 *)(r10 - 16) = 0;"	/* SPI 1 - dead */
	"r1 = r10;"
	"r1 += -24;"
	"r2 = 0;"
	"r3 = 10;"
	"call %[bpf_iter_num_new];"
"1:"
	"r1 = r10;"
	"r1 += -24;"
	"call %[bpf_iter_num_next];"
	"if r0 == 0 goto 2f;"
	"goto 1b;"
"2:"
	"r1 = r10;"
	"r1 += -24;"
	"call %[bpf_iter_num_destroy];"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_iter_num_new),
	   __imm(bpf_iter_num_next),
	   __imm(bpf_iter_num_destroy)
	: __clobber_all);
}

/*
 * Test for soundness bug in static stack liveness analysis.
 *
 * The static pre-pass tracks FP-derived register offsets to determine
 * which stack slots are accessed. When a PTR_TO_STACK is spilled to
 * the stack and later reloaded, the reload (BPF_LDX) kills FP-derived
 * tracking, making subsequent accesses through the reloaded pointer
 * invisible to the static analysis.
 *
 * This causes the analysis to incorrectly mark SPI 0 as dead at the
 * merge point. clean_verifier_state() zeros it in the cached state,
 * and stacksafe() accepts the new state against STACK_INVALID,
 * enabling incorrect pruning.
 *
 * Path A (verified first): stores PTR_TO_MAP_VALUE in SPI 0
 * Path B (verified second): stores scalar 42 in SPI 0
 * After merge: reads SPI 0 through spilled/reloaded PTR_TO_STACK
 * and dereferences the result as a pointer.
 *
 * Correct behavior: reject (path B dereferences a scalar)
 * Bug behavior: accept (path B is incorrectly pruned)
 */
SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__failure __msg("R0 invalid mem access 'scalar'")
__naked void spill_ptr_liveness_type_confusion(void)
{
	asm volatile (
	/* Map lookup to get PTR_TO_MAP_VALUE */
	"r1 = %[map] ll;"
	"*(u32 *)(r10 - 32) = 0;"
	"r2 = r10;"
	"r2 += -32;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto l_exit%=;"
	/* r6 = PTR_TO_MAP_VALUE (callee-saved) */
	"r6 = r0;"
	/* Branch: fall-through (path A) verified first */
	"call %[bpf_get_prandom_u32];"
	"if r0 != 0 goto l_scalar%=;"
	/* Path A: store map value ptr at SPI 0 */
	"*(u64 *)(r10 - 8) = r6;"
	"goto l_merge%=;"
"l_scalar%=:"
	/* Path B: store scalar at SPI 0 */
	"r1 = 42;"
	"*(u64 *)(r10 - 8) = r1;"
"l_merge%=:"
	/*
	 * Spill PTR_TO_STACK{off=-8} to SPI 1, then reload.
	 * Reload kills FP-derived tracking, hiding the
	 * subsequent SPI 0 access from the static analysis.
	 */
	"r1 = r10;"
	"r1 += -8;"
	"*(u64 *)(r10 - 16) = r1;"
	"goto +0;"			/* checkpoint */
	"goto +0;"			/* checkpoint */
	"goto +0;"			/* checkpoint */
	"r1 = *(u64 *)(r10 - 16);"
	/* Read SPI 0 through reloaded pointer */
	"r0 = *(u64 *)(r1 + 0);"
	/* Dereference: safe for map value (path A),
	 * unsafe for scalar (path B).
	 */
	"r0 = *(u64 *)(r0 + 0);"
	"exit;"
"l_exit%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_get_prandom_u32),
	  __imm_addr(map)
	: __clobber_all);
}
