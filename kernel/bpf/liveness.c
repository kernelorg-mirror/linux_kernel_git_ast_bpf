// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf_verifier.h>
#include <linux/btf.h>


int bpf_jmp_offset(struct bpf_insn *insn)
{
	u8 code = insn->code;

	if (code == (BPF_JMP32 | BPF_JA))
		return insn->imm;
	return insn->off;
}

__diag_push();
__diag_ignore_all("-Woverride-init", "Allow field initialization overrides for opcode_info_tbl");

/*
 * Returns an array of instructions succ, with succ->items[0], ...,
 * succ->items[n-1] with successor instructions, where n=succ->cnt
 */
inline struct bpf_iarray *
bpf_insn_successors(struct bpf_verifier_env *env, u32 idx)
{
	static const struct opcode_info {
		bool can_jump;
		bool can_fallthrough;
	} opcode_info_tbl[256] = {
		[0 ... 255] = {.can_jump = false, .can_fallthrough = true},
	#define _J(code, ...) \
		[BPF_JMP   | code] = __VA_ARGS__, \
		[BPF_JMP32 | code] = __VA_ARGS__

		_J(BPF_EXIT,  {.can_jump = false, .can_fallthrough = false}),
		_J(BPF_JA,    {.can_jump = true,  .can_fallthrough = false}),
		_J(BPF_JEQ,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JNE,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JLT,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JLE,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JGT,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JGE,   {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSGT,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSGE,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSLT,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSLE,  {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JCOND, {.can_jump = true,  .can_fallthrough = true}),
		_J(BPF_JSET,  {.can_jump = true,  .can_fallthrough = true}),
	#undef _J
	};
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = &prog->insnsi[idx];
	const struct opcode_info *opcode_info;
	struct bpf_iarray *succ, *jt;
	int insn_sz;

	jt = env->insn_aux_data[idx].jt;
	if (unlikely(jt))
		return jt;

	/* pre-allocated array of size up to 2; reset cnt, as it may have been used already */
	succ = env->succ;
	succ->cnt = 0;

	opcode_info = &opcode_info_tbl[BPF_CLASS(insn->code) | BPF_OP(insn->code)];
	insn_sz = bpf_is_ldimm64(insn) ? 2 : 1;
	if (opcode_info->can_fallthrough)
		succ->items[succ->cnt++] = idx + insn_sz;

	if (opcode_info->can_jump)
		succ->items[succ->cnt++] = idx + bpf_jmp_offset(insn) + 1;

	return succ;
}

__diag_pop();


/*
 * Forward dataflow analysis to determine constant register values at every
 * instruction. Tracks 64-bit constant values in R0-R9 through the program,
 * using a fixed-point iteration in reverse postorder. Records which registers
 * hold known constants and their values in
 * env->insn_aux_data[].{const_reg_mask, const_reg_vals}.
 */

enum const_arg_state {
	CONST_ARG_UNVISITED,	/* instruction not yet reached */
	CONST_ARG_UNKNOWN,	/* register value not a known constant */
	CONST_ARG_CONST,	/* register holds a known constant */
};

struct const_arg_info {
	enum const_arg_state state;
	u64 val;
};

/*
 * Transfer function: compute output register state from instruction.
 * ci_out[] is initialized to the input state before calling this.
 */
static void const_reg_transfer(struct const_arg_info *ci_out,
			       struct bpf_insn *insn, struct bpf_insn *insns,
			       int idx)
{
	u8 class = BPF_CLASS(insn->code);
	u8 code = BPF_OP(insn->code);
	int r;

	if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_K) {
		if (code == BPF_MOV) {
			ci_out[insn->dst_reg].state = CONST_ARG_CONST;
			ci_out[insn->dst_reg].val = (s64)insn->imm;
		} else if (code == BPF_ADD && ci_out[insn->dst_reg].state == CONST_ARG_CONST) {
			ci_out[insn->dst_reg].val += insn->imm;
		} else if (code == BPF_SUB && ci_out[insn->dst_reg].state == CONST_ARG_CONST) {
			ci_out[insn->dst_reg].val -= insn->imm;
		} else {
			ci_out[insn->dst_reg].state = CONST_ARG_UNKNOWN;
		}
	} else if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_X) {
		if (code == BPF_MOV) {
			ci_out[insn->dst_reg] = ci_out[insn->src_reg];
			/* Sign-extending move */
			if (insn->off && ci_out[insn->dst_reg].state == CONST_ARG_CONST) {
				s64 val = ci_out[insn->dst_reg].val;

				if (insn->off == 8)
					val = (s8)val;
				else if (insn->off == 16)
					val = (s16)val;
				else if (insn->off == 32)
					val = (s32)val;
				ci_out[insn->dst_reg].val = val;
			}
		} else {
			ci_out[insn->dst_reg].state = CONST_ARG_UNKNOWN;
		}
	} else if (class == BPF_ALU && BPF_SRC(insn->code) == BPF_K) {
		if (code == BPF_MOV) {
			ci_out[insn->dst_reg].state = CONST_ARG_CONST;
			ci_out[insn->dst_reg].val = (u32)insn->imm;
		} else {
			ci_out[insn->dst_reg].state = CONST_ARG_UNKNOWN;
		}
	} else if (class == BPF_ALU) {
		ci_out[insn->dst_reg].state = CONST_ARG_UNKNOWN;
	} else if (class == BPF_LD && BPF_MODE(insn->code) == BPF_IMM &&
		   BPF_SIZE(insn->code) == BPF_DW) {
		/* LD_IMM64: two-insn encoding */
		ci_out[insn->dst_reg].state = CONST_ARG_CONST;
		ci_out[insn->dst_reg].val = (u64)(u32)insn->imm | ((u64)(u32)insns[idx + 1].imm << 32);
	} else if (class == BPF_JMP && code == BPF_CALL) {
		/* Calls clobber R0-R5 */
		for (r = BPF_REG_0; r <= BPF_REG_5; r++)
			ci_out[r].state = CONST_ARG_UNKNOWN;
	} else if (class == BPF_LDX) {
		ci_out[insn->dst_reg].state = CONST_ARG_UNKNOWN;
	} else if (class == BPF_STX && BPF_MODE(insn->code) == BPF_ATOMIC) {
		if (insn->imm == BPF_CMPXCHG)
			ci_out[BPF_REG_0].state = CONST_ARG_UNKNOWN;
		else if (insn->imm == BPF_LOAD_ACQ)
			ci_out[insn->dst_reg].state = CONST_ARG_UNKNOWN;
		else if (insn->imm & BPF_FETCH)
			ci_out[insn->src_reg].state = CONST_ARG_UNKNOWN;
	}
}

/*
 * Join function: merge output state into a successor's input state.
 * Returns true if the successor's state changed.
 */
static bool const_reg_join(struct const_arg_info *ci_target,
			   struct const_arg_info *ci_out)
{
	bool changed = false;
	int r;

	for (r = 0; r < MAX_BPF_REG; r++) {
		struct const_arg_info *old = &ci_target[r];
		struct const_arg_info *new = &ci_out[r];

		if (old->state == CONST_ARG_UNVISITED) {
			ci_target[r] = *new;
			changed = true;
		} else if (old->state == CONST_ARG_CONST &&
			   (new->state != CONST_ARG_CONST || new->val != old->val)) {
			old->state = CONST_ARG_UNKNOWN;
			changed = true;
		}
		/* UNKNOWN stays UNKNOWN */
	}
	return changed;
}

int compute_const_regs(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *insn_aux = env->insn_aux_data;
	struct bpf_insn *insns = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	struct const_arg_info (*ci_in)[MAX_BPF_REG];
	struct const_arg_info ci_out[MAX_BPF_REG];
	struct bpf_iarray *succ;
	bool changed;
	int i, r;

	ci_in = kvzalloc_objs(*ci_in, insn_cnt, GFP_KERNEL_ACCOUNT);
	if (!ci_in)
		return -ENOMEM;

	/* kvzalloc zeroes memory, so all entries start as CONST_ARG_UNVISITED (0) */

	/* Entry point: all registers unknown */
	for (r = 0; r < MAX_BPF_REG; r++)
		ci_in[0][r].state = CONST_ARG_UNKNOWN;

	/* Subprogram entries: all registers unknown */
	for (i = 0; i < env->subprog_cnt; i++) {
		int start = env->subprog_info[i].start;

		for (r = 0; r < MAX_BPF_REG; r++)
			ci_in[start][r].state = CONST_ARG_UNKNOWN;
	}

	/* Forward fixed-point: iterate in reverse postorder */
	changed = true;
	while (changed) {
		changed = false;
		for (i = env->cfg.cur_postorder - 1; i >= 0; i--) {
			int idx = env->cfg.insn_postorder[i];
			struct bpf_insn *insn = &insns[idx];

			/* Skip unvisited instructions */
			if (ci_in[idx][0].state == CONST_ARG_UNVISITED)
				continue;

			memcpy(ci_out, ci_in[idx], sizeof(ci_out));

			const_reg_transfer(ci_out, insn, insns, idx);

			/* Propagate to successors */
			succ = bpf_insn_successors(env, idx);
			for (int s = 0; s < succ->cnt; s++)
				changed |= const_reg_join(ci_in[succ->items[s]], ci_out);
		}
	}

	/* Extract constant R0-R9 at all instruction sites */
	for (i = 0; i < insn_cnt; i++) {
		u16 mask = 0;

		if (ci_in[i][0].state == CONST_ARG_UNVISITED)
			continue;

		for (r = BPF_REG_0; r < MAX_BPF_REG; r++) {
			if (ci_in[i][r].state == CONST_ARG_CONST) {
				mask |= BIT(r);
				insn_aux[i].const_reg_vals[r] =	ci_in[i][r].val;
			}
		}
		insn_aux[i].const_reg_mask = mask;
	}

	kvfree(ci_in);
	return 0;
}

static inline int spis_hweight(const u64 spis[2])
{
	return hweight64(spis[0]) + hweight64(spis[1]);
}

static inline int spis_ffs(const u64 spis[2])
{
	if (spis[0])
		return __ffs(spis[0]);
	if (spis[1])
		return 64 + __ffs(spis[1]);
	return -1;
}

/* Returns true if a has any bits set that are not in b: (a & ~b) != 0 */
static inline bool spis_any_new(const u64 a[2], const u64 b[2])
{
	return (a[0] & ~b[0]) || (a[1] & ~b[1]);
}

static inline bool spis_and_nonzero(const u64 a[2], const u64 b[2])
{
	return (a[0] & b[0]) || (a[1] & b[1]);
}

/* Print the BTF function prototype and detected access pattern for a subprog */
static void print_subprog_arg_access(struct bpf_verifier_env *env,
				     int subprog,
				     struct subprog_arg_access *access)
{
	struct bpf_prog_aux *aux = env->prog->aux;
	const struct btf_type *func, *func_proto;
	const struct btf_param *args;
	struct btf *btf = aux->btf;
	char buf[256];
	u32 nr_args;
	int len, i;

	if (!aux->func_info)
		return;
	if (!btf)
		return;

	func = btf_type_by_id(btf, aux->func_info[subprog].type_id);
	if (!func || !btf_type_is_func(func))
		return;
	func_proto = btf_type_by_id(btf, func->type);
	if (!func_proto || !btf_type_is_func_proto(func_proto))
		return;

	nr_args = btf_type_vlen(func_proto);
	args = btf_params(func_proto);

	/* Print C-like prototype */
	len = btf_type_snprintf(btf, func_proto->type, buf, sizeof(buf));
	len += snprintf(buf + len, max((int)sizeof(buf) - len, 0), " %s(",
			btf_name_by_offset(btf, func->name_off) ?: "?");
	for (i = 0; i < nr_args; i++) {
		if (i)
			len += snprintf(buf + len,
					max((int)sizeof(buf) - len, 0), ", ");
		len += btf_type_snprintf(btf, args[i].type, buf + len,
					 sizeof(buf) - len);
		len += snprintf(buf + len, max((int)sizeof(buf) - len, 0),
				" %s",
				btf_name_by_offset(btf, args[i].name_off) ?: "");
	}
	len += snprintf(buf + len, max((int)sizeof(buf) - len, 0), ")");

	verbose(env, "subprog#%d: %s\n", subprog, buf);

	/* Print access pattern per argument */
	for (i = 1; i < NUM_AT_IDS && i <= nr_args; i++) {
		u64 *r = access->read[i];
		u64 *w = access->write[i];

		if (spis_is_all(r) || spis_is_all(w))
			verbose(env, "  r%d: all (conservative)\n", i);
		else if (!spis_is_zero(r) || !spis_is_zero(w))
			verbose(env, "  r%d read: 0x%llx:%llx  write: 0x%llx:%llx\n",
				i, r[1], r[0], w[1], w[0]);
	}
}

/*
 * Per-register tracking state for compute_subprog_arg_tracking().
 * Tracks which argument register (R1-R5) a value is derived from
 * and the byte offset from that argument's original value.
 *
 * The .arg field forms a lattice with three levels of precision:
 *
 *   precise {arg=0..5, off=N}     -- known arg identity and byte offset
 *        |                          (0=FP, 1-5=R1-R5)
 *   offset-imprecise {arg=0..5, off=OFF_IMPRECISE}
 *        |                        -- known arg identity, unknown offset
 *   fully-imprecise {arg=ARG_IMPRECISE}
 *                                 -- unknown arg identity and offset
 *
 * At CFG merge points, arg_track_join() moves down the lattice:
 *   - same arg + same offset  -> precise
 *   - same arg + different offset -> offset-imprecise
 *   - different args          -> fully-imprecise
 *
 * At memory access sites (LDX/STX/ST), offset-imprecise marks only
 * the known arg's access mask as U64_MAX, while fully-imprecise must
 * conservatively mark all args.
 */
struct arg_track {
	s64 off;	/* byte offset, or OFF_IMPRECISE if unknown */
	s8 arg;		/* 0=FP, 1-5=R1-R5, or enum arg_track_state */
};

enum arg_track_state {
	ARG_NONE	= -1,	/* not derived from any argument */
	ARG_UNVISITED	= -2,	/* not yet reached by dataflow */
	ARG_IMPRECISE	= -3,	/* arg-derived but lost arg identity and offset */
};

#define OFF_IMPRECISE	S64_MIN	/* arg identity known but offset unknown */

/* Track callee stack slots fp-8 through fp-64 (8 slots of 8 bytes each) */
#define MAX_ARG_SPILL_SLOTS 8

/*
 * Convert a byte offset from FP to a callee stack slot index (0-7).
 * Returns -1 if out of range or not 8-byte aligned.
 * Slot 0 = fp-8, slot 1 = fp-16, ..., slot 7 = fp-64.
 */
static int fp_byte_off_to_slot(s64 off)
{
	if (off >= 0 || off < -(s64)(MAX_ARG_SPILL_SLOTS * 8))
		return -1;
	if (off % 8)
		return -1;
	return (int)((-off) / 8) - 1;
}

/*
 * Clear all tracked callee stack slots overlapping the byte range
 * [off, off+sz-1] where off is a negative FP-relative offset.
 */
static void clear_overlapping_stack_slots(struct arg_track *at_stack,
					  s64 off, u32 sz)
{
	s64 end = off + sz;
	int i;

	for (i = 0; i < MAX_ARG_SPILL_SLOTS; i++) {
		s64 slot_start = -(s64)((i + 1) * 8);
		s64 slot_end = slot_start + 8;

		if (slot_start < end && slot_end > off)
			at_stack[i] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
	}
}

/*
 * Join two arg_track values at merge points.
 * Same arg+off = keep, same arg+different off = keep arg with imprecise
 * offset, different args = fully imprecise.
 */
static struct arg_track arg_track_join(struct subprog_arg_access *access,
				       struct arg_track a, struct arg_track b)
{
	if (b.arg == ARG_UNVISITED)
		return a;
	if (a.arg == ARG_UNVISITED)
		return b;
	if (a.arg == b.arg && a.off == b.off)
		return a;
	/* Same arg, different offset: preserve arg identity */
	if (a.arg >= 0 && a.arg == b.arg)
		return (struct arg_track){ .off = OFF_IMPRECISE, .arg = a.arg };
	if (a.arg >= 0 && b.arg == ARG_NONE)
		return (struct arg_track){ .off = OFF_IMPRECISE, .arg = a.arg };
	if (b.arg >= 0 && a.arg == ARG_NONE)
		return (struct arg_track){ .off = OFF_IMPRECISE, .arg = b.arg };
	if (a.arg >= 0)
		access->unknown_args |= BIT(a.arg);
	if (b.arg >= 0)
		access->unknown_args |= BIT(b.arg);
	return (struct arg_track){ .off = 0, .arg = ARG_IMPRECISE };
}

/*
 * Compute the result when an ALU op destroys offset precision.
 * If a single arg is identifiable, preserve it with OFF_IMPRECISE.
 * If two different args are involved or one is already ARG_IMPRECISE,
 * the result is fully ARG_IMPRECISE.
 */
static struct arg_track arg_track_lose_offset(struct subprog_arg_access *access, s8 arg1, s8 arg2)
{
	if (arg1 >= 0 && (arg2 == ARG_NONE || arg2 == arg1))
		return (struct arg_track){ .off = OFF_IMPRECISE, .arg = arg1 };
	if (arg2 >= 0 && arg1 == ARG_NONE)
		return (struct arg_track){ .off = OFF_IMPRECISE, .arg = arg2 };
	if (arg1 == ARG_IMPRECISE || arg2 == ARG_IMPRECISE ||
	    (arg1 >= 0 && arg2 >= 0)) {
		if (arg1 >= 0)
			access->unknown_args |= BIT(arg1);
		if (arg2 >= 0)
			access->unknown_args |= BIT(arg2);
		return (struct arg_track){ .off = 0, .arg = ARG_NONE };
	}
	return (struct arg_track){ .off = 0, .arg = ARG_NONE };
}

static void verbose_arg_track(struct bpf_verifier_env *env, struct arg_track *at)
{
	switch (at->arg) {
	case ARG_NONE:      verbose(env, "_");                          break;
	case ARG_UNVISITED: verbose(env, "?");                          break;
	case ARG_IMPRECISE: verbose(env, "IMP");                        break;
	case AT_FP:
		if (at->off == OFF_IMPRECISE)
			verbose(env, "fp ?");
		else
			verbose(env, "fp%+lld", at->off);
		break;
	default:
		if (at->off == OFF_IMPRECISE)
			verbose(env, "r%d ?", at->arg);
		else
			verbose(env, "r%d%+lld", at->arg, at->off);
		break;
	}
}

/*
 * Record an argument-derived memory access in the read/write bitmasks.
 * @is_read:      true for reads (LDX), false for writes (STX/ST)
 * @access_size:  access size in bytes (1, 2, 4, or 8)
 *
 * Operates at 4-byte slot granularity. For writes: only slot-aligned
 * accesses that fully cover the 4-byte slot go to the write mask;
 * sub-slot or unaligned writes are treated as reads (conservative).
 */
static void record_arg_mem_access(struct subprog_arg_access *access,
				  u64 (*arg_use)[NUM_AT_IDS][2],
				  int local_idx,
				  struct arg_track *ptr, s16 insn_off,
				  bool is_read, u32 access_size)
{
	u32 slot, slot_hi, s;
	s64 acc_off;
	int arg;

	if (ptr->arg < 1 || ptr->arg >= NUM_AT_IDS)
		return;
	arg = ptr->arg;

	if (ptr->off == OFF_IMPRECISE) {
		spis_set_all(access->read[arg]);
		if (!is_read)
			spis_set_all(access->write[arg]);
		spis_set_all(arg_use[local_idx][arg]);
		return;
	}

	acc_off = ptr->off + insn_off;
	if (acc_off < 0) {
		spis_set_all(access->read[arg]);
		if (!is_read)
			spis_set_all(access->write[arg]);
		spis_set_all(arg_use[local_idx][arg]);
		return;
	}

	slot = acc_off / STACK_SLOT_SZ;
	if (slot >= STACK_SLOTS)
		return;

	slot_hi = (acc_off + access_size - 1) / STACK_SLOT_SZ;
	if (slot_hi >= STACK_SLOTS)
		slot_hi = STACK_SLOTS - 1;

	if (!is_read && access_size >= STACK_SLOT_SZ &&
	    !(acc_off % STACK_SLOT_SZ)) {
		/* Write covers full 4-byte slot(s) */
		for (s = slot; s <= slot_hi; s++)
			spis_set_bit(access->write[arg], s);
	} else {
		/* Reads, or sub-slot/unaligned writes treated as reads */
		for (s = slot; s <= slot_hi; s++) {
			spis_set_bit(access->read[arg], s);
			spis_set_bit(arg_use[local_idx][arg], s);
		}
	}
}

/*
 * Fold callee's argument access masks into the caller's access summary.
 *
 * When caller passes (arg + byte_off) as callee_arg to a known callee,
 * shift the callee's per-argument 4-byte slot masks by byte_off/4 and
 * merge them into the caller's masks for 'arg'.
 */
static void fold_callee_arg_access(struct subprog_arg_access *access,
				   u64 (*arg_use)[NUM_AT_IDS][2],
				   int local_idx,
				   struct subprog_arg_access *callee,
				   struct arg_track *at_out)
{
	int r;

	for (r = BPF_REG_1; r <= BPF_REG_5; r++) {
		int callee_arg, shift, arg;
		s32 byte_off;

		if (at_out[r].arg < 1 || at_out[r].arg >= NUM_AT_IDS)
			continue;
		arg = at_out[r].arg;
		if (at_out[r].off == OFF_IMPRECISE) {
			spis_set_all(access->read[arg]);
			spis_set_all(access->write[arg]);
			spis_set_all(arg_use[local_idx][arg]);
			continue;
		}
		callee_arg = r - BPF_REG_1 + 1;
		byte_off = (s32)at_out[r].off;
		if (spis_is_all(callee->read[callee_arg]) ||
		    spis_is_all(callee->write[callee_arg]) ||
		    byte_off < 0 || (byte_off & (STACK_SLOT_SZ - 1))) {
			spis_set_all(access->read[arg]);
			spis_set_all(access->write[arg]);
			spis_set_all(arg_use[local_idx][arg]);
			continue;
		}
		shift = byte_off / STACK_SLOT_SZ;
		if (spis_shift_would_overflow(callee->read[callee_arg], shift)) {
			spis_set_all(access->read[arg]);
			spis_set_all(arg_use[local_idx][arg]);
		} else {
			spis_shift_or(access->read[arg],
				      callee->read[callee_arg], shift);
			spis_shift_or(arg_use[local_idx][arg],
				      callee->read[callee_arg], shift);
		}
		if (spis_shift_would_overflow(callee->write[callee_arg], shift)) {
			spis_set_all(access->write[arg]);
		} else {
			spis_shift_or(access->write[arg],
				      callee->write[callee_arg], shift);
		}
	}
}

/*
 * Compute effective FP offset for a memory access through @reg + insn->off.
 * If @reg is R10 (FP), the offset is simply insn->off.
 * If @reg is FP-derived with a known offset, combine them.
 * Returns OFF_IMPRECISE when the effective offset cannot be determined.
 */
static s64 effective_fp_off(struct bpf_insn *insn, struct arg_track *at_out,
			    int reg)
{
	if (reg == BPF_REG_FP)
		return insn->off;
	if (at_out[reg].off == OFF_IMPRECISE)
		return OFF_IMPRECISE;
	return at_out[reg].off + insn->off;
}

/*
 * Pure dataflow transfer function for arg_track state.
 * Updates at_out[] based on how the instruction modifies registers.
 * Does not record memory accesses or handle inter-procedural folding.
 */
static void arg_track_xfer(struct bpf_verifier_env *env,
			   struct bpf_insn *insn,
			   struct subprog_arg_access *access,
			   struct arg_track *at_out,
			   struct arg_track *at_stack_out)
{
	u8 class = BPF_CLASS(insn->code);
	u8 code = BPF_OP(insn->code);
	int r;

	if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_K) {
		if (code == BPF_MOV) {
			at_out[insn->dst_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
		} else if (code == BPF_ADD && at_out[insn->dst_reg].arg >= 0) {
			if (at_out[insn->dst_reg].off != OFF_IMPRECISE)
				at_out[insn->dst_reg].off += insn->imm;
		} else if (code == BPF_SUB && at_out[insn->dst_reg].arg >= 0) {
			if (at_out[insn->dst_reg].off != OFF_IMPRECISE)
				at_out[insn->dst_reg].off -= insn->imm;
		} else if (at_out[insn->dst_reg].arg == ARG_IMPRECISE ||
			   (at_out[insn->dst_reg].arg >= 0 &&
			    at_out[insn->dst_reg].off == OFF_IMPRECISE)) {
			; /* keep imprecise state unchanged */
		} else {
			at_out[insn->dst_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
		}
	} else if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_X) {
		if (code == BPF_MOV) {
			if (insn->off == 0) {
				at_out[insn->dst_reg] = at_out[insn->src_reg];
			} else {
				/* addr_space_cast */
				at_out[insn->dst_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
			}
		} else {
			at_out[insn->dst_reg] = arg_track_lose_offset(access,
				at_out[insn->dst_reg].arg,
				at_out[insn->src_reg].arg);
		}
	} else if (class == BPF_ALU || class == BPF_ALU64) {
		s8 sa = BPF_SRC(insn->code) == BPF_X ?
			at_out[insn->src_reg].arg : ARG_NONE;

		if (code == BPF_MOV)
			at_out[insn->dst_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
		else
			at_out[insn->dst_reg] = arg_track_lose_offset(access,
								      at_out[insn->dst_reg].arg, sa);
	} else if (class == BPF_JMP && code == BPF_CALL) {
		/* Calls clobber R0-R5 */
		for (r = BPF_REG_0; r <= BPF_REG_5; r++)
			at_out[r] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
	} else if (class == BPF_LDX) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
		bool src_is_fp = (insn->src_reg == BPF_REG_FP ||
				  at_out[insn->src_reg].arg == AT_FP);

		/*
		 * Reload from callee stack: if src is FP-derived with
		 * precise offset, 8-byte BPF_MEM load, and the slot
		 * holds an arg identity, restore it to dst.
		 */
		if (src_is_fp &&
		    BPF_MODE(insn->code) == BPF_MEM && sz == 8) {
			s64 eff_off = effective_fp_off(insn, at_out, insn->src_reg);
			int slot;

			slot = (eff_off != OFF_IMPRECISE) ?
				fp_byte_off_to_slot(eff_off) : -1;
			if (slot >= 0 && at_stack_out[slot].arg >= 1) {
				at_out[insn->dst_reg] = at_stack_out[slot];
			} else {
				at_out[insn->dst_reg] = (struct arg_track){
					.off = 0, .arg = ARG_NONE };
			}
		} else {
			at_out[insn->dst_reg] = (struct arg_track){
				.off = 0, .arg = ARG_NONE };
		}
	} else if (class == BPF_LD && BPF_MODE(insn->code) == BPF_IMM) {
		at_out[insn->dst_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
	} else if (class == BPF_STX) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
		bool dst_is_fp;
		s64 eff_off;

		/* Track spills to FP-derived callee stack */
		dst_is_fp = (insn->dst_reg == BPF_REG_FP ||
			     at_out[insn->dst_reg].arg == AT_FP);
		if (dst_is_fp && BPF_MODE(insn->code) == BPF_MEM) {
			eff_off = effective_fp_off(insn, at_out, insn->dst_reg);
			if (eff_off != OFF_IMPRECISE) {
				int slot = fp_byte_off_to_slot(eff_off);

				if (slot >= 0 && sz == 8) {
					/* Precise 8-byte spill: track src */
					at_stack_out[slot] = at_out[insn->src_reg];
				} else {
					/* Partial or misaligned: clear overlapping */
					clear_overlapping_stack_slots(at_stack_out,
								     eff_off, sz);
					if (at_out[insn->src_reg].arg >= 1)
						access->unknown_args |=
							BIT(at_out[insn->src_reg].arg);
				}
			} else {
				/* Imprecise offset: clear all slots */
				for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
					at_stack_out[r] = (struct arg_track){
						.off = 0, .arg = ARG_NONE };
				if (at_out[insn->src_reg].arg >= 1)
					access->unknown_args |=
						BIT(at_out[insn->src_reg].arg);
			}
		}

		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			/* Atomics to FP-derived dst: clear overlapping slots */
			dst_is_fp = (insn->dst_reg == BPF_REG_FP ||
				     at_out[insn->dst_reg].arg == AT_FP);
			if (dst_is_fp) {
				eff_off = effective_fp_off(insn, at_out,
							   insn->dst_reg);
				if (eff_off != OFF_IMPRECISE)
					clear_overlapping_stack_slots(at_stack_out,
								     eff_off, sz);
				else
					for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
						at_stack_out[r] = (struct arg_track){
							.off = 0, .arg = ARG_NONE };
			}

			if (insn->imm == BPF_CMPXCHG)
				at_out[BPF_REG_0] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
			else if (insn->imm == BPF_LOAD_ACQ)
				at_out[insn->dst_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
			else if (insn->imm & BPF_FETCH)
				at_out[insn->src_reg] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
		}
	} else if (class == BPF_ST && BPF_MODE(insn->code) == BPF_MEM) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
		bool dst_is_fp = (insn->dst_reg == BPF_REG_FP ||
				  at_out[insn->dst_reg].arg == AT_FP);

		/* BPF_ST to FP-derived dst: clear overlapping stack slots */
		if (dst_is_fp) {
			s64 eff_off = effective_fp_off(insn, at_out,
						       insn->dst_reg);
			if (eff_off != OFF_IMPRECISE)
				clear_overlapping_stack_slots(at_stack_out,
							     eff_off, sz);
			else
				for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
					at_stack_out[r] = (struct arg_track){
						.off = 0, .arg = ARG_NONE };
		}
	}
}

/*
 * Record all argument-derived memory accesses for a single instruction,
 * using the converged arg_track state at that instruction.
 */
static void record_insn_mem_accesses(struct bpf_insn *insn,
				     struct subprog_arg_access *access,
				     u64 (*arg_use)[NUM_AT_IDS][2],
				     int local_idx,
				     struct arg_track *at)
{
	u8 class = BPF_CLASS(insn->code);

	if (class == BPF_LDX) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));

		if (BPF_MODE(insn->code) == BPF_MEM ||
		    BPF_MODE(insn->code) == BPF_MEMSX)
			record_arg_mem_access(access, arg_use, local_idx,
					      &at[insn->src_reg],
					      insn->off, true, sz);
	} else if (class == BPF_STX) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));

		if (BPF_MODE(insn->code) == BPF_MEM)
			record_arg_mem_access(access, arg_use, local_idx,
					      &at[insn->dst_reg],
					      insn->off, false, sz);
		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			if (insn->imm == BPF_STORE_REL)
				record_arg_mem_access(access, arg_use, local_idx,
						      &at[insn->dst_reg],
						      insn->off, false, sz);
			else
				record_arg_mem_access(access, arg_use, local_idx,
						      &at[insn->dst_reg],
						      insn->off, true, sz);
		}
	} else if (class == BPF_ST && BPF_MODE(insn->code) == BPF_MEM) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));

		record_arg_mem_access(access, arg_use, local_idx,
				      &at[insn->dst_reg],
				      insn->off, false, sz);
	}
}

/*
 * Backward pass: compute per-instruction argument read liveness.
 * arg_live[i][arg] = union of arg_use[j][arg] for all j reachable from i.
 * No def-kills: conservative (reads through written slots stay live).
 *
 * For nested calls (subprog0 -> subprog1 -> subprog2), this works
 * transitively: the forward pass folds inner callee reads into arg_use
 * at each BPF-to-BPF call instruction, so arg_live for subprog1 already
 * includes reads that subprog2 makes through subprog1's arguments.
 * clean_verifier_state() only needs to consult the immediate child's
 * arg_live to get correct liveness for any call depth.
 */
static int compute_arg_live(struct bpf_verifier_env *env,
			    int subprog, int start, int len,
			    struct subprog_arg_access *access,
			    u64 (*arg_use)[NUM_AT_IDS][2])
{
	int po_start = env->subprog_info[subprog].postorder_start;
	int po_end = (subprog + 1 < env->subprog_cnt)
		     ? env->subprog_info[subprog + 1].postorder_start
		     : env->cfg.cur_postorder;
	bool changed = true;

	access->subprog_len = len;
	access->arg_live = kvzalloc_objs(*access->arg_live, len, GFP_KERNEL_ACCOUNT);
	if (!access->arg_live)
		return -ENOMEM;

	while (changed) {
		changed = false;
		for (int p = po_start; p < po_end; p++) {
			int insn_idx = env->cfg.insn_postorder[p];
			int li = insn_idx - start;
			struct bpf_iarray *succ;
			u64 new_live[NUM_AT_IDS][2] = {};
			int a;

			succ = bpf_insn_successors(env, insn_idx);
			for (int s = 0; s < succ->cnt; s++) {
				int target = succ->items[s];

				if (target < start || target >= start + len)
					continue;
				for (a = 0; a < NUM_AT_IDS; a++)
					spis_or(new_live[a],
						access->arg_live[target - start][a]);
			}
			for (a = 0; a < NUM_AT_IDS; a++)
				spis_or(new_live[a], arg_use[li][a]);

			for (a = 0; a < NUM_AT_IDS; a++) {
				if (!spis_equal(new_live[a],
						access->arg_live[li][a])) {
					spis_copy(access->arg_live[li][a],
						  new_live[a]);
					changed = true;
				}
			}
		}
	}
	return 0;
}

/* Per-subprog intermediate state kept alive across analysis phases */
struct subprog_at_info {
	struct arg_track (*at_in)[MAX_BPF_REG];
	u64 (*arg_use)[NUM_AT_IDS][2];
	int len;
};

/*
 * Phase 1: Compute arg tracking dataflow for a single subprog.
 * Runs forward fixed-point with arg_track_xfer(), then records
 * memory accesses in a single linear pass over converged state.
 * Stores at_in and arg_use in info for later phases.
 */
static int compute_subprog_arg_tracking(struct bpf_verifier_env *env,
					struct bpf_insn *insns,
					int subprog,
					struct subprog_arg_access *access,
					struct subprog_at_info *info)
{
	int start = env->subprog_info[subprog].start;
	int end = env->subprog_info[subprog + 1].start;
	int len = end - start;
	struct arg_track (*at_in)[MAX_BPF_REG] = NULL;
	struct arg_track at_out[MAX_BPF_REG];
	struct arg_track (*at_stack_in)[MAX_ARG_SPILL_SLOTS] = NULL;
	struct arg_track at_stack_out[MAX_ARG_SPILL_SLOTS];
	u64 (*arg_use)[NUM_AT_IDS][2] = NULL;
	bool changed;
	u32 mask;
	int i, r, err;

	for (i = 0; i < NUM_AT_IDS; i++) {
		spis_clear(access->read[i]);
		spis_clear(access->write[i]);
	}

	at_in = kvmalloc_array(len, sizeof(*at_in), GFP_KERNEL_ACCOUNT);
	if (!at_in) {
		err = -ENOMEM;
		goto err_free;
	}

	at_stack_in = kvmalloc_array(len, sizeof(*at_stack_in), GFP_KERNEL_ACCOUNT);
	if (!at_stack_in) {
		err = -ENOMEM;
		goto err_free;
	}

	arg_use = kvzalloc_objs(*arg_use, len, GFP_KERNEL_ACCOUNT);
	if (!arg_use) {
		err = -ENOMEM;
		goto err_free;
	}

	/* Initialize all registers to unvisited */
	for (i = 0; i < len; i++)
		for (r = 0; r < MAX_BPF_REG; r++)
			at_in[i][r] = (struct arg_track){ .off = 0, .arg = ARG_UNVISITED };

	/* Initialize all stack slots to unvisited */
	for (i = 0; i < len; i++)
		for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
			at_stack_in[i][r] = (struct arg_track){ .off = 0, .arg = ARG_UNVISITED };

	/* Entry: R1-R5 are arg-derived with offset 0, FP is identity 0 */
	for (r = 0; r < MAX_BPF_REG; r++)
		at_in[0][r] = (struct arg_track){ .off = 0, .arg = ARG_NONE };
	at_in[0][BPF_REG_FP] = (struct arg_track){ .off = 0, .arg = AT_FP };
	for (r = BPF_REG_1; r <= BPF_REG_5; r++)
		at_in[0][r] = (struct arg_track){ .off = 0, .arg = r - BPF_REG_1 + 1 };

	/* Entry: all stack slots are ARG_NONE (empty) */
	for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
		at_stack_in[0][r] = (struct arg_track){ .off = 0, .arg = ARG_NONE };

	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "subprog#%d: analyzing...\n", subprog);

	/* Forward fixed-point iteration (dataflow only) */
	changed = true;
	while (changed) {
		changed = false;
		for (i = 0; i < len; i++) {
			int idx = start + i;
			struct bpf_insn *insn = &insns[idx];
			struct bpf_iarray *succ;

			if (at_in[i][0].arg == ARG_UNVISITED &&
			    at_in[i][1].arg == ARG_UNVISITED)
				continue;

			memcpy(at_out, at_in[i], sizeof(at_out));
			memcpy(at_stack_out, at_stack_in[i], sizeof(at_stack_out));
			arg_track_xfer(env, insn, access, at_out, at_stack_out);

			/* Log transfer function changes */
			if (env->log.level & BPF_LOG_LEVEL2) {
				for (r = 0; r < MAX_BPF_REG; r++) {
					if (at_out[r].arg != at_in[i][r].arg ||
					    at_out[r].off != at_in[i][r].off) {
						verbose(env, "%3d: ", idx);
						verbose_insn(env, insn);
						bpf_vlog_reset(&env->log, env->log.end_pos - 1);
						verbose(env, "\tr%d: ", r);
						verbose_arg_track(env, &at_in[i][r]);
						verbose(env, " -> ");
						verbose_arg_track(env, &at_out[r]);
						verbose(env, "\n");
					}
				}
			}

			/* Propagate to successors within this subprogram */
			succ = bpf_insn_successors(env, idx);
			for (int s = 0; s < succ->cnt; s++) {
				int target = succ->items[s];
				int ti;

				/* Filter: stay within the subprogram's range */
				if (target < start || target >= end)
					continue;
				ti = target - start;

				for (r = 0; r < MAX_BPF_REG; r++) {
					struct arg_track old = at_in[ti][r];
					struct arg_track new_val = arg_track_join(access, old, at_out[r]);

					if (new_val.arg != old.arg || new_val.off != old.off) {
						if ((env->log.level & BPF_LOG_LEVEL2) && old.arg != ARG_UNVISITED) {
							verbose(env, "arg_track: JOIN insn %d -> %d r%d: ",
								idx, target, r);
							verbose_arg_track(env, &old);
							verbose(env, " + ");
							verbose_arg_track(env, &at_out[r]);
							verbose(env, " => ");
							verbose_arg_track(env, &new_val);
							verbose(env, "\n");
						}
						at_in[ti][r] = new_val;
						changed = true;
					}
				}

				/* Join callee stack slots */
				for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++) {
					struct arg_track old = at_stack_in[ti][r];
					struct arg_track new_val = arg_track_join(access, old,
										  at_stack_out[r]);

					if (new_val.arg != old.arg || new_val.off != old.off) {
						at_stack_in[ti][r] = new_val;
						changed = true;
					}
				}
			}
		}
	}

	/* Apply unknown_args to access masks */
	mask = access->unknown_args;
	while (mask) {
		int k = __ffs(mask);

		spis_set_all(access->read[k]);
		spis_set_all(access->write[k]);
		mask &= mask - 1;
	}

	kvfree(at_stack_in);

	/* Linear pass: record memory accesses using converged at_in */
	for (i = 0; i < len; i++) {
		struct bpf_insn *insn = &insns[start + i];

		if (at_in[i][0].arg == ARG_UNVISITED &&
		    at_in[i][1].arg == ARG_UNVISITED)
			continue;

		record_insn_mem_accesses(insn, access, arg_use, i, at_in[i]);
	}

	if (env->log.level & BPF_LOG_LEVEL2)
		print_subprog_arg_access(env, subprog, access);

	info->at_in = at_in;
	info->arg_use = arg_use;
	info->len = len;
	return 0;

err_free:
	kvfree(arg_use);
	kvfree(at_stack_in);
	kvfree(at_in);
	return err;
}

/*
 * Phase 2: Fold callee access masks into callers.
 * Iterates until no caller's access masks change.
 * Converges in at most MAX_CALL_FRAMES iterations since fold only ORs bits.
 */
static void fold_subprog_callee_accesses(struct bpf_verifier_env *env,
					 struct bpf_insn *insns,
					 struct subprog_at_info *info)
{
	bool changed;

	do {
		changed = false;
		for (int i = 1; i < env->subprog_cnt; i++) {
			int start = env->subprog_info[i].start;
			struct subprog_arg_access *access = &env->subprog_arg_access[i];
			int len = info[i].len;
			int j;

			for (j = 0; j < len; j++) {
				struct bpf_insn *insn = &insns[start + j];
				int callee, target;
				u64 old_read[NUM_AT_IDS][2], old_write[NUM_AT_IDS][2];
				int a;

				if (!bpf_pseudo_call(insn))
					continue;

				target = start + j + insn->imm + 1;
				callee = find_subprog(env, target);
				if (callee < 0)
					continue;

				/* Save current masks to detect changes */
				for (a = 0; a < NUM_AT_IDS; a++) {
					spis_copy(old_read[a], access->read[a]);
					spis_copy(old_write[a], access->write[a]);
				}

				fold_callee_arg_access(access, info[i].arg_use,
						       j,
						       &env->subprog_arg_access[callee],
						       info[i].at_in[j]);

				for (a = 0; a < NUM_AT_IDS; a++) {
					if (!spis_equal(old_read[a], access->read[a]) ||
					    !spis_equal(old_write[a], access->write[a])) {
						changed = true;
						break;
					}
				}
			}
		}
	} while (changed);
}

int compute_subprog_arg_access(struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi;
	struct subprog_at_info *info;
	int i, err;

	if (env->subprog_cnt <= 1)
		return 0;

	env->subprog_arg_access = kvcalloc(env->subprog_cnt,
					   sizeof(*env->subprog_arg_access),
					   GFP_KERNEL_ACCOUNT);
	if (!env->subprog_arg_access)
		return -ENOMEM;

	info = kvcalloc(env->subprog_cnt, sizeof(*info), GFP_KERNEL_ACCOUNT);
	if (!info)
		return -ENOMEM;

	/* Phase 1: compute arg tracking per subprog (independent) */
	for (i = 1; i < env->subprog_cnt; i++) {
		err = compute_subprog_arg_tracking(env, insns, i,
						   &env->subprog_arg_access[i],
						   &info[i]);
		if (err)
			goto err_free;
	}

	/* Phase 2: fold callee access into callers (iterate until convergence) */
	fold_subprog_callee_accesses(env, insns, info);

	/* Phase 3: compute backward arg liveness per subprog */
	for (i = 1; i < env->subprog_cnt; i++) {
		int start = env->subprog_info[i].start;
		struct subprog_arg_access *access = &env->subprog_arg_access[i];

		err = compute_arg_live(env, i, start, info[i].len,
				       access, info[i].arg_use);
		if (err)
			goto err_free;
	}

err_free:
	for (i = 1; i < env->subprog_cnt; i++) {
		kvfree(info[i].at_in);
		kvfree(info[i].arg_use);
	}
	kvfree(info);
	return err;
}

enum fp_off_state {
	FP_OFF_UNVISITED,	/* instruction not yet reached */
	FP_OFF_UNKNOWN,		/* register doesn't hold a known FP offset */
	FP_OFF_KNOWN,		/* FP-derived; spis is bitmask of possible slots */
};

/*
 * Convert arg-relative 4-byte slot bitmask to absolute stack slot bitmask.
 * Arg-relative slot K (access at arg + K*4) maps to absolute stack slot
 * (base_slot - K).
 */
static inline void arg_slots_to_spis(u64 mask[2], int base_slot,
				     const u64 arg_mask[2])
{
	int w;

	for (w = 0; w < 2; w++) {
		u64 bits = arg_mask[w];

		while (bits) {
			int k = w * 64 + __ffs(bits);
			int abs_slot = base_slot - k;

			if (abs_slot >= 0 && abs_slot < STACK_SLOTS)
				mask[abs_slot / 64] |= BIT_ULL(abs_slot % 64);
			bits &= bits - 1;
		}
	}
}

struct fp_off_info {
	enum fp_off_state state;
	u64 spis[2];	/* bitmask of possible 4-byte stack slots; all-zero means FP itself */
};

static void verbose_fp_off(struct bpf_verifier_env *env, struct fp_off_info *info)
{
	switch (info->state) {
	case FP_OFF_UNVISITED: verbose(env, "?");                            break;
	case FP_OFF_UNKNOWN:   verbose(env, "_");                            break;
	case FP_OFF_KNOWN:
		if (spis_is_zero(info->spis)) {
			verbose(env, "fp");
		} else if (spis_hweight(info->spis) == 1) {
			int slot = spis_ffs(info->spis);
			s64 off = -(s64)((u64)(slot + 1) * STACK_SLOT_SZ);

			verbose(env, "fp%+lld", off);
		} else {
			verbose(env, "fp(spis=%llx:%llx)", info->spis[1], info->spis[0]);
		}
		break;
	default:               verbose(env, "???");                          break;
	}
}


/* Apply access_bytes from helper/kfunc resolution to stack_use/stack_def.
 *   access_bytes > 0:      stack read  — mark touched slots as stack_use
 *   access_bytes < 0:      stack write — mark touched slots as stack_def
 *   access_bytes == S64_MIN: unknown   — conservative, mark [0..slot] as stack_use
 *   access_bytes == 0:      no access
 */
static void apply_stack_access_bytes(struct insn_live_regs *st,
				     s64 fp_off, u32 slot, s64 access_bytes)
{
	u32 slot_last;

	if (access_bytes == S64_MIN) {
		spis_or_range(st->stack_use, 0, slot);
	} else if (access_bytes > 0) {
		slot_last = (-fp_off - access_bytes) / STACK_SLOT_SZ;
		if (slot_last > slot)
			slot_last = slot;
		spis_or_range(st->stack_use, slot_last, slot);
	} else if (access_bytes < 0) {
		access_bytes = -access_bytes;
		slot_last = (-fp_off - access_bytes) / STACK_SLOT_SZ;
		if (slot_last > slot)
			slot_last = slot;
		spis_or_range(st->stack_def, slot_last, slot);
	}
}

/*
 * Compute frame IP for a call stack frame in verifier state.
 * Top frame uses st->insn_idx, outer frames use child callsite.
 */
static u32 frame_insn_idx_from_state(const struct bpf_verifier_state *st, u32 frame)
{
	return frame == st->curframe
	       ? st->insn_idx
	       : st->frame[frame + 1]->callsite;
}

/*
 * Compute refined caller stack liveness for frame @frame_idx
 * at the current pruning point. Uses per-instruction argument
 * liveness from analyze_subprog_arg_access() to strip caller
 * stack slots that the callee has already consumed.
 *
 * Only the immediate child frame (frame_idx + 1) is consulted.
 * This is sufficient for arbitrary call depth because
 * analyze_subprog_arg_access() recursively folds inner callee
 * reads into the outer callee's arg_use at each call instruction.
 * The backward pass then propagates those transitive reads, so
 * arg_live[i] for any subprog already reflects what all deeper
 * callees still need from that subprog's arguments.
 *
 * Outputs live_stack_before[callsite] if refinement is not
 * possible (no arg_live data, conservative fallback).
 */
void refined_caller_live_stack(struct bpf_verifier_env *env,
			       struct bpf_verifier_state *st,
			       int frame_idx,
			       u64 live_stack_out[2])
{
	u32 callsite = st->frame[frame_idx + 1]->callsite;
	u32 callee_ip = frame_insn_idx_from_state(st, frame_idx + 1);
	u32 callee_subprog = st->frame[frame_idx + 1]->subprogno;
	u64 *caller_live_after = env->insn_aux_data[callsite + 1].live_stack_before;
	struct subprog_arg_access *sa;
	u64 still_needed[2] = {};
	u32 callee_offset;
	int a;

	if (callee_subprog == 0 ||
	    callee_subprog >= env->subprog_cnt) {
		spis_copy(live_stack_out,
			       env->insn_aux_data[callsite].live_stack_before);
		return;
	}

	/*
	 * Refined liveness only applies to direct subprog calls where
	 * call_arg_slot[] maps caller stack slots to callee arguments.
	 * For helper/kfunc callbacks (e.g. bpf_loop), the callback
	 * accesses the caller's stack through a ctx pointer, not
	 * through direct stack pointer arguments, so call_arg_slot[]
	 * is not meaningful.  Fall back to the conservative
	 * live_stack_before at the callsite.
	 */
	if (!bpf_pseudo_call(&env->prog->insnsi[callsite])) {
		spis_copy(live_stack_out,
			       env->insn_aux_data[callsite].live_stack_before);
		return;
	}

	sa = &env->subprog_arg_access[callee_subprog];
	callee_offset = callee_ip - env->subprog_info[callee_subprog].start;

	/*
	 * When the child frame is mid-call, callee_ip is the call insn.
	 * arg_live there includes transitive reads by the grandchild
	 * chain, but those reads have already been initiated.  Advance
	 * to callee_offset + 1 (the insn after the call) to get what
	 * the child still needs from the caller AFTER its callee returns.
	 * This is sound: state pruning only requires matching slots read
	 * from the checkpoint forward, and the grandchild's pointer and
	 * data were established before the checkpoint.
	 */
	if (frame_idx + 1 < st->curframe &&
	    bpf_pseudo_call(&env->prog->insnsi[callee_ip]))
		callee_offset++;

	if (callee_offset >= sa->subprog_len) {
		spis_copy(live_stack_out,
			       env->insn_aux_data[callsite].live_stack_before);
		return;
	}

	/* Translate per-instruction argument liveness to caller slots */
	for (a = 1; a < NUM_AT_IDS; a++) {
		s16 base_slot = env->insn_aux_data[callsite].call_arg_slot[a];

		if (base_slot < 0)
			continue;
		arg_slots_to_spis(still_needed, base_slot,
				  sa->arg_live[callee_offset][a]);
	}

	spis_copy(live_stack_out, caller_live_after);
	spis_or(live_stack_out, still_needed);
}

/*
 * Per-instruction transfer function for FP-offset tracking.
 * Updates fp_out[] and fp_stack_out based on how the instruction
 * modifies register state relative to the frame pointer.
 */
static void fp_off_insn_xfer(struct bpf_insn *insn,
			     struct fp_off_info *fp_out,
			     u64 *fp_stack_out)
{
	u8 class = BPF_CLASS(insn->code);
	u8 code = BPF_OP(insn->code);

	if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_K) {
		if (code == BPF_MOV) {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		} else if ((code == BPF_ADD || code == BPF_SUB) &&
			   fp_out[insn->dst_reg].state == FP_OFF_KNOWN) {
			s64 delta = (code == BPF_ADD) ? insn->imm : -(s64)insn->imm;

			if (spis_is_zero(fp_out[insn->dst_reg].spis) && delta < 0) {
				/* FP itself + negative imm => precise slot */
				u32 slot = (-delta - 1) / STACK_SLOT_SZ;

				if (slot < STACK_SLOTS)
					spis_set_bit(fp_out[insn->dst_reg].spis, slot);
				else
					spis_set_all(fp_out[insn->dst_reg].spis);
			} else {
				/*
				 * Already at some slot or positive offset;
				 * can't track precisely, go conservative.
				 */
				spis_set_all(fp_out[insn->dst_reg].spis);
			}
		} else if (fp_out[insn->dst_reg].state == FP_OFF_KNOWN) {
			/* Other ALU op on FP-derived register: lose tracking */
			spis_set_all(fp_out[insn->dst_reg].spis);
		} else {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		}
	} else if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_X) {
		if (code == BPF_MOV) {
			if (insn->off == 0) {
				fp_out[insn->dst_reg] = fp_out[insn->src_reg];
			} else {
				/* addr_space_cast */
				fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
				spis_clear(fp_out[insn->dst_reg].spis);
			}
		} else if (fp_out[insn->dst_reg].state == FP_OFF_KNOWN) {
			/* Other ALU op on FP-derived register: lose tracking */
			spis_set_all(fp_out[insn->dst_reg].spis);
		} else {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		}
	} else if (class == BPF_JMP && code == BPF_CALL) {
		int r;

		for (r = BPF_REG_0; r <= BPF_REG_5; r++) {
			fp_out[r].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[r].spis);
		}
	} else if (class == BPF_ALU) {
		if (code == BPF_MOV) {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		} else if (fp_out[insn->dst_reg].state == FP_OFF_KNOWN) {
			/* Other ALU op on FP-derived register: lose tracking */
			spis_set_all(fp_out[insn->dst_reg].spis);
		} else {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		}
	} else if (class == BPF_LDX) {
		/*
		 * If loading from a stack slot that may hold an FP-derived
		 * value, propagate as KNOWN with all slots set.
		 */
		bool fp_reload = false;

		if (BPF_MODE(insn->code) == BPF_MEM &&
		    fp_out[insn->src_reg].state == FP_OFF_KNOWN && BPF_SIZE(insn->code) == BPF_DW) {
			u64 *src_spis = fp_out[insn->src_reg].spis;
			u64 load_spis[2];

			spis_set_all(load_spis);

			if (spis_is_zero(src_spis) && insn->off < 0) {
				/*
				 * .. = *(u64 *)(fp - const)
				 *   or
				 * rX = r10
				 * .. = *(u64 *)(rX - const)
				 */
				u32 slot = (-insn->off - 1) / STACK_SLOT_SZ;
				u32 slot2 = (-insn->off - BPF_REG_SIZE) / STACK_SLOT_SZ;

				spis_clear(load_spis);
				if (slot < STACK_SLOTS)
					spis_set_bit(load_spis, slot);
				if (slot2 < STACK_SLOTS)
					spis_set_bit(load_spis, slot2);
				if (spis_is_zero(load_spis))
					spis_set_all(load_spis);
			} else if (!spis_is_zero(src_spis) && insn->off == 0) {
				/*
				 * rX = r10
				 * rX += -const
				 * .. = *(u64 *)(rX)
				 */
				spis_copy(load_spis, src_spis);
			}
			if (spis_and_nonzero(load_spis, fp_stack_out))
				fp_reload = true;
		}
		if (fp_reload) {
			fp_out[insn->dst_reg].state = FP_OFF_KNOWN;
			spis_set_all(fp_out[insn->dst_reg].spis);
		} else {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		}
	} else if (class == BPF_LD && BPF_MODE(insn->code) == BPF_IMM) {
		fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
		spis_clear(fp_out[insn->dst_reg].spis);
	} else if (class == BPF_STX && BPF_MODE(insn->code) == BPF_ATOMIC) {
		if (insn->imm == BPF_CMPXCHG) {
			fp_out[BPF_REG_0].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[BPF_REG_0].spis);
		} else if (insn->imm == BPF_LOAD_ACQ) {
			fp_out[insn->dst_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->dst_reg].spis);
		} else if (insn->imm & BPF_FETCH) {
			fp_out[insn->src_reg].state = FP_OFF_UNKNOWN;
			spis_clear(fp_out[insn->src_reg].spis);
		}
	}

	/*
	 * Track FP-derived values spilled to the stack. When a register with
	 * FP_OFF_KNOWN is stored to a stack slot, mark that slot in
	 * fp_stack_out so that subsequent reloads produce FP_OFF_KNOWN with
	 * all slots set.
	 */
	if (class == BPF_STX && BPF_MODE(insn->code) == BPF_MEM && BPF_SIZE(insn->code) == BPF_DW &&
	    fp_out[insn->dst_reg].state == FP_OFF_KNOWN && fp_out[insn->src_reg].state == FP_OFF_KNOWN) {
		u64 *dst_spis = fp_out[insn->dst_reg].spis;
		u64 store_spis[2];

		spis_set_all(store_spis);

		if (spis_is_zero(dst_spis) && insn->off < 0 && !((-insn->off) % BPF_REG_SIZE)) {
			/*
			 * *(u64 *)(fp - const) = rY where rY is FP-derived
			 *   or
			 * rX = r10
			 * *(u64 *)(rX - const) = rY where rY is FP-derived
			 */
			u32 slot = (-insn->off - 1) / STACK_SLOT_SZ;
			u32 slot2 = (-insn->off - BPF_REG_SIZE) / STACK_SLOT_SZ;

			spis_clear(store_spis);
			if (slot < STACK_SLOTS)
				spis_set_bit(store_spis, slot);
			if (slot2 < STACK_SLOTS)
				spis_set_bit(store_spis, slot2);
			if (spis_is_zero(store_spis))
				spis_set_all(store_spis);
		} else if (!spis_is_zero(dst_spis) && insn->off == 0) {
			/*
			 * rX = r10
			 * rX += -const
			 * *(u64 *)(rX) = rY where rY is FP-derived
			 */
			spis_copy(store_spis, dst_spis);
		}
		spis_or(fp_stack_out, store_spis);
	}
}

/*
 * Apply subprogram argument access masks to caller's stack_use.
 * Maps callee's per-argument read/write bitmasks onto the caller's
 * stack slots starting at @spi.
 */
static void apply_callee_stack_access(struct insn_live_regs *st,
				      struct subprog_arg_access *sa,
				      int arg, u32 slot)
{
	u64 combined[2];

	if (spis_is_all(sa->read[arg]) || spis_is_all(sa->write[arg])) {
		/*
		 * Unknown access pattern: mark slots from 0 up to the
		 * argument's base slot as live. The callee cannot access
		 * above the argument's base, so avoid marking the entire
		 * 512B stack live.
		 */
		spis_or_range(st->stack_use, 0, slot);
		return;
	}

	/*
	 * Both read and write-only bits become stack_use.
	 * Write-only bits are "may write" not "must write",
	 * so they cannot be stack_def.
	 */
	spis_copy(combined, sa->read[arg]);
	spis_or(combined, sa->write[arg]);
	arg_slots_to_spis(st->stack_use, slot, combined);
}

/*
 * Check for stack access via FP-derived (or R10 directly) register.
 * LDX: stack read => stack_use.
 * STX/ST MEM: stack write => stack_def (if slot-aligned and fully covered).
 * Atomics: LOAD_ACQ => read, STORE_REL => write, others => read (conservative).
 */
static void set_indirect_stack_access(struct bpf_verifier_env *env,
				      struct bpf_insn *insn, int insn_idx,
				      struct insn_live_regs *st,
				      struct fp_off_info *fp_regs)
{
	u8 class = BPF_CLASS(insn->code);
	int ptr_reg = -1;
	bool is_write = false;
	const char *op_name = NULL;

	if (class == BPF_LDX && (BPF_MODE(insn->code) == BPF_MEM ||
				 BPF_MODE(insn->code) == BPF_MEMSX)) {
		ptr_reg = insn->src_reg;
		op_name = "LDX";
	} else if (class == BPF_STX && BPF_MODE(insn->code) == BPF_MEM) {
		ptr_reg = insn->dst_reg;
		is_write = true;
		op_name = "STX";
	} else if (class == BPF_ST && BPF_MODE(insn->code) == BPF_MEM) {
		ptr_reg = insn->dst_reg;
		is_write = true;
		op_name = "ST";
	} else if (class == BPF_STX && BPF_MODE(insn->code) == BPF_ATOMIC) {
		switch (insn->imm) {
		case BPF_LOAD_ACQ:
			ptr_reg = insn->src_reg;
			op_name = "LOAD_ACQ";
			break;
		case BPF_STORE_REL:
			ptr_reg = insn->dst_reg;
			is_write = true;
			op_name = "STORE_REL";
			break;
		default:
			/* Other atomics may write conditionally; treat as read */
			ptr_reg = insn->dst_reg;
			op_name = "ATOMIC";
			break;
		}
	}

	if (ptr_reg < 0)
		/* not a load and not a store */
		return;

	if (fp_regs[ptr_reg].state != FP_OFF_KNOWN)
		/* load/store through non-FP-derived register */
		return;

	if (spis_is_zero(fp_regs[ptr_reg].spis)) {
		/* Register is FP itself; compute precise slot */
		s64 stack_off = insn->off;
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));

		if (stack_off < 0 &&
		    (!is_write || (sz >= STACK_SLOT_SZ &&
				   !((-stack_off) % STACK_SLOT_SZ)))) {
			u32 slot_hi = (-stack_off - 1) / STACK_SLOT_SZ;
			u32 slot_lo = (-stack_off - sz) / STACK_SLOT_SZ;

			if (slot_hi < STACK_SLOTS) {
				if (is_write)
					spis_or_range(st->stack_def, slot_lo, slot_hi);
				else
					spis_or_range(st->stack_use, slot_lo, slot_hi);
				if (env->log.level & BPF_LOG_LEVEL2) {
					verbose(env, "fp_off: %s insn %d r%d ",
						op_name, insn_idx, ptr_reg);
					verbose_fp_off(env, &fp_regs[ptr_reg]);
					verbose(env, " +%d => fp%lld %s slots[%u..%u]\n",
						insn->off, stack_off,
						is_write ? "stack_def" : "stack_use",
						slot_lo, slot_hi);
				}
			}
		}
	} else {
		/* Register points to known slot(s); work at 4-byte granularity */
		u64 slot_mask[2];
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));

		spis_copy(slot_mask, fp_regs[ptr_reg].spis);

		if (insn->off != 0) {
			/*
			 * Shift slot bitmask by -insn->off / STACK_SLOT_SZ.
			 * Positive shift = deeper into stack (left shift).
			 * Negative shift = closer to FP (right shift).
			 */
			int shift = -insn->off / (int)STACK_SLOT_SZ;
			u64 shifted[2] = {};

			if (shift >= 0 && shift < STACK_SLOTS) {
				spis_shift_or(shifted, slot_mask, shift);
			} else if (shift < 0 && -shift < STACK_SLOTS) {
				spis_shift_right_or(shifted, slot_mask, -shift);
			} else {
				spis_set_all(shifted);
			}
			spis_copy(slot_mask, shifted);

			/* If not 4-byte aligned, expand ±1 slot for boundary */
			if (insn->off % (int)STACK_SLOT_SZ) {
				u64 expanded[2] = {};

				spis_shift_or(expanded, slot_mask, 1);
				spis_shift_right_or(expanded, slot_mask, 1);
				spis_or(slot_mask, expanded);
			}
		}

		/* DW access spans 2 slots; expand one slot closer to FP */
		if (sz > STACK_SLOT_SZ)
			spis_shift_right_or(slot_mask, slot_mask, 1);

		if (is_write)
			spis_or(st->stack_def, slot_mask);
		else
			spis_or(st->stack_use, slot_mask);
		if (env->log.level & BPF_LOG_LEVEL2) {
			verbose(env, "fp_off: %s insn %d r%d ",
				op_name, insn_idx, ptr_reg);
			verbose_fp_off(env, &fp_regs[ptr_reg]);
			verbose(env, " +%d => %s|=%llx:%llx\n",
				insn->off,
				is_write ? "stack_def" : "stack_use",
				slot_mask[1], slot_mask[0]);
		}
	}
}

/* Resolve stack access for a single FP-derived argument at a call site. */
static void resolve_arg_stack_access(struct bpf_verifier_env *env,
				     struct bpf_insn *insn, int insn_idx,
				     struct insn_live_regs *st,
				     struct fp_off_info *fp_regs, int r)
{
	int param = r - BPF_REG_1;	/* 0-based param index for helpers/kfuncs */
	int at_id = r - BPF_REG_1 + 1;	/* 1-based arg-track identity for call_arg_slot */
	u64 spis[2];

	spis[0] = fp_regs[r].spis[0];
	spis[1] = fp_regs[r].spis[1];

	while (!spis_is_zero(spis)) {
		u32 slot = spis_ffs(spis);
		s64 synth_off = -(s64)((u64)(slot + 1) * STACK_SLOT_SZ);

		spis[slot / 64] &= ~BIT_ULL(slot % 64);

		if (bpf_helper_call(insn)) {
			s64 bytes = bpf_helper_stack_access_bytes(env, insn, param, insn_idx);

			apply_stack_access_bytes(st, synth_off, slot, bytes);
		} else if (bpf_pseudo_call(insn)) {
			int target = insn_idx + insn->imm + 1;
			/* callee is valid, already checked in arg_track_insn_xfer */
			int callee = find_subprog(env, target);

			/*
			 * For single slot, record it for cross-subprog tracking.
			 * For multi-slot, set -1 (conservative).
			 */
			if (spis_hweight(fp_regs[r].spis) == 1)
				env->insn_aux_data[insn_idx].call_arg_slot[at_id] =
					spis_ffs(fp_regs[r].spis);

			apply_callee_stack_access(st,
						  &env->subprog_arg_access[callee],
						  at_id, slot);
		} else if (bpf_pseudo_kfunc_call(insn)) {
			s64 bytes = bpf_kfunc_stack_access_bytes(env, insn, param, insn_idx);

			apply_stack_access_bytes(st, synth_off, slot, bytes);
		} else {
			/* unknown call: conservative */
			spis_or_range(st->stack_use, 0, slot);
		}
	}
}

/*
 * Resolve stack access for a single call instruction by examining
 * FP-derived pointer arguments. Sets stack_use/stack_def based on
 * helper, kfunc, or subprog access patterns.
 */
static void set_call_stack_access(struct bpf_verifier_env *env,
				  struct bpf_insn *insn, int insn_idx,
				  struct insn_live_regs *st,
				  struct fp_off_info *fp_regs)
{
	struct call_summary cs;
	int r, num_params;

	num_params = 5;
	if (get_call_summary(env, insn, &cs))
		num_params = cs.num_params;

	if (env->log.level & BPF_LOG_LEVEL2) {
		verbose(env, "fp_off: CALL insn %d ", insn_idx);
		verbose_insn(env, insn);
		bpf_vlog_reset(&env->log, env->log.end_pos - 1);
		for (r = BPF_REG_1; r <= BPF_REG_5 && r < BPF_REG_1 + num_params; r++) {
			verbose(env, "  r%d: ", r);
			verbose_fp_off(env, &fp_regs[r]);
		}
		verbose(env, "\n");
	}

	if (bpf_pseudo_call(insn)) {
		for (int a = 0; a < NUM_AT_IDS; a++)
			env->insn_aux_data[insn_idx].call_arg_slot[a] = -1;
	}

	for (r = BPF_REG_1; r <= BPF_REG_5 && r < BPF_REG_1 + num_params; r++) {
		if (fp_regs[r].state != FP_OFF_KNOWN)
			continue;

		if (spis_is_zero(fp_regs[r].spis)) {
			/* Pointer is FP itself (e.g. bpf_loop ctx).
			 * A helper or its callback may access stack
			 * at negative offsets from this pointer.
			 * Mark all stack slots as used.
			 */
			if (env->log.level & BPF_LOG_LEVEL2)
				verbose(env, "insn %d reg %d spis == 0 (FP)\n",
					insn_idx, r);
			spis_set_all(st->stack_use);
			continue;
		}

		resolve_arg_stack_access(env, insn, insn_idx, st, fp_regs, r);
	}
}

/*
 * Use converged fp_in from the forward analysis to set stack_use/stack_def
 * at CALL instructions (helper, subprog, kfunc) and indirect memory accesses
 * (LDX/STX/ST via FP-derived registers).
 */
static void set_stack_access(struct bpf_verifier_env *env,
				struct bpf_insn *insns,
				struct insn_live_regs *state,
				struct fp_off_info (*fp_in)[MAX_BPF_REG],
				int insn_cnt)
{
	int i;

	for (i = 0; i < insn_cnt; i++) {
		struct bpf_insn *insn = &insns[i];

		set_indirect_stack_access(env, insn, i, &state[i], fp_in[i]);

		if (BPF_CLASS(insn->code) == BPF_JMP &&
		    BPF_OP(insn->code) == BPF_CALL)
			set_call_stack_access(env, insn, i, &state[i], fp_in[i]);
	}
}

/*
 * JOIN a single successor's fp_off state with the output of the current
 * instruction. Returns true if any state changed (requires another iteration).
 *
 * Lattice per register:
 *   UNVISITED  -- not yet reached, absorbs any incoming value
 *   UNKNOWN    -- not FP-derived on any path seen so far
 *   KNOWN(spis) -- FP-derived; spis is union of possible slot sets
 *
 * Transitions:
 *   UNVISITED + X       => X          (first visit)
 *   KNOWN     + KNOWN   => KNOWN(OR)  (widen slot set)
 *   KNOWN     + UNKNOWN => KNOWN      (some path is FP-derived)
 *   UNKNOWN   + KNOWN   => KNOWN      (promote)
 *   UNKNOWN   + UNKNOWN => UNKNOWN    (no change)
 */
static bool fp_off_join(struct bpf_verifier_env *env, int idx, int target,
			struct fp_off_info *fp_out, struct fp_off_info *fp_target,
			u64 fp_stack_out[2], u64 fp_stack_target[2])
{
	bool changed = false;
	int r;

	/* JOIN fp_stack: OR (may-contain-FP union) */
	if (spis_any_new(fp_stack_out, fp_stack_target)) {
		spis_or(fp_stack_target, fp_stack_out);
		changed = true;
	}

	for (r = 0; r < MAX_BPF_REG; r++) {
		struct fp_off_info *old = &fp_target[r];
		struct fp_off_info *new = &fp_out[r];

		if (old->state == FP_OFF_UNVISITED) {
			*old = *new;
			changed = true;
		} else if (old->state == FP_OFF_KNOWN && new->state == FP_OFF_KNOWN) {
			/* KNOWN + KNOWN: OR the slot bitmasks */
			if (spis_any_new(new->spis, old->spis)) {
				if (env->log.level & BPF_LOG_LEVEL2) {
					verbose(env, "fp_off: JOIN %d -> %d r%d: ",
						idx, target, r);
					verbose_fp_off(env, old);
					verbose(env, " + ");
					verbose_fp_off(env, new);
					verbose(env, " => ");
				}
				spis_or(old->spis, new->spis);
				if (env->log.level & BPF_LOG_LEVEL2) {
					verbose_fp_off(env, old);
					verbose(env, "\n");
				}
				changed = true;
			}
		} else if (old->state == FP_OFF_UNKNOWN && new->state == FP_OFF_KNOWN) {
			/* UNKNOWN + KNOWN: promote to KNOWN */
			if (env->log.level & BPF_LOG_LEVEL2) {
				verbose(env, "fp_off: JOIN %d -> %d r%d: ",
					idx, target, r);
				verbose_fp_off(env, old);
				verbose(env, " + ");
				verbose_fp_off(env, new);
				verbose(env, " => ");
			}
			*old = *new;
			if (env->log.level & BPF_LOG_LEVEL2) {
				verbose_fp_off(env, old);
				verbose(env, "\n");
			}
			changed = true;
		}
		/* KNOWN + UNKNOWN or UNKNOWN + UNKNOWN: no change */
	}
	return changed;
}

/*
 * Forward fixed-point analysis: track FP-derived offsets per register
 * and compute stack_use/stack_def for indirect stack accesses and
 * stack pointer arguments at call sites.
 */
int compute_stack_access(struct bpf_verifier_env *env,
			 struct bpf_insn *insns,
			 struct insn_live_regs *state,
			 int insn_cnt)
{
	struct fp_off_info (*fp_in)[MAX_BPF_REG];
	struct fp_off_info fp_out[MAX_BPF_REG];
	struct bpf_iarray *succ;
	u64 fp_stack_out[2];
	bool changed;
	u64 (*fp_stack)[2];
	int i, r;

	fp_in = kvzalloc_objs(*fp_in, insn_cnt, GFP_KERNEL_ACCOUNT);
	if (!fp_in)
		return -ENOMEM;

	/* Per-instruction bitmask: which slots may hold FP-derived values.
	 * Used to propagate FP-offset knowledge through stack spill/reload.
	 */
	fp_stack = kvzalloc_objs(*fp_stack, insn_cnt, GFP_KERNEL_ACCOUNT);
	if (!fp_stack) {
		kvfree(fp_in);
		return -ENOMEM;
	}

	/* kvzalloc zeroes memory, so all entries start as FP_OFF_UNVISITED (0) */

	/* Entry point: R10 has FP offset 0, rest unknown */
	for (r = 0; r < MAX_BPF_REG; r++) {
		fp_in[0][r].state = FP_OFF_UNKNOWN;
		spis_clear(fp_in[0][r].spis);
	}
	fp_in[0][BPF_REG_FP].state = FP_OFF_KNOWN;
	spis_clear(fp_in[0][BPF_REG_FP].spis);

	/* Subprogram entries: same initialization */
	for (i = 0; i < env->subprog_cnt; i++) {
		int start = env->subprog_info[i].start;

		for (r = 0; r < MAX_BPF_REG; r++) {
			fp_in[start][r].state = FP_OFF_UNKNOWN;
			spis_clear(fp_in[start][r].spis);
		}
		fp_in[start][BPF_REG_FP].state = FP_OFF_KNOWN;
		spis_clear(fp_in[start][BPF_REG_FP].spis);
	}

	/* Forward fixed-point: iterate in reverse postorder */
	changed = true;
	while (changed) {
		changed = false;
		for (i = env->cfg.cur_postorder - 1; i >= 0; i--) {
			int idx = env->cfg.insn_postorder[i];
			struct bpf_insn *insn = &insns[idx];

			/* Skip unvisited instructions */
			if (fp_in[idx][0].state == FP_OFF_UNVISITED)
				continue;

			/* Start with fp_in, apply transfer function */
			memcpy(fp_out, fp_in[idx], sizeof(fp_out));
			spis_copy(fp_stack_out, fp_stack[idx]);
			fp_off_insn_xfer(insn, fp_out, fp_stack_out);

			/* Log transfer function changes */
			if (env->log.level & BPF_LOG_LEVEL2) {
				for (r = 0; r < MAX_BPF_REG; r++) {
					if (fp_out[r].state != fp_in[idx][r].state ||
					    !spis_equal(fp_out[r].spis, fp_in[idx][r].spis)) {
						verbose(env, "%3d: ", idx);
						verbose_insn(env, insn);
						bpf_vlog_reset(&env->log, env->log.end_pos - 1);
						verbose(env, "\tr%d: ", r);
						verbose_fp_off(env, &fp_in[idx][r]);
						verbose(env, " -> ");
						verbose_fp_off(env, &fp_out[r]);
						verbose(env, "\n");
					}
				}
			}

			/* Propagate to successors with JOIN */
			succ = bpf_insn_successors(env, idx);
			for (int s = 0; s < succ->cnt; s++) {
				int target = succ->items[s];

				changed |= fp_off_join(env, idx, target,
						       fp_out, fp_in[target],
						       fp_stack_out, fp_stack[target]);
			}
		}
	}

	kvfree(fp_stack);

	set_stack_access(env, insns, state, fp_in, insn_cnt);

	kvfree(fp_in);
	return 0;
}
