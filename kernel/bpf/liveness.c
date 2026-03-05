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
 * Per-register tracking state for compute_subprog_args().
 * Tracks which frame's FP a value is derived from
 * and the byte offset from that frame's FP.
 *
 * The .frame field forms a lattice with three levels of precision:
 *
 *   precise {frame=N, off=V}      -- known absolute frame index and byte offset
 *        |
 *   offset-imprecise {frame=N, off=OFF_IMPRECISE}
 *        |                        -- known frame identity, unknown offset
 *   fully-imprecise {frame=ARG_IMPRECISE, mask=bitmask}
 *                                 -- unknown frame identity; .mask is a
 *                                    bitmask of which frame indices might be
 *                                    involved
 *
 * At CFG merge points, arg_track_join() moves down the lattice:
 *   - same frame + same offset  -> precise
 *   - same frame + different offset -> offset-imprecise
 *   - different frames          -> fully-imprecise (bitmask OR)
 *
 * At memory access sites (LDX/STX/ST), offset-imprecise marks only
 * the known frame's access mask as U64_MAX, while fully-imprecise
 * iterates bits in the bitmask and routes each frame to its target.
 */
#define MAX_ARG_OFFSETS 4

struct arg_track {
	union {
		s16 off[MAX_ARG_OFFSETS]; /* byte offsets; off_cnt says how many */
		u16 mask;	/* arg bitmask when arg == ARG_IMPRECISE */
	};
	s8 frame;	/* absolute frame index, or enum arg_track_state */
	s8 off_cnt;	/* 0 = offset-imprecise, 1-4 = # of precise offsets */
};

enum arg_track_state {
	ARG_NONE	= -1,	/* not derived from any argument */
	ARG_UNVISITED	= -2,	/* not yet reached by dataflow */
	ARG_IMPRECISE	= -3,	/* lost identity; .mask is arg bitmask */
};

#define OFF_IMPRECISE	S16_MIN	/* arg identity known but offset unknown */

/* Track callee stack slots fp-8 through fp-64 (8 slots of 8 bytes each) */
#define MAX_ARG_SPILL_SLOTS 64


static bool arg_is_visited(const struct arg_track *at)
{
	return at->frame != ARG_UNVISITED;
}

static bool arg_is_fp(const struct arg_track *at)
{
	return at->frame >= 0 || at->frame == ARG_IMPRECISE;
}

/*
 * Clear all tracked callee stack slots overlapping the byte range
 * [off, off+sz-1] where off is a negative FP-relative offset.
 */
static void clear_overlapping_stack_slots(struct arg_track *at_stack, s16 off, u32 sz)
{
	struct arg_track none = { .frame = ARG_NONE };

	if (off == OFF_IMPRECISE) {
		for (int i = 0; i < MAX_ARG_SPILL_SLOTS; i++)
			at_stack[i] = none;
		return;
	}
	for (int i = 0; i < MAX_ARG_SPILL_SLOTS; i++) {
		int slot_start = -((i + 1) * 8);
		int slot_end = slot_start + 8;

		if (slot_start < off + sz && slot_end > off)
			at_stack[i] = none;
	}
}

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

static void verbose_arg_track(struct bpf_verifier_env *env, struct arg_track *at)
{
	int i;

	switch (at->frame) {
	case ARG_NONE:      verbose(env, "_");                          break;
	case ARG_UNVISITED: verbose(env, "?");                          break;
	case ARG_IMPRECISE: verbose(env, "IMP%x", at->mask);            break;
	default:
		/* frame >= 0: absolute frame index */
		if (at->off_cnt == 0) {
			verbose(env, "fp%d ?", at->frame);
		} else {
			for (i = 0; i < at->off_cnt; i++) {
				if (i)
					verbose(env, "|");
				verbose(env, "fp%d%+d", at->frame, at->off[i]);
			}
		}
		break;
	}
}

static bool arg_track_eq(const struct arg_track *a, const struct arg_track *b)
{
	int i;

	if (a->frame != b->frame)
		return false;
	if (a->frame == ARG_IMPRECISE)
		return a->mask == b->mask;
	if (a->frame < 0)
		return true;
	if (a->off_cnt != b->off_cnt)
		return false;
	for (i = 0; i < a->off_cnt; i++)
		if (a->off[i] != b->off[i])
			return false;
	return true;
}

static struct arg_track arg_single(s8 arg, s16 off)
{
	struct arg_track at = {};

	at.frame = arg;
	at.off[0] = off;
	at.off_cnt = 1;
	return at;
}

/*
 * Merge two sorted offset arrays, deduplicate.
 * Returns off_cnt=0 if the result exceeds MAX_ARG_OFFSETS.
 * Both args must have the same frame and off_cnt > 0.
 */
static struct arg_track arg_merge_offsets(struct arg_track a, struct arg_track b)
{
	struct arg_track result = { .frame = a.frame };
	struct arg_track imp = { .frame = a.frame };
	int i = 0, j = 0, k = 0;

	while (i < a.off_cnt && j < b.off_cnt) {
		s16 v;

		if (a.off[i] <= b.off[j]) {
			v = a.off[i++];
			if (v == b.off[j])
				j++;
		} else {
			v = b.off[j++];
		}
		if (k > 0 && result.off[k - 1] == v)
			continue;
		if (k >= MAX_ARG_OFFSETS)
			return imp;
		result.off[k++] = v;
	}
	while (i < a.off_cnt) {
		if (k >= MAX_ARG_OFFSETS)
			return imp;
		result.off[k++] = a.off[i++];
	}
	while (j < b.off_cnt) {
		if (k >= MAX_ARG_OFFSETS)
			return imp;
		result.off[k++] = b.off[j++];
	}
	result.off_cnt = k;
	return result;
}
/*
 * Collapse to ARG_IMPRECISE with a bitmask of which arg
 * identities are involved.  This lets memory access sites
 * mark only the relevant args' access masks and only set
 * stack_use when AT_CURRENT (bit 0) is in the bitmask.
 */
static struct arg_track arg_join_imprecise(struct arg_track a, struct arg_track b)
{
	u32 m = 0;

	if (a.frame >= 0)
		m |= BIT(a.frame);
	else if (a.frame == ARG_IMPRECISE)
		m |= a.mask;

	if (b.frame >= 0)
		m |= BIT(b.frame);
	else if (b.frame == ARG_IMPRECISE)
		m |= b.mask;

	return (struct arg_track){ .mask = m, .frame = ARG_IMPRECISE };
}

/* Join two arg_track values at merge points */
static struct arg_track __arg_track_join(struct arg_track a, struct arg_track b)
{
	if (!arg_is_visited(&b))
		return a;
	if (!arg_is_visited(&a))
		return b;
	if (a.frame == b.frame && a.frame >= 0) {
		/* Both offset-imprecise: stay imprecise */
		if (a.off_cnt == 0 || b.off_cnt == 0)
			return (struct arg_track){ .frame = a.frame };
		/* Merge offset sets; falls back to off_cnt=0 if >4 */
		return arg_merge_offsets(a, b);
	}

	/*
	 * args are different, but one of them is known
	 * arg + none -> arg
	 * none + arg -> arg
	 *
	 * none + none -> none
	 */
	if (a.frame == ARG_NONE && b.frame == ARG_NONE)
		return a;
	if (a.frame >= 0 && b.frame == ARG_NONE) {
		/*
		 * When joining single fp-N add fake fp+0 to
		 * keep stack_use and prevent stack_def
		 */
		if (a.off_cnt == 1)
			return arg_merge_offsets(a, arg_single(a.frame, 0));
		return a;
	}
	if (b.frame >= 0 && a.frame == ARG_NONE) {
		if (b.off_cnt == 1)
			return arg_merge_offsets(b, arg_single(b.frame, 0));
		return b;
	}

	return arg_join_imprecise(a, b);
}

static bool arg_track_join(struct bpf_verifier_env *env, int idx, int target, int r,
			   struct arg_track *in, struct arg_track out)
{
	struct arg_track old = *in;
	struct arg_track new_val = __arg_track_join(old, out);

	if (arg_track_eq(&new_val, &old))
		return false;

	*in = new_val;
	if (!(env->log.level & BPF_LOG_LEVEL2) || !arg_is_visited(&old))
		return true;

	verbose(env, "arg JOIN insn %d -> %d ", idx, target);
	if (r >= 0)
		verbose(env, "r%d: ", r);
	else
		verbose(env, "fp%+d: ", r * 8);
	verbose_arg_track(env, &old);
	verbose(env, " + ");
	verbose_arg_track(env, &out);
	verbose(env, " => ");
	verbose_arg_track(env, &new_val);
	verbose(env, "\n");
	return true;
}

/*
 * Compute the result when an ALU op destroys offset precision.
 * If a single arg is identifiable, preserve it with OFF_IMPRECISE.
 * If two different args are involved or one is already ARG_IMPRECISE,
 * the result is fully ARG_IMPRECISE.
 */
static void arg_track_alu64(struct arg_track *dst, const struct arg_track *src)
{
	WARN_ON_ONCE(!arg_is_visited(dst));
	WARN_ON_ONCE(!arg_is_visited(src));

	if (dst->frame >= 0 && (src->frame == ARG_NONE || src->frame == dst->frame)) {
		/*
		 * rX += rY where rY is not arg derived
		 * rX += rX
		 */
		dst->off_cnt = 0;
		return;
	}
	if (src->frame >= 0 && dst->frame == ARG_NONE) {
		/*
		 * rX += rY where rX is not arg derived
		 * rY identity leaks into rX
		 */
		dst->off_cnt = 0;
		dst->frame = src->frame;
		return;
	}

	if (dst->frame == ARG_NONE && src->frame == ARG_NONE)
		return;

	*dst = arg_join_imprecise(*dst, *src);
}

static s16 arg_add(s16 off, s64 delta)
{
	s64 res;

	if (off == OFF_IMPRECISE)
		return OFF_IMPRECISE;
	res = (s64)off + delta;
	if (res < S16_MIN + 1 || res > S16_MAX)
		return OFF_IMPRECISE;
	return res;
}

static void arg_padd(struct arg_track *at, s64 delta)
{
	int i;

	if (at->off_cnt == 0)
		return;
	for (i = 0; i < at->off_cnt; i++) {
		s16 new_off = arg_add(at->off[i], delta);

		if (new_off == OFF_IMPRECISE) {
			at->off_cnt = 0;
			return;
		}
		at->off[i] = new_off;
	}
}

/*
 * Convert a byte offset from FP to a callee stack slot index (0-7).
 * Returns -1 if out of range or not 8-byte aligned.
 * Slot 0 = fp-8, slot 1 = fp-16, ..., slot 7 = fp-64.
 */
static int fp_off_to_slot(s16 off)
{
	if (off == OFF_IMPRECISE)
		return -1;
	if (off >= 0 || off < -(int)(MAX_ARG_SPILL_SLOTS * 8))
		return -1;
	if (off % 8)
		return -1;
	return (-off) / 8 - 1;
}

/*
 * Join stack slot states across all possible FP offsets tracked in @reg.
 * When a register holds multiple possible FP-derived offsets (off_cnt > 1),
 * this merges the arg_track from each corresponding stack slot rather than
 * falling back to imprecise.
 */
static struct arg_track fill_from_stack(struct bpf_insn *insn,
					struct arg_track *at_out, int reg,
					struct arg_track *at_stack_out,
					int depth)
{
	int frame = at_out[reg].frame;
	struct arg_track imp = {
		.mask = frame >= 0 ? BIT(frame) : (1u << (depth + 1)) - 1,
		.frame = ARG_IMPRECISE
	};
	struct arg_track result = { .frame = ARG_NONE };
	int cnt, i;

	if (reg == BPF_REG_FP) {
		int slot = fp_off_to_slot(insn->off);

		return slot >= 0 ? at_stack_out[slot] : imp;
	}
	cnt = at_out[reg].off_cnt;
	if (cnt == 0)
		return imp;

	for (i = 0; i < cnt; i++) {
		s16 fp_off = arg_add(at_out[reg].off[i], insn->off);
		int slot = fp_off_to_slot(fp_off);

		if (slot < 0)
			return imp;
		result = __arg_track_join(result, at_stack_out[slot]);
	}
	return result;
}

/*
 * Spill @val to all possible stack slots indicated by the FP offsets in @reg.
 * For an 8-byte store, each candidate slot gets @val; for sub-8-byte stores
 * the slot is cleared to ARG_NONE.
 */
static void spill_to_stack(struct bpf_insn *insn, struct arg_track *at_out,
			   int reg, struct arg_track *at_stack_out,
			   struct arg_track *val, u32 sz)
{
	struct arg_track none = { .frame = ARG_NONE };
	int cnt, i;

	if (reg == BPF_REG_FP) {
		int slot = fp_off_to_slot(insn->off);

		if (slot >= 0)
			at_stack_out[slot] = sz == 8 ? *val : none;
		else
			clear_overlapping_stack_slots(at_stack_out, insn->off, sz);
		return;
	}
	cnt = at_out[reg].off_cnt;
	if (cnt == 0) {
		clear_overlapping_stack_slots(at_stack_out, OFF_IMPRECISE, sz);
		return;
	}
	for (i = 0; i < cnt; i++) {
		s16 fp_off = arg_add(at_out[reg].off[i], insn->off);
		int slot = fp_off_to_slot(fp_off);

		if (slot >= 0)
			at_stack_out[slot] = sz == 8 ? *val : none;
		else
			clear_overlapping_stack_slots(at_stack_out, fp_off, sz);
	}
}

/*
 * Clear stack slots overlapping all possible FP offsets in @reg.
 */
static void clear_stack_for_all_offs(struct bpf_insn *insn,
				     struct arg_track *at_out, int reg,
				     struct arg_track *at_stack_out, u32 sz)
{
	int cnt, i;

	if (reg == BPF_REG_FP) {
		clear_overlapping_stack_slots(at_stack_out, insn->off, sz);
		return;
	}
	cnt = at_out[reg].off_cnt;
	if (cnt == 0) {
		clear_overlapping_stack_slots(at_stack_out, OFF_IMPRECISE, sz);
		return;
	}
	for (i = 0; i < cnt; i++) {
		s16 fp_off = arg_add(at_out[reg].off[i], insn->off);

		clear_overlapping_stack_slots(at_stack_out, fp_off, sz);
	}
}

static void arg_track_log(struct bpf_verifier_env *env, struct bpf_insn *insn, int idx,
			  struct arg_track *at_in, struct arg_track *at_stack_in,
			  struct arg_track *at_out, struct arg_track *at_stack_out)
{
	bool printed = false;
	int i;

	if (!(env->log.level & BPF_LOG_LEVEL2))
		return;
	for (i = 0; i < MAX_BPF_REG; i++) {
		if (arg_track_eq(&at_out[i], &at_in[i]))
			continue;
		if (!printed) {
			verbose(env, "%3d: ", idx);
			bpf_verbose_insn(env, insn);
			bpf_vlog_reset(&env->log, env->log.end_pos - 1);
			printed = true;
		}
		verbose(env, "\tr%d: ", i); verbose_arg_track(env, &at_in[i]);
		verbose(env, " -> "); verbose_arg_track(env, &at_out[i]);
	}
	for (i = 0; i < MAX_ARG_SPILL_SLOTS; i++) {
		if (arg_track_eq(&at_stack_out[i], &at_stack_in[i]))
			continue;
		if (!printed) {
			verbose(env, "%3d: ", idx);
			bpf_verbose_insn(env, insn);
			bpf_vlog_reset(&env->log, env->log.end_pos - 1);
			printed = true;
		}
		verbose(env, "\tfp%+d: ", -(i + 1) * 8); verbose_arg_track(env, &at_stack_in[i]);
		verbose(env, " -> "); verbose_arg_track(env, &at_stack_out[i]);
	}
	if (printed)
		verbose(env, "\n");
}

/*
 * Pure dataflow transfer function for arg_track state.
 * Updates at_out[] based on how the instruction modifies registers.
 * Tracks spill/fill, but not other memory accesses.
 */
static void arg_track_xfer(struct bpf_verifier_env *env, struct bpf_insn *insn,
			   int insn_idx,
			   struct arg_track *at_out, struct arg_track *at_stack_out,
			   int depth, int *callsite_chain)
{
	u8 class = BPF_CLASS(insn->code);
	u8 code = BPF_OP(insn->code);
	struct arg_track *dst = &at_out[insn->dst_reg];
	struct arg_track *src = &at_out[insn->src_reg];
	struct arg_track none = { .frame = ARG_NONE };
	int r;

	if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_K) {
		if (code == BPF_MOV) {
			*dst = none;
		} else if (dst->frame >= 0) {
			if (code == BPF_ADD)
				arg_padd(dst, insn->imm);
			else if (code == BPF_SUB)
				arg_padd(dst, -(s64)insn->imm);
			else
				/* Any other 64-bit alu on the pointer makes it imprecise */
				dst->off_cnt = 0;
		} /* else if dst->frame is imprecise it stays so */
	} else if (class == BPF_ALU64 && BPF_SRC(insn->code) == BPF_X) {
		if (code == BPF_MOV) {
			if (insn->off == 0) {
				*dst = *src;
			} else {
				/* addr_space_cast destroys a pointer */
				*dst = none;
			}
		} else {
			arg_track_alu64(dst, src);
		}
	} else if (class == BPF_ALU) {
		/*
		 * 32-bit alu destroys the pointer.
		 * If src was a pointer it cannot leak into dst
		 */
		*dst = none;
	} else if (class == BPF_JMP && code == BPF_CALL) {
		/*
		 * at_stack_out[slot] is not cleared by the helper and subprog calls.
		 * The fill_from_stack() may return the stale spill — which is an FP-derived arg_track
		 * (the value that was originally spilled there). The loaded register then carries
		 * a phantom FP-derived identity that doesn't correspond to what's actually in the slot.
		 * This phantom FP pointer propagates forward, and wherever it's subsequently used
		 * (as a helper argument, another store, etc.), it sets stack liveness bits.
		 * Those bits correspond to stack accesses that don't actually happen.
		 * So the effect is over-reporting stack liveness — marking slots as live that aren't
		 * actually accessed. The verifier preserves more state than necessary across calls,
		 * which is conservative.
		 *
		 * helpers can scratch stack slots, but they won't make a valid pointer out of it.
		 * subprogs are allowed to write into parent slots, but they cannot write
		 * _any_ FP-derived pointer into it (either their own or parent's FP).
		 */
		for (r = BPF_REG_0; r <= BPF_REG_5; r++)
			at_out[r] = none;
	} else if (class == BPF_LDX) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
		bool src_is_local_fp = insn->src_reg == BPF_REG_FP || src->frame == depth ||
				       (src->frame == ARG_IMPRECISE && (src->mask & BIT(depth)));

		/*
		 * Reload from callee stack: if src is current-frame FP-derived
		 * and the load is an 8-byte BPF_MEM, try to restore the spill
		 * identity.  For imprecise sources fill_from_stack() returns
		 * ARG_IMPRECISE (off_cnt == 0).
		 */
		if (src_is_local_fp && BPF_MODE(insn->code) == BPF_MEM && sz == 8) {
			*dst = fill_from_stack(insn, at_out, insn->src_reg, at_stack_out, depth);
		} else if (src->frame >= 0 && src->frame < depth &&
			   BPF_MODE(insn->code) == BPF_MEM && sz == 8) {
			struct arg_track *parent_stack =
				env->callsite_at_stack[callsite_chain[src->frame]];

			*dst = fill_from_stack(insn, at_out, insn->src_reg,
					       parent_stack, src->frame);
		} else if (src->frame == ARG_IMPRECISE &&
			   !(src->mask & BIT(depth)) && src->mask &&
			   BPF_MODE(insn->code) == BPF_MEM && sz == 8) {
			/*
			 * Imprecise src with only parent-frame bits:
			 * conservative fallback.
			 */
			*dst = *src;
		} else {
			*dst = none;
		}
	} else if (class == BPF_LD && BPF_MODE(insn->code) == BPF_IMM) {
		*dst = none;
	} else if (class == BPF_STX) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
		bool dst_is_local_fp;

		/* Track spills to current-frame FP-derived callee stack */
		dst_is_local_fp = insn->dst_reg == BPF_REG_FP || dst->frame == depth;
		if (dst_is_local_fp && BPF_MODE(insn->code) == BPF_MEM)
			spill_to_stack(insn, at_out, insn->dst_reg,
				       at_stack_out, src, sz);

		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			if (dst_is_local_fp)
				clear_stack_for_all_offs(insn, at_out, insn->dst_reg,
							 at_stack_out, sz);

			if (insn->imm == BPF_CMPXCHG)
				at_out[BPF_REG_0] = none;
			else if (insn->imm == BPF_LOAD_ACQ)
				*dst = none;
			else if (insn->imm & BPF_FETCH)
				*src = none;
		}
	} else if (class == BPF_ST && BPF_MODE(insn->code) == BPF_MEM) {
		u32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
		bool dst_is_local_fp = insn->dst_reg == BPF_REG_FP || dst->frame == depth;

		/* BPF_ST to FP-derived dst: clear overlapping stack slots */
		if (dst_is_local_fp)
			clear_stack_for_all_offs(insn, at_out, insn->dst_reg,
						 at_stack_out, sz);
	}
}

/*
 * Record access_bytes from helper/kfunc or load/store insn into stack_use/stack_def.
 *   access_bytes > 0:      stack read  — mark touched slots as stack_use
 *   access_bytes < 0:      stack write — mark touched slots as stack_def
 *   access_bytes == S64_MIN: unknown   — conservative, mark [0..slot] as stack_use
 *   access_bytes == 0:      no access
 */
static void record_stack_access_off(u64 use[2], u64 def[2], s64 fp_off, s64 access_bytes)
{
	s32 slot_hi, slot_lo;

	if (fp_off >= 0)
		/*
		 * out of bounds stack access doesn't contribute
		 * into actual stack liveness. It will be rejected
		 * by the main verifier pass later.
		 */
		return;
	if (access_bytes == S64_MIN) {
		/* helper/kfunc read unknown amount of bytes from fp_off until fp+0 */
		spis_or_range(use, 0, (-fp_off - 1) / STACK_SLOT_SZ);
		return;
	}
	if (access_bytes > 0) {
		/* Mark any touched slot as use */
		slot_hi = (-fp_off - 1) / STACK_SLOT_SZ;
		slot_lo = max_t(s32, (-fp_off - access_bytes) / STACK_SLOT_SZ, 0);
		spis_or_range(use, slot_lo, slot_hi);
	} else if (access_bytes < 0) {
		/* Mark only fully covered slots as def */
		access_bytes = -access_bytes;
		slot_hi = (-fp_off) / STACK_SLOT_SZ - 1;
		slot_lo = max_t(s32, (-fp_off - access_bytes + STACK_SLOT_SZ - 1) / STACK_SLOT_SZ, 0);
		if (slot_lo <= slot_hi)
			spis_or_range(def, slot_lo, slot_hi);
	}
}

/*
 * 'arg' is FP-derived argument to helper/kfunc or load/store that
 * reads (positive) or writes (negative) 'access_bytes' into 'use' or 'def'.
 */
static void record_stack_access(u64 use[2], u64 def[2], const struct arg_track *arg,
				s64 access_bytes)
{
	int i;

	if (access_bytes == 0)
		return;
	if (arg->off_cnt == 0) {
		if (access_bytes > 0)
			spis_set_all(use);
		return;
	}
	if (access_bytes != S64_MIN && access_bytes < 0 && arg->off_cnt != 1)
		/* multi-offset write cannot set stack_def */
		return;

	for (i = 0; i < arg->off_cnt; i++)
		record_stack_access_off(use, def, arg->off[i], access_bytes);
}

/*
 * When a pointer is ARG_IMPRECISE, conservatively mark every frame in
 * the bitmask as fully used.
 */
static void record_imprecise(u32 mask, u64 stack_use[2],
			     u64 (*nonlocal_use)[2], int depth)
{
	int f;

	for (f = 0; mask; f++, mask >>= 1) {
		if (!(mask & 1))
			continue;
		if (f == depth)
			spis_set_all(stack_use);
		else if (f < depth)
			spis_set_all(nonlocal_use[depth - 1 - f]);
	}
}

/*
 * Record load/store access for a given 'at' state of 'insn'.
 * Route to local stack stack_use/stack_def or
 * ancestor frame nonlocal_use/nonlocal_def which are caller-relative:
 *   [0] = immediate caller
 *   [1] = caller's caller
 */
static void record_load_store_access(struct bpf_insn *insn, struct arg_track *at,
				     struct insn_live_regs *st,
				     u64 (*nonlocal_use)[2], u64 (*nonlocal_def)[2], int depth)
{
	s32 sz = bpf_size_to_bytes(BPF_SIZE(insn->code));
	u8 class = BPF_CLASS(insn->code);
	struct arg_track resolved, *ptr;
	int oi;

	switch (class) {
	case BPF_LDX:
		ptr = &at[insn->src_reg];
		break;
	case BPF_STX:
		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			if (insn->imm == BPF_STORE_REL)
				sz = -sz;
			if (insn->imm == BPF_LOAD_ACQ)
				ptr = &at[insn->src_reg];
			else
				ptr = &at[insn->dst_reg];
		} else {
			ptr = &at[insn->dst_reg];
			sz = -sz;
		}
		break;
	case BPF_ST:
		ptr = &at[insn->dst_reg];
		sz = -sz;
		break;
	default:
		return;
	}

	/* Resolve offsets: fold insn->off into arg_track */
	if (ptr->off_cnt > 0) {
		resolved.off_cnt = ptr->off_cnt;
		resolved.frame = ptr->frame;
		for (oi = 0; oi < ptr->off_cnt; oi++) {
			resolved.off[oi] = arg_add(ptr->off[oi], insn->off);
			if (resolved.off[oi] == OFF_IMPRECISE) {
				resolved.off_cnt = 0;
				break;
			}
		}
		ptr = &resolved;
	}

	if (ptr->frame == depth) {
		record_stack_access(st->stack_use, st->stack_def, ptr, sz);
	} else if (ptr->frame >= 0 && ptr->frame < depth) {
		int rel = depth - 1 - ptr->frame;

		record_stack_access(nonlocal_use[rel], nonlocal_def[rel], ptr, sz);
	} else if (ptr->frame == ARG_IMPRECISE) {
		record_imprecise(ptr->mask, st->stack_use, nonlocal_use, depth);
	}
	/* ARG_NONE: not derived from any frame pointer, skip */
}

/* Record stack access for a given 'at' state of helper/kfunc 'insn' */
static void record_call_access(struct bpf_verifier_env *env, struct arg_track *at,
			       struct bpf_insn *insn, int insn_idx, struct insn_live_regs *st,
			       u64 (*nonlocal_use)[2], u64 (*nonlocal_def)[2], int depth)
{
	struct bpf_call_summary cs;
	int r, num_params = 5;

	if (bpf_pseudo_call(insn))
		return;

	if (bpf_get_call_summary(env, insn, &cs))
		num_params = cs.num_params;

	for (r = BPF_REG_1; r < BPF_REG_1 + num_params; r++) {
		int frame = at[r].frame;
		s64 bytes;

		if (!arg_is_fp(&at[r]))
			continue;

		if (bpf_helper_call(insn)) {
			bytes = bpf_helper_stack_access_bytes(env, insn, r - 1, insn_idx);
		} else if (bpf_pseudo_kfunc_call(insn)) {
			bytes = bpf_kfunc_stack_access_bytes(env, insn, r - 1, insn_idx);
		} else {
			spis_set_all(st->stack_use);
			for (int f = 0; f < depth; f++)
				spis_set_all(nonlocal_use[f]);
			return;
		}
		if (bytes == 0)
			continue;

		if (frame == depth) {
			record_stack_access(st->stack_use, st->stack_def, &at[r], bytes);
		} else if (frame >= 0 && frame < depth) {
			int rel = depth - 1 - frame;

			record_stack_access(nonlocal_use[rel], nonlocal_def[rel], &at[r], bytes);
		} else if (frame == ARG_IMPRECISE) {
			record_imprecise(at[r].mask, st->stack_use, nonlocal_use, depth);
		}
	}
}

/*
 * For a calls_callback helper, find the callback subprog and determine
 * which caller register maps to which callback register for FP passthrough.
 */
static int find_callback_subprog(struct bpf_verifier_env *env,
				 struct bpf_insn *insn, int insn_idx,
				 int *caller_reg, int *callee_reg)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	int cb_reg = -1;

	*caller_reg = -1;
	*callee_reg = -1;

	if (!bpf_helper_call(insn))
		return -1;
	switch (insn->imm) {
	case BPF_FUNC_loop:
		/* bpf_loop(nr, cb, ctx, flags): cb=R2, R3->cb R2 */
		cb_reg = BPF_REG_2;
		*caller_reg = BPF_REG_3;
		*callee_reg = BPF_REG_2;
		break;
	case BPF_FUNC_for_each_map_elem:
		/* for_each_map_elem(map, cb, ctx, flags): cb=R2, R3->cb R4 */
		cb_reg = BPF_REG_2;
		*caller_reg = BPF_REG_3;
		*callee_reg = BPF_REG_4;
		break;
	case BPF_FUNC_find_vma:
		/* find_vma(task, addr, cb, ctx, flags): cb=R3, R4->cb R3 */
		cb_reg = BPF_REG_3;
		*caller_reg = BPF_REG_4;
		*callee_reg = BPF_REG_3;
		break;
	case BPF_FUNC_user_ringbuf_drain:
		/* user_ringbuf_drain(map, cb, ctx, flags): cb=R2, R3->cb R2 */
		cb_reg = BPF_REG_2;
		*caller_reg = BPF_REG_3;
		*callee_reg = BPF_REG_2;
		break;
	default:
		return -1;
	}

	if (!(aux->const_reg_subprog_mask & BIT(cb_reg)))
		return -2;

	return aux->const_reg_vals[cb_reg];
}

/* Per-subprog intermediate state kept alive across analysis phases */
struct subprog_at_info {
	struct arg_track (*at_in)[MAX_BPF_REG];
	int len;
};

static void print_subprog_arg_access(struct bpf_verifier_env *env,
				     int subprog,
				     struct subprog_at_info *info,
				     struct arg_track (*at_stack_in)[MAX_ARG_SPILL_SLOTS],
				     struct insn_live_regs *state,
				     u64 (*nonlocal_use)[MAX_CALL_FRAMES][2],
				     u64 (*nonlocal_def)[MAX_CALL_FRAMES][2])
{
	struct bpf_insn *insns = env->prog->insnsi;
	int start = env->subprog_info[subprog].start;
	int len = info->len;
	int i, r, f;

	if (!(env->log.level & BPF_LOG_LEVEL2))
		return;

	verbose(env, "subprog#%d %s:\n", subprog,
		env->prog->aux->func_info
		? btf_name_by_offset(env->prog->aux->btf,
				     btf_type_by_id(env->prog->aux->btf,
						    env->prog->aux->func_info[subprog].type_id)->name_off)
		: "");
	for (i = 0; i < len; i++) {
		int idx = start + i;
		bool has_extra = false;
		u8 cls = BPF_CLASS(insns[idx].code);
		bool is_ldx_stx_call = cls == BPF_LDX || cls == BPF_STX ||
				       insns[idx].code == (BPF_JMP | BPF_CALL);

		verbose(env, "%3d: ", idx);
		bpf_verbose_insn(env, &insns[idx]);

		/* Collect what needs printing */
		has_extra = !spis_is_zero(state[idx].stack_def) ||
			    !spis_is_zero(state[idx].stack_use);
		for (f = 0; f < MAX_CALL_FRAMES; f++) {
			if (!spis_is_zero(nonlocal_use[i][f]) ||
			    !spis_is_zero(nonlocal_def[i][f]))
				has_extra = true;
		}
		if (is_ldx_stx_call &&
		    arg_is_visited(&info->at_in[i][0])) {
			for (r = 0; r < MAX_BPF_REG - 1; r++)
				if (arg_is_fp(&info->at_in[i][r]))
					has_extra = true;
		}
		if (is_ldx_stx_call) {
			for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
				if (arg_is_fp(&at_stack_in[i][r]))
					has_extra = true;
		}

		if (!has_extra) {
			if (bpf_is_ldimm64(&insns[idx]))
				i++;
			continue;
		}

		bpf_vlog_reset(&env->log, env->log.end_pos - 1);
		verbose(env, " //");

		if (!spis_is_zero(state[idx].stack_def))
			verbose(env, " stack_def=%llx:%llx",
				state[idx].stack_def[1], state[idx].stack_def[0]);
		if (!spis_is_zero(state[idx].stack_use))
			verbose(env, " stack_use=%llx:%llx",
				state[idx].stack_use[1], state[idx].stack_use[0]);

		for (f = 0; f < MAX_CALL_FRAMES; f++) {
			if (!spis_is_zero(nonlocal_use[i][f]))
				verbose(env, " nonlocal_use[%d]=%llx:%llx",
					f, nonlocal_use[i][f][1], nonlocal_use[i][f][0]);
			if (!spis_is_zero(nonlocal_def[i][f]))
				verbose(env, " nonlocal_def[%d]=%llx:%llx",
					f, nonlocal_def[i][f][1], nonlocal_def[i][f][0]);
		}

		if (is_ldx_stx_call && info->at_in &&
		    arg_is_visited(&info->at_in[i][0])) {
			for (r = 0; r < MAX_BPF_REG - 1; r++) {
				if (!arg_is_fp(&info->at_in[i][r]))
					continue;
				verbose(env, " r%d=", r);
				verbose_arg_track(env, &info->at_in[i][r]);
			}
		}

		if (is_ldx_stx_call) {
			for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++) {
				if (!arg_is_fp(&at_stack_in[i][r]))
					continue;
				verbose(env, " fp%+d=", -(r + 1) * 8);
				verbose_arg_track(env, &at_stack_in[i][r]);
			}
		}

		verbose(env, "\n");
		if (bpf_is_ldimm64(&insns[idx]))
			i++;
	}
}

/*
 * Compute arg tracking dataflow for a single subprog.
 * Runs forward fixed-point with arg_track_xfer(), then records
 * memory accesses in a single linear pass over converged state.
 *
 * @callee_entry: pre-populated entry state for R1-R5
 *                NULL for main (subprog 0).
 * @ctx:          call context with absolute frame depth and ancestor targets.
 * @nonlocal_use: this subprog's per-insn direct use bitmasks for ancestor frames
 * @nonlocal_def: this subprog's per-insn direct def bitmasks for ancestor frames
 * @info:         stores at_in, len for debug printing.
 */
static int compute_subprog_args(struct bpf_verifier_env *env, struct bpf_insn *insns,
				int subprog, struct subprog_at_info *info,
				struct insn_live_regs *state, struct arg_track *callee_entry,
				u64 (*nonlocal_use)[MAX_CALL_FRAMES][2],
				u64 (*nonlocal_def)[MAX_CALL_FRAMES][2],
				int depth, int *callsite_chain)
{
	int start = env->subprog_info[subprog].start;
	int po_start = env->subprog_info[subprog].postorder_start;
	int end = env->subprog_info[subprog + 1].start;
	int po_end = env->subprog_info[subprog + 1].postorder_start;
	int len = end - start;
	struct arg_track (*at_in)[MAX_BPF_REG] = NULL;
	struct arg_track at_out[MAX_BPF_REG];
	struct arg_track (*at_stack_in)[MAX_ARG_SPILL_SLOTS] = NULL;
	struct arg_track *at_stack_out = NULL;
	struct arg_track unvisited = { .frame = ARG_UNVISITED };
	struct arg_track none = { .frame = ARG_NONE };
	bool changed;
	int i, p, r, err = -ENOMEM;

	at_in = kvmalloc_objs(*at_in, len, GFP_KERNEL_ACCOUNT);
	if (!at_in)
		goto err_free;

	at_stack_in = kvmalloc_objs(*at_stack_in, len, GFP_KERNEL_ACCOUNT);
	if (!at_stack_in)
		goto err_free;

	at_stack_out = kvmalloc_objs(*at_stack_out, MAX_ARG_SPILL_SLOTS, GFP_KERNEL_ACCOUNT);
	if (!at_stack_out)
		goto err_free;

	for (i = 0; i < len; i++) {
		for (r = 0; r < MAX_BPF_REG; r++)
			at_in[i][r] = unvisited;
		for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
			at_stack_in[i][r] = unvisited;
	}

	for (r = 0; r < MAX_BPF_REG; r++)
		at_in[0][r] = none;

	/* Entry: R10 is always precisely the current frame's FP */
	at_in[0][BPF_REG_FP] = arg_single(depth, 0);

	/* R1-R5: from caller or ARG_NONE for main */
	if (callee_entry) {
		for (r = BPF_REG_1; r <= BPF_REG_5; r++)
			at_in[0][r] = callee_entry[r];
	}

	/* Entry: all stack slots are ARG_NONE */
	for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
		at_stack_in[0][r] = none;

	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "subprog#%d: analyzing (depth %d)...\n", subprog, depth);

	/* Forward fixed-point iteration in reverse post order */
redo:
	changed = false;
	for (p = po_end - 1; p >= po_start; p--) {
		int idx = env->cfg.insn_postorder[p];
		int i = idx - start;
		struct bpf_insn *insn = &insns[idx];
		struct bpf_iarray *succ;

		if (!arg_is_visited(&at_in[i][0]) && !arg_is_visited(&at_in[i][1]))
			continue;

		memcpy(at_out, at_in[i], sizeof(at_out));
		memcpy(at_stack_out, at_stack_in[i], MAX_ARG_SPILL_SLOTS * sizeof(*at_stack_out));

		arg_track_xfer(env, insn, idx, at_out, at_stack_out, depth, callsite_chain);
		arg_track_log(env, insn, idx, at_in[i], at_stack_in[i], at_out, at_stack_out);

		/* Propagate to successors within this subprogram */
		succ = bpf_insn_successors(env, idx);
		for (int s = 0; s < succ->cnt; s++) {
			int target = succ->items[s];
			int ti;

			/* Filter: stay within the subprogram's range */
			if (target < start || target >= end)
				continue;
			ti = target - start;

			for (r = 0; r < MAX_BPF_REG; r++)
				changed |= arg_track_join(env, idx, target, r,
							  &at_in[ti][r], at_out[r]);

			for (r = 0; r < MAX_ARG_SPILL_SLOTS; r++)
				changed |= arg_track_join(env, idx, target, -r - 1,
							  &at_stack_in[ti][r], at_stack_out[r]);
		}
	}
	if (changed)
		goto redo;

	/* Record memory accesses using converged at_in (RPO skips dead code) */
	for (p = po_end - 1; p >= po_start; p--) {
		int idx = env->cfg.insn_postorder[p];
		int i = idx - start;
		struct bpf_insn *insn = &insns[idx];

		record_load_store_access(insn, at_in[i], &state[idx],
					 nonlocal_use[i], nonlocal_def[i], depth);

		if (insn->code == (BPF_JMP | BPF_CALL))
			record_call_access(env, at_in[i], insn, idx, &state[idx],
					   nonlocal_use[i], nonlocal_def[i], depth);

		if (bpf_pseudo_call(insn) || bpf_calls_callback(env, idx)) {
			kvfree(env->callsite_at_stack[idx]);
			env->callsite_at_stack[idx] =
				kvmalloc_objs(*env->callsite_at_stack[idx],
					      MAX_ARG_SPILL_SLOTS, GFP_KERNEL_ACCOUNT);
			if (!env->callsite_at_stack[idx])
				goto err_free;
			memcpy(env->callsite_at_stack[idx],
			       at_stack_in[i], sizeof(struct arg_track) * MAX_ARG_SPILL_SLOTS);
		}
	}

	info->at_in = at_in;
	at_in = NULL;
	info->len = len;
	print_subprog_arg_access(env, subprog, info, at_stack_in, state, nonlocal_use, nonlocal_def);
	err = 0;

err_free:
	kvfree(at_stack_out);
	kvfree(at_stack_in);
	kvfree(at_in);
	return err;
}

static int compute_nonlocal_live(struct bpf_verifier_env *env, int subprog,
				 u64 (*nonlocal_use)[MAX_CALL_FRAMES][2],
				 u64 (*nonlocal_def)[MAX_CALL_FRAMES][2],
				 int depth, bool is_sync_cb,
				 struct bpf_callsite_nonlocal_live **live_out)
{
	struct bpf_insn *insns = env->prog->insnsi;
	int start = env->subprog_info[subprog].start;
	int po_start = env->subprog_info[subprog].postorder_start;
	int end = env->subprog_info[subprog + 1].start;
	int po_end = env->subprog_info[subprog + 1].postorder_start;
	int len = end - start;
	struct bpf_callsite_nonlocal_live *info;
	u64 (*live)[MAX_CALL_FRAMES][2];
	bool changed;

	info = kvzalloc_obj(*info, GFP_KERNEL_ACCOUNT);
	if (!info)
		return -ENOMEM;

	live = kvzalloc_objs(*live, len, GFP_KERNEL_ACCOUNT);
	if (!live) {
		kvfree(info);
		return -ENOMEM;
	}

redo:
	changed = false;
	for (int p = po_start; p < po_end; p++) {
		int insn_idx = env->cfg.insn_postorder[p];
		int li = insn_idx - start;
		struct bpf_iarray *succ;
		u64 new_live_out[MAX_CALL_FRAMES][2] = {};
		u64 new_live[MAX_CALL_FRAMES][2];

		succ = bpf_insn_successors(env, insn_idx);
		for (int s = 0; s < succ->cnt; s++) {
			int target = succ->items[s];

			if (target < start || target >= end)
				continue;
			for (int f = 0; f < depth; f++)
				spis_or(new_live_out[f], live[target - start][f]);
		}

		/*
		 * Sync callbacks (e.g. bpf_loop) can be invoked multiple
		 * times.  Model this by adding an artificial exit -> entry
		 * edge so that ancestor stack slots used by the callback
		 * remain live throughout the entire body, not just up to the
		 * last use before exit.
		 */
		if (is_sync_cb && insns[insn_idx].code == (BPF_JMP | BPF_EXIT))
			for (int f = 0; f < depth; f++)
				spis_or(new_live_out[f], live[0][f]);

		for (int f = 0; f < depth; f++) {
			new_live[f][0] = (new_live_out[f][0] & ~nonlocal_def[li][f][0]) |
					 nonlocal_use[li][f][0];
			new_live[f][1] = (new_live_out[f][1] & ~nonlocal_def[li][f][1]) |
					 nonlocal_use[li][f][1];

			if (!spis_equal(new_live[f], live[li][f])) {
				spis_copy(live[li][f], new_live[f]);
				changed = true;
			}
		}
	}
	if (changed)
		goto redo;

	info->live = live;
	info->start = start;
	info->len = len;
	info->depth = depth;
	*live_out = info;
	return 0;
}

static int merge_nonlocal_live(struct bpf_verifier_env *env,
			       struct bpf_callsite_nonlocal_live **dstp,
			       struct bpf_callsite_nonlocal_live *src)
{
	struct bpf_callsite_nonlocal_live *dst = *dstp;

	if (!dst) {
		*dstp = src;
		return 0;
	}

	/*
	 * callsite calls a specific subprog, hence its start idx and length
	 * has to be the same.
	 */
	if (verifier_bug_if(dst->start != src->start || dst->len != src->len, env,
			    "callsite nonlocal live mismatch: dst=%u+%u src=%u+%u",
			    dst->start, dst->len, src->start, src->len)) {
		kvfree(src->live);
		kvfree(src);
		return -EFAULT;
	}

	for (u32 i = 0; i < src->len; i++)
		for (int f = 0; f < src->depth; f++)
			spis_or(dst->live[i][f], src->live[i][f]);
	dst->depth = max(dst->depth, src->depth);
	kvfree(src->live);
	kvfree(src);
	return 0;
}

static void fold_callee_liveness(struct bpf_verifier_env *env, u32 callsite,
				 int caller_depth, u64 stack_use[2], u64 (*nonlocal_use)[2])
{
	struct bpf_callsite_nonlocal_live *info;

	info = env->callsite_nonlocal_live[callsite];
	/* If callee didn't access parent or grandparent stack the info == NULL */
	if (!info)
		return;

	if (info->depth > 0)
		/*
		 * live[0][0] is callee liveness at entry. It is what callee
		 * may access from immediate parent stack. OR it into this
		 * callsite.
		 */
		spis_or(stack_use, info->live[0][0]);

	/*
	 * info->live[] is indexed relative to the callee's caller:
	 *   rel 0 -> callee's immediate caller (= current subprog, local)
	 *   rel 1 -> caller's caller (= nonlocal_use[0])
	 *   rel 2 -> caller's caller's caller (= nonlocal_use[1])
	 *   ...
	 */
	for (int rel = 1; rel < info->depth && rel <= caller_depth; rel++)
		spis_or(nonlocal_use[rel - 1], info->live[0][rel]);
}

/* Return true if any of R1-R5 is derived from a frame pointer. */
static bool has_fp_args(struct arg_track *args)
{
	for (int r = BPF_REG_1; r <= BPF_REG_5; r++)
		if (args[r].frame != ARG_NONE)
			return true;
	return false;
}

/*
 * Recursively analyze a subprog with specific 'entry_args'.
 * Each callee is analyzed with the exact args from its call site.
 * Accesses to ancestor stacks are recorded in nonlocal_use/nonlocal_def
 * and propagated to the caller via compute_nonlocal_live + merge.
 *
 * Args are recomputed for each call because the dataflow result at_in[]
 * depends on the entry args and frame depth. Consider: A->C->D and B->C->D
 * Callsites in A and B pass different args into C, so C is recomputed.
 * Then within C the same callsite passes different args into D.
 */
static int analyze_subprog(struct bpf_verifier_env *env, int subprog,
			   struct arg_track *entry_args, int depth,
			   struct insn_live_regs *state, struct subprog_at_info *info,
			   int caller_callsite, bool is_sync_cb, int *callsite_chain)
{
	struct bpf_insn *insns = env->prog->insnsi;
	int start = env->subprog_info[subprog].start;
	int po_start = env->subprog_info[subprog].postorder_start;
	int end = env->subprog_info[subprog + 1].start;
	int po_end = env->subprog_info[subprog + 1].postorder_start;
	int len = end - start;
	u64 (*nonlocal_use)[MAX_CALL_FRAMES][2];
	u64 (*nonlocal_def)[MAX_CALL_FRAMES][2];
	struct bpf_callsite_nonlocal_live *nonlocal_live = NULL;
	int j, err;

	if (depth >= MAX_CALL_FRAMES)
		return -EINVAL;

	nonlocal_use = kvzalloc_objs(*nonlocal_use, len, GFP_KERNEL_ACCOUNT);
	if (!nonlocal_use)
		return -ENOMEM;
	nonlocal_def = kvzalloc_objs(*nonlocal_def, len, GFP_KERNEL_ACCOUNT);
	if (!nonlocal_def) {
		kvfree(nonlocal_use);
		return -ENOMEM;
	}

	/* Free prior analysis if this subprog was already visited */
	kvfree(info[subprog].at_in);
	info[subprog].at_in = NULL;

	err = compute_subprog_args(env, insns, subprog, &info[subprog], state, entry_args,
				   nonlocal_use, nonlocal_def, depth, callsite_chain);
	if (err)
		goto out;

	/* For each reachable call site in the subprog, recurse into callees */
	for (int p = po_start; p < po_end; p++) {
		int idx = env->cfg.insn_postorder[p];
		struct arg_track callee_args[BPF_REG_5 + 1];
		struct arg_track none = { .frame = ARG_NONE };
		struct bpf_insn *insn = &insns[idx];
		int callee, target;
		int caller_reg, cb_callee_reg;

		j = idx - start; /* relative index within this subprog */

		if (bpf_pseudo_call(insn)) {
			target = idx + insn->imm + 1;
			callee = bpf_find_subprog(env, target);
			if (callee < 0)
				continue;

			/* Build entry args: R1-R5 from at_in at call site */
			for (int r = BPF_REG_1; r <= BPF_REG_5; r++)
				callee_args[r] = info[subprog].at_in[j][r];
		} else if (bpf_calls_callback(env, idx)) {
			callee = find_callback_subprog(env, insn, idx, &caller_reg, &cb_callee_reg);
			if (callee == -2) {
				/*
				 * same bpf_loop() calls two different callbacks and passes
				 * stack pointer to them
				 */
				if (info[subprog].at_in[j][caller_reg].frame == ARG_NONE)
					continue;
				for (int f = 0; f < depth; f++)
					spis_set_all(nonlocal_use[j][f]);
				spis_set_all(state[idx].stack_use);
				continue;
			}
			if (callee < 0)
				continue;

			for (int r = BPF_REG_1; r <= BPF_REG_5; r++)
				callee_args[r] = none;
			callee_args[cb_callee_reg] = info[subprog].at_in[j][caller_reg];
		} else {
			continue;
		}

		/*
		 * If the callee receives no FP-derived arguments it cannot
		 * access any ancestor stack frame, so there is nothing to
		 * propagate back to the caller via nonlocal_use.  Skip the
		 * recursion and let compute_subprog_arg_access() handle it
		 * separately at depth 0, just like async callbacks.
		 */
		if (!has_fp_args(callee_args))
			continue;

		callsite_chain[depth] = idx;
		err = analyze_subprog(env, callee, callee_args, depth + 1, state, info,
				      idx, bpf_calls_callback(env, idx), callsite_chain);
		if (err)
			goto out;

		fold_callee_liveness(env, idx, depth, state[idx].stack_use, nonlocal_use[j]);
	}

	if (caller_callsite >= 0) {
		err = compute_nonlocal_live(env, subprog, nonlocal_use, nonlocal_def,
					    depth, is_sync_cb, &nonlocal_live);
		if (err)
			goto out;
		err = merge_nonlocal_live(env, &env->callsite_nonlocal_live[caller_callsite], nonlocal_live);
		if (err)
			goto out;
		nonlocal_live = NULL;
	}

out:
	if (nonlocal_live) {
		kvfree(nonlocal_live->live);
		kvfree(nonlocal_live);
	}
	kvfree(nonlocal_def);
	kvfree(nonlocal_use);
	return err;
}

int compute_subprog_arg_access(struct bpf_verifier_env *env, struct insn_live_regs *state)
{
	int insn_cnt = env->prog->len;
	int callsite_chain[MAX_CALL_FRAMES] = {};
	struct subprog_at_info *info;
	int k, err = 0;

	info = kvzalloc_objs(*info, env->subprog_cnt, GFP_KERNEL_ACCOUNT);
	if (!info)
		return -ENOMEM;

	env->callsite_nonlocal_live = kvzalloc_objs(*env->callsite_nonlocal_live, insn_cnt,
						    GFP_KERNEL_ACCOUNT);
	if (!env->callsite_nonlocal_live) {
		kvfree(info);
		return -ENOMEM;
	}

	env->callsite_at_stack = kvzalloc_objs(*env->callsite_at_stack, insn_cnt,
					       GFP_KERNEL_ACCOUNT);
	if (!env->callsite_at_stack) {
		kvfree(env->callsite_nonlocal_live);
		env->callsite_nonlocal_live = NULL;
		kvfree(info);
		return -ENOMEM;
	}

	err = analyze_subprog(env, 0, NULL, 0, state, info, -1, false, callsite_chain);
	if (err)
		goto out;

	/*
	 * Subprogs and callbacks that don't receive FP-derived arguments
	 * cannot access ancestor stack frames, so they were skipped during
	 * the recursive walk above.  Async callbacks (timer, workqueue) are
	 * also not reachable from the main program's call graph.  Analyze
	 * all unvisited subprogs as independent roots at depth 0.
	 *
	 * Use reverse topological order (callers before callees) so that
	 * each subprog is analyzed before its callees, allowing the
	 * recursive walk inside analyze_subprog() to naturally
	 * reach nested callees that also lack FP-derived args.
	 */
	for (k = env->subprog_cnt - 1; k >= 0; k--) {
		int sub = env->subprog_topo_order[k];

		if (info[sub].at_in)
			continue;
		err = analyze_subprog(env, sub, NULL, 0, state, info, -1, false, callsite_chain);
		if (err)
			break;
	}

out:
	for (k = 0; k < insn_cnt; k++)
		kvfree(env->callsite_at_stack[k]);
	kvfree(env->callsite_at_stack);
	env->callsite_at_stack = NULL;
	for (k = 0; k < env->subprog_cnt; k++)
		kvfree(info[k].at_in);
	kvfree(info);
	return err;
}


/*
 * Compute refined caller stack liveness for frame @frame_idx
 * at the current pruning point. Start with caller liveness after
 * the immediate child returns, then add direct non-local liveness
 * from every active descendant frame.
 */
static void add_children_stack_access(struct bpf_verifier_env *env,
				      const struct bpf_verifier_state *st,
				      u32 target_frame,
				      u64 live_stack_out[2])
{
	struct bpf_callsite_nonlocal_live *info;
	u32 callsite, rel_ip;

	for (u32 f = target_frame + 1; f <= st->curframe; f++) {
		int rel = f - 1 - target_frame;

		callsite = st->frame[f]->callsite;
		info = env->callsite_nonlocal_live[callsite];

		/* callee didn't access parent(s) stack */
		if (!info)
			continue;

		/*
		 * A->B->C. C may access B, but not A's stack.
		 * C's info->depth == 1 && rel == 1
		 */
		if (rel >= info->depth)
			continue;

		rel_ip = bpf_frame_insn_idx(st, f) - info->start;
		spis_or(live_stack_out, info->live[rel_ip][rel]);
	}
}

void refined_caller_live_stack(struct bpf_verifier_env *env,
			       struct bpf_verifier_state *st,
			       int frame_idx,
			       u64 live_stack_out[2])
{
	u32 callsite = st->frame[frame_idx + 1]->callsite;

	spis_copy(live_stack_out, env->insn_aux_data[callsite + 1].live_stack_before);
	add_children_stack_access(env, st, frame_idx, live_stack_out);
}
