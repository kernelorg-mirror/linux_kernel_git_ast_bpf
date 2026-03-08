// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>

/*
 * This file implements live stack slots analysis. After accumulating
 * stack usage data, the analysis answers queries about whether a
 * particular stack slot may be read by an instruction or any of it's
 * successors.  This data is consumed by the verifier states caching
 * mechanism to decide which stack slots are important when looking for a
 * visited state corresponding to the current state.
 *
 * The analysis is call chain sensitive, meaning that data is collected
 * and queried for tuples (call chain, subprogram instruction index).
 * Such sensitivity allows identifying if some subprogram call always
 * leads to writes in the caller's stack.
 *
 * The basic idea is as follows:
 * - As the verifier accumulates a set of visited states, the analysis instance
 *   accumulates a conservative estimate of stack slots that can be read
 *   or must be written for each visited tuple (call chain, instruction index).
 * - If several states happen to visit the same instruction with the same
 *   call chain, stack usage information for the corresponding tuple is joined:
 *   - "may_read" set represents a union of all possibly read slots
 *     (any slot in "may_read" set might be read at or after the instruction);
 *   - "must_write" set represents an intersection of all possibly written slots
 *     (any slot in "must_write" set is guaranteed to be written by the instruction).
 * - The analysis is split into two phases:
 *   - read and write marks accumulation;
 *   - read and write marks propagation.
 * - The propagation phase is a textbook live variable data flow analysis:
 *
 *     state[cc, i].live_after = U [state[cc, s].live_before for s in bpf_insn_successors(i)]
 *     state[cc, i].live_before =
 *       (state[cc, i].live_after / state[cc, i].must_write) U state[i].may_read
 *
 *   Where:
 *   - `U`  stands for set union
 *   - `/`  stands for set difference;
 *   - `cc` stands for a call chain;
 *   - `i` and `s` are instruction indexes;
 *
 *   The above equations are computed for each call chain and instruction
 *   index until state stops changing.
 * - Additionally, in order to transfer "must_write" information from a
 *   subprogram to call instructions invoking this subprogram,
 *   the "must_write_acc" set is tracked for each (cc, i) tuple.
 *   A set of stack slots that are guaranteed to be written by this
 *   instruction or any of its successors (within the subprogram).
 *   The equation for "must_write_acc" propagation looks as follows:
 *
 *     state[cc, i].must_write_acc =
 *       ∩ [state[cc, s].must_write_acc for s in bpf_insn_successors(i)]
 *       U state[cc, i].must_write
 *
 *   (An intersection of all "must_write_acc" for instruction successors
 *    plus all "must_write" slots for the instruction itself).
 * - After the propagation phase completes for a subprogram, information from
 *   (cc, 0) tuple (subprogram entry) is transferred to the caller's call chain:
 *   - "must_write_acc" set is intersected with the call site's "must_write" set;
 *   - "may_read" set is added to the call site's "may_read" set.
 * - Any live stack queries must be taken after the propagation phase.
 * - Accumulation and propagation phases can be entered multiple times,
 *   at any point in time:
 *   - "may_read" set only grows;
 *   - "must_write" set only shrinks;
 *   - for each visited verifier state with zero branches, all relevant
 *     read and write marks are already recorded by the analysis instance.
 *
 * Technically, the analysis is facilitated by the following data structures:
 * - Call chain: for given verifier state, the call chain is a tuple of call
 *   instruction indexes leading to the current subprogram plus the subprogram
 *   entry point index.
 * - Function instance: for a given call chain, for each instruction in
 *   the current subprogram, a mapping between instruction index and a
 *   set of "may_read", "must_write" and other marks accumulated for this
 *   instruction.
 * - A hash table mapping call chains to function instances.
 */

struct callchain {
	u32 callsites[MAX_CALL_FRAMES];	/* instruction pointer for each frame */
	/* cached subprog_info[*].start for functions owning the frames:
	 * - sp_starts[curframe] used to get insn relative index within current function;
	 * - sp_starts[0..current-1] used for fast callchain_frame_up().
	 */
	u32 sp_starts[MAX_CALL_FRAMES];
	u32 curframe;			/* depth of callsites and sp_starts arrays */
};

struct per_frame_masks {
	u64 may_read;		/* stack slots that may be read by this instruction */
	u64 must_write;		/* stack slots written by this instruction */
	u64 must_write_acc;	/* stack slots written by this instruction and its successors */
	u64 live_before;	/* stack slots that may be read by this insn and its successors */
};

/*
 * A function instance created for a specific callchain.
 * Encapsulates read and write marks for each instruction in the function.
 * Marks are tracked for each frame in the callchain.
 */
struct func_instance {
	struct hlist_node hl_node;
	struct callchain callchain;
	u32 insn_cnt;		/* cached number of insns in the function */
	bool updated;
	bool must_write_dropped;
	/* Per frame, per instruction masks, frames allocated lazily. */
	struct per_frame_masks *frames[MAX_CALL_FRAMES];
	/* For each instruction a flag telling if "must_write" had been initialized for it. */
	bool *must_write_set;
};

struct live_stack_query {
	struct func_instance *instances[MAX_CALL_FRAMES]; /* valid in range [0..curframe] */
	u32 curframe;
	u32 insn_idx;
};

struct bpf_liveness {
	DECLARE_HASHTABLE(func_instances, 8);		/* maps callchain to func_instance */
	struct live_stack_query live_stack_query;	/* cache to avoid repetitive ht lookups */
	/* Cached instance corresponding to env->cur_state, avoids per-instruction ht lookup */
	struct func_instance *cur_instance;
	/*
	 * Below fields are used to accumulate stack write marks for instruction at
	 * @write_insn_idx before submitting the marks to @cur_instance.
	 */
	u64 write_masks_acc[MAX_CALL_FRAMES];
	u32 write_insn_idx;
};

/* Compute callchain corresponding to state @st at depth @frameno */
static void compute_callchain(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			      struct callchain *callchain, u32 frameno)
{
	struct bpf_subprog_info *subprog_info = env->subprog_info;
	u32 i;

	memset(callchain, 0, sizeof(*callchain));
	for (i = 0; i <= frameno; i++) {
		callchain->sp_starts[i] = subprog_info[st->frame[i]->subprogno].start;
		if (i < st->curframe)
			callchain->callsites[i] = st->frame[i + 1]->callsite;
	}
	callchain->curframe = frameno;
	callchain->callsites[callchain->curframe] = callchain->sp_starts[callchain->curframe];
}

static u32 hash_callchain(struct callchain *callchain)
{
	return jhash2(callchain->callsites, callchain->curframe, 0);
}

static bool same_callsites(struct callchain *a, struct callchain *b)
{
	int i;

	if (a->curframe != b->curframe)
		return false;
	for (i = a->curframe; i >= 0; i--)
		if (a->callsites[i] != b->callsites[i])
			return false;
	return true;
}

/*
 * Find existing or allocate new function instance corresponding to @callchain.
 * Instances are accumulated in env->liveness->func_instances and persist
 * until the end of the verification process.
 */
static struct func_instance *__lookup_instance(struct bpf_verifier_env *env,
					       struct callchain *callchain)
{
	struct bpf_liveness *liveness = env->liveness;
	struct bpf_subprog_info *subprog;
	struct func_instance *result;
	u32 subprog_sz, size, key;

	key = hash_callchain(callchain);
	hash_for_each_possible(liveness->func_instances, result, hl_node, key)
		if (same_callsites(&result->callchain, callchain))
			return result;

	subprog = bpf_find_containing_subprog(env, callchain->sp_starts[callchain->curframe]);
	subprog_sz = (subprog + 1)->start - subprog->start;
	size = sizeof(struct func_instance);
	result = kvzalloc(size, GFP_KERNEL_ACCOUNT);
	if (!result)
		return ERR_PTR(-ENOMEM);
	result->must_write_set = kvzalloc_objs(*result->must_write_set,
					       subprog_sz, GFP_KERNEL_ACCOUNT);
	if (!result->must_write_set) {
		kvfree(result);
		return ERR_PTR(-ENOMEM);
	}
	memcpy(&result->callchain, callchain, sizeof(*callchain));
	result->insn_cnt = subprog_sz;
	hash_add(liveness->func_instances, &result->hl_node, key);
	return result;
}

static struct func_instance *lookup_instance(struct bpf_verifier_env *env,
					     struct bpf_verifier_state *st,
					     u32 frameno)
{
	struct callchain callchain;

	compute_callchain(env, st, &callchain, frameno);
	return __lookup_instance(env, &callchain);
}

int bpf_stack_liveness_init(struct bpf_verifier_env *env)
{
	env->liveness = kvzalloc_obj(*env->liveness, GFP_KERNEL_ACCOUNT);
	if (!env->liveness)
		return -ENOMEM;
	hash_init(env->liveness->func_instances);
	return 0;
}

void bpf_stack_liveness_free(struct bpf_verifier_env *env)
{
	struct func_instance *instance;
	struct hlist_node *tmp;
	int bkt, i;

	if (!env->liveness)
		return;
	hash_for_each_safe(env->liveness->func_instances, bkt, tmp, instance, hl_node) {
		for (i = 0; i <= instance->callchain.curframe; i++)
			kvfree(instance->frames[i]);
		kvfree(instance->must_write_set);
		kvfree(instance);
	}
	kvfree(env->liveness);
}

/*
 * Convert absolute instruction index @insn_idx to an index relative
 * to start of the function corresponding to @instance.
 */
static int relative_idx(struct func_instance *instance, u32 insn_idx)
{
	return insn_idx - instance->callchain.sp_starts[instance->callchain.curframe];
}

static struct per_frame_masks *get_frame_masks(struct func_instance *instance,
					       u32 frame, u32 insn_idx)
{
	if (!instance->frames[frame])
		return NULL;

	return &instance->frames[frame][relative_idx(instance, insn_idx)];
}

static struct per_frame_masks *alloc_frame_masks(struct bpf_verifier_env *env,
						 struct func_instance *instance,
						 u32 frame, u32 insn_idx)
{
	struct per_frame_masks *arr;

	if (!instance->frames[frame]) {
		arr = kvzalloc_objs(*arr, instance->insn_cnt,
				    GFP_KERNEL_ACCOUNT);
		instance->frames[frame] = arr;
		if (!arr)
			return ERR_PTR(-ENOMEM);
	}
	return get_frame_masks(instance, frame, insn_idx);
}

void bpf_reset_live_stack_callchain(struct bpf_verifier_env *env)
{
	env->liveness->cur_instance = NULL;
}

/* If @env->liveness->cur_instance is null, set it to instance corresponding to @env->cur_state. */
static int ensure_cur_instance(struct bpf_verifier_env *env)
{
	struct bpf_liveness *liveness = env->liveness;
	struct func_instance *instance;

	if (liveness->cur_instance)
		return 0;

	instance = lookup_instance(env, env->cur_state, env->cur_state->curframe);
	if (IS_ERR(instance))
		return PTR_ERR(instance);

	liveness->cur_instance = instance;
	return 0;
}

/* Accumulate may_read masks for @frame at @insn_idx */
static int mark_stack_read(struct bpf_verifier_env *env,
			   struct func_instance *instance, u32 frame, u32 insn_idx, u64 mask)
{
	struct per_frame_masks *masks;
	u64 new_may_read;

	masks = alloc_frame_masks(env, instance, frame, insn_idx);
	if (IS_ERR(masks))
		return PTR_ERR(masks);
	new_may_read = masks->may_read | mask;
	if (new_may_read != masks->may_read &&
	    ((new_may_read | masks->live_before) != masks->live_before))
		instance->updated = true;
	masks->may_read |= mask;
	return 0;
}

int bpf_mark_stack_read(struct bpf_verifier_env *env, u32 frame, u32 insn_idx, u64 mask)
{
	int err;

	err = ensure_cur_instance(env);
	err = err ?: mark_stack_read(env, env->liveness->cur_instance, frame, insn_idx, mask);
	return err;
}

static void reset_stack_write_marks(struct bpf_verifier_env *env,
				    struct func_instance *instance, u32 insn_idx)
{
	struct bpf_liveness *liveness = env->liveness;
	int i;

	liveness->write_insn_idx = insn_idx;
	for (i = 0; i <= instance->callchain.curframe; i++)
		liveness->write_masks_acc[i] = 0;
}

int bpf_reset_stack_write_marks(struct bpf_verifier_env *env, u32 insn_idx)
{
	struct bpf_liveness *liveness = env->liveness;
	int err;

	err = ensure_cur_instance(env);
	if (err)
		return err;

	reset_stack_write_marks(env, liveness->cur_instance, insn_idx);
	return 0;
}

void bpf_mark_stack_write(struct bpf_verifier_env *env, u32 frame, u64 mask)
{
	env->liveness->write_masks_acc[frame] |= mask;
}

static int commit_stack_write_marks(struct bpf_verifier_env *env,
				    struct func_instance *instance)
{
	struct bpf_liveness *liveness = env->liveness;
	u32 idx, frame, curframe, old_must_write;
	struct per_frame_masks *masks;
	u64 mask;

	if (!instance)
		return 0;

	curframe = instance->callchain.curframe;
	idx = relative_idx(instance, liveness->write_insn_idx);
	for (frame = 0; frame <= curframe; frame++) {
		mask = liveness->write_masks_acc[frame];
		/* avoid allocating frames for zero masks */
		if (mask == 0 && !instance->must_write_set[idx])
			continue;
		masks = alloc_frame_masks(env, instance, frame, liveness->write_insn_idx);
		if (IS_ERR(masks))
			return PTR_ERR(masks);
		old_must_write = masks->must_write;
		/*
		 * If instruction at this callchain is seen for a first time, set must_write equal
		 * to @mask. Otherwise take intersection with the previous value.
		 */
		if (instance->must_write_set[idx])
			mask &= old_must_write;
		if (old_must_write != mask) {
			masks->must_write = mask;
			instance->updated = true;
		}
		if (old_must_write & ~mask)
			instance->must_write_dropped = true;
	}
	instance->must_write_set[idx] = true;
	liveness->write_insn_idx = 0;
	return 0;
}

/*
 * Merge stack writes marks in @env->liveness->write_masks_acc
 * with information already in @env->liveness->cur_instance.
 */
int bpf_commit_stack_write_marks(struct bpf_verifier_env *env)
{
	return commit_stack_write_marks(env, env->liveness->cur_instance);
}

static char *fmt_callchain(struct bpf_verifier_env *env, struct callchain *callchain)
{
	char *buf_end = env->tmp_str_buf + sizeof(env->tmp_str_buf);
	char *buf = env->tmp_str_buf;
	int i;

	buf += snprintf(buf, buf_end - buf, "(");
	for (i = 0; i <= callchain->curframe; i++)
		buf += snprintf(buf, buf_end - buf, "%s%d", i ? "," : "", callchain->callsites[i]);
	snprintf(buf, buf_end - buf, ")");
	return env->tmp_str_buf;
}

static void log_mask_change(struct bpf_verifier_env *env, struct callchain *callchain,
			    char *pfx, u32 frame, u32 insn_idx, u64 old, u64 new)
{
	u64 changed_bits = old ^ new;
	u64 new_ones = new & changed_bits;
	u64 new_zeros = ~new & changed_bits;

	if (!changed_bits)
		return;
	bpf_log(&env->log, "%s frame %d insn %d ", fmt_callchain(env, callchain), frame, insn_idx);
	if (new_ones) {
		bpf_fmt_stack_mask(env->tmp_str_buf, sizeof(env->tmp_str_buf), new_ones);
		bpf_log(&env->log, "+%s %s ", pfx, env->tmp_str_buf);
	}
	if (new_zeros) {
		bpf_fmt_stack_mask(env->tmp_str_buf, sizeof(env->tmp_str_buf), new_zeros);
		bpf_log(&env->log, "-%s %s", pfx, env->tmp_str_buf);
	}
	bpf_log(&env->log, "\n");
}

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

static struct func_instance *get_outer_instance(struct bpf_verifier_env *env,
						struct func_instance *instance)
{
	struct callchain callchain = instance->callchain;

	/* Adjust @callchain to represent callchain one frame up */
	callchain.callsites[callchain.curframe] = 0;
	callchain.sp_starts[callchain.curframe] = 0;
	callchain.curframe--;
	callchain.callsites[callchain.curframe] = callchain.sp_starts[callchain.curframe];
	return __lookup_instance(env, &callchain);
}

static u32 callchain_subprog_start(struct callchain *callchain)
{
	return callchain->sp_starts[callchain->curframe];
}

/*
 * Transfer @may_read and @must_write_acc marks from the first instruction of @instance,
 * to the call instruction in function instance calling @instance.
 */
static int propagate_to_outer_instance(struct bpf_verifier_env *env,
				       struct func_instance *instance)
{
	struct callchain *callchain = &instance->callchain;
	u32 this_subprog_start, callsite, frame;
	struct func_instance *outer_instance;
	struct per_frame_masks *insn;
	int err;

	this_subprog_start = callchain_subprog_start(callchain);
	outer_instance = get_outer_instance(env, instance);
	if (IS_ERR(outer_instance))
		return PTR_ERR(outer_instance);
	callsite = callchain->callsites[callchain->curframe - 1];

	reset_stack_write_marks(env, outer_instance, callsite);
	for (frame = 0; frame < callchain->curframe; frame++) {
		insn = get_frame_masks(instance, frame, this_subprog_start);
		if (!insn)
			continue;
		bpf_mark_stack_write(env, frame, insn->must_write_acc);
		err = mark_stack_read(env, outer_instance, frame, callsite, insn->live_before);
		if (err)
			return err;
	}
	commit_stack_write_marks(env, outer_instance);
	return 0;
}

static inline bool update_insn(struct bpf_verifier_env *env,
			       struct func_instance *instance, u32 frame, u32 insn_idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	u64 new_before, new_after, must_write_acc;
	struct per_frame_masks *insn, *succ_insn;
	struct bpf_iarray *succ;
	u32 s;
	bool changed;

	succ = bpf_insn_successors(env, insn_idx);
	if (succ->cnt == 0)
		return false;

	changed = false;
	insn = get_frame_masks(instance, frame, insn_idx);
	new_before = 0;
	new_after = 0;
	/*
	 * New "must_write_acc" is an intersection of all "must_write_acc"
	 * of successors plus all "must_write" slots of instruction itself.
	 */
	must_write_acc = U64_MAX;
	for (s = 0; s < succ->cnt; ++s) {
		succ_insn = get_frame_masks(instance, frame, succ->items[s]);
		new_after |= succ_insn->live_before;
		must_write_acc &= succ_insn->must_write_acc;
	}
	must_write_acc |= insn->must_write;
	/*
	 * New "live_before" is a union of all "live_before" of successors
	 * minus slots written by instruction plus slots read by instruction.
	 */
	new_before = (new_after & ~insn->must_write) | insn->may_read;
	changed |= new_before != insn->live_before;
	changed |= must_write_acc != insn->must_write_acc;
	if (unlikely(env->log.level & BPF_LOG_LEVEL2) &&
	    (insn->may_read || insn->must_write ||
	     insn_idx == callchain_subprog_start(&instance->callchain) ||
	     aux[insn_idx].prune_point)) {
		log_mask_change(env, &instance->callchain, "live",
				frame, insn_idx, insn->live_before, new_before);
		log_mask_change(env, &instance->callchain, "written",
				frame, insn_idx, insn->must_write_acc, must_write_acc);
	}
	insn->live_before = new_before;
	insn->must_write_acc = must_write_acc;
	return changed;
}

/* Fixed-point computation of @live_before and @must_write_acc marks */
static int update_instance(struct bpf_verifier_env *env, struct func_instance *instance)
{
	u32 i, frame, po_start, po_end, cnt, this_subprog_start;
	struct callchain *callchain = &instance->callchain;
	int *insn_postorder = env->cfg.insn_postorder;
	struct bpf_subprog_info *subprog;
	struct per_frame_masks *insn;
	bool changed;
	int err;

	this_subprog_start = callchain_subprog_start(callchain);
	/*
	 * If must_write marks were updated must_write_acc needs to be reset
	 * (to account for the case when new must_write sets became smaller).
	 */
	if (instance->must_write_dropped) {
		for (frame = 0; frame <= callchain->curframe; frame++) {
			if (!instance->frames[frame])
				continue;

			for (i = 0; i < instance->insn_cnt; i++) {
				insn = get_frame_masks(instance, frame, this_subprog_start + i);
				insn->must_write_acc = 0;
			}
		}
	}

	subprog = bpf_find_containing_subprog(env, this_subprog_start);
	po_start = subprog->postorder_start;
	po_end = (subprog + 1)->postorder_start;
	cnt = 0;
	/* repeat until fixed point is reached */
	do {
		cnt++;
		changed = false;
		for (frame = 0; frame <= instance->callchain.curframe; frame++) {
			if (!instance->frames[frame])
				continue;

			for (i = po_start; i < po_end; i++)
				changed |= update_insn(env, instance, frame, insn_postorder[i]);
		}
	} while (changed);

	if (env->log.level & BPF_LOG_LEVEL2)
		bpf_log(&env->log, "%s live stack update done in %d iterations\n",
			fmt_callchain(env, callchain), cnt);

	/* transfer marks accumulated for outer frames to outer func instance (caller) */
	if (callchain->curframe > 0) {
		err = propagate_to_outer_instance(env, instance);
		if (err)
			return err;
	}

	return 0;
}

/*
 * Prepare all callchains within @env->cur_state for querying.
 * This function should be called after each verifier.c:pop_stack()
 * and whenever verifier.c:do_check_insn() processes subprogram exit.
 * This would guarantee that visited verifier states with zero branches
 * have their bpf_mark_stack_{read,write}() effects propagated in
 * @env->liveness.
 */
int bpf_update_live_stack(struct bpf_verifier_env *env)
{
	struct func_instance *instance;
	int err, frame;

	bpf_reset_live_stack_callchain(env);
	for (frame = env->cur_state->curframe; frame >= 0; --frame) {
		instance = lookup_instance(env, env->cur_state, frame);
		if (IS_ERR(instance))
			return PTR_ERR(instance);

		if (instance->updated) {
			err = update_instance(env, instance);
			if (err)
				return err;
			instance->updated = false;
			instance->must_write_dropped = false;
		}
	}
	return 0;
}

static bool is_live_before(struct func_instance *instance, u32 insn_idx, u32 frameno, u32 spi)
{
	struct per_frame_masks *masks;

	masks = get_frame_masks(instance, frameno, insn_idx);
	return masks && (masks->live_before & BIT(spi));
}

int bpf_live_stack_query_init(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct live_stack_query *q = &env->liveness->live_stack_query;
	struct func_instance *instance;
	u32 frame;

	memset(q, 0, sizeof(*q));
	for (frame = 0; frame <= st->curframe; frame++) {
		instance = lookup_instance(env, st, frame);
		if (IS_ERR(instance))
			return PTR_ERR(instance);
		q->instances[frame] = instance;
	}
	q->curframe = st->curframe;
	q->insn_idx = st->insn_idx;
	return 0;
}

bool bpf_stack_slot_alive(struct bpf_verifier_env *env, u32 frameno, u32 spi)
{
	/*
	 * Slot is alive if it is read before q->st->insn_idx in current func instance,
	 * or if for some outer func instance:
	 * - alive before callsite if callsite calls callback, otherwise
	 * - alive after callsite
	 */
	struct live_stack_query *q = &env->liveness->live_stack_query;
	struct func_instance *instance, *curframe_instance;
	u32 i, callsite;
	bool alive;

	curframe_instance = q->instances[q->curframe];
	if (is_live_before(curframe_instance, q->insn_idx, frameno, spi))
		return true;

	for (i = frameno; i < q->curframe; i++) {
		callsite = curframe_instance->callchain.callsites[i];
		instance = q->instances[i];
		alive = bpf_calls_callback(env, callsite)
			? is_live_before(instance, callsite, frameno, spi)
			: is_live_before(instance, callsite + 1, frameno, spi);
		if (alive)
			return true;
	}

	return false;
}

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
