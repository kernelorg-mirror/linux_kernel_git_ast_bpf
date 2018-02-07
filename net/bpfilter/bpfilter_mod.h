/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPFILTER_INTERNAL_H
#define _LINUX_BPFILTER_INTERNAL_H

#include "include/uapi/linux/bpfilter.h"
#include <linux/list.h>

struct bpfilter_table {
	struct hlist_node	hash;
	u32			valid_hooks;
	struct			bpfilter_table_info *info;
	int			hold;
	u8			family;
	int			priority;
	const char		name[BPFILTER_XT_TABLE_MAXNAMELEN];
};

struct bpfilter_table_info {
	unsigned int		size;
	u32			num_entries;
	unsigned int		initial_entries;
	unsigned int		hook_entry[BPFILTER_INET_HOOK_MAX];
	unsigned int		underflow[BPFILTER_INET_HOOK_MAX];
//	unsigned int		stacksize;
//	void			***jumpstack;
	unsigned char		entries[0] __aligned(8);
};

struct bpfilter_table *bpfilter_table_get_by_name(const char *name, int name_len);
void bpfilter_table_put(struct bpfilter_table *tbl);
int bpfilter_table_add(struct bpfilter_table *tbl);

struct bpfilter_ipt_standard {
	struct bpfilter_ipt_entry	entry;
	struct bpfilter_standard_target	target;
};

struct bpfilter_ipt_error {
	struct bpfilter_ipt_entry	entry;
	struct bpfilter_error_target	target;
};

#define BPFILTER_IPT_ENTRY_INIT(__sz) 				\
{								\
	.target_offset = sizeof(struct bpfilter_ipt_entry),	\
	.next_offset = (__sz),					\
}

#define BPFILTER_IPT_STANDARD_INIT(__verdict) 					\
{										\
	.entry = BPFILTER_IPT_ENTRY_INIT(sizeof(struct bpfilter_ipt_standard)),	\
	.target = BPFILTER_TARGET_INIT(BPFILTER_STANDARD_TARGET,		\
				       sizeof(struct bpfilter_standard_target)),\
	.target.verdict = -(__verdict) - 1,					\
}

#define BPFILTER_IPT_ERROR_INIT							\
{										\
	.entry = BPFILTER_IPT_ENTRY_INIT(sizeof(struct bpfilter_ipt_error)),	\
	.target = BPFILTER_TARGET_INIT(BPFILTER_ERROR_TARGET,			\
				       sizeof(struct bpfilter_error_target)),	\
	.target.error_name = "ERROR",						\
}

struct bpfilter_target {
	struct list_head	all_target_list;
	char			name[BPFILTER_EXTENSION_MAXNAMELEN];
	unsigned int		size;
	int			hold;
	u16			family;
	u8			rev;
};

struct bpfilter_gen_ctx {
	struct bpf_insn		*img;
	u32			len_cur;
	u32			len_max;
	u32			default_verdict;
	int			fd;
	int			ifindex;
	bool			offloaded;
};

union bpf_attr;
int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size);

int bpfilter_gen_init(struct bpfilter_gen_ctx *ctx);
int bpfilter_gen_prologue(struct bpfilter_gen_ctx *ctx);
int bpfilter_gen_epilogue(struct bpfilter_gen_ctx *ctx);
int bpfilter_gen_append(struct bpfilter_gen_ctx *ctx,
			struct bpfilter_ipt_ip *ent, int verdict);
int bpfilter_gen_commit(struct bpfilter_gen_ctx *ctx);
void bpfilter_gen_destroy(struct bpfilter_gen_ctx *ctx);

struct bpfilter_target *bpfilter_target_get_by_name(const char *name);
void bpfilter_target_put(struct bpfilter_target *tgt);
int bpfilter_target_add(struct bpfilter_target *tgt);

struct bpfilter_table_info *
bpfilter_ipv4_table_alloc(struct bpfilter_table *tbl, __u32 size_ents);
struct bpfilter_table_info *
bpfilter_ipv4_table_finalize(struct bpfilter_table *tbl,
			     struct bpfilter_table_info *info,
			     __u32 size_ents, __u32 num_ents);
struct bpfilter_table_info *
bpfilter_ipv4_table_finalize2(struct bpfilter_table *tbl,
			      struct bpfilter_table_info *info,
			      __u32 size_ents, __u32 num_ents);

int bpfilter_ipv4_register_targets(void);
void bpfilter_tables_init(void);
int bpfilter_get_info(void *addr, int len);
int bpfilter_get_entries(void *cmd, int len);
int bpfilter_set_replace(void *cmd, int len);
int bpfilter_set_add_counters(void *cmd, int len);
int bpfilter_ipv4_init(void);

int copy_from_user(void *dst, void *addr, int len);
int copy_to_user(void *addr, const void *src, int len);
#define put_user(x, ptr) \
({ \
	__typeof__(*(ptr)) __x = (x); \
	copy_to_user(ptr, &__x, sizeof(*(ptr))); \
})
extern int pid;
extern int debug_fd;
#define ENOTSUPP        524

/* Helper macros for filter block array initializers. */

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */

#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg = imm32 */

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Atomic memory add, *(uint *)(dst_reg + off16) += src_reg */

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Unconditional jumps, goto pc + off16 */

#define BPF_JMP_A(OFF)						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Function call */

#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - __bpf_call_base) })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#endif
