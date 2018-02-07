// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/bpf.h>
typedef __u16 __bitwise __sum16; /* hack */
#include <linux/ip.h>

#include <arpa/inet.h>

#include "bpfilter_mod.h"

unsigned int if_nametoindex(const char *ifname);

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int bpf_prog_load(enum bpf_prog_type type,
			 const struct bpf_insn *insns,
			 unsigned int insn_num,
			 __u32 offload_ifindex)
{
	union bpf_attr attr = {};

	attr.prog_type		= type;
	attr.insns		= bpf_ptr_to_u64(insns);
	attr.insn_cnt		= insn_num;
	attr.license		= bpf_ptr_to_u64("GPL");
	attr.prog_ifindex	= offload_ifindex;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	struct sockaddr_nl sa;
	int sock, seq = 0, len, ret = -1;
	char buf[4096];
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | 43/*IFLA_XDP*/;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
	nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = 3/*IFLA_XDP_FLAGS*/;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
		nla->nla_len += nla_xdp->nla_len;
	}

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		printf("recv from netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_pid != getpid()) {
			printf("Wrong pid %d, expected %d\n",
			       nh->nlmsg_pid, getpid());
			goto cleanup;
		}
		if (nh->nlmsg_seq != seq) {
			printf("Wrong seq %d, expected %d\n",
			       nh->nlmsg_seq, seq);
			goto cleanup;
		}
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (!err->error)
				continue;
			printf("nlmsg error %s\n", strerror(-err->error));
			goto cleanup;
		case NLMSG_DONE:
			break;
		}
	}

	ret = 0;

cleanup:
	close(sock);
	return ret;
}

static int bpfilter_load_dev(struct bpfilter_gen_ctx *ctx)
{
	u32 xdp_flags = 0;

	if (ctx->offloaded)
		xdp_flags |= XDP_FLAGS_HW_MODE;
	return bpf_set_link_xdp_fd(ctx->ifindex, ctx->fd, xdp_flags);
}

int bpfilter_gen_init(struct bpfilter_gen_ctx *ctx)
{
	unsigned int len_max = BPF_MAXINSNS;

	memset(ctx, 0, sizeof(*ctx));
	ctx->img = calloc(len_max, sizeof(struct bpf_insn));
	if (!ctx->img)
		return -ENOMEM;
	ctx->len_max = len_max;
	ctx->fd = -1;
	ctx->default_verdict = XDP_PASS;

	return 0;
}

#define EMIT(x)						\
	do {						\
		if (ctx->len_cur + 1 > ctx->len_max)	\
			return -ENOMEM;			\
		ctx->img[ctx->len_cur++] = x;		\
	} while (0)

int bpfilter_gen_prologue(struct bpfilter_gen_ctx *ctx)
{
	EMIT(BPF_MOV64_REG(BPF_REG_9, BPF_REG_1));
	EMIT(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_9,
			 offsetof(struct xdp_md, data)));
	EMIT(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_9,
			 offsetof(struct xdp_md, data_end)));
	EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
	EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, ETH_HLEN));
	EMIT(BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 2));
	EMIT(BPF_MOV32_IMM(BPF_REG_0, ctx->default_verdict));
	EMIT(BPF_EXIT_INSN());
	return 0;
}

int bpfilter_gen_epilogue(struct bpfilter_gen_ctx *ctx)
{
	EMIT(BPF_MOV32_IMM(BPF_REG_0, ctx->default_verdict));
	EMIT(BPF_EXIT_INSN());
	return 0;
}

static int bpfilter_gen_check_entry(const struct bpfilter_ipt_ip *ent)
{
#define M_FF	"\xff\xff\xff\xff"
	static const __u8 mask1[IFNAMSIZ] = M_FF M_FF M_FF M_FF;
	static const __u8 mask0[IFNAMSIZ] = { };
	int ones = strlen(ent->in_iface); ones += ones > 0;
#undef M_FF
	if (strlen(ent->out_iface) > 0)
		return -ENOTSUPP;
	if (memcmp(ent->in_iface_mask, mask1, ones) ||
	    memcmp(&ent->in_iface_mask[ones], mask0, sizeof(mask0) - ones))
		return -ENOTSUPP;
	if ((ent->src_mask != 0 && ent->src_mask != 0xffffffff) ||
	    (ent->dst_mask != 0 && ent->dst_mask != 0xffffffff))
		return -ENOTSUPP;

	return 0;
}

int bpfilter_gen_append(struct bpfilter_gen_ctx *ctx,
			struct bpfilter_ipt_ip *ent, int verdict)
{
	u32 match_xdp = verdict == -1 ? XDP_DROP : XDP_PASS;
	int ret, ifindex, match_state = 0;

	/* convention R1: tmp, R2: data, R3: data_end, R9: xdp_buff */
	ret = bpfilter_gen_check_entry(ent);
	if (ret < 0)
		return ret;
	if (ent->src_mask == 0 && ent->dst_mask == 0)
		return 0;

	ifindex = if_nametoindex(ent->in_iface);
	if (!ifindex)
		return 0;
	if (ctx->ifindex && ctx->ifindex != ifindex)
		return -ENOTSUPP;

	ctx->ifindex = ifindex;
	match_state = !!ent->src_mask + !!ent->dst_mask;

	EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_2));
	EMIT(BPF_MOV32_IMM(BPF_REG_5, 0));
	EMIT(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_1,
			 offsetof(struct ethhdr, h_proto)));
	EMIT(BPF_JMP_IMM(BPF_JNE, BPF_REG_4, htons(ETH_P_IP),
			 3 + match_state * 3));
	EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
			   sizeof(struct ethhdr) + sizeof(struct iphdr)));
	EMIT(BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 1 + match_state * 3));
	EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -(int)sizeof(struct iphdr)));
	if (ent->src_mask) {
		EMIT(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1,
				 offsetof(struct iphdr, saddr)));
		EMIT(BPF_JMP_IMM(BPF_JNE, BPF_REG_4, ent->src, 1));
		EMIT(BPF_ALU32_IMM(BPF_ADD, BPF_REG_5, 1));
	}
	if (ent->dst_mask) {
		EMIT(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1,
				 offsetof(struct iphdr, daddr)));
		EMIT(BPF_JMP_IMM(BPF_JNE, BPF_REG_4, ent->dst, 1));
		EMIT(BPF_ALU32_IMM(BPF_ADD, BPF_REG_5, 1));
	}
	EMIT(BPF_JMP_IMM(BPF_JNE, BPF_REG_5, match_state, 2));
	EMIT(BPF_MOV32_IMM(BPF_REG_0, match_xdp));
	EMIT(BPF_EXIT_INSN());
	return 0;
}

int bpfilter_gen_commit(struct bpfilter_gen_ctx *ctx)
{
	int ret;

	ret = bpf_prog_load(BPF_PROG_TYPE_XDP, ctx->img,
			    ctx->len_cur, ctx->ifindex);
	if (ret > 0)
		ctx->offloaded = true;
	if (ret < 0)
		ret = bpf_prog_load(BPF_PROG_TYPE_XDP, ctx->img,
				    ctx->len_cur, 0);
	if (ret > 0) {
		ctx->fd = ret;
		ret = bpfilter_load_dev(ctx);
	}

	return ret < 0 ? ret : 0;
}

void bpfilter_gen_destroy(struct bpfilter_gen_ctx *ctx)
{
	free(ctx->img);
	close(ctx->fd);
}
