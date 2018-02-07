// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>

#include "bpfilter_mod.h"

/* TODO: Get all of this in here properly done in encoding/decoding layer. */
static int fetch_name(void *addr, int len, char *name, int name_len)
{
	if (copy_from_user(name, addr, name_len))
		return -EFAULT;

	name[BPFILTER_XT_TABLE_MAXNAMELEN-1] = '\0';
	return 0;
}

int bpfilter_get_info(void *addr, int len)
{
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	struct bpfilter_ipt_get_info resp;
	struct bpfilter_table_info *info;
	struct bpfilter_table *tbl;
	int err;

	if (len != sizeof(struct bpfilter_ipt_get_info))
		return -EINVAL;

	err = fetch_name(addr, len, name, sizeof(name));
	if (err)
		return err;

	tbl = bpfilter_table_get_by_name(name, strlen(name));
	if (!tbl)
		return -ENOENT;

	info = tbl->info;
	if (!info) {
		err = -ENOENT;
		goto out_put;
	}

	memset(&resp, 0, sizeof(resp));
	memcpy(resp.name, name, sizeof(resp.name));
	resp.valid_hooks = tbl->valid_hooks;
	memcpy(&resp.hook_entry, info->hook_entry, sizeof(resp.hook_entry));
	memcpy(&resp.underflow, info->underflow, sizeof(resp.underflow));
	resp.num_entries = info->num_entries;
	resp.size = info->size;

	err = 0;
	if (copy_to_user(addr, &resp, len))
		err = -EFAULT;
out_put:
	bpfilter_table_put(tbl);
	return err;
}

static int target_u2k(struct bpfilter_standard_target *kt)
{
	kt->target.u.kernel.target =
		bpfilter_target_get_by_name(kt->target.u.user.name);
	return kt->target.u.kernel.target ? 0 : -EINVAL;
}

static int target_k2u(struct bpfilter_standard_target *ut,
		      struct bpfilter_standard_target *kt)
{
	struct bpfilter_target *tgt;

	if (put_user(kt->target.u.target_size,
		     &ut->target.u.target_size))
		return -EFAULT;

	tgt = kt->target.u.kernel.target;
	if (copy_to_user(ut->target.u.user.name, tgt->name, strlen(tgt->name)))
		return -EFAULT;
	if (put_user(tgt->rev, &ut->target.u.user.revision))
		return -EFAULT;
	if (copy_to_user(ut->target.data, kt->target.data, tgt->size))
		return -EFAULT;

	return 0;
}

static int do_get_entries(void *up,
			  struct bpfilter_table *tbl,
			  struct bpfilter_table_info *info)
{
	const struct bpfilter_ipt_entry *ent;
	unsigned int total_size = info->size;
	void *base = info->entries;
	unsigned int off;

	for (off = 0; off < total_size; off += ent->next_offset) {
		struct bpfilter_standard_target *tgt;
		struct bpfilter_xt_counters *cntrs;

		ent = base + off;
		if (copy_to_user(up + off, ent, sizeof(*ent)))
			return -EFAULT;
		/* XXX: Just clear counters for now. */
		cntrs = up + off + offsetof(struct bpfilter_ipt_entry, cntrs);
		if (put_user(0, &cntrs->packet_cnt) ||
		    put_user(0, &cntrs->byte_cnt))
			return -EINVAL;
		tgt = (void *)ent + ent->target_offset;
		if (target_k2u(up + off + ent->target_offset, tgt))
			return -EFAULT;
	}
	return 0;
}

int bpfilter_get_entries(void *cmd, int len)
{
	struct bpfilter_ipt_get_entries *uptr = cmd;
	struct bpfilter_ipt_get_entries req;
	struct bpfilter_table_info *info;
	struct bpfilter_table *tbl;
	int err;

	if (len < sizeof(struct bpfilter_ipt_get_entries))
		return -EINVAL;
	if (copy_from_user(&req, cmd, sizeof(req)))
		return -EFAULT;
	tbl = bpfilter_table_get_by_name(req.name, strlen(req.name));
	if (!tbl)
		return -ENOENT;
	info = tbl->info;
	if (!info) {
		err = -ENOENT;
		goto out_put;
	}
	if (info->size != req.size) {
		err = -EINVAL;
		goto out_put;
	}
	err = do_get_entries(uptr->entries, tbl, info);
out_put:
	bpfilter_table_put(tbl);
	return err;
}

static int do_set_replace(struct bpfilter_ipt_replace *req, void *base,
			  struct bpfilter_table *tbl)
{
	unsigned int total_size = req->size;
	struct bpfilter_table_info *info;
	struct bpfilter_ipt_entry *ent;
	struct bpfilter_gen_ctx ctx;
	unsigned int off, sents = 0, ents = 0;
	int ret;

	ret = bpfilter_gen_init(&ctx);
	if (ret < 0)
		return ret;
	ret = bpfilter_gen_prologue(&ctx);
	if (ret < 0)
		return ret;
	info = bpfilter_ipv4_table_alloc(tbl, total_size);
	if (!info)
		return -ENOMEM;
	if (copy_from_user(&info->entries[0], base, req->size)) {
		free(info);
		return -EFAULT;
	}
	base = &info->entries[0];
	for (off = 0; off < total_size; off += ent->next_offset) {
		struct bpfilter_standard_target *tgt;
		ent = base + off;
		ents++;
		sents += ent->next_offset;
		tgt = (void *) ent + ent->target_offset;
		target_u2k(tgt);
		ret = bpfilter_gen_append(&ctx, &ent->ip, tgt->verdict);
                if (ret < 0)
                        goto err;
	}
	info->num_entries = ents;
	info->size = sents;
	memcpy(info->hook_entry, req->hook_entry, sizeof(info->hook_entry));
	memcpy(info->underflow, req->underflow, sizeof(info->hook_entry));
	ret = bpfilter_gen_epilogue(&ctx);
	if (ret < 0)
		goto err;
	ret = bpfilter_gen_commit(&ctx);
	if (ret < 0)
		goto err;
	free(tbl->info);
	tbl->info = info;
	bpfilter_gen_destroy(&ctx);
	dprintf(debug_fd, "offloaded %u\n", ctx.offloaded);
	return ret;
err:
	free(info);
	return ret;
}

int bpfilter_set_replace(void *cmd, int len)
{
	struct bpfilter_ipt_replace *uptr = cmd;
	struct bpfilter_ipt_replace req;
	struct bpfilter_table_info *info;
	struct bpfilter_table *tbl;
	int err;

	if (len < sizeof(req))
		return -EINVAL;
	if (copy_from_user(&req, cmd, sizeof(req)))
		return -EFAULT;
	if (req.num_counters >= INT_MAX / sizeof(struct bpfilter_xt_counters))
		return -ENOMEM;
	if (req.num_counters == 0)
		return -EINVAL;
	req.name[sizeof(req.name) - 1] = 0;
	tbl = bpfilter_table_get_by_name(req.name, strlen(req.name));
	if (!tbl)
		return -ENOENT;
	info = tbl->info;
	if (!info) {
		err = -ENOENT;
		goto out_put;
	}
	err = do_set_replace(&req, uptr->entries, tbl);
out_put:
	bpfilter_table_put(tbl);
	return err;
}

int bpfilter_set_add_counters(void *cmd, int len)
{
	return 0;
}
