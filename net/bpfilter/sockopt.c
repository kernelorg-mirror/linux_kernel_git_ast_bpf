// SPDX-License-Identifier: GPL-2.0
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "bpfilter_mod.h"

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

static int copy_target(struct bpfilter_standard_target *ut,
		       struct bpfilter_standard_target *kt)
{
	struct bpfilter_target *tgt;
	int sz;


	if (put_user(kt->target.u.target_size,
		     &ut->target.u.target_size))
		return -EFAULT;

	tgt = kt->target.u.kernel.target;
	if (copy_to_user(ut->target.u.user.name, tgt->name, strlen(tgt->name)))
		return -EFAULT;

	if (put_user(tgt->rev, &ut->target.u.user.revision))
		return -EFAULT;

	sz = tgt->size;
	if (copy_to_user(ut->target.data, kt->target.data, sz))
		return -EFAULT;

	return 0;
}

static int do_get_entries(void *up,
			  struct bpfilter_table *tbl,
			  struct bpfilter_table_info *info)
{
	unsigned int total_size = info->size;
	const struct bpfilter_ipt_entry *ent;
	unsigned int off;
	void *base;

	base = info->entries;

	for (off = 0; off < total_size; off += ent->next_offset) {
		struct bpfilter_xt_counters *cntrs;
		struct bpfilter_standard_target *tgt;

		ent = base + off;
		if (copy_to_user(up + off, ent, sizeof(*ent)))
			return -EFAULT;

		/* XXX Just clear counters for now. XXX */
		cntrs = up + off + offsetof(struct bpfilter_ipt_entry, cntrs);
		if (put_user(0, &cntrs->packet_cnt) ||
		    put_user(0, &cntrs->byte_cnt))
			return -EINVAL;

		tgt = (void *) ent + ent->target_offset;
		dprintf(debug_fd, "target.verdict %d\n", tgt->verdict);
		if (copy_target(up + off + ent->target_offset, tgt))
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
	dprintf(debug_fd, "do_get_entries %d req.size %d\n", err, req.size);

out_put:
	bpfilter_table_put(tbl);

	return err;
}

