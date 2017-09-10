/*
 * Functions to manage eBPF programs attached to cgroups
 *
 * Copyright (c) 2016 Daniel Mack
 *
 * This file is subject to the terms and conditions of version 2 of the GNU
 * General Public License.  See the file COPYING in the main directory of the
 * Linux distribution for more details.
 */

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <net/sock.h>

DEFINE_STATIC_KEY_FALSE(cgroup_bpf_enabled_key);
EXPORT_SYMBOL(cgroup_bpf_enabled_key);

/**
 * cgroup_bpf_put() - put references of all bpf programs
 * @cgrp: the cgroup to modify
 */
void cgroup_bpf_put(struct cgroup *cgrp)
{
	unsigned int type;

	for (type = 0; type < ARRAY_SIZE(cgrp->bpf.progs); type++) {
		struct list_head *progs = &cgrp->bpf.progs[type];
		struct bpf_prog_list *pl;

		list_for_each_entry(pl, progs, node) {
			bpf_prog_put(pl->prog);
			static_branch_dec(&cgroup_bpf_enabled_key);
		}
		bpf_prog_array_free(cgrp->bpf.effective[type]);
	}
}

/* count number of elements in the list.
 * it's slow but the list cannot be long
 */
static u32 list_length(struct list_head *head)
{
	struct list_head *pos;
	u32 cnt = 0;

	list_for_each(pos, head)
		cnt++;
	return cnt;
}

/* if parent has non-overridable prog attached,
 * disallow attaching new programs to the descendent cgroup.
 * if parent has overridable or multi-prog, allow attaching
 */
static bool hierarchy_allows_attach(struct cgroup *cgrp,
				    enum bpf_attach_type type,
				    u32 new_flags)
{
	struct cgroup *p;

	p = cgroup_parent(cgrp);
	do {
		u32 flags = p->bpf.flags[type];
		u32 cnt;

		if (flags & BPF_F_ALLOW_MULTI)
			return true;
		cnt = list_length(&p->bpf.progs[type]);
		WARN_ON_ONCE(cnt > 1);
		if (cnt == 1)
			return !!(flags & BPF_F_ALLOW_OVERRIDE);
		p = cgroup_parent(p);
	} while (p);
	return true;
}

/* compute a chain of effective programs for a given cgroup:
 * start from the list of programs in this cgroup and add
 * all parent programs.
 * Note that parent's F_ALLOW_OVERRIDE-type program is yelding
 * to programs in this cgroup
 */
static int compute_effective_progs(struct cgroup *cgrp,
				   enum bpf_attach_type type)
{
	struct bpf_prog_array __rcu *progs, *old_progs;
	struct cgroup *p = cgrp;
	struct bpf_prog_list *pl;
	int cnt = 0;
	u32 flags;

	/* count number of effective programs by walking parents */
	do {
		flags = p->bpf.flags[type];
		if (cnt == 0 || (flags & BPF_F_ALLOW_MULTI))
			cnt += list_length(&p->bpf.progs[type]);
		p = cgroup_parent(p);
	} while (p);

	progs = bpf_prog_array_alloc(cnt, GFP_KERNEL);
	if (!progs)
		return -ENOMEM;

	/* populate the array with effective progs */
	cnt = 0;
	p = cgrp;
	do {
		if (cnt == 0 || (p->bpf.flags[type] & BPF_F_ALLOW_MULTI))
			list_for_each_entry(pl,
					    &p->bpf.progs[type], node)
				progs->progs[cnt++] = pl->prog;
		p = cgroup_parent(p);
	} while (p);

	old_progs = xchg(&cgrp->bpf.effective[type], progs);
	/* free prog array after grace period, since __cgroup_bpf_run_*()
	 * might be still walking the array
	 */
	bpf_prog_array_free(old_progs);
	return 0;
}

/**
 * cgroup_bpf_inherit() - inherit effective programs from parent
 * @cgrp: the cgroup to modify
 */
int cgroup_bpf_inherit(struct cgroup *cgrp)
{
	unsigned int type;

	for (type = 0; type < ARRAY_SIZE(cgrp->bpf.progs); type++)
		INIT_LIST_HEAD(&cgrp->bpf.progs[type]);

	for (type = 0; type < ARRAY_SIZE(cgrp->bpf.progs); type++)
		if (compute_effective_progs(cgrp, type))
			goto cleanup;
	return 0;
cleanup:
	BUILD_BUG_ON(ARRAY_SIZE(cgrp->bpf.effective) != ARRAY_SIZE(cgrp->bpf.progs));
	for (type = 0; type < ARRAY_SIZE(cgrp->bpf.effective); type++)
		bpf_prog_array_free(cgrp->bpf.effective[type]);
	return -ENOMEM;
}

#define BPF_CGROUP_MAX_PROGS 64

/**
 * __cgroup_bpf_attach() - Attach the program to a cgroup, and
 *                         propagate the change to descendants
 * @cgrp: The cgroup which descendants to traverse
 * @parent: The parent of @cgrp
 * @prog: A program to attach
 * @type: Type of attach operation
 *
 * Must be called with cgroup_mutex held.
 */
int __cgroup_bpf_attach(struct cgroup *cgrp, struct cgroup *parent,
			struct bpf_prog *prog, enum bpf_attach_type type,
			u32 flags)
{
	struct list_head *progs = &cgrp->bpf.progs[type];
	struct bpf_prog *old_prog = NULL;
	struct cgroup_subsys_state *css;
	struct bpf_prog_list *pl;

	if ((flags & BPF_F_ALLOW_OVERRIDE) && (flags & BPF_F_ALLOW_MULTI))
		/* invalid combination */
		return -EINVAL;

	if (!hierarchy_allows_attach(cgrp, type, flags))
		return -EPERM;

	if (!list_empty(progs) && cgrp->bpf.flags[type] != flags)
		/* Disallow attaching non-overridable on top
		 * of existing overridable in this cgroup.
		 * Disallow attaching multi-prog if overridable or none
		 */
		return -EPERM;

	if (list_length(progs) >= BPF_CGROUP_MAX_PROGS)
		return -E2BIG;

	if (flags & BPF_F_ALLOW_MULTI) {
		list_for_each_entry(pl, progs, node)
			if (pl->prog == prog)
				/* disallow attaching the same prog twice */
				return -EINVAL;

		pl = kmalloc(sizeof(*pl), GFP_KERNEL);
		if (!pl)
			return -ENOMEM;
		pl->prog = prog;
		list_add_tail(&pl->node, progs);
	} else {
		if (list_empty(progs)) {
			pl = kmalloc(sizeof(*pl), GFP_KERNEL);
			if (!pl)
				return -ENOMEM;
			list_add_tail(&pl->node, progs);
		} else {
			old_prog = pl->prog;
			pl = list_first_entry(progs, typeof(*pl), node);
		}
		pl->prog = prog;
	}

	cgrp->bpf.flags[type] = flags;

	css_for_each_descendant_pre(css, &cgrp->self) {
		struct cgroup *desc = container_of(css, struct cgroup, self);

		if (compute_effective_progs(desc, type))
			goto cleanup;
	}

	static_branch_inc(&cgroup_bpf_enabled_key);

	if (old_prog) {
		bpf_prog_put(old_prog);
		static_branch_dec(&cgroup_bpf_enabled_key);
	}
	return 0;

cleanup:
	/* oom while computing effective! we cannot recompute
	 * effective progs that were successfully computed,
	 * since it involves allocating and freeing memory,
	 * hence find the new prog in the effective array and replace
	 * with dummy prog that acts like a nop when executed or
	 * old_prog if it was valid
	 */
	css_for_each_descendant_pre(css, &cgrp->self) {
		struct cgroup *desc = container_of(css, struct cgroup, self);

		if ((flags & BPF_F_ALLOW_MULTI) || !old_prog)
			bpf_prog_array_delete_safe(desc->bpf.effective[type],
						   prog);
		else
			bpf_prog_array_replace_with(desc->bpf.effective[type],
						    prog, old_prog);
	}

	/* now need to cleanup the list */
	if (flags & BPF_F_ALLOW_MULTI) {
		list_for_each_entry(pl, progs, node)
			if (pl->prog == prog) {
				list_del(&pl->node);
				kfree(pl);
			}
	} else {
		pl = list_first_entry(progs, typeof(*pl), node);
		if (old_prog) {
			pl->prog = old_prog;
		} else {
			list_del(&pl->node);
			kfree(pl);
			WARN_ON_ONCE(!list_empty(progs));
		}
	}

	return -ENOMEM;
}

/**
 * __cgroup_bpf_detach() - Detach the program from a cgroup, and
 *                         propagate the change to descendants
 * @cgrp: The cgroup which descendants to traverse
 * @parent: The parent of @cgrp
 * @prog: A program to detach or NULL
 * @type: Type of detach operation
 *
 * Must be called with cgroup_mutex held.
 */
int __cgroup_bpf_detach(struct cgroup *cgrp, struct cgroup *parent,
			struct bpf_prog *prog, enum bpf_attach_type type,
			u32 unused_flags)
{
	struct list_head *progs = &cgrp->bpf.progs[type];
	u32 flags = cgrp->bpf.flags[type];
	struct bpf_prog *old_prog = NULL;
	struct cgroup_subsys_state *css;
	struct bpf_prog_list *pl;

	if (flags & BPF_F_ALLOW_MULTI) {
		if (!prog)
			/* to detach MULTI prog the user has to specify valid FD
			 * of the program to be detached
			 */
			return -EINVAL;

		/* find the prog and detach it */
		list_for_each_entry(pl, progs, node) {
			if (pl->prog != prog)
				continue;
			old_prog = pl->prog;
			list_del(&pl->node);
			kfree(pl);
			break;
		}
		if (!old_prog)
			return -ENOENT;
	} else {
		if (list_empty(progs))
			/* report error when trying to detach and nothing is attached */
			return -ENOENT;
		/* to maintain backward compatiblity NONE and OVERRIDE cgroups
		 * allow detaching with invalid FD (prog==NULL)
		 */
		pl = list_first_entry(progs, typeof(*pl), node);
		old_prog = pl->prog;
		list_del(&pl->node);
		kfree(pl);
	}

	if (list_empty(progs))
		/* last program was detached, reset flags to zero */
		cgrp->bpf.flags[type] = 0;

	/* recompute effective */
	css_for_each_descendant_pre(css, &cgrp->self) {
		struct cgroup *desc = container_of(css, struct cgroup, self);

		if (compute_effective_progs(desc, type))
			goto cleanup;
	}

ok:
	bpf_prog_put(old_prog);
	static_branch_dec(&cgroup_bpf_enabled_key);
	return 0;

cleanup:
	/* oom while computing effective!
	 * since we're detaching the prog, modify the effective
	 * array in place and replace that old prog with dummy prog
	 * that acts like a nop when executed.
	 * Next detach or attach will automatically get rid of it
	 */
	css_for_each_descendant_pre(css, &cgrp->self) {
		struct cgroup *desc = container_of(css, struct cgroup, self);

		bpf_prog_array_delete_safe(desc->bpf.effective[type],
					   old_prog);
	}

	/* no need to cleanup the list, we're detaching the prog and
	 * though it's an error case the detach is still successful
	 */
	goto ok;
}

/**
 * __cgroup_bpf_run_filter_skb() - Run a program for packet filtering
 * @sk: The socket sending or receiving traffic
 * @skb: The skb that is being sent or received
 * @type: The type of program to be exectuted
 *
 * If no socket is passed, or the socket is not of type INET or INET6,
 * this function does nothing and returns 0.
 *
 * The program type passed in via @type must be suitable for network
 * filtering. No further check is performed to assert that.
 *
 * This function will return %-EPERM if any if an attached program was found
 * and if it returned != 1 during execution. In all other cases, 0 is returned.
 */
int __cgroup_bpf_run_filter_skb(struct sock *sk,
				struct sk_buff *skb,
				enum bpf_attach_type type)
{
	struct bpf_prog **prog;
	struct cgroup *cgrp;
	int ret = 0;

	if (!sk || !sk_fullsock(sk))
		return 0;

	if (sk->sk_family != AF_INET &&
	    sk->sk_family != AF_INET6)
		return 0;

	cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);

	rcu_read_lock();

	prog = rcu_dereference(cgrp->bpf.effective[type])->progs;
	for (; *prog && !ret; prog++) {
		unsigned int offset = skb->data - skb_network_header(skb);
		struct sock *save_sk = skb->sk;

		skb->sk = sk;
		__skb_push(skb, offset);
		ret = bpf_prog_run_save_cb(*prog, skb) == 1 ? 0 : -EPERM;
		__skb_pull(skb, offset);
		skb->sk = save_sk;
	}

	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter_skb);

/**
 * __cgroup_bpf_run_filter_sk() - Run a program on a sock
 * @sk: sock structure to manipulate
 * @type: The type of program to be exectuted
 *
 * socket is passed is expected to be of type INET or INET6.
 *
 * The program type passed in via @type must be suitable for sock
 * filtering. No further check is performed to assert that.
 *
 * This function will return %-EPERM if any if an attached program was found
 * and if it returned != 1 during execution. In all other cases, 0 is returned.
 */
int __cgroup_bpf_run_filter_sk(struct sock *sk,
			       enum bpf_attach_type type)
{
	struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	struct bpf_prog **prog;
	int ret = 0;


	rcu_read_lock();

	prog = rcu_dereference(cgrp->bpf.effective[type])->progs;
	for (; *prog && !ret; prog++)
		ret = BPF_PROG_RUN(*prog, sk) == 1 ? 0 : -EPERM;

	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter_sk);

/**
 * __cgroup_bpf_run_filter_sock_ops() - Run a program on a sock
 * @sk: socket to get cgroup from
 * @sock_ops: bpf_sock_ops_kern struct to pass to program. Contains
 * sk with connection information (IP addresses, etc.) May not contain
 * cgroup info if it is a req sock.
 * @type: The type of program to be exectuted
 *
 * socket passed is expected to be of type INET or INET6.
 *
 * The program type passed in via @type must be suitable for sock_ops
 * filtering. No further check is performed to assert that.
 *
 * This function will return %-EPERM if any if an attached program was found
 * and if it returned != 1 during execution. In all other cases, 0 is returned.
 */
int __cgroup_bpf_run_filter_sock_ops(struct sock *sk,
				     struct bpf_sock_ops_kern *sock_ops,
				     enum bpf_attach_type type)
{
	struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	struct bpf_prog **prog;
	int ret = 0;


	rcu_read_lock();

	prog = rcu_dereference(cgrp->bpf.effective[type])->progs;
	for (; *prog && !ret; prog++)
		ret = BPF_PROG_RUN(*prog, sock_ops) == 1 ? 0 : -EPERM;

	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter_sock_ops);
