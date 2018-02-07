// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/umh.h>
#include <linux/bpfilter.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "msgfmt.h"

#define UMH_start _binary_net_bpfilter_bpfilter_umh_start
#define UMH_end _binary_net_bpfilter_bpfilter_umh_end

extern char UMH_start;
extern char UMH_end;

static struct umh_info info;

static void shutdown_umh(struct umh_info *info)
{
	struct task_struct *tsk;

	tsk = pid_task(find_vpid(info->pid), PIDTYPE_PID);
	if (tsk)
		force_sig(SIGKILL, tsk);
	fput(info->pipe_to_umh);
	fput(info->pipe_from_umh);
}

static void stop_umh(void)
{
	if (bpfilter_process_sockopt) {
		bpfilter_process_sockopt = NULL;
		shutdown_umh(&info);
	}
}

static int __bpfilter_process_sockopt(struct sock *sk, int optname,
				      char __user *optval,
				      unsigned int optlen, bool is_set)
{
	struct mbox_request req;
	struct mbox_reply reply;
	loff_t pos;
	ssize_t n;

	req.is_set = is_set;
	req.pid = current->pid;
	req.cmd = optname;
	req.addr = (long) optval;
	req.len = optlen;
	n = __kernel_write(info.pipe_to_umh, &req, sizeof(req), &pos);
	if (n != sizeof(req)) {
		pr_err("write fail %zd\n", n);
		stop_umh();
		return -EFAULT;
	}
	pos = 0;
	n = kernel_read(info.pipe_from_umh, &reply, sizeof(reply), &pos);
	if (n != sizeof(reply)) {
		pr_err("read fail %zd\n", n);
		stop_umh();
		return -EFAULT;
	}
	return reply.status;
}

static int __init load_umh(void)
{
	int err;

	err = fork_usermode_blob(&UMH_start, &UMH_end - &UMH_start, &info);
	if (err)
		return err;
	pr_info("Loaded umh pid %d\n", info.pid);
	bpfilter_process_sockopt = &__bpfilter_process_sockopt;

	if (__bpfilter_process_sockopt(NULL, 0, 0, 0, 0) != 0) {
		stop_umh();
		return -EFAULT;
	}
	return 0;
}

static void __exit fini_umh(void)
{
	stop_umh();
}
module_init(load_umh);
module_exit(fini_umh);
MODULE_LICENSE("GPL");
