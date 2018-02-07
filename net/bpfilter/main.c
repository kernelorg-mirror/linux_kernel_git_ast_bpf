// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/uio.h>
#include <sys/socket.h>

#include <asm/unistd.h>

#include "include/uapi/linux/bpf.h"

#include "bpfilter_mod.h"

extern long int syscall (long int __sysno, ...);

int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(321, cmd, attr, size);
}

int pid;
int debug_fd;

int copy_from_user(void *dst, void *addr, int len)
{
	struct iovec local;
	struct iovec remote;

	local.iov_base = dst;
	local.iov_len = len;
	remote.iov_base = addr;
	remote.iov_len = len;
	return process_vm_readv(pid, &local, 1, &remote, 1, 0) != len;
}

int copy_to_user(void *addr, const void *src, int len)
{
	struct iovec local;
	struct iovec remote;

	local.iov_base = (void *)src;
	local.iov_len = len;
	remote.iov_base = addr;
	remote.iov_len = len;
	return process_vm_writev(pid, &local, 1, &remote, 1, 0) != len;
}

static int handle_get_cmd(struct bpf_mbox_request *cmd)
{
	pid = cmd->pid;
	switch (cmd->cmd) {
	case BPFILTER_IPT_SO_GET_INFO:
		return bpfilter_get_info((void *)(long)cmd->addr, cmd->len);
	case BPFILTER_IPT_SO_GET_ENTRIES:
		return bpfilter_get_entries((void *)(long)cmd->addr, cmd->len);
	default:
		break;
	}
	return -ENOPROTOOPT;
}

static int handle_set_cmd(struct bpf_mbox_request *cmd)
{
	pid = cmd->pid;
	switch (cmd->cmd) {
	case BPFILTER_IPT_SO_SET_REPLACE:
		return bpfilter_set_replace((void *)(long)cmd->addr, cmd->len);
	case BPFILTER_IPT_SO_SET_ADD_COUNTERS:
		return bpfilter_set_add_counters((void *)(long)cmd->addr, cmd->len);
	default:
		break;
	}
	return -ENOPROTOOPT;
}

static void loop(void)
{
	bpfilter_tables_init();
	bpfilter_ipv4_init();

	while (1) {
		union bpf_attr req = {};
		union bpf_attr rep = {};
		struct bpf_mbox_request *cmd;

		req.mbox_request.subsys = BPF_MBOX_SUBSYS_BPFILTER;
		sys_bpf(BPF_MBOX_REQUEST, &req, sizeof(req));
		cmd = &req.mbox_request;
		rep.mbox_reply.subsys = BPF_MBOX_SUBSYS_BPFILTER;
		rep.mbox_reply.status = cmd->kind == BPF_MBOX_KIND_SET ?
					handle_set_cmd(cmd) :
					handle_get_cmd(cmd);
		sys_bpf(BPF_MBOX_REPLY, &rep, sizeof(rep));
	}
}

int main(void)
{
	char buf[4];

	debug_fd = open("/dev/console", 00000002 | 00000100);
	dprintf(debug_fd, "Starting bpfilter\n");
	if (read(0, buf, sizeof(buf)) != 4 || strncmp(buf, "PING", 4) != 0) {
		dprintf(debug_fd,
			"invalid hello message %x\n", *(u32 *)buf);
		return 1;
	}
	if (write(1, buf, sizeof(buf)) != 4)
		return 2;
	dprintf(debug_fd, "Started bpfilter\n");
	loop();
	close(debug_fd);
	return 0;
}
#include <linux/stringify.h>
#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)
#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)
#define __MODULE_INFO(tag, name, info) \
	const char __UNIQUE_ID(name)[] \
	__attribute__((section(".modinfo"), unused, aligned(1))) \
	= __stringify(tag) "=" info
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
MODULE_LICENSE("GPL");
MODULE_INFO(version, "1");
MODULE_INFO(umh, "Y");
