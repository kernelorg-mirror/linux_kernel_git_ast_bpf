/* Copyright (c) 2011-2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _LINUX_KERNEL_BPF_TRACE_H
#define _LINUX_KERNEL_BPF_TRACE_H

/* For tracepoint filters argN fields match one to one to arguments
 * passed to tracepoint events
 *
 * For syscall entry filters argN fields match syscall arguments
 * For syscall exit filters arg1 is a return value
 */
struct bpf_context {
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 arg4;
	u64 arg5;
	u64 arg6;
};

#endif /* _LINUX_KERNEL_BPF_TRACE_H */
