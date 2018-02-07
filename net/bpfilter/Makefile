# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux BPFILTER layer.
#

hostprogs-y := bpfilter_umh
bpfilter_umh-objs := main.o tgts.o targets.o tables.o init.o ctor.o sockopt.o
HOSTCFLAGS += -I. -Itools/include/

quiet_cmd_copy_umh = GEN $@
      cmd_copy_umh = echo ':' > $(obj)/.bpfilter_umh.o.cmd; objcopy -I binary -O elf64-x86-64 -B i386 --rename-section .data=.init.rodata $< $@

$(obj)/bpfilter_umh.o: $(obj)/bpfilter_umh
	$(call cmd,copy_umh)

obj-$(CONFIG_BPFILTER) += bpfilter.o
bpfilter-objs += bpfilter_kern.o bpfilter_umh.o
