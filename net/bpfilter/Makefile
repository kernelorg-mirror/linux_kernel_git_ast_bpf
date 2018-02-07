# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux BPFILTER layer.
#

hostprogs-y := bpfilter_umh
bpfilter_umh-objs := main.o tgts.o targets.o tables.o init.o ctor.o sockopt.o gen.o
HOSTCFLAGS += -I. -Itools/include/

# a bit of elf magic to convert bpfilter_umh binary into a binary blob
# inside bpfilter_umh.o elf file referenced by
# _binary_net_bpfilter_bpfilter_umh_start symbol
# which bpfilter_kern.c passes further into umh blob loader at run-time
quiet_cmd_copy_umh = GEN $@
      cmd_copy_umh = echo ':' > $(obj)/.bpfilter_umh.o.cmd; \
      $(OBJCOPY) -I binary -O $(CONFIG_OUTPUT_FORMAT) \
      -B `$(OBJDUMP) -f $<|grep architecture|cut -d, -f1|cut -d' ' -f2` \
      --rename-section .data=.init.rodata $< $@

$(obj)/bpfilter_umh.o: $(obj)/bpfilter_umh
	$(call cmd,copy_umh)

obj-$(CONFIG_BPFILTER_UMH) += bpfilter.o
bpfilter-objs += bpfilter_kern.o bpfilter_umh.o
