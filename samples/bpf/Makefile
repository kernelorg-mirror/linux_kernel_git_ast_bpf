# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# List of programs to build
hostprogs-y := dropmon test_verifier ex1 ex2

dropmon-objs := dropmon.o libbpf.o
test_verifier-objs := test_verifier.o libbpf.o
ex1-objs := bpf_load.o libbpf.o ex1_user.o
ex2-objs := bpf_load.o libbpf.o ex2_user.o

# Tell kbuild to always build the programs
always := $(hostprogs-y) ex1_kern.o ex2_kern.o

HOSTCFLAGS += -I$(objtree)/usr/include

HOSTCFLAGS_bpf_load.o += -I$(objtree)/usr/include -Wno-unused-variable
HOSTLOADLIBES_ex1 += -lelf
HOSTLOADLIBES_ex2 += -lelf

LLC=$(srctree)/tools/bpf/llvm/bld/Debug+Asserts/bin/llc

%.o: %.c
	clang $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-O2 -emit-llvm -c $< -o -| $(LLC) -o $@
