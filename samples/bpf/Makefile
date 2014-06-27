# kbuild trick to avoid linker error. Can be omitted if a module is built.
obj- := dummy.o

# List of programs to build
hostprogs-y := dropmon test_verifier

dropmon-objs := dropmon.o libbpf.o
test_verifier-objs := test_verifier.o libbpf.o

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS += -I$(objtree)/usr/include
