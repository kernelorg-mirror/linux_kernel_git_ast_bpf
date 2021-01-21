================
BPF BATCH Design
================

Present state
=============
Currently libbpf and golang ebpf libraries require sophisticated ELF file
parsers. ELF parsing followed by relocation processing (for maps, BTF.ext,
CO-RE, functions) is 90% work that libbpf and other libraries do. The following
design allows abstracting this work as a new file format.

BPF BATCH Goals
===============

- minimize amount of work libbpf needs to do to load programs.
- remove libelf dependency from various program loaders.
- enable feature parity between libbpf, libbcc and other libraries (golang).
- enable signed BPF programs.
- enable batched BPF syscall to improve performance.
  The batched map_lookup/update/delete can be generalized for all sys_bpf
  commands. For example: attach of multiple programs to different points will
  be possible with one syscall.

Overview
========

Represent the program loading as a sequence of sys_bpf commands with trivial
chaining. For example: to load a program that uses a map the map should be
created first with BPF_MAP_CREATE command. Then its result (map_fd) should be
used to adjust program instructions. Then BPF_PROG_LOAD command can be
executed. In more complex cases BTF needs to be loaded first. Then maps
created. And then programs loaded.

BPF BATCH File Format (BBFF) or Bare Bone File Format
=====================================================

  cmd_0 cmd_1 ... cmd_N signature

Where signature is kernel module like signature that covers [cmd_1 .. cmd_N].

Every command is a variable length structure::

  struct {
    u8 opcode;
    // arguments
  };

cmd_0 always has opcode == BBFF_ARGS and not included in the signature.
It serves as a storage of input arguments (max_entries for maps, attach
locations for progs, rodata, log_level) and output arguments
(log_buf, map/prog FDs).

The opcodes are::

  enum bpf_batch {
    BBFF_EXIT_ON_ERR = 0,
    BBFF_ARGS,         // array of byte arguments
    BBFF_APPLY_ARGS,   // instruction to apply N bytes from argument
                       // array to a specified location
    BBFF_DATA,         // array of data (set of bpf_insn, bpf_line_info, BTF)
    BBFF_CMD,          // execute sys_bpf command
    BBFF_APPLY,        // apply the result of the previous command
                       // (64-bit pointer or 32-bit file descriptor)
                       // to a specified location
    BBFF_COPY_USER,    // copy the result of the previous command
                       // into user memory
  };

The pseudo code for the sys_bpf() BPF_BATCH command::

 int bpf_batch(void __user * user_cmds, int size) {
  copy_from_user(cmd, user_cmds, size);
  verify_signature(cmd[1..N]);
  for_each(cmd)
    switch (cmd->op) {
    case BBFF_EXIT_ON_ERR:
        struct bbff_exit_on_err {
          u8 opcode;
        } * cmd;
        if ((s64)last_result < 0) return last_result;

    case BBFF_ARGS:
        struct bbff_args {
          u8 opcode;
          u32 size;
          u8 args[];
        } * cmd;
        args = cmd->args;

    case BBFF_APPLY_ARGS:
        struct bbff_apply_args {
          u8 opcode;
          u8 size;
          u32 arg_offset;
          u32 tgt_offset;
        } * cmd;
        memcpy((void * )cmd + cmd->tgt_offset, args + cmd->arg_offset, cmd->size);

    case BBFF_DATA:
        struct bbff_data {
          u8 opcode;
          u32 size;
          u8 data[];
        } * cmd;
        last_result = (u64) cmd->data;

    case BBFF_CMD:
        struct bbff_cmd {
          u8 opcode;
          u8 cmd;
          u8 size;
          u8 attr[];
        } * cmd;
        last_result = (s64) (s32) sys_bpf(cmd->cmd, cmd->attr, cmd->size);

    case BBFF_APPLY:
        struct bbff_apply {
          u8 opcode;
          u8 size; // 4 or 8
          u32 tgt_offset;
        } * cmd;
        memcpy((void * )cmd + cmd->tgt_offset, &last_result, cmd->size);

    case BBFF_COPY_USER:
        struct bbff_copy_user {
          u8 opcode;
          u8 size; // always 4
          u32 arg_offset;
        } * cmd;
        copy_to_user(((struct bbff_args * )user_cmds)->args + cmd->arg_offset,
                     &last_result, cmd->size);
    }

Every BBFF operation is a trivial single-liner.

The following BPF program::

  struct {
          __uint(type, BPF_MAP_TYPE_ARRAY);
          __uint(max_entries, 1024);
          __type(key, __u32);
          __type(value, __u64);
  } my_array SEC(".maps");

  SEC("cgroup_skb/ingress")
  int my_bpf_prog(struct __sk_buff *skb)
  {
          int key = 0;
          bpf_map_lookup_elem(&my_array, &key);
          return 0;
  }

represented as BBFF will look like::

  (struct bbff_args) {
    .opcode = ARGS, .size = 12,
    .args = {
      (u32) 1024 /* max_entries */,
      (u32) 0 /* map_fd will be stored here */,
      (u32) 0 /* prog_fd will be stored here */,
    },
  },
  (struct bbff_apply_args) { // store max_entries into map_create's bpf_attr
    .opcode = APPLY_ARGS, .size = 4, .arg_offset = 0, .tgt_offset = &LABEL3,
  },
  (struct bbff_data) {
    .opcode = DATA, .size = ...,
    .data = { BTF blob copied from ELF },
  },
  (struct bbff_apply) { // store btf pointer into btf_load's bpf_attr
    .opcode = APPLY, .size = 8, .tgt_offset = &LABEL1,
  },
  (struct bbff_cmd) { // load BTF
    .opcode = CMD, .cmd = BPF_BTF_LOAD, .size = 40,
    .attr = (union bpf_attr) {
       .btf = .., // LABEL1. btf pointer will be stored into here
       .btf_size = .., // same as bbff_data.size above
    },
  },
  (struct bbff_apply) { // store btf_fd into map_create's bpf_attr
    .opcode = APPLY, .size = 4, .tgt_offset = &LABEL2,
  },
  (struct bbff_cmd) { // create a map
    .opcode = CMD, .cmd = BPF_MAP_CREATE, .size = 60,
    .attr = (union bpf_attr) {
       .map_type = BPF_MAP_TYPE_ARRAY,
       .btf_fd = .., // LABEL2
       .key_size = 4,
       .btf_key_type_id = ..,
       .max_entries = .., // LABEL3
    },
  },
  (struct bbff_apply) { // store map_fd somewhere inside bpf_insn stream
    .opcode = APPLY, .size = 4, .tgt_offset = &LABEL4,
  },
  (struct bbff_copy_user) { // store map_fd back to user space
    .opcode = COPY_USER, .size = 4, .arg_offset = 4,
  },
  (struct bbff_exit_on_err) { .opcode = EXIT_ON_ERR },
  (struct bbff_data) {
    .opcode = DATA, .size = ..,
    .data = { // bpf_insn array
      BPF_LDX_MEM(),
      ..,
      BPF_LD_MAP_FD(), // LABEL4
      ..,
      BPF_EXIT_INSN(),
    },
  },
  (struct bbff_apply) { // store bpf_insn pointer into prog_load's bpf_attr
    .opcode = APPLY, .size = 8, .tgt_offset = &LABEL5,
  },
  (struct bbff_cmd) { // load program
    .opcode = CMD, .cmd = BPF_PROG_LOAD, .size = 80,
    .attr = (union bpf_attr) {
       .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
       .expected_attach_type = BPF_CGROUP_INET_INGRESS,
       .insns = .., // LABEL5
    },
  },
  (struct bbff_copy_user) { // store prog_fd back to user space
    .opcode = COPY_USER, .size = 4, .arg_offset = 8,
  },

This is how the user space will use BBFF to load this program::

  u8 bbff_blob[] = { ... };
  struct bbff_args *bbff_args = bbff_blob;
  struct my_args {
    u32 my_array__max_entries; // input
    int my_array__fd;          // output
    int my_bpf_prog__fd;       // output
  } *args = bbff_args->args;

  // adjust args->my_array__max_entries from 1024 to other value if necessary
  sys_bpf(BPF_BATCH, bbff_blob, sizeof(bbff_blob));
  // args->my_array__fd

The bpftool will generate .c, .h, and .bbff files out of .o file.
The .bbff file will contain BBFF in binary format.
The .c file will contain the same BBFF in .c like above.
The .h will contain single struct that describes layout of arguments
like struct my_args above.

By default the bpftool will generate .h with the following args to be
customized by the user::

  struct args {
    /* inputs */
    struct {
      u32 max_entries;
    } map_name1, map_nameN;
    struct {
      u32 attach_prog_fd;
      u32 attach_btf_id;
    } prog_name1, prog_nameN;
    u32 log_level;
    u32 log_size;
    u64 log_buf; /* verifier log stored here */
    /* outputs */
    int map_name1__fd;
    int map_nameN__fd;
    int prog_name1__fd;
    int prog_nameN__fd;
  };

If rodata or global variables are used by the program they will be generated
with their actual names as part of 'struct args' as well.

BBFF can be seen as a replacement for "skeleton" that doesn't rely on ELF
and needs minimal libbpf support. These few libbpf functions can be split
into libbpf-mini or libbbff.

Handling CO-RE
==============

1. CO-RE can be supported as bbff_args, but then non-trivial part of libbpf
would have to run to compute those args before BPF_BATCH command.
Hence it's cleaner to:
2. refactor libbpf's CO-RE handling code to be run in the kernel and let kernel
handle CO-RE relocation as part of BPF_PROG_LOAD command. It has important
additional benefit that complex verifier.c:btf_struct_access() and
btf_struct_walk() logic will be deprecated. The field access will be precise.
The skb->dev->ifindex dereferences will no longer be ambiguous.
