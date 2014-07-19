#ifndef __BPF_LOAD_H
#define __BPF_LOAD_H

#define MAX_MAPS 64

extern int map_fd[MAX_MAPS];

/* parses elf file compiled by llvm .c->.o
 * . parses 'maps' section and creates maps via BPF syscall
 * . parses 'license' section and passes it to syscall
 * . parses elf relocations for BPF maps and adjusts BPF_LD_IMM64 insns by
 *   storing map_fd into insn->imm and marking such insns as BPF_PSEUDO_MAP_FD
 * . loads eBPF program via BPF syscall
 * . attaches program FD to tracepoint events
 *
 * One ELF file can contain multiple BPF programs attached to multiple
 * tracepoint events
 *
 * returns zero on success
 */
int load_bpf_file(char *path);

/* forever reads /sys/.../trace_pipe */
void read_trace_pipe(void);

#endif
