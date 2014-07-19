#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_fetch_ptr)(void *unsafe_ptr) = (void *) BPF_FUNC_fetch_ptr;
static unsigned long long (*bpf_fetch_u64)(void *unsafe_ptr) = (void *) BPF_FUNC_fetch_u64;
static unsigned int (*bpf_fetch_u32)(void *unsafe_ptr) = (void *) BPF_FUNC_fetch_u32;
static unsigned short (*bpf_fetch_u16)(void *unsafe_ptr) = (void *) BPF_FUNC_fetch_u16;
static unsigned char (*bpf_fetch_u8)(void *unsafe_ptr) = (void *) BPF_FUNC_fetch_u8;
static int (*bpf_printk)(const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_printk;
static int (*bpf_memcmp)(void *unsafe_ptr, void *safe_ptr, int size) = (void *) BPF_FUNC_memcmp;
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void*) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value) = (void*) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) = (void *) BPF_FUNC_map_delete_elem;
static void (*bpf_dump_stack)(void) = (void *) BPF_FUNC_dump_stack;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static void *(*bpf_get_current)(void) = (void *) BPF_FUNC_get_current;

struct bpf_map_def {
	int type;
	int key_size;
	int value_size;
	int max_entries;
};

#endif
