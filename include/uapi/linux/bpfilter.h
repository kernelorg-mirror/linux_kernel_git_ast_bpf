/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_LINUX_BPFILTER_H
#define _UAPI_LINUX_BPFILTER_H

#include <linux/if.h>

enum {
	BPFILTER_IPT_SO_SET_REPLACE = 64,
	BPFILTER_IPT_SO_SET_ADD_COUNTERS = 65,
	BPFILTER_IPT_SET_MAX,
};

enum {
	BPFILTER_IPT_SO_GET_INFO = 64,
	BPFILTER_IPT_SO_GET_ENTRIES = 65,
	BPFILTER_IPT_SO_GET_REVISION_MATCH = 66,
	BPFILTER_IPT_SO_GET_REVISION_TARGET = 67,
	BPFILTER_IPT_GET_MAX,
};

enum {
	BPFILTER_XT_TABLE_MAXNAMELEN = 32,
};

enum {
	BPFILTER_NF_DROP = 0,
	BPFILTER_NF_ACCEPT = 1,
	BPFILTER_NF_STOLEN = 2,
	BPFILTER_NF_QUEUE = 3,
	BPFILTER_NF_REPEAT = 4,
	BPFILTER_NF_STOP = 5,
	BPFILTER_NF_MAX_VERDICT = BPFILTER_NF_STOP,
};

enum {
	BPFILTER_INET_HOOK_PRE_ROUTING	= 0,
	BPFILTER_INET_HOOK_LOCAL_IN	= 1,
	BPFILTER_INET_HOOK_FORWARD	= 2,
	BPFILTER_INET_HOOK_LOCAL_OUT	= 3,
	BPFILTER_INET_HOOK_POST_ROUTING	= 4,
	BPFILTER_INET_HOOK_MAX,
};

enum {
	BPFILTER_PROTO_UNSPEC	= 0,
	BPFILTER_PROTO_INET	= 1,
	BPFILTER_PROTO_IPV4	= 2,
	BPFILTER_PROTO_ARP	= 3,
	BPFILTER_PROTO_NETDEV	= 5,
	BPFILTER_PROTO_BRIDGE	= 7,
	BPFILTER_PROTO_IPV6	= 10,
	BPFILTER_PROTO_DECNET	= 12,
	BPFILTER_PROTO_NUMPROTO,
};

#ifndef INT_MAX
#define INT_MAX		((int)(~0U>>1))
#endif
#ifndef INT_MIN
#define INT_MIN         (-INT_MAX - 1)
#endif

enum {
	BPFILTER_IP_PRI_FIRST			= INT_MIN,
	BPFILTER_IP_PRI_CONNTRACK_DEFRAG	= -400,
	BPFILTER_IP_PRI_RAW			= -300,
	BPFILTER_IP_PRI_SELINUX_FIRST		= -225,
	BPFILTER_IP_PRI_CONNTRACK		= -200,
	BPFILTER_IP_PRI_MANGLE			= -150,
	BPFILTER_IP_PRI_NAT_DST			= -100,
	BPFILTER_IP_PRI_FILTER			= 0,
	BPFILTER_IP_PRI_SECURITY		= 50,
	BPFILTER_IP_PRI_NAT_SRC			= 100,
	BPFILTER_IP_PRI_SELINUX_LAST		= 225,
	BPFILTER_IP_PRI_CONNTRACK_HELPER	= 300,
	BPFILTER_IP_PRI_CONNTRACK_CONFIRM	= INT_MAX,
	BPFILTER_IP_PRI_LAST			= INT_MAX,
};

#define BPFILTER_FUNCTION_MAXNAMELEN	30
#define BPFILTER_EXTENSION_MAXNAMELEN	29
#define BPFILTER_TABLE_MAXNAMELEN	32

struct bpfilter_match;
struct bpfilter_entry_match {
	union {
		struct {
			__u16		match_size;
			char		name[BPFILTER_EXTENSION_MAXNAMELEN];
			__u8		revision;
		} user;
		struct {
			__u16			match_size;
			struct bpfilter_match	*match;
		} kernel;
		__u16		match_size;
	} u;
	unsigned char	data[0];
};

struct bpfilter_target;
struct bpfilter_entry_target {
	union {
		struct {
			__u16		target_size;
			char		name[BPFILTER_EXTENSION_MAXNAMELEN];
			__u8		revision;
		} user;
		struct {
			__u16			target_size;
			struct bpfilter_target	*target;
		} kernel;
		__u16		target_size;
	} u;
	unsigned char	data[0];
};

struct bpfilter_standard_target {
	struct bpfilter_entry_target	target;
	int				verdict;
};

struct bpfilter_error_target {
	struct bpfilter_entry_target	target;
	char				error_name[BPFILTER_FUNCTION_MAXNAMELEN];
};

#define __ALIGN_KERNEL(x, a)            __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)    (((x) + (mask)) & ~(mask))

#define BPFILTER_ALIGN(__X)	\
	__ALIGN_KERNEL(__X, __alignof__(__u64))

#define BPFILTER_TARGET_INIT(__name, __size)			\
{								\
	.target.u.user = {					\
		.target_size	= BPFILTER_ALIGN(__size),	\
		.name		= (__name),			\
	},							\
}
#define BPFILTER_STANDARD_TARGET	""
#define BPFILTER_ERROR_TARGET		"ERROR"

struct bpfilter_xt_counters {
	__u64	packet_cnt;
	__u64	byte_cnt;
};

struct bpfilter_ipt_ip {
	__u32	src;
	__u32	dst;
	__u32	src_mask;
	__u32	dst_mask;
	char	in_iface[IFNAMSIZ];
	char	out_iface[IFNAMSIZ];
	__u8	in_iface_mask[IFNAMSIZ];
	__u8	out_iface_mask[IFNAMSIZ];
	__u16	protocol;
	__u8	flags;
	__u8	inv_flags;
};

struct bpfilter_ipt_entry {
	struct bpfilter_ipt_ip		ip;
	__u32				bfcache;
	__u16				target_offset;
	__u16				next_offset;
	__u32				camefrom;
	struct bpfilter_xt_counters	cntrs;
	__u8				elems[0];
};

struct bpfilter_ipt_get_info {
	char				name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32				valid_hooks;
	__u32				hook_entry[BPFILTER_INET_HOOK_MAX];
	__u32				underflow[BPFILTER_INET_HOOK_MAX];
	__u32				num_entries;
	__u32				size;
};

struct bpfilter_ipt_get_entries {
	char				name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32				size;
	struct bpfilter_ipt_entry	entries[0];
};

struct bpfilter_ipt_replace {
	char				name[BPFILTER_XT_TABLE_MAXNAMELEN];
	__u32				valid_hooks;
	__u32				num_entries;
	__u32				size;
	__u32				hook_entry[BPFILTER_INET_HOOK_MAX];
	__u32				underflow[BPFILTER_INET_HOOK_MAX];
	__u32				num_counters;
	struct bpfilter_xt_counters	*cntrs;
	struct bpfilter_ipt_entry	entries[0];
};

#endif /* _UAPI_LINUX_BPFILTER_H */
