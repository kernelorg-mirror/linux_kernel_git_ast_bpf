#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <trace/bpf_trace.h>
#include "bpf_helpers.h"

SEC("events/net/netif_receive_skb")
int bpf_prog1(struct bpf_context *ctx)
{
	/*
	 * attaches to /sys/kernel/debug/tracing/events/net/netif_receive_skb
	 * prints events for loobpack device only
	 */
	char devname[] = "lo";
	struct net_device *dev;
	struct sk_buff *skb = 0;

	skb = (struct sk_buff *) ctx->arg1;
	dev = bpf_fetch_ptr(&skb->dev);
	if (bpf_memcmp(dev->name, devname, 2) == 0) {
		char fmt[] = "skb %x dev %x\n";
		bpf_printk(fmt, sizeof(fmt), skb, dev);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
