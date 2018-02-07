#include <linux/uaccess.h>
#include <linux/bpfilter.h>
#include <uapi/linux/bpf.h>
#include <linux/wait.h>
#include <linux/kmod.h>
struct sock;

extern struct wait_queue_head bpfilter_get_cmd_wq;
extern struct wait_queue_head bpfilter_reply_wq;
extern bool bpfilter_get_cmd_ready;
extern bool bpfilter_reply_ready;
extern struct bpfilter_get_cmd bpfilter_get_cmd_mbox;
extern struct bpfilter_reply bpfilter_reply_mbox;

bool loaded = false;

int bpfilter_ip_set_sockopt(struct sock *sk, int optname, char __user *optval,
			    unsigned int optlen)
{
	int err;

	if (!loaded) {
		err = request_module("bpfilter");
		if (err) {
			printk("request_module %d\n", err);
			return err;
		}
		loaded = true;
	}
	bpfilter_get_cmd_mbox.pid = current->pid;
	bpfilter_get_cmd_mbox.cmd = optname;
	bpfilter_get_cmd_mbox.addr = (long) optval;
	bpfilter_get_cmd_mbox.len = optlen;
	bpfilter_get_cmd_ready = true;
	wake_up(&bpfilter_get_cmd_wq);
	wait_event_killable(bpfilter_reply_wq, bpfilter_reply_ready);
	bpfilter_reply_ready = false;
	return bpfilter_reply_mbox.status;
}

int bpfilter_ip_get_sockopt(struct sock *sk, int optname, char __user *optval,
			    int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	return bpfilter_ip_set_sockopt(sk, optname, optval, len);
}
