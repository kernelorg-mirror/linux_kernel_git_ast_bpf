#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>

#define UMH_start _binary_net_bpfilter_bpfilter_umh_start
#define UMH_end _binary_net_bpfilter_bpfilter_umh_end

extern char UMH_start;
extern char UMH_end;
int run_umh(void *data, size_t size);

static int __init load_umh(void)
{
	int ret = 0;

	ret = run_umh(&UMH_start, &UMH_end - &UMH_start);
	return ret;
}

static void __exit fini(void)
{
}

module_init(load_umh);
module_exit(fini);

MODULE_LICENSE("GPL");
