#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <linux/vs_network.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SETXID.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("");
MODULE_DESCRIPTION("");
MODULE_ALIAS("ipt_SETXID");

static unsigned int
target_v2(struct sk_buff *skb,
	  const struct xt_target_param *par)



{
	const struct xt_setxid_target_info_v2 *setxidinfo = par->targinfo;

	switch (setxidinfo->mode) {
	case XT_SET_PACKET_XID:
		skb->skb_tag = setxidinfo->mark;
		break;
	}
	return XT_CONTINUE;
}

static bool
checkentry_v2(const struct xt_tgchk_param *par)



{
	struct xt_setxid_target_info_v2 *setxidinfo = par->targinfo;

	if (setxidinfo->mode != XT_SET_PACKET_XID) {
		printk(KERN_WARNING "SETXID: unknown mode %u\n",
		       setxidinfo->mode);
		return 0;
	}

	return 1;
}

static struct xt_target xt_setxid_target[] = {
	{
	 .name = "SETXID",
	 .family = AF_INET,
	 .revision = 2,
	 .checkentry = checkentry_v2,
	 .target = target_v2,
	 .targetsize = sizeof(struct xt_setxid_target_info_v2),
	 .table = "mangle",
	 .me = THIS_MODULE,
	 }
};

static int __init init(void)
{
	int err;

	err =
	    xt_register_target(xt_setxid_target);
	return err;
}

static void __exit fini(void)
{
	xt_unregister_target(xt_setxid_target);
}

module_init(init);
module_exit(fini);
