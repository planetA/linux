#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/addrconf.h>
#include <rdma/rdma_netlink.h>

#include "ovey.h"
#include "ovey_verbs.h"

MODULE_AUTHOR("Maksym Planeta");
MODULE_DESCRIPTION("Overlay RDMA-network");
MODULE_LICENSE("GPL");

/* attributes */
enum {
	OVEY_A_UNSPEC,
	OVEY_A_MSG,
	OVEY_A_VIRT_DEVICE,
	OVEY_A_PARENT_DEVICE,
	__OVEY_A_MAX,
};
#define OVEY_A_MAX (__OVEY_A_MAX - 1)

/* commands */
enum {
	OVEY_C_UNSPEC,
	OVEY_C_ECHO,
	OVEY_C_NEW_DEVICE,
	OVEY_C_DELETE_DEVICE,
	__OVEY_C_ECHO,
};
#define OVEY_C_MAX (__OVEY_C_MAX - 1)

int ovey_gnl_echo(struct sk_buff *skb, struct genl_info *info);
int ovey_gnl_new_device(struct sk_buff *skb, struct genl_info *info);
int ovey_gnl_delete_device(struct sk_buff *skb, struct genl_info *info);

void ovey_dealloc_driver(struct ib_device *base_dev);

/* attribute policy */
static struct nla_policy ovey_genl_policy[OVEY_A_MAX + 1] = {
	[OVEY_A_MSG] = { .type = NLA_NUL_STRING },
	[OVEY_A_VIRT_DEVICE] = { .type = NLA_NUL_STRING },
	[OVEY_A_PARENT_DEVICE] = { .type = NLA_NUL_STRING },
};

static const struct genl_ops ovey_gnl_ops[] = {
	{
		.cmd = OVEY_C_ECHO,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = 0,
		.doit = ovey_gnl_echo,
		.dumpit = NULL
	},
	{
		.cmd = OVEY_C_NEW_DEVICE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = 0,
		.doit = ovey_gnl_new_device,
		.dumpit = NULL
	},
	{
		.cmd = OVEY_C_DELETE_DEVICE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.flags = 0,
		.doit = ovey_gnl_delete_device,
		.dumpit = NULL
	},
};

/* family definition */
static struct genl_family ovey_gnl_family = {
	.hdrsize = 0,
	.name = "rdma-ovey",
	.version = 1,
	.maxattr = OVEY_A_MAX,
	.policy = ovey_genl_policy,
	.module = THIS_MODULE,
	.ops = ovey_gnl_ops,
	.n_ops = ARRAY_SIZE(ovey_gnl_ops),
};

static const struct ib_device_ops ovey_device_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = OVEY_ABI_VERSION,
	.driver_id = RDMA_DRIVER_OVEY,

	.dealloc_driver = ovey_dealloc_driver,
	.query_device = ovey_query_device,
	.query_port = ovey_query_port,
	.query_gid = ovey_query_gid,
	.query_pkey = ovey_query_pkey,
	.get_port_immutable = ovey_get_port_immutable,
	.alloc_ucontext = ovey_alloc_ucontext,
	.dealloc_ucontext = ovey_dealloc_ucontext,
	.alloc_pd = ovey_alloc_pd,
	.dealloc_pd = ovey_dealloc_pd,
	.mmap = ovey_mmap,
	.mmap_free = ovey_mmap_free,
	.alloc_mr = ovey_alloc_mr,
	.reg_user_mr = ovey_reg_user_mr,
	.map_mr_sg = ovey_map_mr_sg,
	.get_dma_mr = ovey_get_dma_mr,
	.dereg_mr = ovey_dereg_mr,
	.create_cq = ovey_create_cq,
	.poll_cq = ovey_poll_cq,
	.req_notify_cq = ovey_req_notify_cq,
	.destroy_cq = ovey_destroy_cq,
	.create_qp = ovey_create_qp,
	.query_qp = ovey_query_qp,
	.modify_qp = ovey_modify_qp,
	.post_send = ovey_post_send,
	.post_recv = ovey_post_recv,
	.destroy_qp = ovey_destroy_qp,

	INIT_RDMA_OBJ_SIZE(ib_cq, ovey_cq, base_cq),
	INIT_RDMA_OBJ_SIZE(ib_pd, ovey_pd, base_pd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, ovey_ucontext, base_ucontext),
};

/* handler */
int ovey_gnl_echo(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	void *msg_head;
	int ret = 0;

	pr_info("Got echo\n");
	reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (reply_skb == NULL) {
		ret = -ENOMEM;
		goto err;
	}


	/* create the message headers */
	msg_head = genlmsg_put_reply(reply_skb, info, &ovey_gnl_family, 0, OVEY_C_ECHO);
	if (msg_head == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	/* add a OVEY_A_MSG attribute */
	ret = nla_put_string(reply_skb, OVEY_A_MSG, "Generic Netlink Rocks");
	if (ret < 0) {
		goto err_free;
	}
	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	return genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid);

  err_free:
	nlmsg_free(reply_skb);

  err:
	return ret;
}

static struct ovey_device *ovey_new_device(struct ib_device *parent)
{
	struct ovey_device *ovey_dev = NULL;

	ovey_dev = ib_alloc_device(ovey_device, base);
	if (!ovey_dev)
		return NULL;

	ovey_dev->parent = parent;

	ovey_dev->base.node_guid = parent->node_guid;

	ovey_dev->base.uverbs_cmd_mask =
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
		(1ULL << IB_USER_VERBS_CMD_QUERY_PORT) |
		(1ULL << IB_USER_VERBS_CMD_GET_CONTEXT) |
		(1ULL << IB_USER_VERBS_CMD_ALLOC_PD) |
		(1ULL << IB_USER_VERBS_CMD_DEALLOC_PD) |
		(1ULL << IB_USER_VERBS_CMD_REG_MR) |
		(1ULL << IB_USER_VERBS_CMD_DEREG_MR) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_CQ) |
		(1ULL << IB_USER_VERBS_CMD_POLL_CQ) |
		(1ULL << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_CQ) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_QP) |
		(1ULL << IB_USER_VERBS_CMD_QUERY_QP) |
		(1ULL << IB_USER_VERBS_CMD_MODIFY_QP) |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_QP) |
		(1ULL << IB_USER_VERBS_CMD_POST_SEND) |
		(1ULL << IB_USER_VERBS_CMD_POST_RECV);

	ovey_dev->base.node_type = RDMA_NODE_RNIC;
	memcpy(ovey_dev->base.node_desc, OVEY_NODE_DESC_COMMON,
	       sizeof(OVEY_NODE_DESC_COMMON));

	/*
	 * current model (one-to-one device association):
	 * one softiwarp device per net_device or, equivalently,
	 * per physical port.
	 */
	ovey_dev->base.phys_port_cnt = parent->phys_port_cnt;
	ovey_dev->base.dev.parent = parent->dev.parent;
	ovey_dev->base.dev.dma_ops = parent->dev.dma_ops;
	ovey_dev->base.dev.dma_parms = parent->dev.dma_parms;
	ovey_dev->base.num_comp_vectors = parent->num_comp_vectors;

	xa_init_flags(&ovey_dev->qp_xa, XA_FLAGS_ALLOC1);

	ib_set_device_ops(&ovey_dev->base, &ovey_device_ops);
	ovey_dev->base.uverbs_ex_cmd_mask = (
		parent->uverbs_ex_cmd_mask &
		(1ull << IB_USER_VERBS_EX_CMD_QUERY_DEVICE));

	ovey_dev->base.ops.uverbs_abi_ver = parent->ops.uverbs_abi_ver;
	ovey_dev->base.ops.driver_id = parent->ops.driver_id;
#define UNSET_OVEY_OP(name)					\
	do {							\
		if (!parent->ops.name)				\
			ovey_dev->base.ops.name = NULL;		\
	} while (0)
/* #define SET_OVEY_OBJ_SIZE(name)					\ */
/* 	do {							\ */
/* 		ovey_dev->base.ops				\ */
/* 			INIT_RDMA_OBJ_SIZE(ib_##name, ovey_##name, base_##name); \ */
/* 	} while (0) */

	/* UNSET_OVEY_OP(query_gid); */
	/* UNSET_OVEY_OP(alloc_ucontext); */
	/* UNSET_OVEY_OP(dealloc_ucontext); */
	/* UNSET_OVEY_OP(mmap); */
	/* UNSET_OVEY_OP(mmap_free); */
	/* UNSET_OVEY_OP(alloc_mr); */
	/* UNSET_OVEY_OP(reg_user_mr); */
	/* UNSET_OVEY_OP(map_mr_sg); */
	/* UNSET_OVEY_OP(get_dma_mr); */
	/* UNSET_OVEY_OP(poll_cq); */
	/* UNSET_OVEY_OP(query_qp); */

	/* SET_OVEY_OBJ_SIZE(ah); */
	/* SET_OVEY_OBJ_SIZE(cq); */
	/* SET_OVEY_OBJ_SIZE(pd); */
	/* SET_OVEY_OBJ_SIZE(srq); */
	/* SET_OVEY_OBJ_SIZE(ucontext); */

	return ovey_dev;

  error:
	ib_dealloc_device(&ovey_dev->base);

	return NULL;
}

static int ovey_device_register(struct ovey_device *ovey_dev, const char *name)
{
	static int dev_id = 1;
	int ret;

	ret = ib_register_device(&ovey_dev->base, name);
	if (ret) {
		pr_warn("ovey: device registration error %d\n", ret);
		return ret;
	}

	ovey_dbg(&ovey_dev->base, "Registered\n");

	return 0;
}

static int ovey_new_device_if_not_exists(const char *basedev_name, struct ib_device *parent)
{
	struct ib_device *ovey_ib_dev;
	struct ovey_device *ovey_dev = NULL;
	int ret = -ENOMEM;

	pr_err("Attempt to create link\n");

	ovey_ib_dev = ib_device_get_by_name(basedev_name, RDMA_DRIVER_OVEY);
	if (ovey_ib_dev) {
		ib_device_put(ovey_ib_dev);
		return -EEXIST;
	}

	ovey_dev = ovey_new_device(parent);
	if (ovey_dev) {
		ovey_dbg(parent, "ovey: new device\n");
		pr_err("WAH %s %d\n", __FILE__, __LINE__);

		ret = ovey_device_register(ovey_dev, basedev_name);
		pr_err("WAH %s %d\n", __FILE__, __LINE__);
		if (ret)
			ib_dealloc_device(&ovey_dev->base);
	}
	pr_err("WAH %s %d\n", __FILE__, __LINE__);
	return ret;
}

int ovey_gnl_new_device(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	void *msg_head;
	int ret = 0;
	struct ib_device *parent;
	char new_iface_name[IFNAMSIZ];
	char parent_iface_name[IFNAMSIZ];

	if (!info->attrs[OVEY_A_VIRT_DEVICE]) {
		ret = -EINVAL;
		goto err;
	}
	ret = nla_strlcpy(new_iface_name, info->attrs[OVEY_A_VIRT_DEVICE], IFNAMSIZ);
	if (ret < 0) {
		ret = -EINVAL;
		goto err;
	}

	if (!info->attrs[OVEY_A_PARENT_DEVICE]) {
		ret = -EINVAL;
		goto err;
	}
	ret = nla_strlcpy(parent_iface_name, info->attrs[OVEY_A_PARENT_DEVICE], IFNAMSIZ);
	if (ret < 0) {
		ret = -EINVAL;
		goto err;
	}

	parent = ib_device_get_by_name(parent_iface_name, RDMA_DRIVER_UNKNOWN);
	if (!parent) {
		ret = -EINVAL;
		goto err;
	}
	pr_info("Request to create a device: %s (parent %s)\n", new_iface_name, parent_iface_name);

	pr_err("WAH %s %d\n", __FILE__, __LINE__);
	ret = ovey_new_device_if_not_exists(new_iface_name, parent);
	pr_err("WAH %s %d\n", __FILE__, __LINE__);
	if (ret < 0) {
		goto err_put;
	}
	pr_err("WAH %s %d\n", __FILE__, __LINE__);

	reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	pr_err("WAH %s %d\n", __FILE__, __LINE__);
	if (reply_skb == NULL) {
		ret = -ENOMEM;
		goto err_put;
	}
	pr_err("WAH %s %d\n", __FILE__, __LINE__);


	/* create the message headers */
	msg_head = genlmsg_put_reply(reply_skb, info, &ovey_gnl_family, 0, OVEY_C_NEW_DEVICE);
	pr_err("WAH %s %d\n", __FILE__, __LINE__);
	if (msg_head == NULL) {
		ret = -ENOMEM;
		goto err_put;
	}
	pr_err("WAH %s %d\n", __FILE__, __LINE__);
	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	return genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid);

  err_put:
	ib_device_put(parent);

  err:
	return ret;
}

void ovey_dealloc_driver(struct ib_device *base_dev)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);

	xa_destroy(&ovey_dev->qp_xa);

	ib_device_put(ovey_dev->parent);
}

int ovey_delete_device(char *device_name)
{
	struct ib_device *ovey_ib_dev;

	ovey_ib_dev = ib_device_get_by_name(device_name, RDMA_DRIVER_OVEY);
	if (!ovey_ib_dev) {
		return -ENOENT;
	}

	ib_unregister_device_and_put(ovey_ib_dev);

	return 0;
}

int ovey_gnl_delete_device(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	void *msg_head;
	int ret = 0;
	char device_name[IFNAMSIZ];

	if (!info->attrs[OVEY_A_VIRT_DEVICE]) {
		ret = -EINVAL;
		goto err;
	}
	ret = nla_strlcpy(device_name, info->attrs[OVEY_A_VIRT_DEVICE], IFNAMSIZ);
	if (ret < 0) {
		ret = -EINVAL;
		goto err;
	}

	pr_info("Request to delete a device: %s\n", device_name);

	ret = ovey_delete_device(device_name);
	if (ret < 0) {
		goto err;
	}

	reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (reply_skb == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	/* create the message headers */
	msg_head = genlmsg_put_reply(reply_skb, info, &ovey_gnl_family, 0, OVEY_C_DELETE_DEVICE);
	if (msg_head == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	return genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid);

  err:
	return ret;
}

static int __init ovey_module_init(void)
{
	int err;
	err = genl_register_family(&ovey_gnl_family);
	if (err < 0) {
		pr_err("Failed to register netlink family: %d", err);
		return -EINVAL;
	}

	return 0;
}

static void __exit ovey_module_exit(void)
{
	genl_unregister_family(&ovey_gnl_family);

	pr_info("unloaded\n");
}

late_initcall(ovey_module_init);
module_exit(ovey_module_exit);

MODULE_ALIAS_RDMA_LINK("ovey");
