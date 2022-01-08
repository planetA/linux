// Needs at least Linux 5.4 to compile (because of iverbs api)

#include <linux/wait.h>

#include <asm/uaccess.h>
#include <net/addrconf.h>
#include <rdma/ib_cache.h>

#include "ovey.h"
#include "oveyd.h"

MODULE_AUTHOR("Maksym Planeta");
MODULE_AUTHOR("Philipp Schuster");
MODULE_DESCRIPTION("Overlay RDMA-network");
MODULE_LICENSE("GPL");

#define OVEY_DEVICE_NAME_PREFIX "ovey"

extern const struct ib_device_ops ovey_device_ops;

static ssize_t parent_name_show(struct device *device,
				struct device_attribute *attr, char *buf)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);

	return scnprintf(buf, PAGE_SIZE, "%.*s\n", IB_DEVICE_NAME_MAX,
			 ovey_dev->parent->name);
}
static DEVICE_ATTR_RO(parent_name);

static ssize_t parent_driver_id_show(struct device *device,
				     struct device_attribute *attr, char *buf)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 ovey_dev->parent->ops.driver_id);
}
static DEVICE_ATTR_RO(parent_driver_id);

static int real_status_read(const char *buf, size_t size)
{
	int value;
	int ret = kstrtou32(buf, 0, &value);

	if (ret)
		return ret;

	if (value < 0 || value > 1)
		return -EINVAL;

	return value;
}

static ssize_t real_guid_store(struct device *device,
			       struct device_attribute *attr, const char *buf,
			       size_t size)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);
	int real = real_status_read(buf, size);

	if (real < 0) {
		return real;
	}
	atomic_set(&ovey_dev->real_guid, real);
	return size;
}

static ssize_t real_guid_show(struct device *device,
			      struct device_attribute *attr, char *buf)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&ovey_dev->real_guid));
}
static DEVICE_ATTR_RW(real_guid);

static ssize_t real_gid_store(struct device *device,
			      struct device_attribute *attr, const char *buf,
			      size_t size)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);
	int real = real_status_read(buf, size);

	if (real < 0) {
		return real;
	}
	atomic_set(&ovey_dev->real_gid, real);
	return size;
}

static ssize_t real_gid_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&ovey_dev->real_gid));
}
static DEVICE_ATTR_RW(real_gid);

static ssize_t real_lid_store(struct device *device,
			      struct device_attribute *attr, const char *buf,
			      size_t size)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);
	int real = real_status_read(buf, size);

	if (real < 0) {
		return real;
	}
	atomic_set(&ovey_dev->real_lid, real);
	return size;
}

static ssize_t real_lid_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&ovey_dev->real_lid));
}
static DEVICE_ATTR_RW(real_lid);

static ssize_t real_qpn_store(struct device *device,
			      struct device_attribute *attr, const char *buf,
			      size_t size)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);
	int real = real_status_read(buf, size);

	if (real < 0) {
		return real;
	}
	atomic_set(&ovey_dev->real_qpn, real);
	return size;
}

static ssize_t real_qpn_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct ovey_device *ovey_dev =
		rdma_device_to_drv_device(device, struct ovey_device, base);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&ovey_dev->real_qpn));
}
static DEVICE_ATTR_RW(real_qpn);

static struct attribute *ovey_class_attributes[] = {
	&dev_attr_parent_name.attr,
	&dev_attr_parent_driver_id.attr,
	&dev_attr_real_guid.attr,
	&dev_attr_real_gid.attr,
	&dev_attr_real_lid.attr,
	&dev_attr_real_qpn.attr,
	NULL,
};

const struct attribute_group ovey_attr_group = {
	.attrs = ovey_class_attributes,
};

/**
 * Allocates a new ib device and initializes it.
 * This initializes the ib_core-related (basic) stuff as well as Ovey specific attributes.
 */
static int ovey_init_device(const char *ibdev_name,
			    struct ovey_device *ovey_dev,
			    struct net_device *parent_eth)
{
	int ret;

	// init device_info/ovey related stuff

	// ----------------------------------------------------------------------------------
	// init other/verbs related stuff

	// defines the transport type to the Userland (like in ibv_devinfo)
	// see https://elixir.bootlin.com/linux/latest/source/drivers/infiniband/core/verbs.c#L226
	// (function rdma_node_get_transport())
	ovey_dev->base.node_type = ovey_dev->parent->node_type;

	memcpy(ovey_dev->base.node_desc, OVEY_NODE_DESC_COMMON,
	       sizeof(OVEY_NODE_DESC_COMMON));

	/*
	 * current model: one-to-one device association:
	 */
	ovey_dev->base.dev.parent = ovey_dev->parent->dev.parent;
	ovey_dev->base.dev.dma_ops = ovey_dev->parent->dev.dma_ops;
	ovey_dev->base.dev.dma_parms = ovey_dev->parent->dev.dma_parms;
	ovey_dev->base.num_comp_vectors = ovey_dev->parent->num_comp_vectors;

	ovey_dev->base.phys_port_cnt = OVEY_PHYS_PORT_CNT;

	xa_init_flags(&ovey_dev->qp_xa, XA_FLAGS_ALLOC1);

	// first we set all ops
	ib_set_device_ops(&ovey_dev->base, &ovey_device_ops);
	ovey_dev->base.ops.driver_id = RDMA_DRIVER_OVEY;

	// then we set ops (verbs) null that are not supported by parent driver
	// this is the right way; returning -EOPNOTSUPP inside the verbs doesn't work nicely
#define UNSET_OVEY_OP_IF_NOT_AVAILABLE(name)                                   \
	do {                                                                   \
		if (!ovey_dev->parent->ops.name)                               \
			ovey_dev->base.ops.name = NULL;                        \
	} while (0)

	// KEEP THIS IN SYNC WITH ALL SUPPORTED VERBS
	// deactivate all verbs that are not available on parent
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(alloc_ucontext);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(alloc_mr);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(alloc_pd);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(create_cq);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(create_qp);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(dealloc_ucontext);
	// independent from parent
	// UNSET_OVEY_OP_IF_NOT_AVAILABLE(dealloc_driver);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(dealloc_pd);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(destroy_cq);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(destroy_qp);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(dereg_mr);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(get_dma_mr);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(get_link_layer);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(get_port_immutable);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(mmap);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(mmap_free);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(map_mr_sg);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(modify_qp);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(reg_user_mr);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(req_notify_cq);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(poll_cq);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(post_recv);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(post_send);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_device);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_port);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_gid);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_pkey);
	UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_qp);

	// support the verbs that both parent device and ovey support
	ovey_dev->base.uverbs_cmd_mask =
		ovey_dev->parent->uverbs_cmd_mask &
		(BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT) |
		 BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		 BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE) |
		 BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT) |
		 BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD) |
		 BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD) |
		 /* BIT_ULL(IB_USER_VERBS_CMD_CREATE_SRQ) | */
		 /* BIT_ULL(IB_USER_VERBS_CMD_MODIFY_SRQ) | */
		 /* BIT_ULL(IB_USER_VERBS_CMD_QUERY_SRQ) | */
		 /* BIT_ULL(IB_USER_VERBS_CMD_DESTROY_SRQ) | */
		 /* BIT_ULL(IB_USER_VERBS_CMD_POST_SRQ_RECV) | */
		 BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP) |
		 BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP) |
		 BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP) |
		 BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP) |
		 BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
		 BIT_ULL(IB_USER_VERBS_CMD_POST_RECV) |
		 BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ) |
		 BIT_ULL(IB_USER_VERBS_CMD_RESIZE_CQ) |
		 BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ) |
		 BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ) |
		 BIT_ULL(IB_USER_VERBS_CMD_PEEK_CQ) |
		 BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
		 BIT_ULL(IB_USER_VERBS_CMD_REG_MR) |
		 BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR) |
		 BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH) |
		 BIT_ULL(IB_USER_VERBS_CMD_MODIFY_AH) |
		 BIT_ULL(IB_USER_VERBS_CMD_QUERY_AH) |
		 BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH));

	ovey_dev->base.uverbs_cmd_mask |=
		BIT_ULL(IB_USER_VERBS_CMD_DUMP_CONTEXT) |
		BIT_ULL(IB_USER_VERBS_CMD_RESTORE_OBJECT);
	printk("WAH %s %d mask=%llx\n", __FUNCTION__, __LINE__,
	       ovey_dev->base.uverbs_cmd_mask);
	/* We may support some extended verbs in future */
#if 0
	ovey_dev->base.uverbs_ex_cmd_mask =
		ovey_dev->parent->uverbs_ex_cmd_mask & 0;
#endif

	ret = ib_device_set_netdev(&ovey_dev->base, parent_eth, 1);
	if (ret) {
		opr_err("ovey: set netdev error %d\n", ret);
		goto error;
	}

	ovey_dev->base.ops.size_ib_ah = ovey_dev->parent->ops.size_ib_ah;
	ovey_dev->base.ops.size_ib_counters =
		ovey_dev->parent->ops.size_ib_counters;
	ovey_dev->base.ops.size_ib_ucontext =
		ovey_dev->parent->ops.size_ib_ucontext;
	/* ovey_dev->base.driver_def = ovey_dev->parent->driver_def; */

	opr_info("invoked dma_device %px dma_ops %px\n",
		 ovey_dev->parent->dma_device, ovey_dev->parent->dev.dma_ops);
	ret = ib_register_device(&ovey_dev->base, ibdev_name,
				 ovey_dev->parent->dma_device);
	if (ret) {
		opr_err("ovey: device registration error %d\n", ret);
		goto error;
	}

	opr_info("registered\n");

	return 0;

error:
	return -EINVAL;
}

/**
 * ovey_report_port_gid goes through known gid of a device to report them to the
 * network coordinator
 */
static int ovey_report_known_gid(struct ovey_device *ovey_dev)
{
	unsigned int rdma_port;

	rdma_for_each_port (&ovey_dev->base, rdma_port) {
		int idx;
		int gid_cnt;
		opr_info("Report gid for port %d\n", rdma_port);
		gid_cnt = ovey_dev->base.port_data[rdma_port]
				  .immutable.gid_tbl_len;
		opr_info("Report gid for port %d gid_cnt %d\n", rdma_port,
			 gid_cnt);
		for (idx = 0; idx < gid_cnt; idx++) {
			int ret;
			union ib_gid virt_gid, real_gid;
			ret = rdma_query_gid(&ovey_dev->base, rdma_port, idx,
					     &virt_gid);
			if (ret < 0) {
				continue;
			}

			ret = rdma_query_gid(ovey_dev->parent, rdma_port, idx,
					     &real_gid);
			if (ret < 0) {
				continue;
			}

			/*
			 * Addresses with interface_id 0 and 1 are reserved and
			 * loopback correspondingly. We do not need to report
			 * them.
			 */
			if (real_gid.global.interface_id == 0) {
				continue;
			}

			if (real_gid.global.interface_id == 1) {
				continue;
			}

			opr_info("virt: %llx %llx real %llx %llx\n",
				 virt_gid.global.interface_id,
				 virt_gid.global.subnet_prefix,
				 real_gid.global.interface_id,
				 real_gid.global.subnet_prefix);
			ret = oveyd_set_gid(ovey_dev, rdma_port, idx, &virt_gid,
					    rdma_port, idx, &real_gid);
			WARN_ON(ret);
			/* oveyd_lease_gid(ovey_dev, rdma_port, idx, &gid); */
		}
	}

	return 0;
}

/**
 * ovey_create_device creates a new Ovey device.
 * @param ibdev_name is name of the new device.
 * @param parent_name is name of the parent RDMA device.
 * @param network is the UUID of the network the device is attached to.
*/
static int ovey_create_device(const char *ibdev_name,
			      struct net_device *parent_eth,
			      const char *parent_name, const uuid_t *network)
{
	struct ib_device *ovey_ib_dev;
	struct ovey_device *ovey_dev = NULL;
	struct ib_device *parent;
	int ret = 0;

	opr_info("invoked\n");

	parent = ib_device_get_by_name(parent_name, RDMA_DRIVER_UNKNOWN);
	if (!parent) {
		opr_err("parent device '%s'not found by ib_device_get_by_name()\n",
			parent_name);
		ret = -ENODEV;
		goto err;
	}

	ovey_ib_dev = ib_device_get_by_name(ibdev_name, RDMA_DRIVER_UNKNOWN);
	if (ovey_ib_dev) {
		opr_info("invoked\n");
		ib_device_put(ovey_ib_dev);
		ret = -EEXIST;
		goto err_put;
	}
	opr_info("invoked\n");

	ovey_dev = ib_alloc_device(ovey_device, base);
	if (!ovey_dev) {
		ret = PTR_ERR(ovey_dev);
		goto err_put;
	}

	atomic_set(&ovey_dev->real_guid, 0);
	atomic_set(&ovey_dev->real_gid, 1);
	atomic_set(&ovey_dev->real_lid, 0);
	atomic_set(&ovey_dev->real_qpn, 1);

	uuid_copy(&ovey_dev->network, network);
	generate_random_uuid((unsigned char *)&ovey_dev->device);

	printk("Create device %pUb from %pUb\n", &ovey_dev->device, network);
	ovey_dev->parent = parent;
	init_completion(&ovey_dev->completion);

	/* Request all important IDs from the coordinator */
	ret = oveyd_lease_device(ovey_dev);
	if (ret) {
		goto err_free;
	}

	ret = ovey_init_device(ibdev_name, ovey_dev, parent_eth);
	opr_info("invoked: %px\n", ovey_dev);
	if (ret) {
		opr_err("ovey_device_register() failed: %d\n", ret);
		goto err_free;
	}

	ret = ovey_report_known_gid(ovey_dev);
	opr_info("invoked: %px\n", ovey_dev);
	if (ret) {
		opr_err("ovey_device_register() failed: %d\n", ret);
		goto err_free;
	}

	return 0;
err_free:
	ib_dealloc_device(&ovey_dev->base);
err_put:
	ib_device_put(parent);
err:
	return ret;
}

int ovey_delete_device(char *device_name)
{
	struct ib_device *ovey_ib_dev;

	ovey_ib_dev = ib_device_get_by_name(device_name, RDMA_DRIVER_UNKNOWN);
	opr_info("WAH delete device %px", ovey_ib_dev);
	if (!ovey_ib_dev) {
		return -ENOENT;
	}

	ib_unregister_device_and_put(ovey_ib_dev);

	return 0;
}

struct ovey_device_info *
get_device_info_by_name(char const *const ovey_dev_name,
			struct ovey_device_info *dest)
{
	struct ib_device *ovey_ib_dev;
	struct ovey_device *ovey_dev;

	ovey_ib_dev = ib_device_get_by_name(ovey_dev_name, RDMA_DRIVER_UNKNOWN);
	if (!ovey_ib_dev) {
		opr_err("ib_device_get_by_name() can't find device %s\n",
			ovey_dev_name);
		return NULL;
	}
	ovey_dev = to_ovey_dev(ovey_ib_dev);

	dest->device_name = ovey_dev_name;
	dest->parent_device_name = ovey_dev->parent->name;
	dest->node_guid = ovey_dev->base.node_guid;
	dest->parent_node_guid = ovey_dev->parent->node_guid;
	uuid_copy(&dest->network, &ovey_dev->network);

	opr_info("get_device_info_by_name() for device='%s'\n", ovey_dev_name);
	opr_info("    parent_device_name='%s'\n", dest->parent_device_name);
	opr_info("    guid              ='%016llx'\n", dest->node_guid);
	opr_info("    parent guid       ='%016llx'\n", dest->parent_node_guid);
	opr_info("    virt_network_id   ='%pUb'\n", &dest->network);

	// release memory again; counterpart of ib_device_get_by_name
	ib_device_put(ovey_ib_dev);

	// return NULL or pointer to dest (=OK)
	return dest;
}

int ovey_newlink_virt(const char *ibdev_name, struct net_device *parent_eth,
		      const char *parent, const uuid_t *network)
{
	int ret = 0;

	ret = ovey_create_device(ibdev_name, parent_eth, parent, network);
	if (ret) {
		opr_err("ovey_new_device_if_not_exists() failed because of %d!\n",
			ret);
		goto err;
	}
err:
	return ret;
}

static struct rdma_link_ops ovey_link_ops = {
	.type = "ovey",
	.newlink_virt = ovey_newlink_virt,
};

static int __init ovey_module_init(void)
{
	int err;
	opr_info("loaded\n");
	// register ovey netlink family

	err = ovey_eventdev_init();
	if (err < 0) {
		goto err1;
	}

	rdma_link_register(&ovey_link_ops);

	return 0;

err1:
	return err;
}

static void __exit ovey_module_exit(void)
{
	opr_info("unloaded\n");

	// TODO tell daemon that Kernel module gets unloaded

	rdma_link_unregister(&ovey_link_ops);

	// unregisters all "ovey" devices
	ib_unregister_driver(RDMA_DRIVER_OVEY);

	ovey_eventdev_exit();
}

late_initcall(ovey_module_init);
module_exit(ovey_module_exit);

MODULE_ALIAS_RDMA_LINK("ovey");
