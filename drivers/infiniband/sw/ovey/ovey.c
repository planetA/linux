// Needs at least Linux 5.4 to compile (because of iverbs api)

#include <linux/cdev.h>
#include <linux/wait.h>

#include <asm/uaccess.h>
#include <net/addrconf.h>

#include "ovey.h"
#include "ocp.h"

MODULE_AUTHOR("Maksym Planeta");
MODULE_AUTHOR("Philipp Schuster");
MODULE_DESCRIPTION("Overlay RDMA-network");
MODULE_LICENSE("GPL");

#define OVEY_DEVICE_NAME_PREFIX "ovey"

extern const struct ib_device_ops ovey_device_ops;

static DEFINE_SPINLOCK(oveyd_lock);
static struct list_head oveyd_request_list = LIST_HEAD_INIT(oveyd_request_list);
static DECLARE_WAIT_QUEUE_HEAD(ovey_eventdev_queue);
atomic_t oveyd_next_seq = ATOMIC_INIT(1);

enum oveyd_req_type {
	OVEYD_REQ_LEASE_DEVICE,
};

/* Ovey daemon request to lease device */
struct oveydr_lease_device {

};

struct oveydr_lease_device_resp {

};

struct oveyd_req_pkt {
	u8 type;
	u8 len;
	u32 seq;
	uuid_t network;
	union {
		struct oveydr_lease_device lease_device;
	};
};

struct oveyd_resp_pkt {
	u8 type;
	u8 len;
	u32 seq;
	union {
		struct oveydr_lease_device_resp lease_device;
	};
};

struct oveyd_request {
	struct list_head head;
	struct completion *completion;
	struct oveyd_req_pkt req;
	struct oveyd_resp_pkt resp;
};

/**
 * Allocates a new ib device and initializes it.
 * This initializes the ib_core-related (basic) stuff as well as Ovey specific attributes.
 */
static int ovey_init_device(const char *ibdev_name, struct ovey_device *ovey_dev)
{
	struct net_device *netdev = NULL;
	int ret;

	// init device_info/ovey related stuff

	// ----------------------------------------------------------------------------------
	// init other/verbs related stuff

	// support all verbs that parent device supports
	ovey_dev->base.uverbs_cmd_mask = ovey_dev->parent->uverbs_cmd_mask;
	// support all verbs that parent device supports
	ovey_dev->base.uverbs_ex_cmd_mask = ovey_dev->parent->uverbs_ex_cmd_mask;

	// defines the transport type to the Userland (like in ibv_devinfo)
	// see https://elixir.bootlin.com/linux/latest/source/drivers/infiniband/core/verbs.c#L226
	// (function rdma_node_get_transport())
	ovey_dev->base.node_type = ovey_dev->parent->node_type;

	memcpy(ovey_dev->base.node_desc, OVEY_NODE_DESC_COMMON,
	       sizeof(OVEY_NODE_DESC_COMMON));

	/*
	 * current model: one-to-one device association:
	 */
	ovey_dev->base.phys_port_cnt = ovey_dev->parent->phys_port_cnt;
	ovey_dev->base.dev.parent = ovey_dev->parent->dev.parent;
	ovey_dev->base.dev.dma_ops = ovey_dev->parent->dev.dma_ops;
	ovey_dev->base.dev.dma_parms = ovey_dev->parent->dev.dma_parms;
	ovey_dev->base.num_comp_vectors = ovey_dev->parent->num_comp_vectors;

	xa_init_flags(&ovey_dev->qp_xa, XA_FLAGS_ALLOC1);

	// first we set all ops
	ib_set_device_ops(&ovey_dev->base, &ovey_device_ops);
	ovey_dev->base.ops.driver_id = RDMA_DRIVER_OVEY;

	// no we make some changes
	ovey_dev->base.ops.uverbs_abi_ver = ovey_dev->parent->ops.uverbs_abi_ver;

	// then we set ops (verbs) null that are not supported by parent driver
	// this is the right way; returning -EOPNOTSUPP inside the verbs doesn't work nicely
#define UNSET_OVEY_OP_IF_NOT_AVAILABLE(name)                                   \
	do {                                                                   \
		if (!ovey_dev->parent->ops.name)			\
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

	netdev = ib_device_get_netdev(ovey_dev->parent, 1);
	ret = ib_device_set_netdev(&ovey_dev->base, netdev, 1);
	if (ret) {
		opr_err("ovey: set netdev error %d\n", ret);
		goto error;
	}

	opr_info("invoked\n");
	ret = ib_register_device(&ovey_dev->base, ibdev_name, NULL);
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
 * oveyd_lease_device - Request ovey daemon to lease the device identifiers.
 *
 */
int oveyd_lease_device(struct ovey_device *ovey_dev)
{
	int ret;
	unsigned long flags;
	struct oveyd_request request;

	request.req.type = OVEYD_REQ_LEASE_DEVICE;
	request.req.len = sizeof(request.req);
	request.req.seq = atomic_fetch_add(1, &oveyd_next_seq);
	uuid_copy(&request.req.network, &ovey_dev->network);
	request.completion = &ovey_dev->completion;

	printk("Create new request %u\n", request.req.seq);

	spin_lock_irqsave(&oveyd_lock, flags);
	reinit_completion(&ovey_dev->completion);

	list_add_tail(&request.head, &oveyd_request_list);
	spin_unlock_irqrestore(&oveyd_lock, flags);
	wake_up(&ovey_eventdev_queue);

	ret = wait_for_completion_killable_timeout(
		&ovey_dev->completion, OVEY_TIMEOUT);
	if (ret == -ERESTARTSYS) {
		/* Killed */
		goto out;
	} else if (ret == 0) {
		/* Timeout */
		ret = -ECONNREFUSED;
		goto out;
	} else if (ret > 0) {
		/* Completed */
		ret = -ENOTSUPP;
	}

	/* ovey_dev->base.node_guid = device_info->node_guid; */
	ovey_dev->base.node_guid = 444;

out:
	printk("Delete request %u\n", request.req.seq);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_del(&request.head);
	spin_unlock_irqrestore(&oveyd_lock, flags);

	return ret;
}

/**
 * ovey_create_device creates a new Ovey device.
 * @param ibdev_name is name of the new device.
 * @param parent_name is name of the parent RDMA device.
 * @param network is the UUID of the network the device is attached to.
*/
static int ovey_create_device(const char *ibdev_name, const char *parent_name,
			const uuid_t *network)
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

	uuid_copy(&ovey_dev->network, &ovey_dev->network);
	ovey_dev->parent = parent;
	init_completion(&ovey_dev->completion);

	/* Request all important IDs from the coordinator */
	ret = oveyd_lease_device(ovey_dev);
	if (ret) {
		goto err_free;
	}

	ret = ovey_init_device(ibdev_name, ovey_dev);
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

int ovey_newlink_virt(const char *ibdev_name, const char *parent, const uuid_t *network)
{
	int ret = 0;

	ret = ovey_create_device(ibdev_name, parent, network);
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

static int ovey_eventdev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static unsigned int ovey_eventdev_poll(struct file *file, struct poll_table_struct *poll_table)
{
	return 0;
}

/**
 * ovey_eventdev_read - read from eventfile
 *
 * @offset - the driver will pick an event with a sequence number that is at
 * least as large as offset / sizeof(req).
 */
static ssize_t ovey_eventdev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	struct oveyd_request *i, *tmp, *found = NULL;
	struct oveyd_req_pkt req;
	unsigned long flags;
	int ret;
	int min_seq;

	if (*offset % sizeof(req) != 0) {
		return -EINVAL;
	}

	if (count < sizeof(req)) {
		return -ENOMEM;
	}

	min_seq = *offset / sizeof(req);
	printk("Read min_seq %d\n", min_seq);

	if (!access_ok(buf, sizeof(req))) {
		return -EACCES;
	}

	ret = wait_event_interruptible(ovey_eventdev_queue,
				!list_empty(&oveyd_request_list));
	if (ret) {
		return -EINTR;
	}

	spin_lock_irqsave(&oveyd_lock, flags);

	list_for_each_entry_safe(i, tmp, &oveyd_request_list, head) {
		printk("List element %px %u min_seq %d\n", i, i->req.seq, min_seq);
		if (min_seq > i->req.seq) {
			continue;
		}

		/* Found the resp */
		found = i;
		break;
	}

	if (found) {
		memcpy(&req, &found->req, sizeof(req));
	}
	spin_unlock_irqrestore(&oveyd_lock, flags);

	printk("Found element %px\n", found);

	if (!found) {
		return 0;
	}

	ret = copy_to_user(buf, &req, sizeof(req));
	if (ret) {
		/* We need to implement proper reaction to failed copy to kame
		 * sure the event does not get lost. */
		BUG();
		return -EFAULT;
	}

	*offset = (req.seq + 1) * sizeof(req);

	printk("Read: Offset %lld\n", *offset);

	return sizeof(req);
}

static ssize_t ovey_eventdev_write(struct file *file, const char __user *buf,
				size_t count, loff_t *offset)
{
	struct oveyd_request *i, *tmp, *found = NULL;
	unsigned long flags;
	struct oveyd_resp_pkt resp;
	int ret;

	if (*offset % sizeof(struct oveyd_req_pkt) != 0) {
		/* We use offset only for reading. */
		return -EINVAL;
	}

	if (count < sizeof(resp)) {
		/* Give enough memory for at least single response */
		return -ENOMEM;
	}

	if (!access_ok(buf, sizeof(resp))) {
		return -EACCES;
	}

	ret = copy_from_user(&resp, buf, sizeof(resp));
	if (ret) {
		return -EFAULT;
	}

	spin_lock_irqsave(&oveyd_lock, flags);
	list_for_each_entry_safe(i, tmp, &oveyd_request_list, head) {
		if (i->req.seq != resp.seq) {
			continue;
		}

		/* Found the resp */
		found = i;
		break;

	}
	spin_unlock_irqrestore(&oveyd_lock, flags);

	if (!found) {
		return -EINVAL;
	}

	memcpy(&found->resp, &resp, sizeof(resp));
	complete_all(found->completion);

	return sizeof(resp);
}

static const struct file_operations ovey_eventdev_fops = {
	.owner = THIS_MODULE,
	.open = ovey_eventdev_open,
	.poll = ovey_eventdev_poll,
	.read = ovey_eventdev_read,
	.write = ovey_eventdev_write,
};

static int eventdev_major = 0;
static struct class *ovey_eventdev_class = NULL;
static struct cdev ovey_cdev;

static int __init ovey_eventdev_init(void)
{
	struct device *device;
	int err;
	dev_t dev;

	err = alloc_chrdev_region(&dev, 0, 1, "ovey");
	if (err < 0) {
		goto err1;
	}
	eventdev_major = MAJOR(dev);

	ovey_eventdev_class = class_create(THIS_MODULE, "ovey");
	if (IS_ERR(ovey_eventdev_class)) {
		err = PTR_ERR(ovey_eventdev_class);
		goto err2;
	}

	cdev_init(&ovey_cdev, &ovey_eventdev_fops);
	ovey_cdev.owner = THIS_MODULE;

	err = cdev_add(&ovey_cdev, MKDEV(eventdev_major, 0), 1);
	if (err < 0) {
		goto err3;
	}

	device = device_create(ovey_eventdev_class, NULL,
			MKDEV(eventdev_major, 0), NULL, "ovey");
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		goto err3;
	}

	return 0;

err3:
	class_destroy(ovey_eventdev_class);
err2:
	unregister_chrdev_region(MKDEV(eventdev_major, 0), MINORMASK);
err1:
	return err;
}

static void __exit ovey_eventdev_exit(void)
{
	device_destroy(ovey_eventdev_class, MKDEV(eventdev_major, 0));

	class_unregister(ovey_eventdev_class);
	class_destroy(ovey_eventdev_class);

	unregister_chrdev_region(MKDEV(eventdev_major, 0), MINORMASK);
}

static int __init ovey_module_init(void)
{
	int err;
	opr_info("loaded\n");
	// register ovey netlink family
	err = ocp_init();
	if (err < 0) {
		opr_err("ocp_init() failed\n");
		return err;
	}

	err = ovey_eventdev_init();
	if (err < 0) {
		goto err1;
	}

	rdma_link_register(&ovey_link_ops);

	return 0;

err1:
	ocp_fini();
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

	// unregister ovey netlink family
	ocp_fini();
}

late_initcall(ovey_module_init);
module_exit(ovey_module_exit);

MODULE_ALIAS_RDMA_LINK("ovey");
