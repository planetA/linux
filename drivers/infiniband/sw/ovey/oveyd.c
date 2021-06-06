
/**
 * Functions to communicate with ovey daemon
*/

#include <linux/cdev.h>

#include "oveyd.h"

static DEFINE_SPINLOCK(oveyd_lock);
static struct list_head oveyd_request_list = LIST_HEAD_INIT(oveyd_request_list);
static DECLARE_WAIT_QUEUE_HEAD(ovey_eventdev_queue);
atomic_t oveyd_next_seq = ATOMIC_INIT(1);

/**
 * oveyd_lease_device - Request ovey daemon to lease the device identifiers.
 *
 */
int oveyd_lease_device(struct ovey_device *ovey_dev)
{
	int ret;
	unsigned long flags;
	struct oveyd_request request;

	memset(&request.req, 0, sizeof(request.req));
	request.req.type = OVEYD_REQ_LEASE_DEVICE;
	request.req.len = sizeof(request.req);
	request.req.seq = atomic_fetch_add(1, &oveyd_next_seq);
	uuid_copy(&request.req.network, &ovey_dev->network);
	printk("Create header %pUb from %pUb\n", &request.req.network,
		&ovey_dev->network);

	request.req.lease_device.guid = ovey_dev->parent->node_guid;

	request.completion = &ovey_dev->completion;

	printk("Create new request %u\n", request.req.seq);

	spin_lock_irqsave(&oveyd_lock, flags);
	reinit_completion(&ovey_dev->completion);

	list_add_tail(&request.head, &oveyd_request_list);
	spin_unlock_irqrestore(&oveyd_lock, flags);
	wake_up(&ovey_eventdev_queue);

	ret = wait_for_completion_killable_timeout(
		&ovey_dev->completion, OVEY_TIMEOUT);
	printk("Wait over %d\n", ret);
	if (ret == -ERESTARTSYS) {
		/* Killed */
		goto out;
	} else if (ret == 0) {
		/* Timeout */
		ret = -ECONNREFUSED;
		goto out;
	} else if (ret > 0) {
		/* ret indicates time before timeout, not an error. */
		ret = 0;
	}

	/* No other error code should be possible */
	BUG_ON(ret < 0);

	printk("Received reply %lld %lld\n", request.resp.lease_device.guid,
	       request.req.lease_device.guid);
	/* Completed */
	ovey_dev->base.node_guid = request.resp.lease_device.guid;

out:
	printk("Delete request %u\n", request.req.seq);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_del(&request.head);
	spin_unlock_irqrestore(&oveyd_lock, flags);

	return ret;
}

int oveyd_lease_gid(struct ovey_device *ovey_dev, u8 port, int idx,
		union ib_gid *gid)
{
	int ret;
	unsigned long flags;
	struct oveyd_request request;

	memset(&request.req, 0, sizeof(request.req));
	request.req.type = OVEYD_REQ_LEASE_GID;
	request.req.len = sizeof(request.req);
	request.req.seq = atomic_fetch_add(1, &oveyd_next_seq);
	uuid_copy(&request.req.network, &ovey_dev->network);
	printk("Create header %pUb from %pUb\n", &request.req.network,
		&ovey_dev->network);

	request.req.lease_gid.port = port;
	request.req.lease_gid.idx = idx;
	request.req.lease_gid.subnet_prefix = gid->global.subnet_prefix;
	request.req.lease_gid.interface_id = gid->global.interface_id;

	request.completion = &ovey_dev->completion;

	printk("Create new request %u\n", request.req.seq);

	spin_lock_irqsave(&oveyd_lock, flags);
	reinit_completion(&ovey_dev->completion);

	list_add_tail(&request.head, &oveyd_request_list);
	spin_unlock_irqrestore(&oveyd_lock, flags);
	wake_up(&ovey_eventdev_queue);

	ret = wait_for_completion_killable_timeout(
		&ovey_dev->completion, OVEY_TIMEOUT);
	printk("Wait over %d\n", ret);
	if (ret == -ERESTARTSYS) {
		/* Killed */
		goto out;
	} else if (ret == 0) {
		/* Timeout */
		ret = -ECONNREFUSED;
		goto out;
	} else if (ret > 0) {
		/* ret indicates time before timeout, not an error. */
		ret = 0;
	}

	/* No other error code should be possible */
	BUG_ON(ret < 0);

	printk("Received reply %llx-%llx to %llx-%llx\n",
	       request.req.lease_gid.interface_id,
	       request.req.lease_gid.subnet_prefix,
	       request.resp.lease_gid.interface_id,
	       request.resp.lease_gid.subnet_prefix);
	/* Completed */
	gid->global.subnet_prefix = request.resp.lease_gid.subnet_prefix;
	gid->global.interface_id = request.resp.lease_gid.interface_id;

out:
	printk("Delete request %u\n", request.req.seq);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_del(&request.head);
	spin_unlock_irqrestore(&oveyd_lock, flags);

	return ret;
}

static int oveyd_resolve_av_global(struct ovey_qp *ovey_qp, struct rdma_ah_attr *ah)
{
	int ret;
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_qp->base.device);
	struct oveyd_request request;
	unsigned long flags;
	const struct ib_global_route *grh;

	if (!(rdma_ah_get_ah_flags(ah) & IB_AH_GRH)) {
		return -EOPNOTSUPP;
	}

	grh = rdma_ah_read_grh(ah);

	memset(&request.req, 0, sizeof(request.req));
	request.req.type = OVEYD_REQ_RESOLVE_GID;
	request.req.len = sizeof(request.req);
	request.req.seq = atomic_fetch_add(1, &oveyd_next_seq);
	uuid_copy(&request.req.network, &ovey_dev->network);
	printk("Create header %pUb from %pUb\n", &request.req.network,
	       &ovey_dev->network);

	request.req.resolve_gid.subnet_prefix = grh->dgid.global.subnet_prefix;
	request.req.resolve_gid.interface_id = grh->dgid.global.interface_id;

	request.completion = &ovey_dev->completion;

	printk("Create new request %u\n", request.req.seq);

	spin_lock_irqsave(&oveyd_lock, flags);
	reinit_completion(&ovey_dev->completion);

	list_add_tail(&request.head, &oveyd_request_list);
	spin_unlock_irqrestore(&oveyd_lock, flags);
	wake_up(&ovey_eventdev_queue);

	ret = wait_for_completion_killable_timeout(&ovey_dev->completion,
						   OVEY_TIMEOUT);
	printk("Wait over %d\n", ret);
	if (ret == -ERESTARTSYS) {
		/* Killed */
		goto out;
	} else if (ret == 0) {
		/* Timeout */
		ret = -ECONNREFUSED;
		goto out;
	} else if (ret > 0) {
		/* ret indicates time before timeout, not an error. */
		ret = 0;
	}

	/* No other error code should be possible */
	BUG_ON(ret < 0);

	printk("Received reply %llx-%llx to %llx-%llx\n",
	       request.req.resolve_gid.interface_id,
	       request.req.resolve_gid.subnet_prefix,
	       request.resp.resolve_gid.interface_id,
	       request.resp.resolve_gid.subnet_prefix);

	/* Completed */
	rdma_ah_set_subnet_prefix(ah, request.resp.resolve_gid.subnet_prefix);
	rdma_ah_set_interface_id(ah, request.resp.resolve_gid.interface_id);

out:
	printk("Delete request %u\n", request.req.seq);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_del(&request.head);
	spin_unlock_irqrestore(&oveyd_lock, flags);

	return ret;
}

int oveyd_resolve_av(struct ovey_qp *ovey_qp, struct rdma_ah_attr *ah)
{
	return oveyd_resolve_av_global(ovey_qp, ah);
}


static ssize_t ovey_eventdev_write(struct file *file, const char __user *buf,
				size_t count, loff_t *offset)
{
	struct oveyd_request *i, *tmp, *found = NULL;
	unsigned long flags;
	struct oveyd_resp_pkt resp;
	int ret;

	printk("Received write request %d", __LINE__);

	if (*offset % sizeof(struct oveyd_req_pkt) != 0) {
		/* We use offset only for reading. */
		return -EINVAL;
	}

	printk("Received write request %d %lu %lu", __LINE__, count, sizeof(resp));
	if (count > sizeof(resp)) {
		/* Give enough memory for at least single response */
		return -ENOMEM;
	}

	printk("Received write request %d", __LINE__);
	if (!access_ok(buf, sizeof(resp))) {
		return -EACCES;
	}

	printk("Received write request %d", __LINE__);
	ret = copy_from_user(&resp, buf, count);
	if (ret) {
		return -EFAULT;
	}

	printk("Received write request %d", __LINE__);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_for_each_entry_safe(i, tmp, &oveyd_request_list, head) {
		printk("Received write request %d", __LINE__);
		if (i->req.seq != resp.seq) {
			continue;
		}

		printk("Received write request %d", __LINE__);
		found = i;
		/* Found the resp */
		break;

	}
	spin_unlock_irqrestore(&oveyd_lock, flags);

	printk("Received write request %d", __LINE__);
	if (!found) {
		return -EINVAL;
	}
	printk("Received write request %d", __LINE__);

	memcpy(&found->resp, &resp, sizeof(resp));
	complete_all(found->completion);

	printk("Received write request %d %lu", __LINE__, sizeof(resp));
	return sizeof(resp);
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

static int ovey_eventdev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations ovey_eventdev_fops = {
	.owner = THIS_MODULE,
	.open = ovey_eventdev_open,
	.read = ovey_eventdev_read,
	.write = ovey_eventdev_write,
};

static int eventdev_major = 0;
static struct class *ovey_eventdev_class = NULL;
static struct cdev ovey_cdev;

int __init ovey_eventdev_init(void)
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

void __exit ovey_eventdev_exit(void)
{
	device_destroy(ovey_eventdev_class, MKDEV(eventdev_major, 0));

	class_unregister(ovey_eventdev_class);
	class_destroy(ovey_eventdev_class);

	unregister_chrdev_region(MKDEV(eventdev_major, 0), MINORMASK);
}
