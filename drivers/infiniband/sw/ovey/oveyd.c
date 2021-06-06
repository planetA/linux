
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
	struct oveydr_lease_device *cmd = &request.req.lease_device;

	memset(&request.req, 0, sizeof(request.req));
	cmd->hdr.type = OVEYD_REQ_LEASE_DEVICE;
	cmd->hdr.len = sizeof(request.req);
	cmd->hdr.seq = atomic_fetch_add(1, &oveyd_next_seq);
	uuid_copy(&cmd->hdr.network, &ovey_dev->network);
	printk("Create header %pUb from %pUb\n", &cmd->hdr.network,
		&ovey_dev->network);

	request.req.lease_device.guid = ovey_dev->parent->node_guid;

	request.completion = &ovey_dev->completion;

	printk("Create new request %u\n", cmd->hdr.seq);

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
	printk("Delete request %u\n", cmd->hdr.seq);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_del(&request.head);
	spin_unlock_irqrestore(&oveyd_lock, flags);

	return ret;
}


static ssize_t ovey_eventdev_write(struct file *file, const char __user *buf,
				size_t count, loff_t *offset)
{
	struct oveyd_request *i, *tmp, *found = NULL;
	unsigned long flags;
	union oveyd_resp_pkt resp;
	int ret;

	if (*offset % sizeof(union oveyd_req_pkt) != 0) {
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
		if (i->req.hdr.seq != resp.hdr.seq) {
			continue;
		}

		found = i;
		/* Found the resp */
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
/**
 * ovey_eventdev_read - read from eventfile
 *
 * @offset - the driver will pick an event with a sequence number that is at
 * least as large as offset / sizeof(req).
 */
static ssize_t ovey_eventdev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	struct oveyd_request *i, *tmp, *found = NULL;
	union oveyd_req_pkt req;
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
		printk("List element %px %u min_seq %d\n", i, i->req.hdr.seq, min_seq);
		if (min_seq > i->req.hdr.seq) {
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

	*offset = (req.hdr.seq + 1) * sizeof(req);

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
