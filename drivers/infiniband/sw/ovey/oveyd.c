
/**
 * Functions to communicate with ovey daemon
*/

#include "rdma/ib_verbs.h"
#include <linux/cdev.h>

#include "oveyd.h"

static DEFINE_SPINLOCK(oveyd_lock);
static struct list_head oveyd_request_list = LIST_HEAD_INIT(oveyd_request_list);
static DECLARE_WAIT_QUEUE_HEAD(ovey_eventdev_queue);
atomic_t oveyd_next_seq = ATOMIC_INIT(1);

static void oveyd_request_init(struct oveyd_request *request,
			       struct ovey_device *ovey_dev, u16 port, u16 type)
{
	memset(&request->req, 0, sizeof(request->req));
	request->req.type = type;
	request->req.len = sizeof(request->req);
	request->req.seq = atomic_fetch_add(1, &oveyd_next_seq);
	uuid_copy(&request->req.network, &ovey_dev->network);
	uuid_copy(&request->req.device, &ovey_dev->device);
	request->req.port = port;
}

static int send_request_block(struct ovey_device *ovey_dev,
			struct oveyd_request *request)
{
	int ret;
	unsigned long flags;

	request->completion = &ovey_dev->completion;

	opr_info("Create new request %u\n", request->req.seq);

	spin_lock_irqsave(&oveyd_lock, flags);
	reinit_completion(&ovey_dev->completion);

	list_add_tail(&request->head, &oveyd_request_list);
	spin_unlock_irqrestore(&oveyd_lock, flags);
	wake_up(&ovey_eventdev_queue);

	ret = wait_for_completion_killable_timeout(&ovey_dev->completion,
						   OVEY_TIMEOUT);
	opr_info("Wait over %d\n", ret);
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

out:
	printk("Delete request %u\n", request->req.seq);
	spin_lock_irqsave(&oveyd_lock, flags);
	list_del(&request->head);
	spin_unlock_irqrestore(&oveyd_lock, flags);
	return ret;
}

/**
 * oveyd_lease_device - Request ovey daemon to lease the device identifiers.
 *
 */
int oveyd_lease_device(struct ovey_device *ovey_dev)
{
	int ret;
	struct oveyd_request request;

	if (atomic_read(&ovey_dev->real_guid)) {
		ovey_dev->base.node_guid = ovey_dev->parent->node_guid;
		return 0;
	}

	oveyd_request_init(&request, ovey_dev, 0, OVEYD_REQ_LEASE_DEVICE);

	request.req.lease_device.guid = ovey_dev->parent->node_guid;

	ret = send_request_block(ovey_dev, &request);

	printk("Received reply %llx %llx\n", request.resp.lease_device.guid,
	       request.req.lease_device.guid);
	/* Completed */
	ovey_dev->base.node_guid = request.resp.lease_device.guid;

	return ret;
}

/**
 * oveyd_lease_gid() - request virt address from the daemon.
 *
 * @oveyd_dev: Virtual oveyd device
 * @port: Real port id
 * @idx: Real index
 * @gid: Real GID
 *
 * Register the real GID with the coordinator and request the virtual address
 * back from the coordinator.
 */
int oveyd_lease_gid(struct ovey_device *ovey_dev, u8 port, int idx,
		    union ib_gid *gid)
{
	int ret;
	struct oveyd_request request;

	if (gid->global.interface_id == 0) {
		/* No need to resolve RESERVED id 4.1.1 6 IB TA */
		return 0;
	}

	if (gid->global.interface_id == 1) {
		/* No need to resolve RESERVED id 4.1.1 7 IB TA */
		return 0;
	}

	if (atomic_read(&ovey_dev->real_gid)) {
		return 0;
	}

	oveyd_request_init(&request, ovey_dev, port, OVEYD_REQ_LEASE_GID);

	request.req.lease_gid.idx = idx;
	request.req.lease_gid.subnet_prefix = gid->global.subnet_prefix;
	request.req.lease_gid.interface_id = gid->global.interface_id;

	ret = send_request_block(ovey_dev, &request);

	printk("Received reply %llx-%llx to %llx-%llx\n",
	       request.req.lease_gid.interface_id,
	       request.req.lease_gid.subnet_prefix,
	       request.resp.lease_gid.interface_id,
	       request.resp.lease_gid.subnet_prefix);
	/* Completed */
	gid->global.subnet_prefix = request.resp.lease_gid.subnet_prefix;
	gid->global.interface_id = request.resp.lease_gid.interface_id;

	return ret;
}

/**
 * oveyd_set_gid() - report real to virt mapping to the daemon.
 *
 * Forward the exact virtual to real GID mapping to the coordinator.
 *
 * The call is used for the case, when the virtual address is fixed in some way,
 * and cannot be chosen freely by the coordinator. In particular, this happens,
 * when the registering the GID mapping for index 0 and 1. In this case the
 * virtual address must match the IP address of the bound veth device.
 */
int oveyd_set_gid(struct ovey_device *ovey_dev, u8 virt_port, int virt_idx,
		  union ib_gid *virt_gid, u8 real_port, int real_idx,
		  union ib_gid *real_gid)
{
	int ret;
	struct oveyd_request request;

	if (atomic_read(&ovey_dev->real_gid)) {
		return 0;
	}

	oveyd_request_init(&request, ovey_dev, virt_port,
			   OVEYD_REQ_SET_GID);

	request.req.set_gid.real_idx = real_idx;
	request.req.set_gid.real_subnet_prefix = real_gid->global.subnet_prefix;
	request.req.set_gid.real_interface_id = real_gid->global.interface_id;

	request.req.set_gid.virt_idx = virt_idx;
	request.req.set_gid.virt_subnet_prefix = virt_gid->global.subnet_prefix;
	request.req.set_gid.virt_interface_id = virt_gid->global.interface_id;

	opr_info("Set gid send %llx-%llx to %llx-%llx\n",
		 request.req.set_gid.virt_interface_id,
		 request.req.set_gid.virt_subnet_prefix,
		 request.req.set_gid.real_interface_id,
		 request.req.set_gid.real_subnet_prefix);

	ret = send_request_block(ovey_dev, &request);

	/* Completed */
	opr_info("Set gid received reply %llx-%llx to %llx-%llx\n",
		 request.resp.set_gid.virt_interface_id,
		 request.resp.set_gid.virt_subnet_prefix,
		 request.resp.set_gid.real_interface_id,
		 request.resp.set_gid.real_subnet_prefix);

	return ret;
}

/**
 * oveyd_lease_port() - Register a port with a device.
 *
 * @oveyd_dev: Virtual oveyd device
 * @port: Real port id
 * @lid: Real port attr
 *
 * Register the port with the coordinator and request the virtualised settings
 * back from the coordinator.
 */
int oveyd_create_port(struct ovey_device *ovey_dev, u8 port, struct ib_port_immutable *attr)
{
	int ret;
	struct oveyd_request request;

	if (atomic_read(&ovey_dev->real_lid)) {
		return 0;
	}

	oveyd_request_init(&request, ovey_dev, 0, OVEYD_REQ_CREATE_PORT);

	request.req.create_port.port = port;
	request.req.create_port.pkey_tbl_len = attr->pkey_tbl_len;
	request.req.create_port.gid_tbl_len = attr->gid_tbl_len;
	request.req.create_port.core_cap_flags = attr->core_cap_flags;
	request.req.create_port.max_mad_size = attr->max_mad_size;

	ret = send_request_block(ovey_dev, &request);

	printk("Received reply %x to %x\n",
		request.req.create_port.gid_tbl_len,
	       request.resp.create_port.gid_tbl_len);
	/* Completed */
	attr->pkey_tbl_len = request.resp.create_port.pkey_tbl_len;
	attr->gid_tbl_len = request.resp.create_port.gid_tbl_len;
	attr->core_cap_flags = request.resp.create_port.core_cap_flags;
	attr->max_mad_size = request.resp.create_port.max_mad_size;

	return ret;
}

int oveyd_set_port_attr(struct ovey_device *ovey_dev, u8 port,
			struct ib_port_attr *attr)
{
	int ret;
	struct oveyd_request request;

	if (atomic_read(&ovey_dev->real_lid)) {
		return 0;
	}

	oveyd_request_init(&request, ovey_dev, port,
			   OVEYD_REQ_SET_PORT_ATTR);

	request.req.set_port_attr.lid = attr->lid;

	ret = send_request_block(ovey_dev, &request);

	printk("Received reply %d to %x\n", request.req.set_port_attr.lid,
	       request.resp.set_port_attr.lid);
	/* Completed */
	attr->lid = request.resp.set_port_attr.lid;

	return ret;
}

/**
 * oveyd_create_qp() - Register a QP with a device.
 *
 * @ovey_qp: Virtual QP
 *
 * Register the port with the coordinator and request the virtualised settings
 * back from the coordinator.
 */
int oveyd_create_qp(struct ovey_qp *ovey_qp, struct ib_qp_init_attr *attrs)
{
	int ret;
	struct oveyd_request request;
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_qp->base.device);

	if (atomic_read(&ovey_dev->real_qpn)) {
		ovey_qp->base.qp_num = ovey_qp->parent->qp_num;
		return 0;
	}

	oveyd_request_init(&request, ovey_dev, 0, OVEYD_REQ_CREATE_QP);

	request.req.create_qp.qpn = ovey_qp->parent->qp_num;

	ret = send_request_block(ovey_dev, &request);

	printk("Received reply %x to %x\n",
		request.req.create_qp.qpn,
	       request.resp.create_qp.qpn);
	/* Completed */
	ovey_qp->base.qp_num = request.resp.create_qp.qpn;

	return ret;
}

int oveyd_resolve_qp(struct ovey_qp *ovey_qp,
		     const struct ib_qp_attr *qp_attr_virt,
		     struct ib_qp_attr *qp_attr_real, int qp_attr_mask)
{
	int ret;
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_qp->base.device);
	struct oveyd_request request;
	struct oveydr_resolve_qp *req = &request.req.resolve_qp;
	struct oveydr_resolve_qp *resp = &request.resp.resolve_qp;
	const struct ib_global_route *grh;
	u32 dlid;

	grh = rdma_ah_read_grh(&qp_attr_virt->ah_attr);

	memset(&request, 0, sizeof(request));

	oveyd_request_init(&request, ovey_dev, 0, OVEYD_REQ_RESOLVE_QP);

	if (qp_attr_mask & IB_QP_DEST_QPN) {
		/* Set QPN */
		req->qpn = qp_attr_virt->dest_qp_num;
		req->attr_mask |= OVEYDR_RESOLVE_QP_QPN;
	}
	if (qp_attr_mask & IB_QP_AV) {
		/* Set GID */
		if ((rdma_ah_get_ah_flags(&qp_attr_virt->ah_attr) &
		     IB_AH_GRH)) {
			req->subnet_prefix = grh->dgid.global.subnet_prefix;
			req->interface_id = grh->dgid.global.interface_id;
			req->attr_mask |= OVEYDR_RESOLVE_QP_GID;
		} else {
			opr_info("NO GRH support %x\n", qp_attr_mask);
		}

		/* Set LID */
		dlid = rdma_ah_get_dlid(&qp_attr_virt->ah_attr);
		if (dlid) {
			req->lid = dlid;
			req->attr_mask |= OVEYDR_RESOLVE_QP_LID;
		}
	}

	printk("Sending resolve qp request %llx-%llx qpn %d lid %d\n",
		req->interface_id, req->subnet_prefix, req->qpn, req->lid);

	/* Reset flags, when virtualisation is disabled */
	if (atomic_read(&ovey_dev->real_gid)) {
		req->attr_mask &= ~OVEYDR_RESOLVE_QP_GID;
	}
	if (atomic_read(&ovey_dev->real_lid)) {
		req->attr_mask &= ~OVEYDR_RESOLVE_QP_LID;
	}
	if (atomic_read(&ovey_dev->real_qpn)) {
		req->attr_mask &= ~OVEYDR_RESOLVE_QP_QPN;
	}
	/* If nothing to resolve, return immediatelly */
	if (!req->attr_mask) {
		qp_attr_real->ah_attr = qp_attr_virt->ah_attr;
		qp_attr_real->dest_qp_num = qp_attr_virt->dest_qp_num;
		return 0;
	}

	ret = send_request_block(ovey_dev, &request);
	if (ret < 0) {
		goto out;
	}

	printk("Received reply %llx-%llx:%d:%d to %llx-%llx:%d:%d\n",
	       req->interface_id, req->subnet_prefix, req->lid, req->qpn,
	       resp->interface_id, resp->subnet_prefix, resp->lid, resp->qpn);

	/* Completed */
	qp_attr_real->ah_attr.type = qp_attr_virt->ah_attr.type;
	if (rdma_ah_get_ah_flags(&qp_attr_virt->ah_attr) & IB_AH_GRH) {
		if (atomic_read(&ovey_dev->real_gid)) {
			rdma_ah_set_dgid_raw(
				&qp_attr_real->ah_attr,
				&rdma_ah_read_grh(&qp_attr_virt->ah_attr)->dgid);

		} else {
			rdma_ah_set_subnet_prefix(&qp_attr_real->ah_attr,
						  resp->subnet_prefix);
			rdma_ah_set_interface_id(&qp_attr_real->ah_attr,
						 resp->interface_id);
		}

		rdma_ah_set_grh(&qp_attr_real->ah_attr, NULL, grh->flow_label,
				grh->sgid_index, grh->hop_limit,
				grh->traffic_class);
	} else {
		rdma_ah_set_ah_flags(&qp_attr_real->ah_attr, 0);
	}

	if (atomic_read(&ovey_dev->real_lid)) {
		rdma_ah_set_dlid(&qp_attr_real->ah_attr,
				rdma_ah_get_dlid(&qp_attr_virt->ah_attr));
	} else {
		rdma_ah_set_dlid(&qp_attr_real->ah_attr, resp->lid);
	}
	rdma_ah_set_sl(&qp_attr_real->ah_attr,
		       rdma_ah_get_sl(&qp_attr_virt->ah_attr));
	rdma_ah_set_path_bits(&qp_attr_real->ah_attr,
			      rdma_ah_get_path_bits(&qp_attr_virt->ah_attr));
	rdma_ah_set_static_rate(&qp_attr_real->ah_attr,
				rdma_ah_get_static_rate(&qp_attr_virt->ah_attr));
	rdma_ah_set_port_num(&qp_attr_real->ah_attr,
			     rdma_ah_get_port_num(&qp_attr_virt->ah_attr));
	rdma_ah_set_make_grd(&qp_attr_real->ah_attr,
			     rdma_ah_get_make_grd(&qp_attr_virt->ah_attr));
	if (atomic_read(&ovey_dev->real_qpn)) {
		qp_attr_real->dest_qp_num = qp_attr_virt->dest_qp_num;
	} else {
		qp_attr_real->dest_qp_num = resp->qpn;
	}

out:

	return ret;
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

	if (count > sizeof(resp)) {
		/* Give enough memory for at least single response */
		return -ENOMEM;
	}

	if (!access_ok(buf, sizeof(resp))) {
		return -EACCES;
	}

	ret = copy_from_user(&resp, buf, count);
	if (ret) {
		return -EFAULT;
	}

	spin_lock_irqsave(&oveyd_lock, flags);
	list_for_each_entry_safe(i, tmp, &oveyd_request_list, head) {
		if (i->req.seq != resp.seq) {
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
