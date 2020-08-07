// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <net/addrconf.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_user_ioctl_verbs_dump.h>
/* XXX: Hack must be removed */
#include "../../core/uverbs.h"
#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"
#include "rxe_hw_counters.h"

static int init_send_wqe(struct rxe_qp *qp, const struct ib_send_wr *ibwr,
			 unsigned int mask, unsigned int length,
			 struct rxe_send_wqe *wqe);

static int rxe_query_device(struct ib_device *dev,
			    struct ib_device_attr *attr,
			    struct ib_udata *uhw)
{
	struct rxe_dev *rxe = to_rdev(dev);

	if (uhw->inlen || uhw->outlen)
		return -EINVAL;

	*attr = rxe->attr;
	return 0;
}

static int rxe_query_port(struct ib_device *dev,
			  u8 port_num, struct ib_port_attr *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_port *port;
	int rc;

	port = &rxe->port;

	/* *attr being zeroed by the caller, avoid zeroing it here */
	*attr = port->attr;

	mutex_lock(&rxe->usdev_lock);
	rc = ib_get_eth_speed(dev, port_num, &attr->active_speed,
			      &attr->active_width);

	if (attr->state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else if (dev_get_flags(rxe->ndev) & IFF_UP)
		attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	mutex_unlock(&rxe->usdev_lock);

	return rc;
}

static int rxe_query_pkey(struct ib_device *device,
			  u8 port_num, u16 index, u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = IB_DEFAULT_PKEY_FULL;
	return 0;
}

static int rxe_modify_device(struct ib_device *dev,
			     int mask, struct ib_device_modify *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);

	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID |
		     IB_DEVICE_MODIFY_NODE_DESC))
		return -EOPNOTSUPP;

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		rxe->attr.sys_image_guid = cpu_to_be64(attr->sys_image_guid);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		memcpy(rxe->ib_dev.node_desc,
		       attr->node_desc, sizeof(rxe->ib_dev.node_desc));
	}

	return 0;
}

static int rxe_modify_port(struct ib_device *dev,
			   u8 port_num, int mask, struct ib_port_modify *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_port *port;

	port = &rxe->port;

	port->attr.port_cap_flags |= attr->set_port_cap_mask;
	port->attr.port_cap_flags &= ~attr->clr_port_cap_mask;

	if (mask & IB_PORT_RESET_QKEY_CNTR)
		port->attr.qkey_viol_cntr = 0;

	return 0;
}

static enum rdma_link_layer rxe_get_link_layer(struct ib_device *dev,
					       u8 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int rxe_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(uctx->device);
	struct rxe_ucontext *uc = to_ruc(uctx);

	return rxe_add_to_pool(&rxe->uc_pool, &uc->pelem);
}

static void rxe_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	struct rxe_ucontext *uc = to_ruc(ibuc);

	rxe_drop_ref(&uc->pelem);
}

static int rxe_port_immutable(struct ib_device *dev, u8 port_num,
			      struct ib_port_immutable *immutable)
{
	int err;
	struct ib_port_attr attr;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	err = ib_query_port(dev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

static int rxe_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);

	return rxe_add_to_pool(&rxe->pd_pool, &pd->pelem);
}

static int rxe_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct rxe_pd *pd = to_rpd(ibpd);

	rxe_drop_ref(&pd->pelem);
	return 0;
}

static int rxe_save_queue(struct rxe_dump_queue *dump_queue, struct rxe_queue *queue)
{
	if (!queue) {
		return -EINVAL;
	}

	if (!dump_queue) {
		return -EINVAL;
	}

	if (queue->ip) {
		dump_queue->start = queue->ip->vma->vm_start;
		dump_queue->size = queue->ip->info.size;
		if (queue->ip->vma->vm_end - queue->ip->vma->vm_start != dump_queue->size) {
			pr_warn("Found discrepancy in queue size\n");
		}
	} else {
		dump_queue->start = 0;
		dump_queue->size = 0;
	}
	dump_queue->log2_elem_size	= queue->log2_elem_size;
	dump_queue->index_mask	= queue->index_mask;
	dump_queue->producer_index	= queue->buf->producer_index;
	dump_queue->consumer_index	= queue->buf->consumer_index;

	return 0;
}

static int rxe_restore_queue(struct rxe_queue *queue, const struct rxe_dump_queue *dump_queue)
{
	if (!queue)
		return -EINVAL;

	if (!dump_queue)
		return -EINVAL;

	queue->log2_elem_size      = dump_queue->log2_elem_size;
	queue->index_mask          = dump_queue->index_mask;

	if (queue->buf) {
		queue->buf->log2_elem_size = dump_queue->log2_elem_size;
		queue->buf->index_mask     = dump_queue->index_mask;
		queue->buf->producer_index = dump_queue->producer_index;
		queue->buf->consumer_index = dump_queue->consumer_index;
	}

	return 0;
}

static int rxe_dump_ah(struct ib_qp *ib_qp, struct ib_uverbs_dump_object_ah *dump_ah, ssize_t size)
{
	if (size < sizeof(*dump_ah)) {
		return -ENOMEM;
	}

	return sizeof(*dump_ah);
}

static int rxe_dump_qp(struct ib_qp *ib_qp, struct ib_uverbs_dump_object_qp *dump_qp, ssize_t size)
{
	int ret;
	int offset = 0;
	int remain = size - sizeof(*dump_qp);
	struct rxe_qp *qp;

	if (remain < 0) {
		return -ENOMEM;
	}

	qp = to_rqp(ib_qp);

	if (!qp) {
		return -EINVAL;
	}

	if (qp->rq.queue) {
		ret = rxe_save_queue(&dump_qp->rxe.rq, qp->rq.queue);
		if (ret)
			return ret;
		dump_qp->rxe.srq_wqe_offset = 0;
	} else if (qp->srq) {
		if (remain < sizeof(qp->resp.srq_wqe)) {
			return -ENOMEM;
		}

		dump_qp->rxe.srq_wqe_offset = offset;
		dump_qp->rxe.srq_wqe_size = sizeof(qp->resp.srq_wqe);
		memcpy(&dump_qp->rxe.data[dump_qp->rxe.srq_wqe_offset], &qp->resp.srq_wqe, dump_qp->rxe.srq_wqe_size);
		remain -= dump_qp->rxe.srq_wqe_size;
		offset += dump_qp->rxe.srq_wqe_size;
	} else {
		return -EINVAL;
	}

	ret = rxe_save_queue(&dump_qp->rxe.sq, qp->sq.queue);
	if (ret)
		return ret;

	dump_qp->rxe.wqe_index = qp->req.wqe_index;
	dump_qp->rxe.req_opcode = qp->req.opcode;
	dump_qp->rxe.comp_psn = qp->comp.psn;
	dump_qp->rxe.comp_opcode = qp->comp.opcode;
	dump_qp->rxe.msn = qp->resp.msn;
	dump_qp->rxe.resp_opcode = qp->resp.opcode;

	return sizeof(*dump_qp) + offset;
}

static int rxe_dump_srq(struct ib_srq *ib_srq, struct ib_uverbs_dump_object_srq *dump_srq, ssize_t size)
{
	int ret;
	struct rxe_srq *srq;

	if (size < sizeof(*dump_srq)) {
		return -ENOMEM;
	}

	srq = to_rsrq(ib_srq);

	if (!srq) {
		return -EINVAL;
	}

	ret = rxe_save_queue(&dump_srq->queue, srq->rq.queue);
	if (ret)
		return ret;

	return sizeof(*dump_srq);
}

static int rxe_dump_cq(struct ib_cq *ib_cq, struct ib_uverbs_dump_object_cq *dump_cq, ssize_t size)
{
	int ret;
	struct rxe_cq *cq;

	if (size < sizeof(*dump_cq)) {
		return -ENOMEM;
	}

	cq = to_rcq(ib_cq);

	/* Unimportant */
	dump_cq->comp_vector = 0;

	ret = rxe_save_queue(&dump_cq->rxe, cq->queue);
	if (ret)
		return ret;

	return sizeof(*dump_cq);
}

static int rxe_dump_mr(struct ib_mr *ib_mr, struct ib_uverbs_dump_object_mr *dump_mr, ssize_t size)
{
	struct rxe_mem *mr;
	if (size < sizeof(*dump_mr)) {
		return -ENOMEM;
	}

	mr = to_rmr(ib_mr);

	dump_mr->address = mr->umem->address;
	dump_mr->length = mr->length;
	dump_mr->access = mr->access;

	dump_mr->rxe.mrn = mr->pelem.index;

	return sizeof(*dump_mr);
}

static int rxe_dump_pd(struct ib_pd *pd, struct ib_uverbs_dump_object_pd *dump_pd, ssize_t size)
{
	if (size < sizeof(*dump_pd)) {
		return -ENOMEM;
	}

	return sizeof(*dump_pd);
}

static int rxe_dump_object(u32 obj_type, void *req, void *dump, ssize_t size)
{
	switch (obj_type) {
	case IB_UVERBS_OBJECT_PD:
		return rxe_dump_pd(req, dump, size);
	case IB_UVERBS_OBJECT_MR:
		return rxe_dump_mr(req, dump, size);
	case IB_UVERBS_OBJECT_CQ:
		return rxe_dump_cq(req, dump, size);
	case IB_UVERBS_OBJECT_QP:
		return rxe_dump_qp(req, dump, size);
	case IB_UVERBS_OBJECT_AH:
		return rxe_dump_ah(req, dump, size);
	case IB_UVERBS_OBJECT_SRQ:
		return rxe_dump_srq(req, dump, size);
	default:
		return -ENOTSUPP;
	}
	/* Not reached */
}

static int
rxe_restore_cq_refill(struct rxe_cq *rcq,
		      const struct ib_uverbs_restore_object_cq_refill *queue,
		      ssize_t size)
{
	int ret = 0;
	/* unsigned long flags; */
	if (rcq->queue) {
		/* spin_lock_irqsave(&rcq->cq_lock, flags); */
		ret = rxe_restore_queue(rcq->queue, &queue->rxe);
		/* spin_unlock_irqrestore(&rcq->cq_lock, flags); */
	}


	rcq->ibcq.uobject->comp_events_reported = queue->comp_events_reported;
	rcq->ibcq.uobject->uevent.events_reported = queue->async_events_reported;

	return ret;
}

static int rxe_restore_cq(struct ib_cq *cq,
			  u32 cmd, const void *args, ssize_t size)
{
	int ret;
	struct rxe_cq *rcq = to_rcq(cq);

	if (!rcq)
		return -EINVAL;

	switch (cmd) {
	case IB_RESTORE_CQ_REFILL:
		ret = rxe_restore_cq_refill(rcq, args, size);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int rxe_restore_qp_refill(struct rxe_qp *rqp,
				 const struct rxe_dump_qp *qp, ssize_t size)
{
	int ret = 0;

	if (!rqp->sq.queue)
		return -EINVAL;

	/* unsigned long flags; */
	/* spin_lock_irqsave(&rqp->sq.sq_lock, flags); */
	ret = rxe_restore_queue(rqp->sq.queue, &qp->sq);
	/* spin_unlock_irqrestore(&rqp->sq.sq_lock, flags); */

	if (ret)
		return ret;

	/* We can have SRQ or RQ */
	if (rqp->rq.queue) {
		/* unsigned long producer_flags, consumer_flags; */

		/* spin_lock_irqsave(&rqp->rq.consumer_lock, consumer_flags); */
		/* spin_lock_irqsave(&rqp->rq.producer_lock, producer_flags); */
		ret = rxe_restore_queue(rqp->rq.queue, &qp->rq);
		if (ret)
			return ret;
		/* spin_unlock_irqrestore(&rqp->rq.producer_lock, producer_flags); */
		/* spin_unlock_irqrestore(&rqp->rq.consumer_lock, consumer_flags); */
		rqp->resp.wqe = queue_head(rqp->rq.queue);
	} else if (rqp->srq) {
		if (qp->srq_wqe_size != sizeof(rqp->resp.srq_wqe)) {
			return -EINVAL;
		}
		rqp->resp.wqe = &rqp->resp.srq_wqe.wqe;
		memcpy(&rqp->resp.srq_wqe, &qp->data[qp->srq_wqe_offset], sizeof(rqp->resp.srq_wqe));
		ret = 0;
	} else {
		ret = 0;
		pr_err("Skipping RQ of a QP %d\n", __LINE__);
	}

	rqp->req.wqe_index = qp->wqe_index;
	rqp->req.opcode = qp->req_opcode;
	rqp->comp.opcode = qp->comp_opcode;
	rqp->comp.psn = qp->comp_psn;
	rqp->resp.msn = qp->msn;
	rqp->resp.opcode = qp->resp_opcode;

	return ret;
}

static int rxe_restore_qp(struct ib_qp *qp,
			  u32 cmd, const void *args, ssize_t size)
{
	struct rxe_qp *rqp = to_rqp(qp);

	if (!rqp)
		return -EINVAL;

	switch(cmd) {
	case IB_RESTORE_QP_REFILL:
		return rxe_restore_qp_refill(rqp, args, size);
	default:
		return -EINVAL;
	}
}

static int rxe_restore_srq_refill(struct rxe_srq *rsrq,
				  const struct rxe_dump_queue *queue, ssize_t size)
{
	int ret = 0;

	if (!rsrq->rq.queue)
		return -EINVAL;

	if (!queue)
		return -EINVAL;

	ret = rxe_restore_queue(rsrq->rq.queue, queue);
	if (ret) {
		return ret;
	}

	return ret;
}

static int rxe_restore_srq(struct ib_srq *srq,
			   u32 cmd, const void *args, ssize_t size)
{
	struct rxe_srq *rsrq = to_rsrq(srq);

	if (!rsrq)
		return -EINVAL;

	switch(cmd) {
	case IB_RESTORE_SRQ_REFILL:
		return rxe_restore_srq_refill(rsrq, args, size);
	default:
		return -EINVAL;
	}
}

static int rxe_restore_mr_keys(struct rxe_mem *mr,
			       const struct rxe_dump_mr *args, ssize_t size)
{
	int ret = 0;

	if (sizeof(*args) > size) {
		return -EINVAL;
	}

	mr->ibmr.lkey = args->lkey;
	mr->ibmr.rkey = args->rkey;

	return ret;
}

static int rxe_restore_mr(struct ib_mr *mr,
			  u32 cmd, const void *args, ssize_t size)
{
	struct rxe_mem *rmr = to_rmr(mr);

	if (!rmr)
		return -EINVAL;

	switch (cmd) {
	case IB_RESTORE_MR_KEYS:
		return rxe_restore_mr_keys(rmr, args, size);
	default:
		return -EINVAL;
	}
}

static int rxe_restore_object(void *object, u32 obj_type,
			      u32 cmd, const void *args, ssize_t size)
{
	if (!object) {
		return -EINVAL;
	}

	switch (obj_type) {
	case IB_UVERBS_OBJECT_CQ:
		return rxe_restore_cq(object, cmd, args, size);
	case IB_UVERBS_OBJECT_QP:
		return rxe_restore_qp(object, cmd, args, size);
	case IB_UVERBS_OBJECT_MR:
		return rxe_restore_mr(object, cmd, args, size);
	case IB_UVERBS_OBJECT_SRQ:
		return rxe_restore_srq(object, cmd, args, size);
	default:
		return -EINVAL;
	}
}

static int rxe_pause_qp(struct rxe_qp *qp)
{
	switch (qp_type(qp)) {
#if RXE_MIGRATION
	case IB_QPT_RC:
		qp->stopped = true;

		rxe_run_task_wait(&qp->req.task);
		rxe_run_task_wait(&qp->resp.task);
		rxe_run_task_wait(&qp->comp.task);

		return 0;
	case IB_QPT_UD:
		qp->stopped = true;

		rxe_run_task_wait(&qp->req.task);
		rxe_run_task_wait(&qp->resp.task);
		rxe_run_task_wait(&qp->comp.task);
		return 0;
#endif
	default:
		return -ENOTSUPP;
	}
}

#if RXE_MIGRATION
static int rxe_resume_qp_rc(struct rxe_qp *qp)
{
	/* Send an out-of-queue message and wait for an acknowledgement. */
	struct rxe_send_wqe *wqe;
	unsigned int mask;
	unsigned int length = 0;
	/* struct ib_drain_cqe sdrain; */
	struct ib_rdma_wr swr = {
		.wr = {
			.next = NULL,
			/* { .wr_cqe	= &sdrain.cqe, }, */
			.opcode	= IB_WR_RESUME,
			.send_flags = IB_SEND_INLINE,
		},
	};

	if (qp->attr.dest_qp_num == qp_num(qp))
		return 0;

	wqe = kmalloc(sizeof(*wqe), GFP_ATOMIC);
	if (!wqe) {
		return -ENOMEM;
	}

	mask = wr_opcode_mask(swr.wr.opcode, qp);
	init_send_wqe(qp, &swr.wr, mask, length, wqe);

	qp->req.resume_wqe = wqe;
	qp->req.resume_posted = false;
	BUG_ON(qp->paused);

	rxe_run_task_wait(&qp->req.task);

#if 0
	if (cq->poll_ctx == IB_POLL_DIRECT)
		while (wait_for_completion_timeout(&sdrain.done, HZ / 10) <= 0)
			ib_process_cq_direct(cq, -1);
	else
		wait_for_completion(&sdrain.done);
#endif

	return 0;
}
#endif

static int rxe_resume_qp(struct rxe_qp *qp)
{
	switch (qp_type(qp)) {
#if RXE_MIGRATION
	case IB_QPT_RC:
		return rxe_resume_qp_rc(qp);
	case IB_QPT_UD:
		/* XXX: Unpausing UD qp -- doing nothing */
		return 0;
#endif
	default:
		return -ENOTSUPP;
	}
}

static int rxe_pause_resume_qp(struct ib_qp *qp, bool resume)
{
	struct rxe_qp *rqp = to_rqp(qp);

	if (resume)
		return rxe_resume_qp(rqp);
	else
		return rxe_pause_qp(rqp);
}

static int rxe_create_ah(struct ib_ah *ibah,
			 struct rdma_ah_init_attr *init_attr,
			 struct ib_udata *udata)

{
	int err;
	struct rxe_dev *rxe = to_rdev(ibah->device);
	struct rxe_ah *ah = to_rah(ibah);
	struct rxe_create_ah_resp __user *uresp = NULL;

	if (udata) {
		if (udata->outlen < sizeof(*uresp))
			return -EINVAL;
		uresp = udata->outbuf;
	}

	err = rxe_av_chk_attr(rxe, init_attr->ah_attr);
	if (err)
		return err;

	err = rxe_add_to_pool(&rxe->ah_pool, &ah->pelem);
	if (err)
		return err;

	rxe_init_av(init_attr->ah_attr, &ah->av);
	if (copy_to_user(uresp->dmac, ah->av.dmac, sizeof(uresp->dmac))) {
		return -EFAULT;
	};
	return 0;
}

static int rxe_modify_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibah->device);
	struct rxe_ah *ah = to_rah(ibah);

	err = rxe_av_chk_attr(rxe, attr);
	if (err)
		return err;

	rxe_init_av(attr, &ah->av);
	return 0;
}

static int rxe_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr)
{
	struct rxe_ah *ah = to_rah(ibah);

	memset(attr, 0, sizeof(*attr));
	attr->type = ibah->type;
	rxe_av_to_attr(&ah->av, attr);
	return 0;
}

static int rxe_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	struct rxe_ah *ah = to_rah(ibah);

	rxe_drop_ref(&ah->pelem);
	return 0;
}

static int post_one_recv(struct rxe_rq *rq, const struct ib_recv_wr *ibwr)
{
	int err;
	int i;
	u32 length;
	struct rxe_recv_wqe *recv_wqe;
	int num_sge = ibwr->num_sge;

	if (unlikely(queue_full(rq->queue))) {
		err = -ENOMEM;
		goto err1;
	}

	if (unlikely(num_sge > rq->max_sge)) {
		err = -EINVAL;
		goto err1;
	}

	length = 0;
	for (i = 0; i < num_sge; i++)
		length += ibwr->sg_list[i].length;

	recv_wqe = producer_addr(rq->queue);
	recv_wqe->wr_id = ibwr->wr_id;
	recv_wqe->num_sge = num_sge;

	memcpy(recv_wqe->dma.sge, ibwr->sg_list,
	       num_sge * sizeof(struct ib_sge));

	recv_wqe->dma.length		= length;
	recv_wqe->dma.resid		= length;
	recv_wqe->dma.num_sge		= num_sge;
	recv_wqe->dma.cur_sge		= 0;
	recv_wqe->dma.sge_offset	= 0;

	/* make sure all changes to the work queue are written before we
	 * update the producer pointer
	 */
	smp_wmb();

	advance_producer(rq->queue);
	return 0;

err1:
	return err;
}

static int rxe_create_srq(struct ib_srq *ibsrq, struct ib_srq_init_attr *init,
			  struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibsrq->device);
	struct rxe_pd *pd = to_rpd(ibsrq->pd);
	struct rxe_srq *srq = to_rsrq(ibsrq);
	struct rxe_create_srq_resp __user *uresp = NULL;

	if (udata) {
		if (udata->outlen < sizeof(*uresp))
			return -EINVAL;
		uresp = udata->outbuf;
	}

	err = rxe_srq_chk_attr(rxe, NULL, &init->attr, IB_SRQ_INIT_MASK);
	if (err)
		goto err1;

	err = rxe_add_to_pool(&rxe->srq_pool, &srq->pelem);
	if (err)
		goto err1;

	rxe_add_ref(&pd->pelem);
	srq->pd = pd;

	err = rxe_srq_from_init(rxe, srq, init, udata, uresp);
	if (err)
		goto err2;

	return 0;

err2:
	rxe_drop_ref(&pd->pelem);
	rxe_drop_ref(&srq->pelem);
err1:
	return err;
}

static int rxe_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask mask,
			  struct ib_udata *udata)
{
	int err;
	struct rxe_srq *srq = to_rsrq(ibsrq);
	struct rxe_dev *rxe = to_rdev(ibsrq->device);
	struct rxe_modify_srq_cmd ucmd = {};

	if (udata) {
		if (udata->inlen < sizeof(ucmd))
			return -EINVAL;

		err = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
		if (err)
			return err;
	}

	err = rxe_srq_chk_attr(rxe, srq, attr, mask);
	if (err)
		goto err1;

	err = rxe_srq_from_attr(rxe, srq, attr, mask, &ucmd, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}

static int rxe_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);

	if (srq->error)
		return -EINVAL;

	attr->max_wr = srq->rq.queue->buf->index_mask;
	attr->max_sge = srq->rq.max_sge;
	attr->srq_limit = srq->limit;
	return 0;
}

static int rxe_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);

	if (srq->rq.queue)
		rxe_queue_cleanup(srq->rq.queue);

	rxe_drop_ref(&srq->pd->pelem);
	rxe_drop_ref(&srq->pelem);
	return 0;
}

static int rxe_post_srq_recv(struct ib_srq *ibsrq, const struct ib_recv_wr *wr,
			     const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	unsigned long flags;
	struct rxe_srq *srq = to_rsrq(ibsrq);

	spin_lock_irqsave(&srq->rq.producer_lock, flags);

	while (wr) {
		err = post_one_recv(&srq->rq, wr);
		if (unlikely(err))
			break;
		wr = wr->next;
	}

	spin_unlock_irqrestore(&srq->rq.producer_lock, flags);

	if (err)
		*bad_wr = wr;

	return err;
}

extern unsigned int last_qpn;

static struct ib_qp *rxe_create_qp(struct ib_pd *ibpd,
				   struct ib_qp_init_attr *init,
				   struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_qp *qp;
	struct rxe_create_qp_resp __user *uresp = NULL;

	if (udata) {
		if (udata->outlen < sizeof(*uresp))
			return ERR_PTR(-EINVAL);
		uresp = udata->outbuf;
	}

	err = rxe_qp_chk_init(rxe, init);
	if (err)
		goto err1;

	qp = rxe_alloc(&rxe->qp_pool);
	if (!qp) {
		err = -ENOMEM;
		goto err1;
	}

	if (udata) {
		if (udata->inlen) {
			err = -EINVAL;
			goto err2;
		}
		qp->is_user = 1;
	}

	/* XXX: Hacky solution to control qpn */
	rxe->qp_pool.last = last_qpn;

	rxe_add_index(&qp->pelem);

	last_qpn = rxe->qp_pool.last;

	err = rxe_qp_from_init(rxe, qp, pd, init, uresp, ibpd, udata);
	if (err)
		goto err3;

	return &qp->ibqp;

err3:
	rxe_drop_index(&qp->pelem);
err2:
	rxe_drop_ref(&qp->pelem);
err1:
	return ERR_PTR(err);
}

static int rxe_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int mask, struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);

	err = rxe_qp_chk_attr(rxe, qp, attr, mask);
	if (err)
		goto err1;

	err = rxe_qp_from_attr(qp, attr, mask, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}

static int rxe_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int mask, struct ib_qp_init_attr *init)
{
	struct rxe_qp *qp = to_rqp(ibqp);

	rxe_qp_to_init(qp, init);
	rxe_qp_to_attr(qp, attr, mask);

	return 0;
}

static int rxe_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct rxe_qp *qp = to_rqp(ibqp);
	DECLARE_COMPLETION_ONSTACK(cleanup_completion);

	BUG_ON(qp->cleanup_completion);
	qp->cleanup_completion = &cleanup_completion;

	rxe_qp_destroy(qp);
	rxe_drop_index(&qp->pelem);
	rxe_drop_ref(&qp->pelem);

	wait_for_completion(&cleanup_completion);

	return 0;
}

static int validate_send_wr(struct rxe_qp *qp, const struct ib_send_wr *ibwr,
			    unsigned int mask, unsigned int length)
{
	int num_sge = ibwr->num_sge;
	struct rxe_sq *sq = &qp->sq;

	if (unlikely(num_sge > sq->max_sge))
		goto err1;

	if (unlikely(mask & WR_ATOMIC_MASK)) {
		if (length < 8)
			goto err1;

		if (atomic_wr(ibwr)->remote_addr & 0x7)
			goto err1;
	}

	if (unlikely((ibwr->send_flags & IB_SEND_INLINE) &&
		     (length > sq->max_inline)))
		goto err1;

	return 0;

err1:
	return -EINVAL;
}

static void init_send_wr(struct rxe_qp *qp, struct rxe_send_wr *wr,
			 const struct ib_send_wr *ibwr)
{
	wr->wr_id = ibwr->wr_id;
	wr->num_sge = ibwr->num_sge;
	wr->opcode = ibwr->opcode;
	wr->send_flags = ibwr->send_flags;

	if (qp_type(qp) == IB_QPT_UD ||
	    qp_type(qp) == IB_QPT_SMI ||
	    qp_type(qp) == IB_QPT_GSI) {
		wr->wr.ud.remote_qpn = ud_wr(ibwr)->remote_qpn;
		wr->wr.ud.remote_qkey = ud_wr(ibwr)->remote_qkey;
		if (qp_type(qp) == IB_QPT_GSI)
			wr->wr.ud.pkey_index = ud_wr(ibwr)->pkey_index;
		if (wr->opcode == IB_WR_SEND_WITH_IMM)
			wr->ex.imm_data = ibwr->ex.imm_data;
	} else {
		switch (wr->opcode) {
		case IB_WR_RDMA_WRITE_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			fallthrough;
		case IB_WR_RDMA_READ:
		case IB_WR_RDMA_WRITE:
			wr->wr.rdma.remote_addr = rdma_wr(ibwr)->remote_addr;
			wr->wr.rdma.rkey	= rdma_wr(ibwr)->rkey;
			break;
		case IB_WR_SEND_WITH_IMM:
			wr->ex.imm_data = ibwr->ex.imm_data;
			break;
		case IB_WR_SEND_WITH_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
			break;
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			wr->wr.atomic.remote_addr =
				atomic_wr(ibwr)->remote_addr;
			wr->wr.atomic.compare_add =
				atomic_wr(ibwr)->compare_add;
			wr->wr.atomic.swap = atomic_wr(ibwr)->swap;
			wr->wr.atomic.rkey = atomic_wr(ibwr)->rkey;
			break;
		case IB_WR_LOCAL_INV:
			wr->ex.invalidate_rkey = ibwr->ex.invalidate_rkey;
		break;
		case IB_WR_REG_MR:
			wr->wr.reg.mr = reg_wr(ibwr)->mr;
			wr->wr.reg.key = reg_wr(ibwr)->key;
			wr->wr.reg.access = reg_wr(ibwr)->access;
		break;
		default:
			break;
		}
	}
}

static int init_send_wqe(struct rxe_qp *qp, const struct ib_send_wr *ibwr,
			 unsigned int mask, unsigned int length,
			 struct rxe_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;
	struct ib_sge *sge;
	int i;
	u8 *p;

	init_send_wr(qp, &wqe->wr, ibwr);

	if (qp_type(qp) == IB_QPT_UD ||
	    qp_type(qp) == IB_QPT_SMI ||
	    qp_type(qp) == IB_QPT_GSI)
		memcpy(&wqe->av, &to_rah(ud_wr(ibwr)->ah)->av, sizeof(wqe->av));

	if (unlikely(ibwr->send_flags & IB_SEND_INLINE)) {
		p = wqe->dma.inline_data;

		sge = ibwr->sg_list;
		for (i = 0; i < num_sge; i++, sge++) {
			memcpy(p, (void *)(uintptr_t)sge->addr,
					sge->length);

			p += sge->length;
		}
	} else if (mask & WR_REG_MASK) {
		wqe->mask = mask;
		wqe->state = wqe_state_posted;
		return 0;
	} else
		memcpy(wqe->dma.sge, ibwr->sg_list,
		       num_sge * sizeof(struct ib_sge));

	wqe->iova = mask & WR_ATOMIC_MASK ? atomic_wr(ibwr)->remote_addr :
		mask & WR_READ_OR_WRITE_MASK ? rdma_wr(ibwr)->remote_addr : 0;
	wqe->mask		= mask;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= wqe_state_posted;
	wqe->ssn		= atomic_add_return(1, &qp->ssn);

	return 0;
}

static int post_one_send(struct rxe_qp *qp, const struct ib_send_wr *ibwr,
			 unsigned int mask, u32 length)
{
	int err;
	struct rxe_sq *sq = &qp->sq;
	struct rxe_send_wqe *send_wqe;
	unsigned long flags;

	err = validate_send_wr(qp, ibwr, mask, length);
	if (err)
		return err;

	spin_lock_irqsave(&qp->sq.sq_lock, flags);

	if (unlikely(queue_full(sq->queue))) {
		err = -ENOMEM;
		goto err1;
	}

	send_wqe = producer_addr(sq->queue);

	err = init_send_wqe(qp, ibwr, mask, length, send_wqe);
	if (unlikely(err))
		goto err1;

	/*
	 * make sure all changes to the work queue are
	 * written before we update the producer pointer
	 */
	smp_wmb();

	advance_producer(sq->queue);
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);

	return 0;

err1:
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);
	return err;
}

static int rxe_post_send_kernel(struct rxe_qp *qp, const struct ib_send_wr *wr,
				const struct ib_send_wr **bad_wr)
{
	int err = 0;
	unsigned int mask;
	unsigned int length = 0;
	int i;
	struct ib_send_wr *next;

	while (wr) {
		mask = wr_opcode_mask(wr->opcode, qp);
		if (unlikely(!mask)) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		if (unlikely((wr->send_flags & IB_SEND_INLINE) &&
			     !(mask & WR_INLINE_MASK))) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		next = wr->next;

		length = 0;
		for (i = 0; i < wr->num_sge; i++)
			length += wr->sg_list[i].length;

		err = post_one_send(qp, wr, mask, length);

		if (err) {
			*bad_wr = wr;
			break;
		}
		wr = next;
	}

	rxe_run_task(&qp->req.task);
	if (unlikely(qp->req.state == QP_STATE_ERROR))
		rxe_run_task(&qp->comp.task);

	return err;
}

static int rxe_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	struct rxe_qp *qp = to_rqp(ibqp);

	if (unlikely(!qp->valid)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	if (unlikely(qp->req.state < QP_STATE_READY)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	if (qp->is_user) {
		/* Utilize process context to do protocol processing */
		rxe_run_task(&qp->req.task);
		return 0;
	} else
		return rxe_post_send_kernel(qp, wr, bad_wr);
}

static int rxe_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_rq *rq = &qp->rq;
	unsigned long flags;

	if (unlikely((qp_state(qp) < IB_QPS_INIT) || !qp->valid)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	if (unlikely(qp->srq)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	spin_lock_irqsave(&rq->producer_lock, flags);

	while (wr) {
		err = post_one_recv(rq, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}

	spin_unlock_irqrestore(&rq->producer_lock, flags);

	if (qp->resp.state == QP_STATE_ERROR)
		rxe_run_task(&qp->resp.task);

err1:
	return err;
}

static int rxe_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr,
			 struct ib_udata *udata)
{
	int err;
	struct ib_device *dev = ibcq->device;
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_create_cq_resp __user *uresp = NULL;

	if (udata) {
		if (udata->outlen < sizeof(*uresp))
			return -EINVAL;
		uresp = udata->outbuf;
	}

	if (attr->flags)
		return -EINVAL;

	err = rxe_cq_chk_attr(rxe, NULL, attr->cqe, attr->comp_vector);
	if (err)
		return err;

	err = rxe_cq_from_init(rxe, cq, attr->cqe, attr->comp_vector, udata,
			       uresp);
	if (err)
		return err;

	return rxe_add_to_pool(&rxe->cq_pool, &cq->pelem);
}

static int rxe_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct rxe_cq *cq = to_rcq(ibcq);

	rxe_cq_disable(cq);

	rxe_drop_ref(&cq->pelem);
	return 0;
}

static int rxe_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata)
{
	int err;
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_dev *rxe = to_rdev(ibcq->device);
	struct rxe_resize_cq_resp __user *uresp = NULL;

	if (udata) {
		if (udata->outlen < sizeof(*uresp))
			return -EINVAL;
		uresp = udata->outbuf;
	}

	err = rxe_cq_chk_attr(rxe, cq, cqe, 0);
	if (err)
		goto err1;

	err = rxe_cq_resize_queue(cq, cqe, uresp, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}

static int rxe_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	int i;
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);
	for (i = 0; i < num_entries; i++) {
		cqe = queue_head(cq->queue);
		if (!cqe)
			break;

		memcpy(wc++, &cqe->ibwc, sizeof(*wc));
		advance_consumer(cq->queue);
	}
	spin_unlock_irqrestore(&cq->cq_lock, flags);

	return i;
}

static int rxe_peek_cq(struct ib_cq *ibcq, int wc_cnt)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	int count = queue_count(cq->queue);

	return (count > wc_cnt) ? wc_cnt : count;
}

static int rxe_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	unsigned long irq_flags;
	int ret = 0;

	spin_lock_irqsave(&cq->cq_lock, irq_flags);
	if (cq->notify != IB_CQ_NEXT_COMP)
		cq->notify = flags & IB_CQ_SOLICITED_MASK;

	if ((flags & IB_CQ_REPORT_MISSED_EVENTS) && !queue_empty(cq->queue))
		ret = 1;

	spin_unlock_irqrestore(&cq->cq_lock, irq_flags);

	return ret;
}

extern unsigned int last_mrn;

static struct ib_mr *rxe_get_dma_mr(struct ib_pd *ibpd, int access)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	/* XXX: Hacky solution to control mrn */
	rxe->mr_pool.last = last_mrn;

	rxe_add_index(&mr->pelem);

	last_mrn = rxe->mr_pool.last;

	rxe_add_ref(&pd->pelem);
	rxe_mem_init_dma(pd, access, mr);

	return &mr->ibmr;
}

static struct ib_mr *rxe_reg_user_mr(struct ib_pd *ibpd,
				     u64 start,
				     u64 length,
				     u64 iova,
				     int access, struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err2;
	}

	/* XXX: Hacky solution to control mrn */
	rxe->mr_pool.last = last_mrn;

	rxe_add_index(&mr->pelem);

	last_mrn = rxe->mr_pool.last;

	rxe_add_ref(&pd->pelem);

	err = rxe_mem_init_user(pd, start, length, iova,
				access, udata, mr);
	if (err)
		goto err3;

	return &mr->ibmr;

err3:
	rxe_drop_ref(&pd->pelem);
	rxe_drop_index(&mr->pelem);
	rxe_drop_ref(&mr->pelem);
err2:
	return ERR_PTR(err);
}

static int rxe_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct rxe_mem *mr = to_rmr(ibmr);

	mr->state = RXE_MEM_STATE_ZOMBIE;
	rxe_drop_ref(&mr_pd(mr)->pelem);
	rxe_drop_index(&mr->pelem);
	rxe_drop_ref(&mr->pelem);
	return 0;
}

static struct ib_mr *rxe_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type,
				  u32 max_num_sg)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;
	int err;

	if (mr_type != IB_MR_TYPE_MEM_REG)
		return ERR_PTR(-EINVAL);

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err1;
	}

	/* XXX: Hacky solution to control mrn */
	rxe->mr_pool.last = last_mrn;

	rxe_add_index(&mr->pelem);

	last_mrn = rxe->mr_pool.last;

	rxe_add_ref(&pd->pelem);

	err = rxe_mem_init_fast(pd, max_num_sg, mr);
	if (err)
		goto err2;

	return &mr->ibmr;

err2:
	rxe_drop_ref(&pd->pelem);
	rxe_drop_index(&mr->pelem);
	rxe_drop_ref(&mr->pelem);
err1:
	return ERR_PTR(err);
}

static int rxe_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct rxe_mem *mr = to_rmr(ibmr);
	struct rxe_map *map;
	struct rxe_phys_buf *buf;

	if (unlikely(mr->nbuf == mr->num_buf))
		return -ENOMEM;

	map = mr->map[mr->nbuf / RXE_BUF_PER_MAP];
	buf = &map->buf[mr->nbuf % RXE_BUF_PER_MAP];

	buf->addr = addr;
	buf->size = ibmr->page_size;
	mr->nbuf++;

	return 0;
}

static int rxe_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
			 int sg_nents, unsigned int *sg_offset)
{
	struct rxe_mem *mr = to_rmr(ibmr);
	int n;

	mr->nbuf = 0;

	n = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, rxe_set_page);

	mr->va = ibmr->iova;
	mr->iova = ibmr->iova;
	mr->length = ibmr->length;
	mr->page_shift = ilog2(ibmr->page_size);
	mr->page_mask = ibmr->page_size - 1;
	mr->offset = mr->iova & mr->page_mask;

	return n;
}

static int rxe_attach_mcast(struct ib_qp *ibqp, union ib_gid *mgid, u16 mlid)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_mc_grp *grp;

	/* takes a ref on grp if successful */
	err = rxe_mcast_get_grp(rxe, mgid, &grp);
	if (err)
		return err;

	err = rxe_mcast_add_grp_elem(rxe, qp, grp);

	rxe_drop_ref(&grp->pelem);
	return err;
}

static int rxe_detach_mcast(struct ib_qp *ibqp, union ib_gid *mgid, u16 mlid)
{
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);

	return rxe_mcast_drop_grp_elem(rxe, qp, mgid);
}

static ssize_t parent_show(struct device *device,
			   struct device_attribute *attr, char *buf)
{
	struct rxe_dev *rxe =
		rdma_device_to_drv_device(device, struct rxe_dev, ib_dev);

	return scnprintf(buf, PAGE_SIZE, "%s\n", rxe_parent_name(rxe, 1));
}

static DEVICE_ATTR_RO(parent);

static struct attribute *rxe_dev_attributes[] = {
	&dev_attr_parent.attr,
	NULL
};

static const struct attribute_group rxe_attr_group = {
	.attrs = rxe_dev_attributes,
};

static int rxe_enable_driver(struct ib_device *ib_dev)
{
	struct rxe_dev *rxe = container_of(ib_dev, struct rxe_dev, ib_dev);

	rxe_set_port_state(rxe);
	dev_info(&rxe->ib_dev.dev, "added %s\n", netdev_name(rxe->ndev));
	return 0;
}

static const struct ib_device_ops rxe_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_RXE,
	.uverbs_abi_ver = RXE_UVERBS_ABI_VERSION,

	.alloc_hw_stats = rxe_ib_alloc_hw_stats,
	.alloc_mr = rxe_alloc_mr,
	.alloc_pd = rxe_alloc_pd,
	.alloc_ucontext = rxe_alloc_ucontext,
	.attach_mcast = rxe_attach_mcast,
	.create_ah = rxe_create_ah,
	.create_cq = rxe_create_cq,
	.create_qp = rxe_create_qp,
	.create_srq = rxe_create_srq,
	.dealloc_driver = rxe_dealloc,
	.dealloc_pd = rxe_dealloc_pd,
	.dealloc_ucontext = rxe_dealloc_ucontext,
	.dereg_mr = rxe_dereg_mr,
	.destroy_ah = rxe_destroy_ah,
	.destroy_cq = rxe_destroy_cq,
	.destroy_qp = rxe_destroy_qp,
	.destroy_srq = rxe_destroy_srq,
	.detach_mcast = rxe_detach_mcast,
	.enable_driver = rxe_enable_driver,
	.get_dma_mr = rxe_get_dma_mr,
	.get_hw_stats = rxe_ib_get_hw_stats,
	.get_link_layer = rxe_get_link_layer,
	.get_port_immutable = rxe_port_immutable,
	.map_mr_sg = rxe_map_mr_sg,
	.mmap = rxe_mmap,
	.modify_ah = rxe_modify_ah,
	.modify_device = rxe_modify_device,
	.modify_port = rxe_modify_port,
	.modify_qp = rxe_modify_qp,
	.modify_srq = rxe_modify_srq,
	.peek_cq = rxe_peek_cq,
	.poll_cq = rxe_poll_cq,
	.post_recv = rxe_post_recv,
	.post_send = rxe_post_send,
	.post_srq_recv = rxe_post_srq_recv,
	.query_ah = rxe_query_ah,
	.query_device = rxe_query_device,
	.query_pkey = rxe_query_pkey,
	.query_port = rxe_query_port,
	.query_qp = rxe_query_qp,
	.query_srq = rxe_query_srq,
	.reg_user_mr = rxe_reg_user_mr,
	.req_notify_cq = rxe_req_notify_cq,
	.resize_cq = rxe_resize_cq,
	.dump_object = rxe_dump_object,
	.restore_object = rxe_restore_object,
	.pause_resume_qp = rxe_pause_resume_qp,

	INIT_RDMA_OBJ_SIZE(ib_ah, rxe_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, rxe_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, rxe_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_srq, rxe_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, rxe_ucontext, ibuc),
};

int rxe_register_device(struct rxe_dev *rxe, const char *ibdev_name)
{
	int err;
	struct ib_device *dev = &rxe->ib_dev;
	struct crypto_shash *tfm;
	u64 dma_mask;

	strlcpy(dev->node_desc, "rxe", sizeof(dev->node_desc));

	dev->node_type = RDMA_NODE_IB_CA;
	dev->phys_port_cnt = 1;
	dev->num_comp_vectors = num_possible_cpus();
	dev->dev.parent = rxe_dma_device(rxe);
	dev->local_dma_lkey = 0;
	addrconf_addr_eui48((unsigned char *)&dev->node_guid,
			    rxe->ndev->dev_addr);
	dev->dev.dma_parms = &rxe->dma_parms;
	dma_set_max_seg_size(&dev->dev, UINT_MAX);
	dma_mask = IS_ENABLED(CONFIG_64BIT) ? DMA_BIT_MASK(64) : DMA_BIT_MASK(32);
	err = dma_coerce_mask_and_coherent(&dev->dev, dma_mask);
	if (err)
		return err;

	dev->uverbs_cmd_mask = BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT)
	    | BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)
	    | BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE)
	    | BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT)
	    | BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD)
	    | BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD)
	    | BIT_ULL(IB_USER_VERBS_CMD_CREATE_SRQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_MODIFY_SRQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_QUERY_SRQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_DESTROY_SRQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_POST_SRQ_RECV)
	    | BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP)
	    | BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP)
	    | BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP)
	    | BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP)
	    | BIT_ULL(IB_USER_VERBS_CMD_POST_SEND)
	    | BIT_ULL(IB_USER_VERBS_CMD_POST_RECV)
	    | BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_RESIZE_CQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_PEEK_CQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)
	    | BIT_ULL(IB_USER_VERBS_CMD_REG_MR)
	    | BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR)
	    | BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH)
	    | BIT_ULL(IB_USER_VERBS_CMD_MODIFY_AH)
	    | BIT_ULL(IB_USER_VERBS_CMD_QUERY_AH)
	    | BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH)
	    | BIT_ULL(IB_USER_VERBS_CMD_ATTACH_MCAST)
	    | BIT_ULL(IB_USER_VERBS_CMD_DETACH_MCAST)
	    | BIT_ULL(IB_USER_VERBS_CMD_DUMP_CONTEXT)
	    | BIT_ULL(IB_USER_VERBS_CMD_RESTORE_OBJECT)
	    ;

	ib_set_device_ops(dev, &rxe_dev_ops);
	err = ib_device_set_netdev(&rxe->ib_dev, rxe->ndev, 1);
	if (err)
		return err;

	tfm = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("failed to allocate crc algorithm err:%ld\n",
		       PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	rxe->tfm = tfm;

	rdma_set_device_sysfs_group(dev, &rxe_attr_group);
	err = ib_register_device(dev, ibdev_name, NULL);
	if (err)
		pr_warn("%s failed with error %d\n", __func__, err);

	/*
	 * Note that rxe may be invalid at this point if another thread
	 * unregistered it.
	 */
	return err;
}
