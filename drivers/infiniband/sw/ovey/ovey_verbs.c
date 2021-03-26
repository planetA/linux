#include <linux/kernel.h>

#include "ocp.h"
#include "ovey.h"
#include "ocp-util.h"
#include "completions.h"
#include "virtualized_properties.h"

#if 0
DEFINE_XARRAY(qp_xarray);

static inline struct ovey_qp *to_ovey_qp(struct ib_qp *base_qp)
{
	return xa_load(&qp_xarray, (uintptr_t) base_qp);
}
#endif

static int ovey_query_device(struct ib_device *base_dev, struct ib_device_attr *attr,
			     struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	opr_info("verb invoked\n");

	if (ocp_sockets.kernel_daemon_to_sock_pid == -1) {
		opr_err("Can't query device. Ovey Daemon is unknown!");
		return -EINVAL;
	}

	// forward operation to parent
	ret = ovey_dev->parent->ops.query_device(ovey_dev->parent, attr, udata);
	if (ret < 0) {
		opr_err("query_device() on parent device failed! %d\n", ret);
	}

	return ret;
}

static int ovey_query_port(struct ib_device *base_dev, u8 port,
			   struct ib_port_attr *attr)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	struct ovey_completion_chain *chain_node;
	struct ovey_virt_lid virt_lid;
	struct sk_buff *req_sk_buf;
	struct nlmsghdr *hdr;
	int ret;

	opr_info("verb invoked\n");

	// forward operation to parent driver
	ret = ib_query_port(ovey_dev->parent, port, attr);
	if (ret < 0) {
		opr_err("ib_query_port() on parent device failed! %d\n", ret);
	}

	// XXX: Should query lid from ovey
	// VIRTUALIZE PROPERTY PORT->LID
	virt_lid.orig = attr->lid;

	virt_lid.virt = 42;
	attr->lid = virt_lid.virt;
	// END VIRTUALIZE PROPERTY PORT->LID

	chain_node = ovey_completion_add_entry();
	req_sk_buf = ocp_nlmsg_new();
	hdr = ocp_kernel_request_put(req_sk_buf,
				     OVEY_C_STORE_VIRT_PROPERTY_PORT_LID);
	nla_put_u64_64bit(req_sk_buf, OVEY_A_COMPLETION_ID, chain_node->req_id,
			  0);
	nla_put_u32(req_sk_buf, OVEY_A_REAL_PROPERTY_U32, virt_lid.orig);
	nla_put_u32(req_sk_buf, OVEY_A_VIRT_PROPERTY_U32, virt_lid.virt);
	/* finalize the message, IMPORTANT! Update length attribute etc */
	genlmsg_end(req_sk_buf, hdr);
	// sending request to daemon via "kernel to daemon" socket
	nlmsg_unicast(ocp_sockets.genl_sock, req_sk_buf,
		      ocp_sockets.kernel_daemon_to_sock_pid);

	ret = wait_for_completion_killable(&chain_node->completion);
	if (ret == 0) {
		// success
		opr_info("wait_for_completion_killable returned 0");
	} else {
		// process got killed while waiting for the completion
		opr_err("wait_for_completion_killable returned %d", ret);
		return -EINVAL;
	}

	return ret;
}

static int ovey_query_gid(struct ib_device *base_dev, u8 port, int idx,
			  union ib_gid *gid)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;
	opr_info("verb invoked port %d idx %d\n", port, idx);

	// forward operation to parent
	ret = ovey_dev->parent->ops.query_gid(ovey_dev->parent, port, idx, gid);
	if (ret) {
		opr_err("query_gid() on parent device failed! %d\n", ret);
	}

	return ret;
}

static int ovey_query_pkey(struct ib_device *base_dev, u8 port, u16 idx, u16 *pkey)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	opr_info("verb invoked: port=%d, idx=%d, pkey=%d\n", port, idx, *pkey);

	ret = ib_query_pkey(ovey_dev->parent, port, idx, pkey);
	if (ret) {
		opr_err("query_pkey() on parent device failed! %d\n", ret);
	}

	return ret;
}

static enum rdma_link_layer ovey_get_link_layer(struct ib_device *base_dev,
						u8 port_num)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);

	opr_info("verb invoked\n");

	return ovey_dev->parent->ops.get_link_layer(ovey_dev->parent, port_num);
}

static int ovey_get_port_immutable(struct ib_device *base_dev, u8 port,
			    struct ib_port_immutable *port_immutable)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	opr_info("verb invoked\n");

	ret = ovey_dev->parent->ops.get_port_immutable(ovey_dev->parent, port,
						       port_immutable);
	if (ret < 0) {
		opr_err("get_port_immutable() on parent device failed! %d\n",
			ret);
	}

	return 0;
}

static int ovey_alloc_ucontext(struct ib_ucontext *base_ctx, struct ib_udata *udata)
{
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev;
	int ret;

	opr_info("verb invoked base_ctx %px udata %px\n", base_ctx, udata);
	ovey_dev = to_ovey_dev(base_ctx->device);
	opr_info("verb invoked ovey_dev %px\n", ovey_dev);
	opr_info("verb invoked ovey_dev->parent %px\n", ovey_dev->parent);

	opr_info("verb invoked ucontext=%px ufile=%px\n", base_ctx,
		 base_ctx->ufile);
	opr_info("ovey_dev->name=%s, ovey_dev->parent->name=%s\n",
		 ovey_dev->base.name, ovey_dev->parent->name);

	ovey_ctx->parent = base_ctx;
	ovey_ctx->parent->device = ovey_dev->parent;
	ret = ovey_dev->parent->ops.alloc_ucontext(ovey_ctx->parent, udata);
	ovey_ctx->parent->device = &ovey_dev->base;
	opr_err("ret=%d\n", ret);
	if (ret < 0) {
		opr_err("alloc_ucontext() on parent device failed! %d\n", ret);
	}
	opr_info("verb invoked ucontext=%px==%px parent=%px\n", base_ctx,
		 ovey_ctx, ovey_ctx->parent);

	return ret;
}

static void ovey_dealloc_ucontext(struct ib_ucontext *base_ctx)
{
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->parent->device);

	opr_info("verb invoked ucontext=%px==%px parent=%px\n", base_ctx, ovey_ctx, ovey_ctx->parent);

	if (!ovey_dev->parent->ops.dealloc_ucontext) {
		return;
	}

	ovey_dev->parent->ops.dealloc_ucontext(ovey_ctx->parent);
}

static int ovey_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);

	opr_info("verb invoked ibpd %px ovey_pd %px uobject %px ufile %px\n",
		 pd, ovey_pd, pd->uobject,
		 pd->uobject ? pd->uobject->ufile :
				     (struct ib_uverbs_file *)0xf);

#if 1
	ovey_pd->parent = ib_alloc_pd_user(ovey_dev->parent, 0, udata);
#else
	ovey_pd->parent = pd;
	ovey_pd->parent->device = ovey_dev->parent;
	ret = ovey_dev->parent->ops.alloc_pd(ovey_pd->parent, udata);
	ovey_pd->parent->device = &ovey_dev->base;
#endif
	opr_info("verb invoked ovey_pd %px \n", ovey_pd);
	opr_info("verb invoked ovey_pd->parent %px \n", ovey_pd->parent);
	if (IS_ERR(ovey_pd->parent)) {
		opr_err("ib_alloc_pd failed for parent device %ld\n", PTR_ERR(ovey_pd->parent));
		return PTR_ERR(ovey_pd->parent);
	}

	return 0;
}

static int ovey_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	int ret;

	opr_info("verb invoked uobject %px \n", pd->uobject);
	opr_info("verb invoked ovey_pd %px \n", ovey_pd);
	opr_info("verb invoked ovey_pd->parent %px \n", ovey_pd->parent);
	opr_info("verb invoked %s \n", ovey_pd->parent->device->name);

#if 1
	ret = ib_dealloc_pd_user(ovey_pd->parent, udata);
#else
	ovey_pd->parent->device = ovey_dev->parent;
	ret = ovey_dev->parent->ops.dealloc_pd(ovey_pd->parent, udata);
	ovey_pd->parent->device = &ovey_dev->base;
#endif

	opr_info("verb invoked %d\n", ret);

	return ret;
}

static int ovey_create_ah(struct ib_ah *base_ah,
			 struct rdma_ah_init_attr *init_attr,
			 struct ib_udata *udata)

{
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	struct ovey_pd *ovey_pd = to_ovey_pd(base_ah->pd);

	ovey_ah->parent = rdma_create_user_ah(ovey_pd->parent, init_attr->ah_attr, udata);
	if (IS_ERR(ovey_ah->parent)) {
		opr_err("Failed to create AH: %ld\n", PTR_ERR(ovey_ah->parent));
		return PTR_ERR(ovey_ah->parent);
	}

	opr_info("verb invoked %d\n", 0);
	return 0;
}

static int ovey_modify_ah(struct ib_ah *base_ah, struct rdma_ah_attr *attr)
{
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	int ret;

	ret = rdma_modify_ah(ovey_ah->parent, attr);

	opr_info("verb invoked %d\n", ret);
	return ret;
}

static int ovey_query_ah(struct ib_ah *base_ah, struct rdma_ah_attr *attr)
{
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	int ret;

	ret = rdma_query_ah(ovey_ah->parent, attr);

	opr_info("verb invoked %d\n", ret);
	return ret;
}

static int ovey_destroy_ah(struct ib_ah *base_ah, u32 flags)
{
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	int ret;

	ret = rdma_destroy_ah_user(ovey_ah->parent, flags, NULL);

	opr_info("verb invoked %d\n", ret);
	return ret;
}

static int ovey_mmap(struct ib_ucontext *base_ctx, struct vm_area_struct *vma)
{
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->parent->device);
	int ret;

	opr_info("verb invoked\n");

	base_ctx->device = ovey_dev->parent;
	ret = ovey_dev->parent->ops.mmap(ovey_ctx->parent, vma);
	base_ctx->device = &ovey_dev->base;
	if (ret) {
		opr_err("mmap() on parent device failed! %d\n", ret);
	}
	return ret;
}

static void ovey_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct ib_ucontext *base_ctx = rdma_entry->ucontext;
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->parent->device);

	opr_info("verb invoked\n");

	base_ctx->device = ovey_dev->parent;
	base_ctx->device->ops.mmap_free(rdma_entry);
	base_ctx->device = &ovey_dev->base;
}

static struct ib_mr *ovey_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
				   u32 max_sge)
{
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_mr *ovey_mr;

	opr_info("verb invoked pd->uobject %px \n", pd->uobject);

	ovey_mr = kmalloc(sizeof(struct ovey_mr), GFP_KERNEL);
	ovey_mr->parent = ib_alloc_mr(ovey_pd->parent, mr_type, max_sge);
	if (!ovey_mr->parent)
		opr_err("ib_alloc_mr() on parent device failed\n");
	return &ovey_mr->base;
	//return ib_alloc_mr(ovey_pd->parent, mr_type, max_sge);
}

/*
 * ovey_reg_user_mr()
 *
 * Register Memory Region.
 *
 * @pd:		Protection Domain
 * @start:	starting address of MR (virtual address)
 * @len:	len of MR
 * @rnic_va:	not used by ovey
 * @rights:	MR access rights
 * @udata:	user buffer to communicate STag and Key.
 */
static struct ib_mr *ovey_reg_user_mr(struct ib_pd *pd, u64 start, u64 len,
				      u64 rnic_va, int rights,
				      struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_mr *ovey_mr;
	int ret = 0;

	opr_info("verb invoked pd->uobject %px dev %s parent %s\n", pd->uobject,
		 pd->device->name, ovey_pd->parent->device->name);

	ovey_mr = kzalloc(sizeof(*ovey_mr), GFP_KERNEL);
	if (!ovey_mr) {
		ret = -ENOMEM;
		goto err_out;
	}

	dump_stack();
	ovey_mr->parent = ib_reg_user_mr_user(ovey_pd->parent, start, len, rnic_va, rights, udata);
	if (IS_ERR(ovey_mr->parent)) {
		ret = PTR_ERR(ovey_mr->parent);
		goto err_out;
	}
	opr_info("verb invoked: ret=%d\n", ret);

	return &ovey_mr->base;
err_out:
	if (ovey_mr) {
		kfree(ovey_mr);
	}

	return ERR_PTR(ret);
}

static int ovey_map_mr_sg(struct ib_mr *base_mr, struct scatterlist *sl,
			  int num_sle, unsigned int *sg_off)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_mr->device);
	struct ovey_mr *ovey_mr = to_ovey_mr(base_mr);
	int ret;
	opr_info("verb invoked\n");

	ovey_mr->parent->device = ovey_dev->parent;
	ret = ib_map_mr_sg(ovey_mr->parent, sl, num_sle, sg_off, PAGE_SIZE);
	ovey_mr->parent->device = &ovey_dev->base;
	opr_info("verb invoked: %d\n", ret);

	return ret;
}

/*
 * ovey_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 */
static struct ib_mr *ovey_get_dma_mr(struct ib_pd *pd, int rights)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_mr *ovey_mr;
	int ret;

	opr_info("verb invoked\n");

	ovey_mr = kzalloc(sizeof(*ovey_mr), GFP_KERNEL);
	if (!ovey_mr) {
		ret = -ENOMEM;
		goto err_out;
	}

	ovey_mr->parent = ovey_dev->parent->ops.get_dma_mr(ovey_pd->parent, rights);
	if (IS_ERR(ovey_mr->parent)) {
		ret = PTR_ERR(ovey_mr->parent);
		goto err_out;
	}
	ovey_mr->parent->device = ovey_pd->parent->device;
	opr_info("verb invoked %s parent %s\n", ovey_pd->parent->device->name,
		 pd->device->name);
	ovey_mr->parent->pd = ovey_pd->parent;
	ovey_mr->parent->type = IB_MR_TYPE_DMA;
	ovey_mr->parent->uobject = NULL;
	ovey_mr->parent->need_inval = false;

	pr_err("ALLOCATED MR ovey %px &ovey_mr->base %px parent %px parent device %px\n",
	       ovey_mr, &ovey_mr->base, ovey_mr->parent,
	       ovey_mr->parent->device);

	return &ovey_mr->base;

  err_out:
	if (ret) {
		kfree(ovey_mr);
	}

	return ERR_PTR(ret);
}

/*
 * ovey_dereg_mr()
 *
 * Release Memory Region.
 *
 * @base: Base MR contained in ovey MR.
 * @udata: points to user context, unused.
 */
static int ovey_dereg_mr(struct ib_mr *base_mr, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_mr->device);
	struct ovey_mr *ovey_mr = to_ovey_mr(base_mr);
	int ret = 0;

	opr_info("verb invoked mr %px dev %px ovey_mr->parent %px\n", base_mr, ovey_dev, ovey_mr->parent);
	if (ovey_mr->parent) {
		ret = ovey_dev->parent->ops.dereg_mr(ovey_mr->parent, udata);
	}

	kfree(base_mr);

	return ret;
}

/*
 * ovey_create_cq()
 *
 * Populate CQ of requested size
 *
 * @base_cq: CQ as allocated by RDMA midlayer
 * @attr: Initial CQ attributes
 * @udata: relates to user context
 */
static int ovey_create_cq(struct ib_cq *base_cq,
			  const struct ib_cq_init_attr *attr,
			  struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);

	opr_info("verb invoked %px\n", udata);
	// this is the function that also gets invoked after the syscall

	// base_eq gets filled by ioctl syscall which triggers __ib_alloc_cq_user
	// this function calls this one and we forward it to the parent device

	opr_info("base_cq %px ovey_cq %px ovey_dev %px", base_cq, ovey_cq,
		 ovey_dev);
	opr_info("ovey_cq %px\n", ovey_cq);

	ovey_cq->parent =
		ib_alloc_cq_user(ovey_dev->parent, ovey_cq->base.cq_context,
				 (int)attr->cqe, attr->comp_vector, udata,
				 ovey_cq->base.poll_ctx);
	if (IS_ERR(ovey_cq->parent)) {
		opr_err("Failed to create cq: %ld %px\n", PTR_ERR(ovey_cq->parent), udata);
		return PTR_ERR(ovey_cq->parent);
	}

	opr_info("ovey_cq->parent=%px\n", ovey_cq->parent);

	return 0;
}

/*
 * ovey_poll_cq()
 *
 * Reap CQ entries if available and copy work completion status into
 * array of WC's provided by caller. Returns number of reaped CQE's.
 *
 * @base_cq:	Base CQ contained in ovey CQ.
 * @num_cqe:	Maximum number of CQE's to reap.
 * @wc:		Array of work completions to be filled by ovey.
 */
static int ovey_poll_cq(struct ib_cq *base_cq, int num_cqe, struct ib_wc *wc)
{
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
	opr_info("verb invoked\n");

	return ib_poll_cq(ovey_cq->parent, num_cqe, wc);
}

/*
 * ovey_req_notify_cq()
 *
 * Request notification for new CQE's added to that CQ.
 * Defined flags:
 * o OVEY_CQ_NOTIFY_SOLICITED lets ovey trigger a notification
 *   event if a WQE with notification flag set enters the CQ
 * o OVEY_CQ_NOTIFY_NEXT_COMP lets ovey trigger a notification
 *   event if a WQE enters the CQ.
 * o IB_CQ_REPORT_MISSED_EVENTS: return value will provide the
 *   number of not reaped CQE's regardless of its notification
 *   type and current or new CQ notification settings.
 *
 * @base_cq:	Base CQ contained in ovey CQ.
 * @flags:	Requested notification flags.
 */
static int ovey_req_notify_cq(struct ib_cq *base_cq, enum ib_cq_notify_flags flags)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
	int err;
	opr_info("verb invoked\n");

	err = ib_req_notify_cq(ovey_cq->parent, flags);

	return err;
}

static int ovey_destroy_cq(struct ib_cq *base_cq, struct ib_udata *udata)
{
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
	struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);

	opr_info("verb invoked\n");

	ib_destroy_cq_user(ovey_cq->parent, udata);

	return 0;
}

/*
 * ovey_create_qp()
 *
 * Create QP of requested size on given device.
 *
 * @pd:		Protection Domain
 * @attrs:	Initial QP attributes.
 * @udata:	used to provide QP ID, SQ and RQ size back to user.
 */
static struct ib_qp *ovey_create_qp(struct ib_pd *pd,
				    struct ib_qp_init_attr *attrs,
				    struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_qp *qp = NULL;
	int err = 0;

	opr_info("verb invoked udata %px\n", udata);

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		err = -ENOMEM;
		goto err1;
	}

	qp->parent = ib_create_qp_user(ovey_pd->parent, attrs, udata);
	if (IS_ERR(qp->parent)) {
		opr_err("create_qp() failed for parent device\n");
		err = PTR_ERR(qp->parent);
		goto err2;
	}

#if 0
	err = xa_err(xa_store(&qp_xarray, (uintptr_t)qp->parent, qp, GFP_KERNEL));
	if (err) {
		goto err3;
	}
#endif

	opr_info("created qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 qp->parent->device->name);

	return &qp->base;

	ib_destroy_qp(qp->parent);
  err2:
	kfree(qp);
  err1:
	return ERR_PTR(err);
}

/*
 * Minimum ovey_query_qp() verb interface.
 *
 * @qp_attr_mask is not used but all available information is provided
 */
static int ovey_query_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
			 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	int ret;
	opr_info("verb invoked\n");

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	ret = ovey_dev->parent->ops.query_qp(ovey_qp->parent, qp_attr,
					     qp_attr_mask, qp_init_attr);
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

	return ret;
}

static int ovey_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
			  int qp_attr_mask, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	struct ovey_completion_chain *chain_node;
	struct nlmsghdr *hdr;
	struct sk_buff *req_sk_buf;
	int ret;
	opr_info("verb invoked\n");
	opr_info("modify qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	if (!ovey_qp->parent) {
		return -EOPNOTSUPP;
	}

	chain_node = ovey_completion_add_entry();
	req_sk_buf = ocp_nlmsg_new();
	hdr = ocp_kernel_request_put(req_sk_buf, OVEY_C_RESOLVE_COMPLETION);
	nla_put_u64_64bit(req_sk_buf, OVEY_A_COMPLETION_ID, chain_node->req_id,
			  0);
	/* finalize the message, IMPORTANT! Update length attribute etc */
	genlmsg_end(req_sk_buf, hdr);
	// sending request to daemon via "kernel to daemon" socket
	nlmsg_unicast(ocp_sockets.genl_sock, req_sk_buf,
		      ocp_sockets.kernel_daemon_to_sock_pid);

	ret = wait_for_completion_killable(&chain_node->completion);
	if (ret == 0) {
		// success
		opr_info("wait_for_completion_killable returned 0");
	} else {
		// process got killed while waiting for the completion
		opr_err("wait_for_completion_killable returned %d", ret);
		return -EINVAL;
	}

	opr_info("modify 2 qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);

#if 1
	ret = ib_modify_qp_with_udata(ovey_qp->parent, qp_attr, qp_attr_mask,
				      udata);
#else
	ret = ovey_dev->parent->ops.modify_qp(ovey_qp->parent, qp_attr,
					      qp_attr_mask, udata);
#endif
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

	return ret;
}

/*
 * ovey_post_send()
 *
 * Post a list of S-WR's to a SQ.
 *
 * @base_qp:	Base QP contained in ovey QP
 * @wr:		Null terminated list of user WR's
 * @bad_wr:	Points to failing WR in case of synchronous failure.
 */
static int ovey_post_send(struct ib_qp *base_qp, const struct ib_send_wr *wr,
			  const struct ib_send_wr **bad_wr)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	int ret;
	opr_info("verb invoked\n");

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	if (!ovey_qp->parent) {
		return -EOPNOTSUPP;
	}

	opr_info("post_send qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);

	ret = ovey_dev->parent->ops.post_send(ovey_qp->parent, wr, bad_wr);
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

	return ret;
}

/*
 * ovey_post_recv()
 *
 * Post a list of R-WR's to a RQ.
 *
 * @base_qp:	Base QP contained in ovey QP
 * @wr:		Null terminated list of user WR's
 * @bad_wr:	Points to failing WR in case of synchronous failure.
 */
static int ovey_post_recv(struct ib_qp *base_qp, const struct ib_recv_wr *wr,
		   const struct ib_recv_wr **bad_wr)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	int ret;
	opr_info("verb invoked\n");

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	if (!ovey_qp->parent) {
		return -EOPNOTSUPP;
	}

	opr_info("post_recv qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);

	ret = ovey_dev->parent->ops.post_recv(ovey_qp->parent, wr, bad_wr);
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

	return ret;
}

static int ovey_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	struct ovey_qp *old_qp;
	int ret;
	opr_info("verb invoked\n");

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

#if 1
	ret = ib_destroy_qp_user(ovey_qp->parent, udata);
#else
	ret = ovey_dev->parent->ops.destroy_qp(ovey_qp->parent, udata);
#endif
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

#if 0
	old_qp = xa_erase(&qp_xarray, (uintptr_t)ovey_qp->parent);
	BUG_ON(old_qp != ovey_qp);
#endif
	kfree(ovey_qp);

	return ret;
}

static void ovey_dealloc_driver(struct ib_device *base_dev)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);

	opr_info("verb invoked\n");

	// I think this is really the wrong way. We also didn't created the device in the
	// first place. All we have to do is maybe some cleanup of QPs but don't dealloc the
	// actual device; it should survive if a ovey device is removed
	// ovey_dev->parent->ops.dealloc_driver(ovey_dev->parent);
	// xa_destroy(&ovey_dev->qp_xa);

	ib_device_put(ovey_dev->parent);
}

const struct ib_device_ops ovey_device_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = OVEY_ABI_VERSION,
	.driver_id = RDMA_DRIVER_OVEY,

	.alloc_ucontext = ovey_alloc_ucontext,
	.alloc_mr = ovey_alloc_mr,
	.alloc_pd = ovey_alloc_pd,
	.create_ah = ovey_create_ah,
	.create_cq = ovey_create_cq,
	.create_qp = ovey_create_qp,
	.dealloc_ucontext = ovey_dealloc_ucontext,
	.dealloc_driver = ovey_dealloc_driver,
	.dealloc_pd = ovey_dealloc_pd,
	.destroy_ah = ovey_destroy_ah,
	.destroy_cq = ovey_destroy_cq,
	.destroy_qp = ovey_destroy_qp,
	.dereg_mr = ovey_dereg_mr,
	.get_dma_mr = ovey_get_dma_mr,
	.get_link_layer = ovey_get_link_layer,
	.get_port_immutable = ovey_get_port_immutable,
	.mmap = ovey_mmap,
	.mmap_free = ovey_mmap_free,
	.map_mr_sg = ovey_map_mr_sg,
	.modify_ah = ovey_modify_ah,
	.modify_qp = ovey_modify_qp,
	.reg_user_mr = ovey_reg_user_mr,
	.req_notify_cq = ovey_req_notify_cq,
	.poll_cq = ovey_poll_cq,
	.post_recv = ovey_post_recv,
	.post_send = ovey_post_send,
	.query_ah = ovey_query_ah,
	.query_device = ovey_query_device,
	.query_port = ovey_query_port,
	.query_gid = ovey_query_gid,
	.query_pkey = ovey_query_pkey,
	.query_qp = ovey_query_qp,

	// Mapping to application specific structs
	// this way the kernel can alloc a proper amount of memory
	// TODO: also for _srq

	INIT_RDMA_OBJ_SIZE(ib_pd, ovey_pd, base),
	INIT_RDMA_OBJ_SIZE(ib_ah, ovey_ah, base),
	INIT_RDMA_OBJ_SIZE(ib_cq, ovey_cq, base),
};
