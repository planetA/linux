#include "ovey.h"

int ovey_query_device(struct ib_device *base_dev, struct ib_device_attr *attr,
		     struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	pr_err("FAIL: %s\n", __func__);
	if (udata->inlen || udata->outlen)
		return -EINVAL;

	memset(attr, 0, sizeof(*attr));

	ret = ovey_dev->parent->ops.query_device(ovey_dev->parent, attr, udata);
	if (ret < 0) {
		return ret;
	}

	/* /\* Revisit atomic caps if RFC 7306 gets supported *\/ */
	/* attr->atomic_cap = 0; */
	/* attr->device_cap_flags = */
	/* 	IB_DEVICE_MEM_MGT_EXTENSIONS | IB_DEVICE_ALLOW_USER_UNREG; */
	/* attr->max_cq = ovey_dev->attrs.max_cq; */
	/* attr->max_cqe = ovey_dev->attrs.max_cqe; */
	/* attr->max_fast_reg_page_list_len = OVEY_MAX_SGE_PBL; */
	/* attr->max_mr = ovey_dev->attrs.max_mr; */
	/* attr->max_mw = ovey_dev->attrs.max_mw; */
	/* attr->max_mr_size = ~0ull; */
	/* attr->max_pd = ovey_dev->attrs.max_pd; */
	/* attr->max_qp = ovey_dev->attrs.max_qp; */
	/* attr->max_qp_init_rd_atom = ovey_dev->attrs.max_ird; */
	/* attr->max_qp_rd_atom = ovey_dev->attrs.max_ord; */
	/* attr->max_qp_wr = ovey_dev->attrs.max_qp_wr; */
	/* attr->max_recv_sge = ovey_dev->attrs.max_sge; */
	/* attr->max_res_rd_atom = ovey_dev->attrs.max_qp * ovey_dev->attrs.max_ird; */
	/* attr->max_send_sge = ovey_dev->attrs.max_sge; */
	/* attr->max_sge_rd = ovey_dev->attrs.max_sge_rd; */
	/* attr->max_srq = ovey_dev->attrs.max_srq; */
	/* attr->max_srq_sge = ovey_dev->attrs.max_srq_sge; */
	/* attr->max_srq_wr = ovey_dev->attrs.max_srq_wr; */
	/* attr->page_size_cap = PAGE_SIZE; */
	/* attr->vendor_id = OVEY_VENDOR_ID; */
	/* attr->vendor_part_id = ovey_dev->vendor_part_id; */

	/* memcpy(&attr->sys_image_guid, ovey_dev->netdev->dev_addr, 6); */

	pr_err("FAIL: %s\n", __func__);
	return 0;
}

int ovey_query_port(struct ib_device *base_dev, u8 port,
		   struct ib_port_attr *attr)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	memset(attr, 0, sizeof(*attr));
	ret = ovey_dev->parent->ops.query_port(ovey_dev->parent, port, attr);
	if (ret < 0) {
		return ret;
	}

	/* Here I will need to update the ids */
	return ret;
}

int ovey_query_gid(struct ib_device *base_dev, u8 port, int idx,
		  union ib_gid *gid)
{
	/* struct ovey_device *ovey_dev = to_ovey_dev(base_dev); */

	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
	/* /\* subnet_prefix == interface_id == 0; *\/ */
	/* memset(gid, 0, sizeof(*gid)); */
	/* memcpy(&gid->raw[0], ovey_dev->netdev->dev_addr, 6); */

	/* return 0; */
}

int ovey_query_pkey(struct ib_device *base_dev, u8 port, u16 idx, u16 *pkey)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	ret = ovey_dev->parent->ops.query_pkey(ovey_dev->parent, port, idx, pkey);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

int ovey_get_port_immutable(struct ib_device *base_dev, u8 port,
			    struct ib_port_immutable *port_immutable)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	ret = ovey_dev->parent->ops.get_port_immutable(ovey_dev->parent, port, port_immutable);
	if (ret < 0) {
		return ret;
	}

	port_immutable->core_cap_flags &=
		~(RDMA_CORE_CAP_IB_MAD |
		  RDMA_CORE_CAP_IB_SMI |
		  RDMA_CORE_CAP_IB_CM |
		  RDMA_CORE_CAP_IW_CM |
		  RDMA_CORE_CAP_IB_SA |
		  RDMA_CORE_CAP_OPA_MAD);
	port_immutable->max_mad_size = 0;

	return 0;
}

int ovey_alloc_ucontext(struct ib_ucontext *base_ctx, struct ib_udata *udata)
{
  /* 	struct ovey_device *ovey_dev = to_ovey_dev(base_ctx->device); */
  /* 	struct ovey_ucontext *ctx = to_ovey_ctx(base_ctx); */
  /* 	struct ovey_uresp_alloc_ctx uresp = {}; */
  /* 	int rv; */

  /* 	if (atomic_inc_return(&ovey_dev->num_ctx) > OVEY_MAX_CONTEXT) { */
  /* 		rv = -ENOMEM; */
  /* 		goto err_out; */
  /* 	} */
  /* 	ctx->ovey_dev = ovey_dev; */

  /* 	uresp.dev_id = ovey_dev->vendor_part_id; */

  /* 	if (udata->outlen < sizeof(uresp)) { */
  /* 		rv = -EINVAL; */
  /* 		goto err_out; */
  /* 	} */
  /* 	rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp)); */
  /* 	if (rv) */
  /* 		goto err_out; */

  /* 	ovey_dbg(base_ctx->device, "success. now %d context(s)\n", */
  /* 		 atomic_read(&ovey_dev->num_ctx)); */

  /* 	return 0; */

  /* err_out: */
  /* 	atomic_dec(&ovey_dev->num_ctx); */
  /* 	ovey_dbg(base_ctx->device, "failure %d. now %d context(s)\n", rv, */
  /* 		 atomic_read(&ovey_dev->num_ctx)); */

  /* 	return rv; */
	return -EINVAL;
}

void ovey_dealloc_ucontext(struct ib_ucontext *base_ctx)
{
	/* struct ovey_ucontext *uctx = to_ovey_ctx(base_ctx); */

	/* atomic_dec(&uctx->ovey_dev->num_ctx); */
}

int ovey_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);

	pr_err("Alloc pd");
	ovey_dbg_pd(pd, "alloc PD\n");
	ovey_pd->parent = ib_alloc_pd(ovey_dev->parent, pd->flags);
	pr_err("Alloc pd %px %lx", ovey_dev->parent, PTR_ERR(ovey_pd->parent));
	if (IS_ERR(ovey_pd->parent)) {
		pr_err("Alloc pd bad");
		return PTR_ERR(ovey_pd->parent);
	}
	pr_err("Alloc pd good");

	return 0;
}

void ovey_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);

	ib_dealloc_pd_user(ovey_pd->parent, udata);

	ovey_dbg_pd(pd, "free PD\n");
	/* atomic_dec(&ovey_dev->num_pd); */
}

int ovey_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
/* 	struct ovey_ucontext *uctx = to_ovey_ctx(ctx); */
/* 	size_t size = vma->vm_end - vma->vm_start; */
/* 	struct rdma_user_mmap_entry *rdma_entry; */
/* 	struct ovey_user_mmap_entry *entry; */
/* 	int rv = -EINVAL; */

/* 	/\* */
/* 	 * Must be page aligned */
/* 	 *\/ */
/* 	if (vma->vm_start & (PAGE_SIZE - 1)) { */
/* 		pr_warn("ovey: mmap not page aligned\n"); */
/* 		return -EINVAL; */
/* 	} */
/* 	rdma_entry = rdma_user_mmap_entry_get(&uctx->base_ucontext, vma); */
/* 	if (!rdma_entry) { */
/* 		ovey_dbg(&uctx->ovey_dev->base_dev, "mmap lookup failed: %lu, %#zx\n", */
/* 			vma->vm_pgoff, size); */
/* 		return -EINVAL; */
/* 	} */
/* 	entry = to_ovey_mmap_entry(rdma_entry); */

/* 	rv = remap_vmalloc_range(vma, entry->address, 0); */
/* 	if (rv) { */
/* 		pr_warn("remap_vmalloc_range failed: %lu, %zu\n", vma->vm_pgoff, */
/* 			size); */
/* 		goto out; */
/* 	} */
/* out: */
/* 	rdma_user_mmap_entry_put(rdma_entry); */

/* 	return rv; */
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
}

void ovey_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	/* struct ovey_user_mmap_entry *entry = to_ovey_mmap_entry(rdma_entry); */

	/* kfree(entry); */
}

struct ib_mr *ovey_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			   u32 max_sge, struct ib_udata *udata)
{
	pr_err("FAIL: %s\n", __func__);
	return ERR_PTR(-EINVAL);
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
struct ib_mr *ovey_reg_user_mr(struct ib_pd *pd, u64 start, u64 len,
			      u64 rnic_va, int rights, struct ib_udata *udata)
{
	pr_err("FAIL: %s\n", __func__);
	return ERR_PTR(-EINVAL);
}

int ovey_map_mr_sg(struct ib_mr *base_mr, struct scatterlist *sl, int num_sle,
		  unsigned int *sg_off)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
}

/*
 * ovey_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 */
struct ib_mr *ovey_get_dma_mr(struct ib_pd *pd, int rights)
{
	/* struct ovey_device *ovey_dev = to_ovey_dev(pd->device); */
	/* struct ovey_pd *ovey_pd = to_ovey_pd(pd); */
	struct ovey_mr *ovey_mr = NULL;
	/* struct ib_mr *parent_mr; */
	int ret;

	ovey_mr = kzalloc(sizeof(*ovey_mr), GFP_KERNEL);
	if (!ovey_mr) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* parent_mr = ovey_dev->parent->ops.get_dma_mr(ovey_pd->parent, rights); */
	/* if (IS_ERR(parent_mr)) { */
	/* 	ret = PTR_ERR(parent_mr); */
	/* 	goto err_out; */
	/* } */

	/* ovey_mr->parent = parent_mr; */
	/* pr_err("ALLOCATED MR ovey %px parent %px parent device %px\n", ovey_mr, parent_mr, parent_mr->device); */

	return &ovey_mr->base_mr;

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
 * @base_mr: Base MR contained in ovey MR.
 * @udata: points to user context, unused.
 */
int ovey_dereg_mr(struct ib_mr *base_mr, struct ib_udata *udata)
{
	/* struct ovey_device *ovey_dev = to_ovey_dev(base_mr->device); */
	struct ovey_mr *ovey_mr = to_ovey_mr(base_mr);
	int ret = 0;

	/* pr_err("DEALLOCATING MR ovey %px parent %px parent device %px\n", ovey_mr, ovey_mr->parent, ovey_mr->parent->device); */
	/* ret = ovey_dev->parent->ops.dereg_mr(ovey_mr->parent, udata); */
	kfree(ovey_mr);

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

int ovey_create_cq(struct ib_cq *base_cq, const struct ib_cq_init_attr *attr,
		  struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
	struct ib_cq *parent_cq;

	parent_cq = ib_create_cq(ovey_dev->parent, base_cq->comp_handler, base_cq->event_handler, base_cq->cq_context, attr);
	if (IS_ERR(parent_cq)) {
		return PTR_ERR(parent_cq);
	}
	ovey_cq->parent = parent_cq;

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
int ovey_poll_cq(struct ib_cq *base_cq, int num_cqe, struct ib_wc *wc)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
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
int ovey_req_notify_cq(struct ib_cq *base_cq, enum ib_cq_notify_flags flags)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
}

void ovey_destroy_cq(struct ib_cq *base_cq, struct ib_udata *udata)
{
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);

	ib_destroy_cq_user(ovey_cq->parent, udata);
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
struct ib_qp *ovey_create_qp(struct ib_pd *pd,
			    struct ib_qp_init_attr *attrs,
			    struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_qp *qp = NULL;
	int ret;

	if (attrs->qp_type != IB_QPT_RC) {
		return ERR_PTR(-EOPNOTSUPP);
	}

	pr_err("CREATE_QP WAH %d", __LINE__);
	if (udata) {
		pr_err("udata is not supported\n");
		return ERR_PTR(-ENOTSUPP);
	}

	pr_err("CREATE_QP WAH %d", __LINE__);
	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	pr_err("CREATE_QP WAH %d", __LINE__);
	if (!qp) {
		ret = -ENOMEM;
		goto err;
	}
	pr_err("CREATE_QP WAH %d", __LINE__);

	ret = ovey_qp_add(ovey_dev, qp);
	if (ret < 0) {
		goto err_free;
	}
	pr_err("CREATE_QP WAH %d", __LINE__);

	if (attrs->qp_type == IB_QPT_SMI || attrs->qp_type == IB_QPT_GSI) {
		/* These two QPs are created when the device is create */
	}
#if 0
	qp->parent = ib_create_qp(ovey_pd->parent, attrs);
	if (IS_ERR(qp->parent)) {
		ret = PTR_ERR(qp->parent);
		goto err_free;
	}

#endif

	pr_err("CREATE_QP WAH %d", __LINE__);
	return &qp->base_qp;

  err_free:
	kfree(qp);
  err:
	pr_err("CREATE_QP WAH %d %d == %x", __LINE__, ret, ret);
	return ERR_PTR(ret);
}

/*
 * Minimum ovey_query_qp() verb interface.
 *
 * @qp_attr_mask is not used but all available information is provided
 */
int ovey_query_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
		 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
}

int ovey_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *attr,
		   int attr_mask, struct ib_udata *udata)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
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
int ovey_post_send(struct ib_qp *base_qp, const struct ib_send_wr *wr,
		  const struct ib_send_wr **bad_wr)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
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
int ovey_post_recv(struct ib_qp *base_qp, const struct ib_recv_wr *wr,
		   const struct ib_recv_wr **bad_wr)
{
	pr_err("FAIL: %s\n", __func__);
	return -EINVAL;
}

int ovey_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata)
{
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	int ret;

	if (udata) {
		pr_err("qp_destroy: udata is not supported\n");
		return -EINVAL;
	}

#if 0
	pr_err("DESTROY_QP: %d", __LINE__);
	ret = ib_destroy_qp(ovey_qp->parent);
#endif

	pr_err("DESTROY_QP: %d ret %d", __LINE__, ret);
	ovey_qp_put(ovey_qp);

	return ret;
}



void ovey_qp_event(struct ovey_qp *qp, enum ib_event_type etype)
{
}

void ovey_cq_event(struct ovey_cq *cq, enum ib_event_type etype)
{
}

void ovey_port_event(struct ovey_device *ovey_dev, u8 port, enum ib_event_type etype)
{
}
