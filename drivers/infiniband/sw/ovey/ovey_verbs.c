#include <linux/kernel.h>
#include <rdma/restrack.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_verbs.h>

#include "../../core/uverbs.h"

#include "ovey.h"
#include "oveyd.h"

#if OVEY_UCONTEXT
/**
 * XXX: This a hack. I know that rxe driver uses this field to get the
 * address of the context. A proper way would be either to re-engineer
 * the context struct or make sure that I do this swap for all udata
 * fields around all parent calls */
#define replace_udata_context(__udata)                                         \
	({                                                                     \
		struct ovey_ucontext *__ovey_uctx = NULL;                      \
		struct uverbs_attr_bundle *__attrs = container_of(             \
			__udata, struct uverbs_attr_bundle, driver_udata);     \
		if (__udata) {                                                 \
			__ovey_uctx = to_ovey_ctx(__attrs->context);           \
			__attrs->context = __ovey_uctx->parent;                \
		}                                                              \
		__ovey_uctx;                                                   \
	})

#define replace_udata_context_end(__udata, __ovey_uctx)                        \
	({                                                                     \
		struct uverbs_attr_bundle *__attrs = container_of(             \
			__udata, struct uverbs_attr_bundle, driver_udata);     \
		if (__udata) {                                                 \
			__attrs->context = &__ovey_uctx->base;                 \
		}                                                              \
	})
#endif

DEFINE_XARRAY(cq_xarray);
static inline struct ovey_cq *ovey_from_parent(struct ib_cq *base_qp)
{
	return xa_load(&cq_xarray, (uintptr_t)base_qp);
}

static int ovey_query_device(struct ib_device *base_dev,
			     struct ib_device_attr *attr,
			     struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;

	opr_info("verb invoked %px %px\n", udata, ovey_dev);

	// forward operation to parent
	ret = ovey_dev->parent->ops.query_device(ovey_dev->parent, attr, udata);
	if (ret < 0) {
		opr_err("query_device() on parent device failed! %d\n", ret);
	}

	return ret;
}

static int ovey_query_port(struct ib_device *base_dev, u32 port,
			   struct ib_port_attr *attr)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	struct ib_port_data *pdata = &base_dev->port_data[port];
	int ret;

	opr_info("verb invoked\n");

	// TODO: Should pass real port id. For now there is an explicit
	// assumption that virtual and real port ids are the same, which is
	// wrong.

	// forward operation to parent driver
	ret = ib_query_port(ovey_dev->parent, port, attr);
	if (ret < 0) {
		opr_err("ib_query_port() on parent device failed! %d\n", ret);
		goto out;
	}

	opr_info("pdata immutable: %px", pdata);
	attr->gid_tbl_len = pdata->immutable.gid_tbl_len;

	ret = oveyd_set_port_attr(ovey_dev, port, attr);
	if (ret < 0) {
		opr_err("ovey_set_port_attr() on parent device failed! %d\n",
			ret);
		goto out;
	}

	opr_info("LID is %d", attr->lid);
out:

	return ret;
}

static int ovey_query_gid(struct ib_device *base_dev, u32 port, int idx,
			  union ib_gid *gid)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
	int ret;
	opr_info("verb invoked port %d idx %d\n", port, idx);
	opr_info("verb invoked port %px %px\n", ovey_dev, base_dev);
	opr_info("verb invoked port %px %px\n", ovey_dev->parent, gid);
	opr_info("verb invoked port %px %px\n", &ovey_dev->parent->ops,
		 ovey_dev->parent->ops.query_gid);

	// forward operation to parent
	ret = rdma_query_gid(ovey_dev->parent, port, idx, gid);
	if (ret) {
		opr_err("query_gid() on parent device failed! %d\n", ret);
		return ret;
	}

	opr_info("verb invoked port %d idx %d\n", port, idx);
	opr_info("Found parent gid %llx-%llx\n", gid->global.interface_id,
		 gid->global.subnet_prefix);

	ret = oveyd_lease_gid(ovey_dev, port, idx, gid);
	if (ret < 0) {
		opr_err("GID leasing failed: %d", ret);
	}

	return ret;
}

static int ovey_query_pkey(struct ib_device *base_dev, u32 port, u16 idx,
			   u16 *pkey)
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
						u32 port_num)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_dev);

	opr_info("verb invoked\n");

	return ovey_dev->parent->ops.get_link_layer(ovey_dev->parent, port_num);
}

static int ovey_get_port_immutable(struct ib_device *base_dev, u32 port,
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

	ret = oveyd_create_port(ovey_dev, port, port_immutable);
	if (ret < 0) {
		opr_err("get_port_immutable() failed to register with coordinator %d\n",
			ret);
	}

	return 0;
}

void rdma_restrack_add(struct rdma_restrack_entry *res);
void rdma_restrack_new(struct rdma_restrack_entry *res,
		       enum rdma_restrack_type type);
void rdma_restrack_set_name(struct rdma_restrack_entry *res,
			    const char *caller);

static int ovey_alloc_ucontext(struct ib_ucontext *base_ctx,
			       struct ib_udata *udata)
{
#if OVEY_UCONTEXT
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev;
	struct ib_ucontext *ucontext;
	struct ovey_ucontext *ovey_uctx;
	int ret;

	ovey_dev = to_ovey_dev(base_ctx->device);
	opr_info("ovey_dev->name=%s, ovey_dev->parent->name=%s\n",
		 ovey_dev->base.name, ovey_dev->parent->name);

	ucontext = rdma_zalloc_drv_obj(ovey_dev->parent, ib_ucontext);
	if (!ucontext)
		return -ENOMEM;

	ucontext->device = ovey_dev->parent;
	ucontext->ufile = base_ctx->ufile;
	xa_init_flags(&ucontext->mmap_xa, XA_FLAGS_ALLOC);

	rdma_restrack_new(&ucontext->res, RDMA_RESTRACK_CTX);
	rdma_restrack_set_name(&ucontext->res, NULL);

	ret = ib_rdmacg_try_charge(&ucontext->cg_obj, ucontext->device,
				   RDMACG_RESOURCE_HCA_HANDLE);
	if (ret)
		goto err;

	rdma_restrack_add(&ucontext->res);

	ovey_ctx->parent = ucontext;
	ovey_ctx->parent->device = ovey_dev->parent;
	ovey_uctx = replace_udata_context(udata);
	ret = ucontext->device->ops.alloc_ucontext(ucontext, udata);
	replace_udata_context_end(udata, ovey_uctx);
	opr_err("ret=%d\n", ret);
	if (ret < 0) {
		opr_err("alloc_ucontext() on parent device failed! %d\n", ret);
		goto err;
	}
	opr_info("verb invoked ucontext=%px==%px parent=%px\n", base_ctx,
		 ovey_ctx, ovey_ctx->parent);

	/* XXX: That is very hack. We first pretend to be parent, so that
	 * alloc_context in rdma-core works, then we switch to being ovey. */
	return ret;

err:
	kfree(ucontext);
	return ret;
#else
	struct ovey_device *ovey_dev;
	ovey_dev = to_ovey_dev(base_ctx->device);

	base_ctx->wrapper_device = base_ctx->device;
	base_ctx->device = ovey_dev->parent;

	opr_info("verb invoked ovey_dev->base %s\n", ovey_dev->base.name);
	opr_info("verb invoked ovey_dev->parent %s\n", ovey_dev->parent->name);
	return base_ctx->device->ops.alloc_ucontext(base_ctx, udata);
#endif
}

static void ovey_dealloc_ucontext(struct ib_ucontext *base_ctx)
{
#if OVEY_UCONTEXT
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->base.device);

	opr_info("verb invoked ucontext=%px==%px parent=%px\n", base_ctx,
		 ovey_ctx, ovey_ctx->parent);
	opr_info("verb invoked parent->device %px\n", ovey_ctx->parent->device);
	opr_info("verb invoked ovey_dev %px\n", ovey_dev);
	opr_info("verb invoked parent->device %s\n",
		 ovey_ctx->parent->device->name);
	opr_info("verb invoked ovey_dev->parent %px\n", ovey_dev->parent);
	opr_info("verb invoked ovey_dev %px\n",
		 ovey_dev->parent->ops.dealloc_ucontext);

	if (!ovey_dev->parent->ops.dealloc_ucontext) {
		return;
	}

	ovey_dev->parent->ops.dealloc_ucontext(ovey_ctx->parent);
#else
	WARN(1, "NEVER CALLED");
#endif
}

static int ovey_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);

	opr_info("verb invoked ibpd %px ovey_pd %px uobject %px ufile %px\n",
		 pd, ovey_pd, pd->uobject,
		 pd->uobject ? pd->uobject->ufile :
				     (struct ib_uverbs_file *)0xf);
	opr_info("verb invoked ovey_dev->base %s\n", ovey_dev->base.name);
	opr_info("verb invoked ovey_dev->parent %s\n", ovey_dev->parent->name);

	ovey_pd->parent = ib_alloc_pd_user(ovey_dev->parent, 0, udata);
	opr_info("verb invoked ovey_pd %px \n", ovey_pd);
	opr_info("verb invoked ovey_pd->parent %px \n", ovey_pd->parent);
	if (IS_ERR(ovey_pd->parent)) {
		opr_err("ib_alloc_pd failed for parent device %ld\n",
			PTR_ERR(ovey_pd->parent));
		return PTR_ERR(ovey_pd->parent);
	}

	return 0;
}

static int ovey_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	int ret;
	int usecnt, parent_usecnt;

	opr_info("verb invoked uobject %px \n", pd->uobject);
	opr_info("verb invoked ovey_pd %px \n", ovey_pd);
	opr_info("verb invoked ovey_pd->parent %px \n", ovey_pd->parent);
	opr_info("verb invoked %s \n", ovey_pd->parent->device->name);
	opr_info("verb invoked ovey_dev->parent %px\n", ovey_dev->parent);
	opr_info("verb invoked ovey_dev->parent %s\n", ovey_dev->parent->name);
	opr_info("verb invoked ovey_dev->base %s\n", ovey_dev->base.name);
	opr_info("verb invoked ovey_dev->parent %s\n", ovey_dev->parent->name);
	usecnt = atomic_read(&pd->usecnt);
	parent_usecnt = atomic_read(&ovey_pd->parent->usecnt);
	opr_info("WAH usecnt %d parent %d\n", usecnt, parent_usecnt);

	ret = ib_dealloc_pd_user(ovey_pd->parent, udata);
	opr_info("verb invoked %d\n", ret);

	return ret;
}

static int ovey_create_ah(struct ib_ah *base_ah,
			  struct rdma_ah_init_attr *init_attr,
			  struct ib_udata *udata)

{
#if OVEY_UCONTEXT
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	struct ovey_pd *ovey_pd = to_ovey_pd(base_ah->pd);
	struct ovey_ucontext *ovey_uctx;

	ovey_uctx = replace_udata_context(udata);
	ovey_ah->parent =
		rdma_create_user_ah(ovey_pd->parent, init_attr->ah_attr, udata);
	replace_udata_context_end(udata, ovey_uctx);
	if (IS_ERR(ovey_ah->parent)) {
		opr_err("Failed to create AH: %ld\n", PTR_ERR(ovey_ah->parent));
		return PTR_ERR(ovey_ah->parent);
	}

	opr_info("verb invoked %d\n", 0);
	return 0;
#else
	struct ovey_device *ovey_dev = to_ovey_dev(base_ah->device);
	struct ovey_pd *ovey_pd = to_ovey_pd(base_ah->pd);

	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;

	base_ah->device = ovey_dev->parent;
	base_ah->pd = ovey_pd->parent;
	return base_ah->device->ops.create_ah(base_ah, init_attr, udata);
#endif
}

static int ovey_modify_ah(struct ib_ah *base_ah, struct rdma_ah_attr *attr)
{
#if OVEY_UCONTEXT
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	int ret;

	ret = rdma_modify_ah(ovey_ah->parent, attr);

	opr_info("verb invoked %d\n", ret);
	return ret;
#else
	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;
#endif
}

static int ovey_query_ah(struct ib_ah *base_ah, struct rdma_ah_attr *attr)
{
#if OVEY_UCONTEXT
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	int ret;

	ret = rdma_query_ah(ovey_ah->parent, attr);

	opr_info("verb invoked %d\n", ret);
	return ret;
#else
	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;
#endif
}

static int ovey_destroy_ah(struct ib_ah *base_ah, u32 flags)
{
#if OVEY_UCONTEXT
	struct ovey_ah *ovey_ah = to_ovey_ah(base_ah);
	int ret;

	ret = rdma_destroy_ah_user(ovey_ah->parent, flags, NULL);

	opr_info("verb invoked %d\n", ret);
	return ret;
#else
	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;
#endif
}

static int ovey_mmap(struct ib_ucontext *base_ctx, struct vm_area_struct *vma)
{
#if OVEY_UCONTEXT
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev = to_ovey_dev(base_ctx->device);
	int ret;

	opr_info(
		"verb invoked base_ctx %px vma %px base_dev %px ovey_dev %px\n",
		base_ctx, vma, base_ctx->device, ovey_dev);
	opr_info("parent dev %px ctx %px\n", ovey_dev->parent,
		 ovey_ctx->parent);

	ret = ovey_dev->parent->ops.mmap(ovey_ctx->parent, vma);
	if (ret) {
		opr_err("mmap() on parent device failed! %d\n", ret);
	}
	return ret;
#else
	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;
#endif
}

static void ovey_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
#if OVEY_UCONTEXT
	struct ib_ucontext *base_ctx = rdma_entry->ucontext;
	struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->parent->device);

	opr_info("verb invoked\n");

	ovey_dev->parent->ops.mmap_free(rdma_entry);
#else
	opr_info("verb invoked ENOTSUPP\n");
	opr_info("verb invoked\n");
#endif
}

static struct ib_mr *ovey_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
				   u32 max_sge)
{
#if OVEY_UCONTEXT
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_mr *ovey_mr;

	opr_info("verb invoked pd->uobject %px \n", pd->uobject);

	ovey_mr = kmalloc(sizeof(struct ovey_mr), GFP_KERNEL);
	ovey_mr->parent = ib_alloc_mr(ovey_pd->parent, mr_type, max_sge);
	if (!ovey_mr->parent)
		opr_err("ib_alloc_mr() on parent device failed\n");
	return &ovey_mr->base;
#else
	opr_info("verb invoked ENOTSUPP\n");
	opr_info("verb invoked\n");
	return ERR_PTR(-ENOTSUPP);
#endif
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
	struct ovey_pd *ovey_pd = to_ovey_pd(pd);
	struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
	struct ovey_mr *ovey_mr;
	int ret = 0;

	opr_info("verb invoked pd->uobject %px dev %s parent %s\n", pd->uobject,
		 pd->device->name, ovey_pd->parent->device->name);
	opr_info("verb invoked ovey_dev->base %s\n", ovey_dev->base.name);
	opr_info("verb invoked ovey_dev->parent %s\n", ovey_dev->parent->name);

	ovey_mr = kzalloc(sizeof(*ovey_mr), GFP_KERNEL);
	if (!ovey_mr) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* ret = ovey_dev->parent->ops.reg_user_mr(ovey_pd->parent, start, len, */
	/* 					rnic_va, rights, udata); */
	ovey_mr->parent = ib_reg_user_mr_user(ovey_pd->parent, start, len,
					      rnic_va, rights, udata);
	if (IS_ERR(ovey_mr->parent)) {
		ret = PTR_ERR(ovey_mr->parent);
		goto err_out;
	}
	opr_info("verb invoked: ret=%d\n", ret);

	ovey_mr->base.lkey = ovey_mr->parent->lkey;
	ovey_mr->base.rkey = ovey_mr->parent->rkey;

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
#if OVEY_UCONTEXT
	struct ovey_mr *ovey_mr = to_ovey_mr(base_mr);
	int ret;
	opr_info("verb invoked\n");

	ret = ib_map_mr_sg(ovey_mr->parent, sl, num_sle, sg_off, PAGE_SIZE);
	opr_info("verb invoked: %d\n", ret);

	return ret;
#else
	opr_info("verb invoked -ENOTSUPP\n");
	return -ENOTSUPP;
#endif
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
	opr_info("verb invoked ovey_dev->base %s\n", ovey_dev->base.name);
	opr_info("verb invoked ovey_dev->parent %s\n", ovey_dev->parent->name);

	ovey_mr = kzalloc(sizeof(*ovey_mr), GFP_KERNEL);
	if (!ovey_mr) {
		ret = -ENOMEM;
		goto err_out;
	}

	ovey_mr->parent =
		ovey_dev->parent->ops.get_dma_mr(ovey_pd->parent, rights);
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

	ovey_mr->base.lkey = ovey_mr->parent->lkey;
	ovey_mr->base.rkey = ovey_mr->parent->rkey;

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

	opr_info("verb invoked mr %px dev %px ovey_mr->parent %px\n", base_mr,
		 ovey_dev, ovey_mr->parent);

	if (ovey_mr->parent) {
		ret = ib_dereg_mr_user(ovey_mr->parent, udata);
		/* 	ret = ovey_dev->parent->ops.dereg_mr(ovey_mr->parent, udata); */
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
	int err = 0;

	opr_info("verb invoked %px\n", udata);
	// this is the function that also gets invoked after the syscall

	// base_eq gets filled by ioctl syscall which triggers __ib_alloc_cq_user
	// this function calls this one and we forward it to the parent device

	opr_info("base_cq %px ovey_cq %px ovey_dev %px", base_cq, ovey_cq,
		 ovey_dev);
	opr_info("ovey_cq %px context %px\n", ovey_cq, base_cq->cq_context);

	ovey_cq->parent = rdma_zalloc_drv_obj(ovey_dev->parent, ib_cq);
	if (!ovey_cq->parent) {
		err = -ENOMEM;
	}
	opr_info("verb invoked %px\n", ovey_cq->parent);
	BUG_ON(err);

	ovey_cq->parent->device = ovey_dev->parent;
	ovey_cq->parent->uobject = base_cq->uobject;
	ovey_cq->parent->comp_handler = base_cq->comp_handler;
	ovey_cq->parent->event_handler = base_cq->event_handler;
	ovey_cq->parent->cq_context = base_cq->cq_context;
	atomic_set(&ovey_cq->parent->usecnt, 0);
	printk("WAH %s %d cq_context=%px\n", __FUNCTION__, __LINE__,
	       ovey_cq->parent->cq_context);

	rdma_restrack_new(&ovey_cq->parent->res, RDMA_RESTRACK_CQ);
	rdma_restrack_set_name(&ovey_cq->parent->res, NULL);

	err = ovey_dev->parent->ops.create_cq(ovey_cq->parent, attr, udata);
	BUG_ON(err);
	rdma_restrack_add(&ovey_cq->parent->res);

	if (udata) {
		opr_info("%px %px", base_cq->uobject, ovey_cq->parent->uobject);
		opr_info("user_handle %lld %lld",
			 base_cq->uobject->uevent.uobject.user_handle,
			 ovey_cq->parent->uobject->uevent.uobject.user_handle);
		opr_info("id %d %d", base_cq->uobject->uevent.uobject.id,
			 ovey_cq->parent->uobject->uevent.uobject.id);
		opr_info("cqe %d %d", base_cq->cqe, ovey_cq->parent->cqe);
	}

	base_cq->cqe = ovey_cq->parent->cqe;

	err = xa_err(xa_store(&cq_xarray, (uintptr_t)ovey_cq->parent, ovey_cq,
			      GFP_KERNEL));
	if (err) {
		opr_err("failed to store cq entry\n");
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
#if OVEY_UCONTEXT
	struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
	opr_info("verb invoked\n");

	return ib_poll_cq(ovey_cq->parent, num_cqe, wc);
#else
	opr_info("verb invoked -ENOTSUPP\n");
	return -ENOTSUPP;
#endif
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
static int ovey_req_notify_cq(struct ib_cq *base_cq,
			      enum ib_cq_notify_flags flags)
{
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
	opr_info("verb invoked ovey_dev->parent %px\n", ovey_dev->parent);

	ib_destroy_cq_user(ovey_cq->parent, udata);
	xa_erase(&cq_xarray, (uintptr_t)ovey_cq->parent);

	return 0;
}

static int ovey_qp_init_to_parent(struct ib_qp_init_attr *ovey,
				  struct ib_qp_init_attr *parent)
{
	parent->event_handler = ovey->event_handler;
	parent->qp_context = ovey->qp_context;
	parent->send_cq = to_ovey_cq(ovey->send_cq)->parent;
	parent->recv_cq = to_ovey_cq(ovey->recv_cq)->parent;

	opr_info("parent %px %px\n", parent->send_cq, parent->recv_cq);
	opr_info("ovey %px %px\n", ovey->send_cq, ovey->recv_cq);
	parent->srq = NULL;
	parent->xrcd = NULL;

	BUG_ON(ovey->srq != NULL);
	BUG_ON(ovey->xrcd != NULL);
	parent->cap = ovey->cap;
	parent->sq_sig_type = ovey->sq_sig_type;
	parent->qp_type = ovey->qp_type;
	parent->create_flags = ovey->create_flags;
	parent->port_num = ovey->port_num;
	parent->rwq_ind_tbl = ovey->rwq_ind_tbl;
	parent->source_qpn = ovey->source_qpn;
	return 0;
}

static int ovey_qp_init_from_parent(struct ib_qp_init_attr *ovey,
				    struct ib_qp_init_attr *parent)
{
	ovey->event_handler = parent->event_handler;
	ovey->qp_context = parent->qp_context;
	ovey->recv_cq = &ovey_from_parent(parent->recv_cq)->base;
	ovey->send_cq = &ovey_from_parent(parent->send_cq)->base;

	opr_info("parent %px %px\n", parent->send_cq, parent->recv_cq);
	opr_info("ovey %px %px\n", ovey->send_cq, ovey->recv_cq);
	ovey->srq = NULL;
	ovey->xrcd = NULL;

	BUG_ON(parent->srq != NULL);
	BUG_ON(parent->xrcd != NULL);
	ovey->cap = parent->cap;
	ovey->sq_sig_type = parent->sq_sig_type;
	ovey->qp_type = parent->qp_type;
	ovey->create_flags = parent->create_flags;
	ovey->port_num = parent->port_num;
	ovey->rwq_ind_tbl = parent->rwq_ind_tbl;
	ovey->source_qpn = parent->source_qpn;
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
static int ovey_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *attrs,
			  struct ib_udata *udata)
{
	struct ovey_qp *ovey_qp = to_ovey_qp(ibqp);
	struct ovey_device *ovey_dev = to_ovey_dev(ovey_qp->base.device);
	struct ovey_pd *ovey_pd = to_ovey_pd(ovey_qp->base.pd);
	struct ib_qp_init_attr parent_attr;
	int err = 0;

	opr_info("verb invoked udata %px\n", udata);
	opr_info("created qp ovey_dev %s parent_dev %s\n", ovey_dev->base.name,
		 ovey_dev->parent->name);

	err = ovey_qp_init_to_parent(attrs, &parent_attr);
	BUG_ON(err);

	ovey_qp->parent = ib_create_qp_user(ovey_dev->parent, ovey_pd->parent,
					    &parent_attr, udata, ibqp->uobject,
					    KBUILD_MODNAME);
	opr_info("%px %px\n", ovey_qp, ovey_qp->parent);
	if (IS_ERR(ovey_qp->parent)) {
		opr_err("create_qp() failed for parent device: %ld\n",
			PTR_ERR(ovey_qp->parent));
		err = PTR_ERR(ovey_qp->parent);
		goto err1;
	}

	/* Used in oveyd_create_qp, ib_core sets it only after ovey_create_qp */
	ovey_qp->base.device = &ovey_dev->base;

	err = oveyd_create_qp(ovey_qp, attrs);
	if (err < 0) {
		goto err3;
	}

	opr_info("created qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);

	return 0;

err3:
	ib_destroy_qp(ovey_qp->parent);
err1:
	return err;
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
	struct ib_qp_init_attr parent_attr;
	int ret;
	opr_info("verb invoked\n");

	opr_info("query_qp() %px %px\n", ovey_qp, ovey_qp->parent);
	opr_info("query qp ovey_dev %s parent_dev %s\n", ovey_dev->base.name,
		 ovey_dev->parent->name);
	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	ret = ovey_qp_init_to_parent(qp_init_attr, &parent_attr);
	BUG_ON(ret);

	ret = ovey_dev->parent->ops.query_qp(ovey_qp->parent, qp_attr,
					     qp_attr_mask, qp_init_attr);
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

	ret = ovey_qp_init_from_parent(qp_init_attr, &parent_attr);
	BUG_ON(ret);

	qp_init_attr->source_qpn = ovey_qp->base.qp_num;

	return ret;
}

static int ovey_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
			  int qp_attr_mask, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	struct ib_qp_attr *parent_attr;
	int ret;
	opr_info("verb invoked %x\n", qp_attr_mask);
	opr_info("modify qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);
	opr_info("modify qp ovey_dev %s parent_dev %s\n", ovey_dev->base.name,
		 ovey_dev->parent->name);

	opr_info("modify_qp() %px %px\n", ovey_qp, ovey_qp->parent);
	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	if (!ovey_qp->parent) {
		opr_err("No parent QP");
		return -EOPNOTSUPP;
	}

	parent_attr = kzalloc(sizeof(*parent_attr), GFP_KERNEL);
	if (!parent_attr)
		return -ENOMEM;

	if (qp_attr_mask & IB_QP_STATE)
		parent_attr->qp_state = qp_attr->qp_state;
	if (qp_attr_mask & IB_QP_CUR_STATE)
		parent_attr->cur_qp_state = qp_attr->cur_qp_state;
	if (qp_attr_mask & IB_QP_PATH_MTU)
		parent_attr->path_mtu = qp_attr->path_mtu;
	if (qp_attr_mask & IB_QP_PATH_MIG_STATE)
		parent_attr->path_mig_state = qp_attr->path_mig_state;
	if (qp_attr_mask & IB_QP_QKEY)
		parent_attr->qkey = qp_attr->qkey;
	if (qp_attr_mask & IB_QP_RQ_PSN)
		parent_attr->rq_psn = qp_attr->rq_psn;
	if (qp_attr_mask & IB_QP_SQ_PSN)
		parent_attr->sq_psn = qp_attr->sq_psn;
	if (qp_attr_mask & IB_QP_DEST_QPN)
		parent_attr->dest_qp_num = qp_attr->dest_qp_num;
	if (qp_attr_mask & IB_QP_ACCESS_FLAGS)
		parent_attr->qp_access_flags = qp_attr->qp_access_flags;
	if (qp_attr_mask & IB_QP_PKEY_INDEX)
		parent_attr->pkey_index = qp_attr->pkey_index;
	if (qp_attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY)
		parent_attr->en_sqd_async_notify = qp_attr->en_sqd_async_notify;
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		parent_attr->max_rd_atomic = qp_attr->max_rd_atomic;
	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		parent_attr->max_dest_rd_atomic = qp_attr->max_dest_rd_atomic;
	if (qp_attr_mask & IB_QP_MIN_RNR_TIMER)
		parent_attr->min_rnr_timer = qp_attr->min_rnr_timer;
	if (qp_attr_mask & IB_QP_PORT)
		parent_attr->port_num = qp_attr->port_num;
	if (qp_attr_mask & IB_QP_TIMEOUT)
		parent_attr->timeout = qp_attr->timeout;
	if (qp_attr_mask & IB_QP_RETRY_CNT)
		parent_attr->retry_cnt = qp_attr->retry_cnt;
	if (qp_attr_mask & IB_QP_RNR_RETRY)
		parent_attr->rnr_retry = qp_attr->rnr_retry;
	if (qp_attr_mask & IB_QP_ALT_PATH) {
		parent_attr->alt_port_num = qp_attr->alt_port_num;
		parent_attr->alt_timeout = qp_attr->alt_timeout;
		parent_attr->alt_pkey_index = qp_attr->alt_pkey_index;
	}

	if (qp_attr_mask & IB_QP_RATE_LIMIT)
		parent_attr->rate_limit = qp_attr->rate_limit;

	if (qp_attr_mask & IB_QP_AV) {
		ret = oveyd_resolve_qp(ovey_qp, qp_attr, parent_attr,
				       qp_attr_mask);
		if (ret < 0) {
			goto out;
		}
	}

	opr_info("modify 2 qp ovey_dev %s parent_dev %s qp_dev %s\n",
		 ovey_dev->base.name, ovey_dev->parent->name,
		 ovey_qp->parent->device->name);

	ret = ib_modify_qp_with_udata(ovey_qp->parent, parent_attr,
				      qp_attr_mask, udata);
	if (ret) {
		opr_err("%s() failed for parent device: %d\n", __FUNCTION__,
			ret);
		goto out;
	}

out:
	kfree(parent_attr);
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
#if OVEY_UCONTEXT
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	int ret;

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	if (!ovey_qp->parent) {
		return -EOPNOTSUPP;
	}

	ret = ovey_dev->parent->ops.post_send(ovey_qp->parent, wr, bad_wr);
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

	return ret;
#else
	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;
#endif
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
#if OVEY_UCONTEXT
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
#else
	opr_info("verb invoked ENOTSUPP\n");
	return -ENOTSUPP;
#endif
}

static int ovey_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata)
{
	struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
	struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
	int ret;
	opr_info("verb invoked\n");

	if (!ovey_qp) {
		opr_err("Failed to find the QP");
		return -EINVAL;
	}

	opr_info("verb invoked ovey_dev->parent %px\n", ovey_dev->parent);
	ret = ib_destroy_qp_user(ovey_qp->parent, udata);
	if (ret) {
		opr_err("%s() failed for parent device\n", __FUNCTION__);
	}

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

static int ovey_dump_pd(struct ib_pd *pd,
			struct ib_uverbs_dump_object_pd *dump_pd, ssize_t size)
{
	if (size < sizeof(*dump_pd)) {
		return -ENOMEM;
	}

	return sizeof(*dump_pd);
}

static int ovey_dump_cq(struct ib_cq *ib_cq,
			struct ib_uverbs_dump_object_cq *dump_cq, ssize_t size)
{
	if (size < sizeof(*dump_cq)) {
		return -ENOMEM;
	}

	/* Unimportant */
	dump_cq->comp_vector = 0;

	return sizeof(*dump_cq);
}

static int ovey_dump_object(u32 obj_type, void *req, void *dump, ssize_t size)
{
	opr_info("verb invoked\n");

	switch (obj_type) {
	case IB_UVERBS_OBJECT_PD:
		return ovey_dump_pd(req, dump, size);
	case IB_UVERBS_OBJECT_CQ:
		return ovey_dump_cq(req, dump, size);
	default:
		return -ENOTSUPP;
	}
	/* Not reached */
}

static int
ovey_restore_cq_refill(struct ovey_cq *cq,
		       const struct ib_uverbs_restore_object_cq_refill *queue,
		       ssize_t size)
{
	int ret = 0;

	cq->base.uobject->comp_events_reported = queue->comp_events_reported;
	cq->base.uobject->uevent.events_reported =
		queue->async_events_reported;

	return ret;
}

static int ovey_restore_cq(struct ib_cq *cq, u32 cmd, const void *args,
			   ssize_t size)
{
	int ret;
	struct ovey_cq *ovey_cq = to_ovey_cq(cq);

	if (!ovey_cq)
		return -EINVAL;

	switch (cmd) {
	case IB_RESTORE_CQ_REFILL:
		ret = ovey_restore_cq_refill(ovey_cq, args, size);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int ovey_restore_object(void *object, u32 obj_type, u32 cmd,
			       const void *args, ssize_t size)
{
	if (!object) {
		return -EINVAL;
	}

	switch (obj_type) {
	case IB_UVERBS_OBJECT_CQ:
		return ovey_restore_cq(object, cmd, args, size);
	default:
		return -EINVAL;
	}
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
	.device_group = &ovey_attr_group,
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
	.dump_object = ovey_dump_object,
	.restore_object = ovey_restore_object,

	// Mapping to application specific structs
	// this way the kernel can alloc a proper amount of memory
	// TODO: also for _srq

	INIT_RDMA_OBJ_SIZE(ib_pd, ovey_pd, base),
	INIT_RDMA_OBJ_SIZE(ib_qp, ovey_qp, base),
	/* INIT_RDMA_OBJ_SIZE(ib_ah, ovey_ah, base), */
	INIT_RDMA_OBJ_SIZE(ib_cq, ovey_cq, base),
	/* INIT_RDMA_OBJ_SIZE(ib_ucontext, ovey_ucontext, base), */
};
