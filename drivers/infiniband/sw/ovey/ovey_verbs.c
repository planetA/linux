#include <linux/kernel.h>

#include "ocp.h"
#include "ovey.h"
#include "ovey_verbs.h"
#include "ocp-util.h"
#include "completions.h"
#include "virtualized_properties.h"

int ovey_query_device(struct ib_device *base_dev, struct ib_device_attr *attr,
                      struct ib_udata *udata) {
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

int ovey_query_port(struct ib_device *base_dev, u8 port,
                    struct ib_port_attr *attr) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
    int ret;
    struct ovey_completion_chain * chain_node;
    struct sk_buff *req_sk_buf;

    opr_info("verb invoked\n");

    // forward operation to parent driver
    ret = ib_query_port(ovey_dev->parent, port, attr);
    if (ret < 0) {
        opr_err("ib_query_port() on parent device failed! %d\n", ret);
    }

    // VIRTUALIZE PROPERTY PORT->LID
    struct ovey_virt_lid virt_lid;
    virt_lid.orig = attr->lid;
    virt_lid.virt = 0x11223344;
    attr->lid = virt_lid.virt;
    // END VIRTUALIZE PROPERTY PORT->LID

    chain_node = ovey_completion_add_entry();
    req_sk_buf = ocp_nlmsg_new();
    struct nlmsghdr * hdr = ocp_kernel_request_put(req_sk_buf, OVEY_C_STORE_VIRT_PROPERTY_PORT_LID);
    nla_put_u64_64bit(req_sk_buf, OVEY_A_COMPLETION_ID, chain_node->req_id, 0);
    nla_put_u32(req_sk_buf, OVEY_A_REAL_PROPERTY_U32, virt_lid.orig);
    nla_put_u32(req_sk_buf, OVEY_A_VIRT_PROPERTY_U32, virt_lid.virt);
    /* finalize the message, IMPORTANT! Update length attribute etc */
    genlmsg_end(req_sk_buf, hdr);
    // sending request to daemon via "kernel to daemon" socket
    nlmsg_unicast(
            ocp_sockets.genl_sock,
            req_sk_buf,
            ocp_sockets.kernel_daemon_to_sock_pid
    );

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

int ovey_query_gid(struct ib_device *base_dev, u8 port, int idx,
                   union ib_gid *gid) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
    int ret;
    opr_info("verb invoked\n");

    // forward operation to parent
    ret = ovey_dev->parent->ops.query_gid(ovey_dev->parent, port, idx, gid);
    if (ret) {
        opr_err("query_gid() on parent device failed! %d\n", ret);
    }

    return ret;
}

int ovey_query_pkey(struct ib_device *base_dev, u8 port, u16 idx, u16 *pkey) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
    int ret;

    opr_info("verb invoked: port=%d, idx=%d, pkey=%d\n", port, idx, *pkey);

    ret = ib_query_pkey(ovey_dev->parent, port, idx, pkey);
    if (ret < 0) {
        opr_err("query_pkey() on parent device failed! %d\n", ret);
    }

    return ret;
}

enum rdma_link_layer ovey_get_link_layer(struct ib_device *base_dev, u8 port_num) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_dev);

    opr_info("verb invoked\n");

    return ovey_dev->parent->ops.get_link_layer(ovey_dev->parent, port_num);
}

int ovey_get_port_immutable(struct ib_device *base_dev, u8 port,
                            struct ib_port_immutable *port_immutable) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_dev);
    int ret;

    opr_info("verb invoked\n");

    ret = ovey_dev->parent->ops.get_port_immutable(ovey_dev->parent, port, port_immutable);
    if (ret < 0) {
        opr_err("get_port_immutable() on parent device failed! %d\n", ret);
    }

    return 0;
}

int ovey_alloc_ucontext(struct ib_ucontext *base_ctx, struct ib_udata *udata) {
    struct ovey_ucontext *ovey_u_ctx = to_ovey_ctx(base_ctx);
    struct ovey_device *ovey_dev = to_ovey_dev(ovey_u_ctx->base.device);
    int ret;

    opr_info("verb invoked\n");
    opr_info("ovey_dev->name=%s, ovey_dev->parent->name=%s\n", ovey_dev->base.name, ovey_dev->parent->name);

    ovey_u_ctx->parent = rdma_zalloc_drv_obj(ovey_dev->parent, ib_ucontext);
    if (!ovey_u_ctx->parent)
        return -ENOMEM;

    ovey_u_ctx->parent->res.type = RDMA_RESTRACK_CTX;
    ovey_u_ctx->parent->device = ovey_dev->parent;
    ovey_u_ctx->parent->ufile = base_ctx->ufile;
    xa_init_flags(&ovey_u_ctx->parent->mmap_xa, XA_FLAGS_ALLOC);

    // TODO we just forward udata.. is there a memory problem if the parent relies on it
    //  having enough memory fur it's case?
    ret = ovey_dev->parent->ops.alloc_ucontext(ovey_u_ctx->parent, udata);
    opr_err("ret=%d\n", ret);
    if (ret < 0) {
        opr_err("alloc_ucontext() on parent device failed! %d\n", ret);
        kfree(ovey_u_ctx->parent);
    }

    return ret;
}

void ovey_dealloc_ucontext(struct ib_ucontext *base_ctx) {
    struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
    struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->base.device);

    opr_info("verb invoked\n");

    if (!ovey_dev->parent->ops.dealloc_ucontext) {
        return;
    }

    ovey_dev->parent->ops.dealloc_ucontext(ovey_ctx->parent);

    // todo free ovey_ctx itself or just parent?!
    kfree(ovey_ctx->parent);
}

int ovey_alloc_pd(struct ib_pd *pd, struct ib_udata *udata) {
    struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
    struct ovey_pd *ovey_pd = to_ovey_pd(pd);
    int ret;

    opr_info("verb invoked\n");

    ovey_pd->parent = ib_alloc_pd(ovey_dev->parent, pd->flags);
    if (!ovey_pd->parent) {
        opr_err("ib_alloc_pd failed for parent device\n");
    }

    return ret;
}

void ovey_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata) {
    struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
    struct ovey_pd *ovey_pd = to_ovey_pd(pd);

    opr_info("verb invoked\n");

    if (!ovey_dev->parent->ops.dealloc_pd) {
        return;
    }

    ib_dealloc_pd_user(ovey_pd->parent, udata);
}

int ovey_mmap(struct ib_ucontext *base_ctx, struct vm_area_struct *vma) {
    struct ovey_ucontext *ovey_ctx = to_ovey_ctx(base_ctx);
    struct ovey_device *ovey_dev = to_ovey_dev(ovey_ctx->base.device);
    int ret;

    opr_info("verb invoked\n");

    ret = ovey_dev->parent->ops.mmap(ovey_ctx->parent, vma);
    if (!ret) {
        opr_err("mmap() on parent device failed! %d\n", ret);
    }
    return ret;
}

void ovey_mmap_free(struct rdma_user_mmap_entry *rdma_entry) {
    struct ib_ucontext *parent_ctx = rdma_entry->ucontext;
    struct ib_device *parent_dev = parent_ctx->device;

    opr_info("verb invoked\n");

    if (!parent_dev->ops.mmap_free) {
        return;
    }

    return parent_ctx->device->ops.mmap_free(rdma_entry);
}

struct ib_mr *ovey_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
                            u32 max_sge, struct ib_udata *udata) {
    struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
    struct ovey_pd *ovey_pd = to_ovey_pd(pd);
    struct ovey_mr * ovey_mr;

    opr_info("verb invoked\n");

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
struct ib_mr *ovey_reg_user_mr(struct ib_pd *pd, u64 start, u64 len,
                               u64 rnic_va, int rights, struct ib_udata *udata) {
    struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
    struct ovey_pd *ovey_pd = to_ovey_pd(pd);

    opr_info("verb invoked\n");

    return ovey_dev->parent->ops.reg_user_mr(ovey_pd->parent, start, len, rnic_va, rights, udata);
}

int ovey_map_mr_sg(struct ib_mr *base_mr, struct scatterlist *sl, int num_sle,
                   unsigned int *sg_off) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_mr->device);
    struct ovey_mr *ovey_mr = to_ovey_mr(base_mr);
    opr_info("verb invoked\n");

    return ib_map_mr_sg(ovey_mr->parent, sl, num_sle, sg_off, PAGE_SIZE);
}

/*
 * ovey_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 */
struct ib_mr *ovey_get_dma_mr(struct ib_pd *pd, int rights) {
    struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
    struct ovey_pd *ovey_pd = to_ovey_pd(pd);
    struct ovey_mr *ovey_mr = NULL;

    opr_info("verb invoked\n");

    /*ovey_mr = kzalloc(sizeof(*ovey_mr), GFP_KERNEL);
    if (!ovey_mr) {
        ret = -ENOMEM;
        goto err_out;
    }

    ovey_mr->parent = ovey_dev->parent->ops.get_dma_mr(ovey_pd->parent, rights);
    if (IS_ERR(ovey_mr->parent)) {
     	ret = PTR_ERR(ovey_mr->parent);
     	goto err_out;
    }

    / * ovey_mr->parent = parent_mr;
    / * pr_err("ALLOCATED MR ovey %px parent %px parent device %px\n", ovey_mr, parent_mr, parent_mr->device);

    // I think this has to be parent..
    return &ovey_mr->base;

    err_out:
    if (ret) {
        kfree(ovey_mr);
    }

    return ERR_PTR(ret);*/
    return ovey_dev->parent->ops.get_dma_mr(ovey_pd->parent, rights);
}

/*
 * ovey_dereg_mr()
 *
 * Release Memory Region.
 *
 * @base: Base MR contained in ovey MR.
 * @udata: points to user context, unused.
 */
int ovey_dereg_mr(struct ib_mr *base_mr, struct ib_udata *udata) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_mr->device);
    struct ovey_mr *ovey_mr = to_ovey_mr(base_mr);
    int ret;

    opr_info("verb invoked\n");

    ret = ovey_dev->parent->ops.dereg_mr(base_mr, udata);
    // HELL NO! DON'T EVER FREE HERE! OTHERWISE DOUBLE FREE
    // kfree(ovey_mr);

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

int ovey_create_cq(struct ib_cq *base_cq,
                   const struct ib_cq_init_attr *attr,
                   struct ib_udata *udata) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);
    struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);

    // this is the function that also gets invoked after the syscall

    // base_eq gets filled by ioctl syscall which triggers __ib_alloc_cq_user
    // this function calls this one and we forward it to the parent device

    ovey_cq->parent = __ib_alloc_cq_user(
            ovey_dev->parent,
            base_cq->cq_context,
            (int) attr->cqe,
            attr->comp_vector,
            base_cq->poll_ctx,
            // TODO how to get this information?!
            "TODO_UNKNOWN",
            udata
    );

    opr_info("ovey_cq->parent=%px\n", ovey_cq->parent);

    if (ovey_cq->parent == NULL) {
        return -EINVAL;
    }
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
int ovey_poll_cq(struct ib_cq *base_cq, int num_cqe, struct ib_wc *wc) {
    struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
    struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);
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
int ovey_req_notify_cq(struct ib_cq *base_cq, enum ib_cq_notify_flags flags) {
    struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
    struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);
    opr_info("verb invoked\n");

    return ib_req_notify_cq(ovey_cq->parent, flags);
}

void ovey_destroy_cq(struct ib_cq *base_cq, struct ib_udata *udata) {
    struct ovey_cq *ovey_cq = to_ovey_cq(base_cq);
    struct ovey_device *ovey_dev = to_ovey_dev(base_cq->device);

    opr_info("verb invoked\n");

    dump_stack();

    if (!ovey_dev->parent->ops.destroy_cq) {
        return;
    }

    //ib_destroy_cq_user(ovey_cq->parent, udata);
    ovey_dev->parent->ops.destroy_cq(ovey_cq->parent, udata);
    kfree(ovey_cq->parent);
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
                             struct ib_udata *udata) {
    struct ovey_pd *ovey_pd = to_ovey_pd(pd);
    struct ovey_device *ovey_dev = to_ovey_dev(pd->device);
    struct ovey_qp *qp = NULL;

    opr_info("verb invoked\n");

    qp = kzalloc(sizeof(*qp), GFP_KERNEL);
    // like ib_create_qp(ovey_pd->parent, attrs)
    qp->parent = ib_create_qp_user(ovey_pd->parent, attrs, udata);
    if (!qp->parent) {
        opr_err("ib_create_qp() failed for parent device\n");
    }

    // return &qp->base;
    return qp->parent;
}

/*
 * Minimum ovey_query_qp() verb interface.
 *
 * @qp_attr_mask is not used but all available information is provided
 */
int ovey_query_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
                  int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr) {
    struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
    struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
    opr_info("verb invoked\n");

    return ib_query_qp(ovey_qp->parent, qp_attr, qp_attr_mask, qp_init_attr);
}

int ovey_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *attr,
                   int attr_mask, struct ib_udata *udata) {
    struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
    struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
    struct ovey_completion_chain * chain_node;
    struct sk_buff *req_sk_buf;
    int ret;
    opr_info("verb invoked\n");

    chain_node = ovey_completion_add_entry();
    req_sk_buf = ocp_nlmsg_new();
    struct nlmsghdr * hdr = ocp_kernel_request_put(req_sk_buf, OVEY_C_RESOLVE_COMPLETION);
    nla_put_u64_64bit(req_sk_buf, OVEY_A_COMPLETION_ID, chain_node->req_id, 0);
    /* finalize the message, IMPORTANT! Update length attribute etc */
    genlmsg_end(req_sk_buf, hdr);
    // sending request to daemon via "kernel to daemon" socket
    nlmsg_unicast(
            ocp_sockets.genl_sock,
            req_sk_buf,
            ocp_sockets.kernel_daemon_to_sock_pid
    );

    ret = wait_for_completion_killable(&chain_node->completion);
    if (ret == 0) {
        // success
        opr_info("wait_for_completion_killable returned 0");
    } else {
        // process got killed while waiting for the completion
        opr_err("wait_for_completion_killable returned %d", ret);
        return -EINVAL;
    }

    return ib_modify_qp(ovey_qp->parent, attr, attr_mask);
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
                   const struct ib_send_wr **bad_wr) {
    struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
    struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
    opr_info("verb invoked\n");

    return ib_post_send(ovey_qp->parent, wr, bad_wr);
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
                   const struct ib_recv_wr **bad_wr) {
    struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
    struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
    opr_info("verb invoked\n");

    return ib_post_recv(ovey_qp->parent, wr, bad_wr);
}

int ovey_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata) {
    struct ovey_qp *ovey_qp = to_ovey_qp(base_qp);
    struct ovey_device *ovey_dev = to_ovey_dev(base_qp->device);
    int ret;
    opr_info("verb invoked\n");

    ret = ib_destroy_qp(ovey_qp->parent);
    kfree(ovey_qp);

    return ret;
}


void ovey_dealloc_driver(struct ib_device *base_dev) {
    struct ovey_device *ovey_dev = to_ovey_dev(base_dev);

    opr_info("verb invoked\n");

    // I think this is really the wrong way. We also didn't created the device in the
    // first place. All we have to do is maybe some cleanup of QPs but don't dealloc the
    // actual device; it should survive if a ovey device is removed
    // ovey_dev->parent->ops.dealloc_driver(ovey_dev->parent);
    // xa_destroy(&ovey_dev->qp_xa);

    ib_device_put(ovey_dev->parent);
}

void ovey_qp_event(struct ovey_qp *qp, enum ib_event_type etype) {
}

void ovey_cq_event(struct ovey_cq *cq, enum ib_event_type etype) {
}

void ovey_port_event(struct ovey_device *ovey_dev, u8 port, enum ib_event_type etype) {
}
