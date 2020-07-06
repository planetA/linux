#ifndef OVEY_VERBS_H
#define OVEY_VERBS_H

#include <rdma/ib_verbs.h>

#include "ovey.h"

int ovey_query_device(struct ib_device *base_dev, struct ib_device_attr *attr,
                      struct ib_udata *udata);
void ovey_device_cleanup(struct ib_device *base_dev);
int ovey_query_port(struct ib_device *base_dev, u8 port,
                    struct ib_port_attr *attr);
int ovey_query_gid(struct ib_device *base_dev, u8 port, int idx,
                   union ib_gid *gid);
int ovey_query_pkey(struct ib_device *base_dev, u8 port, u16 idx, u16 *pkey);
int ovey_get_port_immutable(struct ib_device *base_dev, u8 port,
                            struct ib_port_immutable *port_immutable);
int ovey_alloc_ucontext(struct ib_ucontext *base_ctx, struct ib_udata *udata);
void ovey_dealloc_ucontext(struct ib_ucontext *base_ctx);
int ovey_alloc_pd(struct ib_pd *base_pd, struct ib_udata *udata);
void ovey_dealloc_pd(struct ib_pd *base_pd, struct ib_udata *udata);
int ovey_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma);
void ovey_mmap_free(struct rdma_user_mmap_entry *rdma_entry);
struct ib_mr *ovey_alloc_mr(struct ib_pd *base_pd, enum ib_mr_type mr_type,
                            u32 max_sge, struct ib_udata *udata);
struct ib_mr *ovey_reg_user_mr(struct ib_pd *base_pd, u64 start, u64 len,
                               u64 rnic_va, int rights, struct ib_udata *udata);
int ovey_map_mr_sg(struct ib_mr *base_mr, struct scatterlist *sl, int num_sle,
                   unsigned int *sg_off);
struct ib_mr *ovey_get_dma_mr(struct ib_pd *base_pd, int rights);
int ovey_dereg_mr(struct ib_mr *base_mr, struct ib_udata *udata);
int ovey_create_cq(struct ib_cq *base_cq, const struct ib_cq_init_attr *attr,
		  struct ib_udata *udata);
int ovey_poll_cq(struct ib_cq *base_cq, int num_entries, struct ib_wc *wc);
int ovey_req_notify_cq(struct ib_cq *base_cq, enum ib_cq_notify_flags flags);
void ovey_destroy_cq(struct ib_cq *base_cq, struct ib_udata *udata);
struct ib_qp *ovey_create_qp(struct ib_pd *base_pd,
			    struct ib_qp_init_attr *attr,
			    struct ib_udata *udata);
int ovey_query_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
		 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
int ovey_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *attr,
                   int attr_mask, struct ib_udata *udata);
int ovey_post_send(struct ib_qp *base_qp, const struct ib_send_wr *wr,
                   const struct ib_send_wr **bad_wr);
int ovey_post_recv(struct ib_qp *base_qp, const struct ib_recv_wr *wr,
                   const struct ib_recv_wr **bad_wr);
int ovey_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata);

void ovey_qp_event(struct ovey_qp *qp, enum ib_event_type type);
void ovey_cq_event(struct ovey_cq *cq, enum ib_event_type type);
void ovey_port_event(struct ovey_device *dev, u8 port, enum ib_event_type type);

#endif /* OVEY_VERBS_H */
