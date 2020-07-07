#ifndef OVEY_H
#define OVEY_H

#include <linux/module.h>
#include <linux/xarray.h>

#include <rdma/ib_verbs.h>

#include <rdma/ovey-abi.h>

#define OVEY_UVERBS_ABI_VERSION		1

struct ovey_device;
struct ovey_qp;

int ovey_qp_add(struct ovey_device *ovey_dev, struct ovey_qp *qp);
void ovey_free_qp(struct kref *ref);

#define ovey_dbg(ibdev, fmt, ...)                                               \
	ibdev_dbg(ibdev, "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovey_dbg_qp(qp, fmt, ...)                                               \
	ibdev_dbg(&qp->ovey_dev->base, "QP[%u] %s: " fmt, qp_id(qp), __func__, \
		  ##__VA_ARGS__)

#define ovey_dbg_cq(cq, fmt, ...)                                               \
	ibdev_dbg(cq->base_cq.device, "CQ[%u] %s: " fmt, cq->id, __func__,     \
		  ##__VA_ARGS__)

#define ovey_dbg_pd(pd, fmt, ...)                                               \
	ibdev_dbg(pd->device, "PD[%u] %s: " fmt, pd->res.id, __func__,         \
		  ##__VA_ARGS__)

#define ovey_dbg_mem(mem, fmt, ...)                                             \
	ibdev_dbg(&mem->sdev->base_dev,                                        \
		  "MEM[0x%08x] %s: " fmt, mem->stag, __func__, ##__VA_ARGS__)

#define ovey_dbg_cep(cep, fmt, ...)                                             \
	ibdev_dbg(&cep->sdev->base_dev, "CEP[0x%pK] %s: " fmt,                 \
		  cep, __func__, ##__VA_ARGS__)

struct ovey_device {
	// The ib_device data structure of the virtual device
	struct ib_device base;
	// The actual device the ovey device backs up
	struct ib_device *parent;

	struct xarray qp_xa;
};

struct ovey_ucontext {
	struct ib_ucontext base_ucontext;
	struct ib_ucontext *parent;
};

struct ovey_pd {
	struct ib_pd base_pd;
	struct ib_pd *parent;
};

struct ovey_qp {
	struct ib_qp base_qp;
	struct ib_qp *parent;
	struct ovey_device *ovey_dev;
	struct kref ref;
	struct rcu_head rcu;
};

struct ovey_cq {
	struct ib_cq base_cq;
	struct ib_cq *parent;
};

struct ovey_mr {
	struct ib_mr base_mr;
	struct ib_mr *parent;
};

static inline u32 *qp_id_p(struct ovey_qp *qp)
{
	return &qp->base_qp.qp_num;
}

static inline u32 qp_id(struct ovey_qp *qp)
{
	return *qp_id_p(qp);
}

static inline void ovey_qp_get(struct ovey_qp *qp)
{
	kref_get(&qp->ref);
}

static inline void ovey_qp_put(struct ovey_qp *qp)
{
	kref_put(&qp->ref, ovey_free_qp);
}

static inline struct ovey_ucontext *to_ovey_ctx(struct ib_ucontext *base_ctx)
{
	return container_of(base_ctx, struct ovey_ucontext, base_ucontext);
}

static inline struct ovey_device *to_ovey_dev(struct ib_device *base_dev)
{
	return container_of(base_dev, struct ovey_device, base);
}

static inline struct ovey_pd *to_ovey_pd(struct ib_pd *base_pd)
{
	return container_of(base_pd, struct ovey_pd, base_pd);
}

static inline struct ovey_cq *to_ovey_cq(struct ib_cq *base_cq)
{
	return container_of(base_cq, struct ovey_cq, base_cq);
}

static inline struct ovey_mr *to_ovey_mr(struct ib_mr *base_mr)
{
	return container_of(base_mr, struct ovey_mr, base_mr);
}

static inline struct ovey_qp *to_ovey_qp(struct ib_qp *base_qp)
{
	return container_of(base_qp, struct ovey_qp, base_qp);
}

#endif  /* OVEY_H */
