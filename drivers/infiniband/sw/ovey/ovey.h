#ifndef OVEY_H
#define OVEY_H

#include <linux/module.h>

#include <rdma/ib_verbs.h>

#include <rdma/ovey-abi.h>

#define OVEY_UVERBS_ABI_VERSION		1

#define ovey_dbg(ibdev, fmt, ...)                                               \
	ibdev_dbg(ibdev, "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovey_dbg_qp(qp, fmt, ...)                                               \
	ibdev_dbg(&qp->sdev->base_dev, "QP[%u] %s: " fmt, qp_id(qp), __func__, \
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
	struct ib_device	base;
	// The actual device the ovey device backs up
	struct net_device *parent_netdev;

	/* physical port state (only one port per device) */
	enum ib_port_state state;
};

struct ovey_ucontext {
	struct ib_ucontext base_ucontext;
	struct ovey_device *ovey_dev;
};

struct ovey_pd {
	struct ib_pd base_pd;
};

struct ovey_qp {
	struct ib_qp base_qp;
};

struct ovey_cq {
	struct ib_cq base_cq;
};

static inline struct ovey_device *to_ovey_dev(struct ib_device *base_dev)
{
	return container_of(base_dev, struct ovey_device, base);
}

#endif  /* OVEY_H */
