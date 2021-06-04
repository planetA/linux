#ifndef OVEY_H
#define OVEY_H

#include <linux/module.h>
#include <linux/xarray.h>
#include <linux/string.h>
#include <rdma/ib_verbs.h>

// #include <rdma/ovey-abi.h>
#include "rdma/ovey-abi.h"

/**
 * like __FILE__ but without the path.
 */
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
/**
 * Format prefix for Ovey. Works like this:
 *
 * pr_err(OVEY_FMT_PRFX "<format string>", __FILENAME__, __LINE__, __FUNCTION__, ...args);
 */
#define OVEY_FMT_PRFX "OVEY [%15s:%03d] %30s(): "
// I expect most files to have 100 to 999 lines, therefore we add some zeros like:
// 1 -> 001, 85 -> 085 --> all logging messages are well aligned in log if from same file

// Please be aware that out of the box probably DEBUG and WARN won't work, see
// https://stackoverflow.com/questions/18607184/dmesg-is-not-showing-printk-statement
// INFO and ERR definitely work

#define opr_err(fmt, ...)                                                \
	pr_err(OVEY_FMT_PRFX fmt, __FILENAME__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define opr_info(fmt, ...)                                               \
	pr_info(OVEY_FMT_PRFX fmt, __FILENAME__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define opr_warn(fmt, ...)                                               \
	pr_warn(OVEY_FMT_PRFX fmt, __FILENAME__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define opr_debug(fmt, ...)                                              \
	pr_debug(OVEY_FMT_PRFX fmt, __FILENAME__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

struct ovey_device;
struct ovey_qp;

int ovey_qp_add(struct ovey_device *ovey_dev, struct ovey_qp *qp);
void ovey_free_qp(struct kref *ref);

#define ovey_dbg(ibdev, fmt, ...)                                               \
	ibdev_dbg(ibdev, "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovey_dbg_qp(qp, fmt, ...)                                               \
	ibdev_dbg(qp->parent->device, "QP[%u] %s: " fmt, qp_id(qp), __func__, \
		  ##__VA_ARGS__)

#define ovey_dbg_cq(cq, fmt, ...)                                               \
	ibdev_dbg(cq->base.device, "CQ[%u] %s: " fmt, cq->id, __func__,     \
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

#define OVEY_TIMEOUT (5*HZ)

struct ovey_device {
	// The ib_device data structure of the virtual device.
	// Seems like this MUST BE FIRST PROPERTY of the struct!
	// otherwise some ib_macros make problems
	struct ib_device base;
	// The actual device the ovey device uses
	struct ib_device *parent;

	struct net_device *ndev;

	// Virtual networks are identified by a uuid.
	uuid_t network;

	struct completion completion;
	// TODO remove probably
	struct xarray qp_xa;
};

struct ovey_ucontext {
	struct ib_ucontext base;
	struct ib_ucontext *parent;
};

struct ovey_pd {
	struct ib_pd base;
	struct ib_pd *parent;
};

struct ovey_ah {
	struct ib_ah base;
	struct ib_ah *parent;
};

struct ovey_qp {
	struct ib_qp base;
	struct ib_qp *parent;
	struct kref ref;
	struct rcu_head rcu;
};

struct ovey_cq {
	struct ib_cq base;
	struct ib_cq *parent;
};

struct ovey_mr {
	struct ib_mr base;
	struct ib_mr *parent;
};

static inline u32 *qp_id_p(struct ovey_qp *qp)
{
	return &qp->base.qp_num;
}

static inline u32 qp_id(struct ovey_qp *qp)
{
	return *qp_id_p(qp);
}

static inline struct ovey_ucontext *to_ovey_ctx(struct ib_ucontext *base_ctx)
{
	return container_of(base_ctx, struct ovey_ucontext, base);
}

static inline struct ovey_device *to_ovey_dev(struct ib_device *base_dev)
{
	return container_of(base_dev, struct ovey_device, base);
}

static inline struct ovey_pd *to_ovey_pd(struct ib_pd *base_pd)
{
	return container_of(base_pd, struct ovey_pd, base);
}

static inline struct ovey_ah *to_ovey_ah(struct ib_ah *base_ah)
{
	return container_of(base_ah, struct ovey_ah, base);
}

static inline struct ovey_cq *to_ovey_cq(struct ib_cq *base_cq)
{
	return container_of(base_cq, struct ovey_cq, base);
}

static inline struct ovey_mr *to_ovey_mr(struct ib_mr *base_mr)
{
	return container_of(base_mr, struct ovey_mr, base);
}

static inline struct ovey_qp *to_ovey_qp(struct ib_qp *base_qp)
{
	return container_of(base_qp, struct ovey_qp, base);
}

// functions that must be accessible from ocp.c


int ovey_delete_device(char *device_name);

/**
 * Returns relevant information about an Ovey device.
 * This is useful if you only have the name of the device and want
 * to get more (ib verbs unrelated) info about it. All pointers inside the
 * struct are pointers OWNED BY OTHER FUNCTIONS. Don't free them!
 *
 * @param ovey_dev_name The name of the existing device, e.g. "ovey0"
 * @param dest The destination buffer.
 * @return NULL or pointer to dest
 */
struct ovey_device_info * get_device_info_by_name(char const * const ovey_dev_name, struct ovey_device_info * dest);

// This struct is used as intermediate struct for the
// OVEY_C_DEVICE_INFO OCP operation. This is assembled either before it is destructed and send via netlink
// or assembled after the properties where received via OCP.
// It bundles all needed information before it's data can be written into the netlink packet.
// All pointers inside the struct are pointers OWNED BY OTHER FUNCTIONS.
// Don't free them!
struct ovey_device_info {
	// e.g. "ovey0"
	char const *device_name;
	// e.g. "rxe0"
	char const *parent_device_name;
	// the virtual guid that identifies this node. Corresponds with the
	// value inside Ovey Coordinator.
	u64 node_guid;
	// the virtual LID of a node
	u64 node_lid;
	// the guid of the real, physical device.
	u64 parent_node_guid;
	// the uuid v4 that describes to what virtual network this device belongs.
	// Corresponds with the value inside Ovey Coordinator.
	uuid_t network;
};

#endif  /* OVEY_H */
