#ifndef OVEYD_H
#define OVEYD_H

#include "ovey.h"
#include "rdma/ib_verbs.h"

enum oveyd_req_type {
	OVEYD_REQ_LEASE_DEVICE,
	OVEYD_REQ_LEASE_GID,
	OVEYD_REQ_RESOLVE_QP,
	OVEYD_REQ_SET_GID,
	OVEYD_REQ_CREATE_PORT,
	OVEYD_REQ_SET_PORT_ATTR,
	OVEYD_REQ_CREATE_QP,
};

struct oveyd_gid {
	__be64 subnet_prefix;
	__be64 interface_id;
};

/* Ovey daemon request to lease device */
struct oveydr_lease_device {
	__be64 guid;
};

/* Ovey daemon request to lease gid */
struct oveydr_lease_gid {
	u32 idx;
	__be64 subnet_prefix;
	__be64 interface_id;
};

/* Ovey daemon request to lease gid */
struct oveydr_set_gid {
	u32 real_idx;
	u32 virt_idx;
	__be64 real_subnet_prefix;
	__be64 real_interface_id;
	__be64 virt_subnet_prefix;
	__be64 virt_interface_id;
};

enum {
	OVEYDR_RESOLVE_QP_GID = (1 << 0),
	OVEYDR_RESOLVE_QP_QPN = (1 << 1),
	OVEYDR_RESOLVE_QP_LID = (1 << 2),
};

/* Ovey daemon request to resolve gid */
struct oveydr_resolve_qp {
	u64 attr_mask;
	__be64 subnet_prefix;
	__be64 interface_id;
	u32 qpn;
	u32 lid;
};

/* Ovey daemon request to register a port */
struct oveydr_create_port {
	u16 port;
	u32 pkey_tbl_len;
	u32 gid_tbl_len;
	u32 core_cap_flags;
	u32 max_mad_size;
};

struct oveydr_set_port_attr {
	u32 lid;
};

/* Ovey daemon request to create QP */
struct oveydr_create_qp {
	u32 qpn;
};

struct oveyd_req_pkt {
	/* Header must always go first */
	u16 type;
	u16 len;
	u32 seq;
	uuid_t network;
	uuid_t device;
	u16 port;
	union {
		struct oveydr_lease_device lease_device;
		struct oveydr_lease_gid lease_gid;
		struct oveydr_resolve_qp resolve_qp;
		struct oveydr_set_gid set_gid;
		struct oveydr_create_port create_port;
		struct oveydr_set_port_attr set_port_attr;
		struct oveydr_create_qp create_qp;
	};
};

struct oveyd_resp_pkt {
	u16 type;
	u16 len;
	u32 seq;
	union {
		struct oveydr_lease_device lease_device;
		struct oveydr_lease_gid lease_gid;
		struct oveydr_resolve_qp resolve_qp;
		struct oveydr_set_gid set_gid;
		struct oveydr_create_port create_port;
		struct oveydr_set_port_attr set_port_attr;
		struct oveydr_create_qp create_qp;
	};
};

struct oveyd_request {
	struct list_head head;
	struct completion *completion;
	struct oveyd_req_pkt req;
	struct oveyd_resp_pkt resp;
};

int oveyd_lease_device(struct ovey_device *ovey_dev);
int oveyd_lease_gid(struct ovey_device *ovey_dev, u8 port, int idx,
		union ib_gid *gid);
int oveyd_set_gid(struct ovey_device *ovey_dev, u8 virt_port, int virt_idx,
		  union ib_gid *virt_gid, u8 real_port, int real_idx,
		  union ib_gid *real_gid);
int oveyd_create_port(struct ovey_device *ovey_dev, u8 port, struct ib_port_immutable *attr);
int oveyd_set_port_attr(struct ovey_device *ovey_dev, u8 port,
			struct ib_port_attr *attr);
int oveyd_create_qp(struct ovey_qp *ovey_qp, struct ib_qp_init_attr *attrs);
int oveyd_resolve_qp(struct ovey_qp *ovey_qp,
		     const struct ib_qp_attr *qp_attr_virt,
		     struct ib_qp_attr *qp_attr_real, int qp_attr_mask);

int ovey_eventdev_init(void);
void ovey_eventdev_exit(void);

#endif /* OVEYD_H */
