#ifndef OVEYD_H
#define OVEYD_H

#include "ovey.h"

enum oveyd_req_type {
	OVEYD_REQ_LEASE_DEVICE,
	OVEYD_REQ_LEASE_GID,
	OVEYD_REQ_RESOLVE_GID,
};

/* Ovey daemon request to lease device */
struct oveydr_lease_device {
	__be64 guid;
};

/* Ovey daemon request to lease gid */
struct oveydr_lease_gid {
	u16 port;
	u32 idx;
	__be64 subnet_prefix;
	__be64 interface_id;
};

/* Ovey daemon request to lease gid */
struct oveydr_resolve_gid {
	__be64 subnet_prefix;
	__be64 interface_id;
};

struct oveyd_req_pkt {
	/* Header must always go first */
	u16 type;
	u16 len;
	u32 seq;
	uuid_t network;
	union {
		struct oveydr_lease_device lease_device;
		struct oveydr_lease_gid lease_gid;
		struct oveydr_resolve_gid resolve_gid;
	};
};

struct oveyd_resp_pkt {
	u16 type;
	u16 len;
	u32 seq;
	union {
		struct oveydr_lease_device lease_device;
		struct oveydr_lease_gid lease_gid;
		struct oveydr_resolve_gid resolve_gid;
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

int oveyd_resolve_av(struct ovey_qp *ovey_qp, struct rdma_ah_attr *ah);

int ovey_eventdev_init(void);
void ovey_eventdev_exit(void);

#endif /* OVEYD_H */
