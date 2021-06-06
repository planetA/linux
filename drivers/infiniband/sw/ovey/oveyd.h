#ifndef OVEYD_H
#define OVEYD_H

#include "ovey.h"

enum oveyd_req_type {
	OVEYD_REQ_LEASE_DEVICE,
	OVEYD_REQ_LEASE_GID,
};

struct oveyd_req_hdr {
	u16 type;
	u16 len;
	u32 seq;
	uuid_t network;
};

/* Ovey daemon request to lease device */
struct oveydr_lease_device {
	/* Header must always go first */
	struct oveyd_req_hdr hdr;
	__be64 guid;
};

struct oveyd_resp_hdr {
	u16 type;
	u16 len;
	u32 seq;
};

struct oveydr_lease_device_resp {
	/* Header must always go first */
	struct oveyd_resp_hdr hdr;
	__be64 guid;
};

union oveyd_req_pkt {
	/* Header must always go first */
	struct oveyd_resp_hdr hdr;
	struct oveydr_lease_device lease_device;
};

union oveyd_resp_pkt {
	/* Header must always go first */
	struct oveyd_resp_hdr hdr;
	struct oveydr_lease_device_resp lease_device;
};

struct oveyd_request {
	struct list_head head;
	struct completion *completion;
	union oveyd_req_pkt req;
	union oveyd_resp_pkt resp;
};

int oveyd_lease_device(struct ovey_device *ovey_dev);

int ovey_eventdev_init(void);
void ovey_eventdev_exit(void);

#endif /* OVEYD_H */
