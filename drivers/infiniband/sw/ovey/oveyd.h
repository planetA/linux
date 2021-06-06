#ifndef OVEYD_H
#define OVEYD_H

#include "ovey.h"

enum oveyd_req_type {
	OVEYD_REQ_LEASE_DEVICE,
	OVEYD_REQ_LEASE_GID,
};

/* Ovey daemon request to lease device */
struct oveydr_lease_device {
	/* Header must always go first */
	__be64 guid;
};

struct oveydr_lease_device_resp {
	/* Header must always go first */
	__be64 guid;
};

struct oveyd_req_pkt {
	/* Header must always go first */
	u16 type;
	u16 len;
	u32 seq;
	uuid_t network;
	union {
		struct oveydr_lease_device lease_device;
	};
};

struct oveyd_resp_pkt {
	u16 type;
	u16 len;
	u32 seq;
	union {
		struct oveydr_lease_device_resp lease_device;
	};
};

struct oveyd_request {
	struct list_head head;
	struct completion *completion;
	struct oveyd_req_pkt req;
	struct oveyd_resp_pkt resp;
};

int oveyd_lease_device(struct ovey_device *ovey_dev);

int ovey_eventdev_init(void);
void ovey_eventdev_exit(void);

#endif /* OVEYD_H */
