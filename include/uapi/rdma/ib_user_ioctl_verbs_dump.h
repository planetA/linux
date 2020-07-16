#ifndef IB_USER_IOCTL_VERBS_DUMP_H
#define IB_USER_IOCTL_VERBS_DUMP_H

#include <linux/types.h>
#include <rdma/ib_user_verbs.h>

enum ib_uverbs_objects_types {
	IB_UVERBS_OBJECT_DEVICE, /* No instances of DEVICE are allowed */
	IB_UVERBS_OBJECT_PD,
	IB_UVERBS_OBJECT_COMP_CHANNEL,
	IB_UVERBS_OBJECT_CQ,
	IB_UVERBS_OBJECT_QP,
	IB_UVERBS_OBJECT_SRQ,
	IB_UVERBS_OBJECT_AH,
	IB_UVERBS_OBJECT_MR,
	IB_UVERBS_OBJECT_MW,
	IB_UVERBS_OBJECT_FLOW,
	IB_UVERBS_OBJECT_XRCD,
	IB_UVERBS_OBJECT_RWQ_IND_TBL,
	IB_UVERBS_OBJECT_WQ,
	IB_UVERBS_OBJECT_FLOW_ACTION,
	IB_UVERBS_OBJECT_DM,
	IB_UVERBS_OBJECT_COUNTERS,
	IB_UVERBS_OBJECT_ASYNC_EVENT,
	IB_UVERBS_OBJECT_TOTAL,
};

struct ib_uverbs_dump_object {
	u32 type;
	u32 size;
	u32 handle;
} __packed;

struct ib_uverbs_dump_object_pd {
	struct ib_uverbs_dump_object obj;
} __packed;

struct rxe_dump_mr {
	u32 lkey;
	u32 rkey;
	u32 mrn;
};

struct ib_uverbs_dump_object_mr {
	struct ib_uverbs_dump_object obj;

	/* Set by driver specific code  */
	u64 address;
	u64 length;
	u32 access;
	/* Set by generic code */
	u32 pd_handle;
	u32 lkey;
	u32 rkey;

	struct rxe_dump_mr rxe;
} __packed;

struct rxe_dump_queue {
	u64	start;
	u64	size;
	u32	log2_elem_size;
	u32	index_mask;
	u32	producer_index;
	u32	consumer_index;
} __packed;

struct rxe_dump_qp {
	struct rxe_dump_queue	sq;
	struct rxe_dump_queue	rq;
	u32			wqe_index;
	u32			req_opcode;
	u32			comp_psn;
	u32			comp_opcode;
	u32			msn;
	u32			resp_opcode;
	u16			srq_wqe_offset;
	u16			srq_wqe_size;
	u8			data[0];
} __packed;

struct ib_uverbs_dump_object_cq {
	struct ib_uverbs_dump_object obj;

	/* Set by driver specific code */
	u32 comp_vector;

	/* Set by generic code */
	u32 cqe;
	u32 comp_channel;

	struct rxe_dump_queue rxe;
} __packed;

struct ib_qp_dump_attr {
	enum ib_qp_state		qp_state;
	enum ib_mtu			path_mtu;
	enum ib_mig_state		path_mig_state;
	u32				qkey;
	u32				rq_psn;
	u32				sq_psn;
	u32				dest_qp_num;
	u32				qp_access_flags;
	struct ib_qp_cap		cap;
	struct ib_uverbs_ah_attr	ah_attr;
	struct ib_uverbs_ah_attr	alt_ah_attr;
	u16				pkey_index;
	u16				alt_pkey_index;
	u8				en_sqd_async_notify;
	u8				sq_draining;
	u8				max_rd_atomic;
	u8				max_dest_rd_atomic;
	u8				min_rnr_timer;
	u8				port_num;
	u8				timeout;
	u8				retry_cnt;
	u8				rnr_retry;
	u8				alt_port_num;
	u8				alt_timeout;
	u32				rate_limit;
} __packed;

struct ib_uverbs_dump_object_qp {
	struct ib_uverbs_dump_object obj;

	/* Set by generic code */
	u32 pd_handle;
	u32 scq_handle;
	u32 rcq_handle;
	u32 srq_handle;

	u32 qp_type;
	u32 sq_sig_all;
	u32 qp_num;

	struct ib_qp_dump_attr attr;

	struct rxe_dump_qp rxe;
} __packed;

struct ib_uverbs_dump_object_ah {
	struct ib_uverbs_dump_object obj;

	u32 pd_handle;
	struct ib_uverbs_ah_attr attr;
} __packed;

struct ib_uverbs_dump_object_srq {
	struct ib_uverbs_dump_object obj;

	u32	pd_handle;
	u32	cq_handle;
	u32	max_wr;
	u32	max_sge;
	u32	srq_limit;

	enum ib_srq_type	srq_type;
	struct rxe_dump_queue	queue;
} __packed;

struct ib_uverbs_dump_object_comp_channel {
	struct ib_uverbs_dump_object obj;
} __packed;

#endif
