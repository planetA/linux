/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Trace point definitions for RDMA uverbs functions.
 *
 * Author: Maksym Planeta <mplaneta@os.inf.tu-dresden.de>
 *
 * Copyright (c) 2023, TU Dresden and/or its affiliates. All rights reserved.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rdma_uverbs

#if !defined(_TRACE_RDMA_UVERBS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RDMA_UVERBS_H

#include <linux/tracepoint.h>
#include <rdma/ib_verbs.h>

/**
 ** Queue pair events
 **/

/*
 * enum ib_qp_type, from include/rdma/ib_verbs.h
 */
#define IB_QP_TYPE_LIST			\
	ib_qp_type_item(SMI)		\
	ib_qp_type_item(GSI)		\
	ib_qp_type_item(RC)		\
	ib_qp_type_item(UD)		\
	ib_qp_type_item(RAW_PACKET)	\
	ib_qp_type_item(XRC_INI)	\
	ib_qp_type_end(XRC_TGT)

#undef ib_qp_type_item
#undef ib_qp_type_end

#define ib_qp_type_item(x)	TRACE_DEFINE_ENUM(IB_QPT_##x);
#define ib_qp_type_end(x)	TRACE_DEFINE_ENUM(IB_QPT_##x);

IB_QP_TYPE_LIST

#undef ib_qp_type_item
#undef ib_qp_type_end

#define ib_qp_type_item(x)	{ IB_QP_TYPE_##x, #x },
#define ib_qp_type_end(x)	{ IB_QP_TYPE_##x, #x }

#define rdma_show_ib_qp_type(x) \
		__print_symbolic(x, IB_QP_TYPE_LIST)


/*
 * enum ib_qp_type, from include/rdma/ib_verbs.h
 */
#define IB_WR_OPCODE_LIST			\
	ib_wr_opcode_item(RDMA_WRITE)		\
	ib_wr_opcode_item(RDMA_WRITE_WITH_IMM)	\
	ib_wr_opcode_item(SEND)			\
	ib_wr_opcode_item(SEND_WITH_IMM)	\
	ib_wr_opcode_item(RDMA_READ)		\
	ib_wr_opcode_end(ATOMIC_WRITE)

#undef ib_wr_opcode_item
#undef ib_wr_opcode_end

#define ib_wr_opcode_item(x)	TRACE_DEFINE_ENUM(IB_WR_##x);
#define ib_wr_opcode_end(x)	TRACE_DEFINE_ENUM(IB_WR_##x);

IB_WR_OPCODE_LIST

#undef ib_wr_opcode_item
#undef ib_wr_opcode_end

#define ib_wr_opcode_item(x)	{ IB_WR_##x, #x },
#define ib_wr_opcode_end(x)	{ IB_WR_##x, #x }

#define rdma_show_ib_wr_opcode(x) \
		__print_symbolic(x, IB_WR_OPCODE_LIST)

TRACE_EVENT(qp_post_send_wr,
	TP_PROTO(
		const struct ib_qp *qp,
		const struct ib_send_wr *wr,
                size_t size,
                int wr_count
	),

	TP_ARGS(qp, wr, size, wr_count),

	TP_STRUCT__entry(
		__field(u32, qpn)
		__field(u64, wr_id)
		__field(u32, num_sge)
		__field(int, opcode)
                __field(u64, size)
                __field(int, wr_count)
	),

	TP_fast_assign(
		__entry->qpn = qp->real_qp->qp_num;
		__entry->wr_id = wr->wr_id;
		__entry->num_sge = wr->num_sge;
		__entry->opcode = wr->opcode;
                __entry->size = size;
                __entry->wr_count = wr_count;
	),

	TP_printk("qpn=%u wr_id=%llu num_sge=%u opcode=%s size=%llu wr_count=%d",
		__entry->qpn, __entry->wr_id, __entry->num_sge,
		rdma_show_ib_wr_opcode(__entry->opcode),
                __entry->size, __entry->wr_count)
);

#endif /* _TRACE_RDMA_UVERBS_H */

#include <trace/define_trace.h>
