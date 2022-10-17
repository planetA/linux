/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019 Mellanox Technologies. All rights reserved */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ib_uverbs

#if !defined(_IB_UVERBS_TRACEPOINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _IB_UVERBS_TRACEPOINT_H

#include <linux/tracepoint.h>

TRACE_EVENT(ib_uverbs_poll_cq_start,
	TP_PROTO(int num_entries),

	TP_ARGS(num_entries),

	TP_STRUCT__entry(
		__field(int, num_entries)
	),

	TP_fast_assign(
		__entry->num_entries = num_entries;
	),

	TP_printk("num_entries %d", __entry->num_entries)
);

TRACE_EVENT(ib_uverbs_poll_cq_end,
	TP_PROTO(int npolled),

	TP_ARGS(npolled),

	TP_STRUCT__entry(
		__field(int, npolled)
	),

	TP_fast_assign(
		__entry->npolled = npolled;
	),

	TP_printk("npolled %d",
		 __entry->npolled)
);

TRACE_EVENT(ib_uverbs_write_start,
	TP_PROTO(int dummy),

	TP_ARGS(dummy),

	TP_STRUCT__entry(
		__field(int, dummy)
	),

	TP_fast_assign(
		__entry->dummy = dummy;
	),

	TP_printk("dummy %d", __entry->dummy)
);

TRACE_EVENT(ib_uverbs_write_end,
	TP_PROTO(int rc),

	TP_ARGS(rc),

	TP_STRUCT__entry(
		__field(int, rc)
	),

	TP_fast_assign(
		__entry->rc = rc;
	),

	TP_printk("rc %d",
		 __entry->rc)
);

TRACE_EVENT(ib_uverbs_ioctl_start,
	TP_PROTO(int cmd),

	TP_ARGS(cmd),

	TP_STRUCT__entry(
		__field(int, cmd)
	),

	TP_fast_assign(
		__entry->cmd = cmd;
	),

	TP_printk("cmd %d", __entry->cmd)
);

TRACE_EVENT(ib_uverbs_ioctl_end,
	TP_PROTO(int err),

	TP_ARGS(err),

	TP_STRUCT__entry(
		__field(int, err)
	),

	TP_fast_assign(
		__entry->err = err;
	),

	TP_printk("err %d",
		 __entry->err)
);

#endif /* _IB_UVERBS_TRACEPOINT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

