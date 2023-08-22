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

TRACE_EVENT(ib_uverbs_probe_return,
    TP_PROTO(pid_t pid, int probe_return, int count, unsigned long cqp),// pid_t calling_pid),

    TP_ARGS(pid, probe_return, count, cqp), //calling_pid),

	TP_STRUCT__entry(
        __field(pid_t, pid)
        __field(int, probe_return)
		__field(int, count)
		__field(unsigned long, cqp)
        //__field(pid_t, calling_pid)
    ),

    TP_fast_assign(
        __entry->pid = pid;
        __entry->probe_return = probe_return;
		__entry->count = count;
		__entry->cqp = cqp;
        //__entry->calling_pid = calling_pid;
    ),

    TP_printk("probe returned: %i for pid: %i, with count: %i, for cq = %lu", __entry->probe_return, __entry->pid, __entry->count, __entry->cqp)

);

TRACE_EVENT(ib_uverbs_probe_before_yield_to,
    TP_PROTO(pid_t pid_to, pid_t pid_from),

    TP_ARGS(pid_to, pid_from),

    TP_STRUCT__entry(
        __field(pid_t, pid_to)
        __field(pid_t, pid_from)
    ),

    TP_fast_assign(
        __entry->pid_to = pid_to;
        __entry->pid_from = pid_from;
    ),

    TP_printk("before %i yield_to %i", __entry->pid_from, __entry->pid_to)

);

TRACE_EVENT(ib_uverbs_probe_before_cond_resched,
    TP_PROTO(pid_t pid_from),

    TP_ARGS(pid_from),

    TP_STRUCT__entry(
        __field(pid_t, pid_from)
    ),

    TP_fast_assign(
        __entry->pid_from = pid_from;
    ),

    TP_printk("before %i cond_resched", __entry->pid_from)

);

TRACE_EVENT(ib_uverbs_probe_after_yield,
    TP_PROTO(pid_t pid),

    TP_ARGS(pid),

    TP_STRUCT__entry(
        __field(pid_t, pid)
    ),

    TP_fast_assign(
        __entry->pid = pid;
    ),

    TP_printk("after yield %i returned", __entry->pid)

);

#endif /* _IB_UVERBS_TRACEPOINT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

