
/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019 Mellanox Technologies. All rights reserved */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mlx5

#if !defined(_MLX5_TRACEPOINT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _MLX5_TRACEPOINT_H

#include <linux/tracepoint.h>

TRACE_EVENT(mlx5_poll_cq_start,
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

TRACE_EVENT(mlx5_poll_cq_end,
	TP_PROTO(int soft_polled, int npolled),

	TP_ARGS(soft_polled, npolled),

	TP_STRUCT__entry(
		__field(int, soft_polled)
		__field(int, npolled)
	),

	TP_fast_assign(
		__entry->soft_polled = soft_polled;
		__entry->npolled = npolled;
	),

	TP_printk("soft_polled %d, npolled %d",
		__entry->soft_polled, __entry->npolled)
);

#endif /* _MLX5_TRACEPOINT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
