/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_QUEUE_H
#define RXE_QUEUE_H

/* implements a simple circular buffer that can optionally be
 * shared between user space and the kernel and can be resized

 * the requested element size is rounded up to a power of 2
 * and the number of elements in the buffer is also rounded
 * up to a power of 2. Since the queue is empty when the
 * producer and consumer indices match the maximum capacity
 * of the queue is one less than the number of element slots
 */

/* this data structure is shared between user space and kernel
 * space for those cases where the queue is shared. It contains
 * the producer and consumer indices. Is also contains a copy
 * of the queue size parameters for user space to use but the
 * kernel must use the parameters in the rxe_queue struct
 * this MUST MATCH the corresponding librxe struct
 * for performance reasons arrange to have producer and consumer
 * pointers in separate cache lines
 * the kernel should always mask the indices to avoid accessing
 * memory outside of the data area
 */
struct rxe_queue_buf {
	__u32			log2_elem_size;
	__u32			index_mask;
	__u32			pad_1[30];
	__u32			producer_index;
	__u32			pad_2[31];
	__u32			consumer_index;
	__u32			pad_3[31];
	__u8			data[];
};

struct rxe_queue {
	struct rxe_dev		*rxe;
	struct rxe_queue_buf	*buf;
	struct rxe_mmap_info	*ip;
	size_t			buf_size;
	size_t			elem_size;
	unsigned int		log2_elem_size;
	unsigned int		index_mask;
};

int do_mmap_info(struct rxe_dev *rxe, struct mminfo __user *outbuf,
		 struct ib_udata *udata, struct rxe_queue_buf *buf,
		 size_t buf_size, struct rxe_mmap_info **ip_p);

void rxe_queue_reset(struct rxe_queue *q);

struct rxe_queue *rxe_queue_init(struct rxe_dev *rxe,
				 int *num_elem,
				 unsigned int elem_size);

int rxe_queue_resize(struct rxe_queue *q, unsigned int *num_elem_p,
		     unsigned int elem_size, struct ib_udata *udata,
		     struct mminfo __user *outbuf,
		     /* Protect producers while resizing queue */
		     spinlock_t *producer_lock,
		     /* Protect consumers while resizing queue */
		     spinlock_t *consumer_lock);

void rxe_queue_cleanup(struct rxe_queue *queue);

static inline int next_index(struct rxe_queue *q, int index)
{
	return (index + 1) & q->buf->index_mask;
}

static inline int queue_empty(struct rxe_queue *q)
{
	return ((q->buf->producer_index - q->buf->consumer_index)
			& q->index_mask) == 0;
}

static inline int queue_full(struct rxe_queue *q)
{
	return ((q->buf->producer_index + 1 - q->buf->consumer_index)
			& q->index_mask) == 0;
}

static inline void advance_producer(struct rxe_queue *q)
{
	q->buf->producer_index = (q->buf->producer_index + 1)
			& q->index_mask;
}

static inline void advance_consumer(struct rxe_queue *q)
{
	q->buf->consumer_index = (q->buf->consumer_index + 1)
			& q->index_mask;
}

static inline void *producer_addr(struct rxe_queue *q)
{
	return q->buf->data + ((q->buf->producer_index & q->index_mask)
				<< q->log2_elem_size);
}

static inline void *consumer_addr(struct rxe_queue *q)
{
	return q->buf->data + ((q->buf->consumer_index & q->index_mask)
				<< q->log2_elem_size);
}

static inline unsigned int producer_index(struct rxe_queue *q)
{
	return q->buf->producer_index;
}

static inline unsigned int consumer_index(struct rxe_queue *q)
{
	return q->buf->consumer_index;
}

static inline void *addr_from_index(struct rxe_queue *q, unsigned int index)
{
	return q->buf->data + ((index & q->index_mask)
				<< q->buf->log2_elem_size);
}

static inline unsigned int index_from_addr(const struct rxe_queue *q,
					   const void *addr)
{
	return (((u8 *)addr - q->buf->data) >> q->log2_elem_size)
		& q->index_mask;
}

static inline unsigned int queue_count(const struct rxe_queue *q)
{
	return (q->buf->producer_index - q->buf->consumer_index)
		& q->index_mask;
}

static inline void *queue_head(struct rxe_queue *q)
{
	return queue_empty(q) ? NULL : consumer_addr(q);
}


static inline int __PRINT_BUF_INFO(char *cur, int n, struct rxe_queue_buf *buf) {
	if (!buf) {
		return snprintf(cur, n, "null");
	}
	return snprintf(cur, n, "{prod = %d, cons = %d}",
			buf->producer_index, buf->consumer_index);
}

static inline const char *wqe_state_string(enum wqe_state s) {
	switch (s) {
		case wqe_state_posted: return "posted";
		case wqe_state_processing: return "processing";
		case wqe_state_pending: return "pending";
		case wqe_state_done: return "done";
		case wqe_state_error: return "error";
		default: return "UNKNOWN";
	}
}

static inline int PRINT_QUEUE_BUF_INFO(char *cur, int n, struct rxe_queue_buf *buf) {
	int read, total = 0;

	read = snprintf(cur, n, "BUF : ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = __PRINT_BUF_INFO(cur, n, buf);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	return total;
}

static inline int PRINT_SEND_WQE_INFO(char *cur, int n, struct rxe_send_wqe *wqe) {
	int read, total = 0;

	if (wqe == NULL) {
		return snprintf(cur, n, "{SEND_WQE: null}");
	}

	read = snprintf(cur, n, "{SEND_WQE: {addr = %px, state = '%s', first = %d, last = %d, ssn = %d}}",
			wqe, wqe_state_string(wqe->state), wqe->first_psn, wqe->last_psn, wqe->ssn);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;


	return total;
}

static inline int PRINT_TAB(char *cur, int n) {
	return snprintf(cur, n, "\t");
}

static inline int PRINT_NEWLINE(char *cur, int n) {
	return snprintf(cur, n, "\n");
}

static inline int PRINT_COMMA(char *cur, int n) {
	return snprintf(cur, n, ", ");
}

static inline int PRINT_OPEN(char *cur, int n) {
	return snprintf(cur, n, "{");
}

static inline int PRINT_CLOSE(char *cur, int n) {
	return snprintf(cur, n, "}");
}

#define PRINT_APPEND(x, ...) ({ \
		read = PRINT_##x (cur, n, ## __VA_ARGS__); \
		cur += read; n -= read; total += read; \
		if (n <= 0) return total; \
	})

static inline int __PRINT_SQ_QUEUE_INFO(char *cur, int n, struct rxe_queue *q) {
	int read, total = 0;

	if (!q) {
		return snprintf(cur, n, "{SEND_WQE: null}");
	}

	PRINT_APPEND(OPEN);
	PRINT_APPEND(SEND_WQE_INFO, queue_head(q));
	PRINT_APPEND(COMMA);
	PRINT_APPEND(QUEUE_BUF_INFO, q->buf);
	PRINT_APPEND(CLOSE);

	return total;
}

static inline int __PRINT_RQ_QUEUE_INFO(char *cur, int n, struct rxe_queue *q) {
	int read, total = 0;
	struct rxe_recv_wqe *wqe;

	if (!q) {
		return snprintf(cur, n, "null");
	}

	wqe = queue_head(q);
	if (!wqe) {
		return snprintf(cur, n, "null");
	}
	read = snprintf(cur, n, "{wr_id = %llu, num_sge = %d, ",
			wqe->wr_id, wqe->num_sge);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	read = PRINT_QUEUE_BUF_INFO(cur, n, q->buf);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	read = snprintf(cur, n, "}");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	return total;
}

static inline int __PRINT_QP_INFO(char *cur, int n, struct rxe_qp *qp) {
	int read, total = 0;
	if (!qp) {
		return snprintf(cur, n, "null");
	}
	read = snprintf(cur, n, " {QPN: %d,", qp_num(qp));
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	read = snprintf(cur, n, "\n\t\tSQ: ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = __PRINT_SQ_QUEUE_INFO(cur, n, qp->sq.queue);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	read = snprintf(cur, n, ",\n\t\tRQ: ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	read = __PRINT_RQ_QUEUE_INFO(cur, n, qp->rq.queue);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

#if RXE_MIGRATION
	read = snprintf(cur, n, ",\n\t\tresume_posted: %d, resp_psn: %d, resp_opcode: %d,"
			" req_psn: %d, req_opcode: %d, comp_psn: %d, comp_opcode: %d",
		       	qp->req.resume_posted, qp->resp.psn, qp->resp.opcode,
		       	qp->req.psn, qp->req.opcode, qp->comp.psn, qp->comp.opcode);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
#endif

	read = snprintf(cur, n, "}");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	return total;
}

static inline int __PRINT_PKT(char *cur, int n, struct rxe_pkt_info *pkt) {
	if (!pkt) {
		return snprintf(cur, n, "null");
	}

	return snprintf(cur, n, "{ psn: %d, opcode: %d }", pkt->psn, pkt->opcode);
}

static inline int __PRINT_QUEUE_PKT_WQE_CNT(const char *file, int line, const char *func,
		char *cur, int n,
		struct rxe_qp *qp, struct rxe_pkt_info *pkt,
		struct rxe_send_wqe *send_wqe, int *cnt) {
	int read, total = 0;

	read = snprintf(cur, n, "{ ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = snprintf(cur, n, "PRINT_QUEUE_INFO: '%s:%d %s' ", file, line, func);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = snprintf(cur, n, ",\n\tPKT: ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = __PRINT_PKT(cur, n, pkt);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = snprintf(cur, n, ",\n\tQUEUE: ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	read = __PRINT_QP_INFO(cur, n, qp);
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;
	PRINT_APPEND(COMMA);
	PRINT_APPEND(NEWLINE);
	PRINT_APPEND(TAB);
	PRINT_APPEND(SEND_WQE_INFO, send_wqe);
	read = snprintf(cur, n, "} ");
	cur += read; n -= read; total += read;
       	if (n <= 0) return total;

	return total;
}

#if 0
#define PRINT_QUEUE_PKT_WQE_CNT(qp, pkt, wqe, cnt) ({ \
		int *__cnt = cnt; \
		char buf[600]; \
		__PRINT_QUEUE_PKT_WQE_CNT(__FILE__, __LINE__, __func__, \
				buf, sizeof(buf), qp, pkt, wqe, __cnt); \
		if (!__cnt) \
			RXE_DO_PRINT_DEBUG("%s\n", buf); \
		else { \
			if (*__cnt > 0) { \
				RXE_DO_PRINT_DEBUG_ALWAYS("[%d] %s\n", *__cnt, buf); \
			} else { \
				RXE_DO_PRINT_DEBUG("[%d] %s\n", *__cnt, buf); \
			}\
			*__cnt = *__cnt - 1; \
		} \
	})

#define PRINT_QUEUE_PKT_WQE(qp, pkt, wqe) ({				\
			static int cnt = 50;				\
			PRINT_QUEUE_PKT_WQE_CNT(qp, pkt, wqe, &cnt);	\
		})

#define PRINT_QUEUE_PKT(qp, pkt) ({					\
			static int cnt = 50;				\
			PRINT_QUEUE_PKT_WQE_CNT(qp, pkt, NULL, &cnt);	\
		})

#define PRINT_QUEUE(qp) PRINT_QUEUE_PKT(qp, NULL)
#else
#define PRINT_QUEUE_PKT_WQE_CNT(qp, pkt, wqe, cnt)
#define PRINT_QUEUE_PKT_WQE(qp, pkt, wqe)
#define PRINT_QUEUE_PKT(qp, pkt)
#define PRINT_QUEUE(qp)
#endif


#endif /* RXE_QUEUE_H */
