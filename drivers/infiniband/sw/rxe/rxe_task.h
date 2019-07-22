/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_TASK_H
#define RXE_TASK_H

/*
 * data structure to describe a 'task' which is a short
 * function that returns 0 as long as it needs to be
 * called again.
 */
struct rxe_task {
	void			*obj;
	struct workqueue_struct	*wq;
	void			*arg;
	int			(*func)(void *arg);
	char			name[16];
	bool			destroyed;
	struct work_struct	work;
	struct work_struct	wait_work;
	struct completion	completion;
};

/*
 * init rxe_task structure
 *	arg  => parameter to pass to fcn
 *	func => function to call until it returns != 0
 */
int rxe_init_task(void *obj, struct rxe_task *task,
		  struct rxe_qp *qp, int (*func)(void *), char *name);

/* cleanup task */
void rxe_cleanup_task(struct rxe_task *task);

/*
 * schedule task to run on a workqueue.
 */
void rxe_run_task(struct rxe_task *task);

/*
 * Run a task and wait until it completes. Recursive dependencies should be
 * avoided.
 */
void rxe_run_task_wait(struct rxe_task *task);

#endif /* RXE_TASK_H */
