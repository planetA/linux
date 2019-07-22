/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	   Redistribution and use in source and binary forms, with or
 *	   without modification, are permitted provided that the following
 *	   conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
 *	fcn  => function to call until it returns != 0
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
