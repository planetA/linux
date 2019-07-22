// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/hardirq.h>

#include "rxe.h"
#include "rxe_task.h"

#define RXE_BURST_SIZE 100
/*
 * common function called by any of the main workqueues
 * If there is any chance that there is additional
 * work to do someone must reschedule the task before
 * leaving
 */
static int rxe_do_task_burst(struct rxe_task *task)
{
	struct rxe_qp *qp = (struct rxe_qp *)task->arg;
	int ret;
	int count = 0;

	while (1) {
		if (task->destroyed) {
			pr_debug("Running a destroyed task %p\n", task);
		}

		if (!qp->valid) {
			pr_debug("Running a task %p with an invalid qp#%d\n", task, qp_num(qp));
		}

		ret = task->func(task->arg);
		if (ret) {
			return ret;
		}

		count ++;
		if (count > RXE_BURST_SIZE) {
			return 0;
		}
	}
}

static void rxe_do_task(struct work_struct *work)
{
	struct rxe_task *task = container_of(work, typeof(*task), work);
	int ret = rxe_do_task_burst(task);
	if (!ret) {
		queue_work(task->wq, work);
	}
}

static void rxe_do_task_notify(struct work_struct *work)
{
	int ret;
	struct rxe_task *task = container_of(work, typeof(*task), wait_work);

	ret = rxe_do_task_burst(task);
	if (!ret) {
		/* The queue was rescheduled and will run again */
		queue_work(task->wq, work);
		return;
	}

	complete_all(&task->completion);
}

int rxe_init_task(void *obj, struct rxe_task *task,
		  struct rxe_qp *qp, int (*func)(void *), char *name)
{
	task->obj	= obj;
	task->arg	= qp;
	task->func	= func;
	snprintf(task->name, sizeof(task->name), "%s", name);
	task->destroyed	= false;

	rxe_add_ref(&qp->pelem);
	init_completion(&task->completion);

	INIT_WORK(&task->work, rxe_do_task);
	INIT_WORK(&task->wait_work, rxe_do_task_notify);

	task->wq = alloc_ordered_workqueue("qp#%d:%s", 0, qp_num(qp), name);
	if (!task->wq) {
		return -ENOMEM;
	}

	return 0;
}

void rxe_cleanup_task(struct rxe_task *task)
{
	struct rxe_qp *qp = (struct rxe_qp *)task->arg;

	/*
	 * Mark the task, then wait for it to finish.
	 */

	rxe_run_task(task);

	task->destroyed = true;

	destroy_workqueue(task->wq);

	rxe_drop_ref(&qp->pelem);
}

void rxe_run_task(struct rxe_task *task)
{
	if (task->destroyed)
		return;

	queue_work(task->wq, &task->work);
}

void rxe_run_task_wait(struct rxe_task *task)
{
	int ret;

	if (task->destroyed)
		return;

	reinit_completion(&task->completion);

	queue_work(task->wq, &task->wait_work);

	do {
		ret = wait_for_completion_interruptible_timeout(&task->completion, HZ / 10);
	} while (ret == -ERESTARTSYS);
}
