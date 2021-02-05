#include "ovey.h"

int ovey_qp_add(struct ovey_device *ovey_dev, struct ovey_qp *qp)
{
        int rv = xa_alloc(&ovey_dev->qp_xa, qp_id_p(qp), qp, xa_limit_32b,
                          GFP_KERNEL);

        if (!rv) {
                kref_init(&qp->ref);
                qp->ovey_dev = ovey_dev;
                ovey_dbg_qp(qp, "new QP\n");
        }
        return rv;
}

void ovey_free_qp(struct kref *ref)
{
        struct ovey_qp *found, *qp = container_of(ref, struct ovey_qp, ref);
        struct ovey_device *ovey_dev = qp->ovey_dev;

	pr_err("FREE_QP: %d\n", __LINE__);
        found = xa_erase(&ovey_dev->qp_xa, qp_id(qp));
	pr_err("FREE_QP: %d found %px\n", __LINE__, found);
        WARN_ON(found != qp);

        ovey_dbg_qp(qp, "free QP\n");
        kfree_rcu(qp, rcu);
}
