// Needs at least Linux 5.4 to compile (because of iverbs api)

#include <net/addrconf.h>

#include "ovey.h"
#include "ovey_verbs.h"
#include "ocp.h"
#include "completions.h"

MODULE_AUTHOR("Maksym Planeta");
MODULE_AUTHOR("Philipp Schuster");
MODULE_DESCRIPTION("Overlay RDMA-network");
MODULE_LICENSE("GPL");

#define RDMA_DRIVER_OVEY_ID 1337

#define OVEY_DEVICE_NAME_PREFIX "ovey"

static const struct ib_device_ops ovey_device_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = OVEY_ABI_VERSION,
	.driver_id = RDMA_DRIVER_OVEY_ID,

    .alloc_ucontext = ovey_alloc_ucontext,
    .alloc_mr = ovey_alloc_mr,
    .alloc_pd = ovey_alloc_pd,
    .create_cq = ovey_create_cq,
    .create_qp = ovey_create_qp,
    .dealloc_ucontext = ovey_dealloc_ucontext,
    .dealloc_driver = ovey_dealloc_driver,
    .dealloc_pd = ovey_dealloc_pd,
    .destroy_cq = ovey_destroy_cq,
    .destroy_qp = ovey_destroy_qp,
    .dereg_mr = ovey_dereg_mr,
    .get_dma_mr = ovey_get_dma_mr,
    .get_link_layer = ovey_get_link_layer,
    .get_port_immutable = ovey_get_port_immutable,
    .mmap = ovey_mmap,
    .mmap_free = ovey_mmap_free,
    .map_mr_sg = ovey_map_mr_sg,
    .modify_qp = ovey_modify_qp,
    .reg_user_mr = ovey_reg_user_mr,
    .req_notify_cq = ovey_req_notify_cq,
    .poll_cq = ovey_poll_cq,
    .post_recv = ovey_post_recv,
    .post_send = ovey_post_send,
    .query_device = ovey_query_device,
    .query_port = ovey_query_port,
    .query_gid = ovey_query_gid,
    .query_pkey = ovey_query_pkey,
    .query_qp = ovey_query_qp,

    // Mapping to application specific structs
    // this way the kernel can alloc a proper amount of memory
    // TODO: also for _ah and _srq?
	INIT_RDMA_OBJ_SIZE(ib_cq, ovey_cq, base),
	INIT_RDMA_OBJ_SIZE(ib_pd, ovey_pd, base),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, ovey_ucontext, base),
};

/**
 * Allocates a new ib device and initializes it.
 * This initializes the ib_core-related (basic) stuff as well as Ovey specific attributes.
 */
static struct ovey_device *ovey_alloc_and_setup_new_device(struct ovey_device_info const * const ovey_device_info, struct ib_device * const parent)
{
	struct ovey_device *ovey_dev = NULL;

	ovey_dev = ib_alloc_device(ovey_device, base);
	if (!ovey_dev)
		return NULL;

	// init device_info/ovey related stuff

	strcpy(ovey_dev->virt_network_id, ovey_device_info->virt_network_id);
	ovey_dev->base.node_guid = ovey_device_info->node_guid;

	// ----------------------------------------------------------------------------------
	// init other/verbs related stuff

    ovey_dev->parent = parent;
	// support all verbs that parent device supports
    ovey_dev->base.uverbs_cmd_mask = parent->uverbs_cmd_mask;
    // support all verbs that parent device supports
    ovey_dev->base.uverbs_ex_cmd_mask = parent->uverbs_ex_cmd_mask;

	// defines the transport type to the Userland (like in ibv_devinfo)
	// see https://elixir.bootlin.com/linux/latest/source/drivers/infiniband/core/verbs.c#L226
	// (function rdma_node_get_transport())
	ovey_dev->base.node_type = parent->node_type;

	memcpy(ovey_dev->base.node_desc, OVEY_NODE_DESC_COMMON,
		   sizeof(OVEY_NODE_DESC_COMMON));

	/*
	 * current model: one-to-one device association:
	 */
	ovey_dev->base.phys_port_cnt = parent->phys_port_cnt;
	ovey_dev->base.dev.parent = parent->dev.parent;
	ovey_dev->base.dev.dma_ops = parent->dev.dma_ops;
	ovey_dev->base.dev.dma_parms = parent->dev.dma_parms;
	ovey_dev->base.num_comp_vectors = parent->num_comp_vectors;

	xa_init_flags(&ovey_dev->qp_xa, XA_FLAGS_ALLOC1);

	// first we set all ops
	ib_set_device_ops(&ovey_dev->base, &ovey_device_ops);

	// no we make some changes
    ovey_dev->base.ops.uverbs_abi_ver = parent->ops.uverbs_abi_ver;

    // then we set ops (verbs) null that are not supported by parent driver
    // this is the right way; returning -EOPNOTSUPP inside the verbs doesn't work nicely
#define UNSET_OVEY_OP_IF_NOT_AVAILABLE(name)					\
do {							\
    if (!parent->ops.name)				\
        ovey_dev->base.ops.name = NULL;		\
} while (0)

    // KEEP THIS IN SYNC WITH ALL SUPPORTED VERBS
    // deactivate all verbs that are not available on parent
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(alloc_ucontext);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(alloc_mr);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(alloc_pd);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(create_cq);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(create_qp);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(dealloc_ucontext);
    // independent from parent
    // UNSET_OVEY_OP_IF_NOT_AVAILABLE(dealloc_driver);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(dealloc_pd);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(destroy_cq);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(destroy_qp);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(dereg_mr);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(get_dma_mr);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(get_link_layer);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(get_port_immutable);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(mmap);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(mmap_free);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(map_mr_sg);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(modify_qp);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(reg_user_mr);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(req_notify_cq);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(poll_cq);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(post_recv);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(post_send);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_device);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_port);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_gid);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_pkey);
    UNSET_OVEY_OP_IF_NOT_AVAILABLE(query_qp);

	return ovey_dev;

  error:
	ib_dealloc_device(&ovey_dev->base);

	return NULL;
}

/**
 *
 * @param ovey_dev
 * @param name
 * @return 0 on succes or negative error
 */
static int ovey_device_register(struct ovey_device *ovey_dev, const char *name)
{
	static int dev_id = 1;
	int ret;

	ret = ib_register_device(&ovey_dev->base, name);
	if (ret) {
		opr_err("ovey: device registration error %d\n", ret);
	}

	ovey_dbg(&ovey_dev->base, "Registered\n");

	return ret;
}

int ovey_new_device_if_not_exists(struct ovey_device_info const * const ovey_device_info, struct ib_device * const parent)
{
	struct ib_device *ovey_ib_dev;
	struct ovey_device *ovey_dev = NULL;
	int ret = -ENOMEM;

	opr_info("invoked\n");

	ovey_ib_dev = ib_device_get_by_name(ovey_device_info->device_name, RDMA_DRIVER_OVEY_ID);
	if (ovey_ib_dev) {
		ib_device_put(ovey_ib_dev);
		return -EEXIST;
	}

	ovey_dev = ovey_alloc_and_setup_new_device(ovey_device_info, parent);
	if (ovey_dev) {
		ovey_dbg(parent, "ovey: new device\n");

		ret = ovey_device_register(ovey_dev, ovey_device_info->device_name);
		if (ret) {
            opr_err("ovey_device_register() failed: %d\n", ret);
		    ib_dealloc_device(&ovey_dev->base);
		}
	}

	return ret;
}

int ovey_delete_device(char *device_name)
{
	struct ib_device *ovey_ib_dev;

	ovey_ib_dev = ib_device_get_by_name(device_name, RDMA_DRIVER_OVEY_ID);
	if (!ovey_ib_dev) {
		return -ENOENT;
	}

	ib_unregister_device_and_put(ovey_ib_dev);

	return 0;
}

/* Checks whether the new device name matches "ovey[0-9]+". */
int ovey_verify_new_device_name(char const * name) {
	int i;
    char c;
	size_t len;
    size_t expected_min_len;

	len = strlen(name);
	expected_min_len = strlen(OVEY_DEVICE_NAME_PREFIX) + 1;

	if (len < expected_min_len) {
		return 0;
	}

	// checks if only numbers are in the name.
	for (i = expected_min_len; i < len; i++) {
		c = name[i];
		if (c < '0' || c > '9') {
			return 0;
		}
	}

	return 1;
};

struct ovey_device_info * get_device_info_by_name(char const * const ovey_dev_name, struct ovey_device_info * dest) {
    struct ib_device * ovey_ib_dev;
    struct ovey_device * ovey_dev;

    ovey_ib_dev = ib_device_get_by_name(ovey_dev_name, RDMA_DRIVER_UNKNOWN);
    if (!ovey_ib_dev) {
        opr_err("ib_device_get_by_name() can't find device %s\n", ovey_dev_name);
        return NULL;
    }
    ovey_dev = to_ovey_dev(ovey_ib_dev);

    dest->device_name = ovey_dev_name;
    dest->parent_device_name = ovey_dev->parent->name;
    dest->node_guid = ovey_dev->base.node_guid;
    dest->parent_node_guid = ovey_dev->parent->node_guid;
    dest->virt_network_id = ovey_dev->virt_network_id;

    opr_info("get_device_info_by_name() for device='%s'\n", ovey_dev_name);
    opr_info("    parent_device_name='%s'\n", dest->parent_device_name);
    opr_info("    guid (be)         ='%016llx'\n", dest->node_guid);
    opr_info("    parent guid (be)  ='%016llx'\n", dest->parent_node_guid);
    opr_info("    virt_network_id   ='%s'\n", dest->virt_network_id);


    // release memory again; counterpart of ib_device_get_by_name
    ib_device_put(ovey_ib_dev);

    // return NULL or pointer to dest (=OK)
    return dest;
}

static int __init ovey_module_init(void)
{
	int err;
    opr_info("loaded\n");
	// register ovey netlink family
	err = ocp_init();
	if (err < 0) {
		opr_err("ocp_init() failed\n");
		return err;
	}

    INIT_LIST_HEAD(&ovey_completion_list.list_item);

	// START: Test code to test completion lists
	/*struct ovey_completion_chain * item = ovey_completion_add_entry();
	ovey_completion_resolve_by_id(item->req_id);
    item = ovey_completion_add_entry();
    ovey_completion_resolve_by_id(item->req_id);
    ovey_completion_add_entry();*/
	// END:   Test code to test completion lists

	return 0;
}

static void __exit ovey_module_exit(void)
{
    opr_info("unloaded\n");

    // TODO tell daemon that Kernel module gets unloaded

    ovey_completion_clear();

	// unregisters all "ovey" devices
	ib_unregister_driver(RDMA_DRIVER_OVEY_ID);

	// unregister ovey netlink family
	ocp_fini();
}

late_initcall(ovey_module_init);
module_exit(ovey_module_exit);

MODULE_ALIAS_RDMA_LINK("ovey");
