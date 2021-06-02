// OCP - Ovey Control Protocol
// Defines the functionality of OCP. All OCP functions work on top of
// generic netlink.

#include <linux/module.h>

#include "ovey.h"
#include "ocp.h"
#include "ocp-properties.h"
#include "ocp-util.h"

/**
 * Connects each OveyAttribute (ocp-properties.h) with a data type netlink
 * supports (https://elixir.bootlin.com/linux/v5.8.9/source/include/net/netlink.h#L165).
 */
static struct nla_policy ovey_genl_policy[OVEY_A_MAX + 1] = {
	[OVEY_A_MSG] = { .type = NLA_NUL_STRING },
	[OVEY_A_VIRT_DEVICE] = { .type = NLA_NUL_STRING },
	[OVEY_A_PARENT_DEVICE] = { .type = NLA_NUL_STRING },
	[OVEY_A_NODE_GUID] = { .type = NLA_U64 },
	[OVEY_A_PARENT_NODE_GUID] = { .type = NLA_NUL_STRING },
	[OVEY_A_VIRT_NET_UUID_STR] = { .type = NLA_NUL_STRING },
	[OVEY_A_SOCKET_KIND] = { .type = NLA_U32 },
	[OVEY_A_COMPLETION_ID] = { .type = NLA_U64 },
};

static struct nla_policy ovey_create_device_policy[] = {
	[OVEY_A_VIRT_DEVICE] = {
		.type = NLA_NUL_STRING,
		.len = IB_DEVICE_NAME_MAX - 1,
	},
	[OVEY_A_PARENT_DEVICE] = {
		.type = NLA_NUL_STRING,
		.len = IB_DEVICE_NAME_MAX - 1,
	},
	[OVEY_A_VIRT_NET_UUID_STR] = {
		.type = NLA_NUL_STRING,
		.len = IB_DEVICE_NAME_MAX - 1,
	},
};

/**
 * Connects each OveyOperation (ocp-properties.h) with a specific callback method.
 */
static const struct genl_ops ovey_gnl_ops[] = {
	{
		.cmd = OVEY_C_NEW_DEVICE,
		.doit = ocp_cb_new_device,
		.flags = GENL_UNS_ADMIN_PERM,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.policy = ovey_create_device_policy,
	},
	{ .cmd = OVEY_C_DELETE_DEVICE,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_delete_device,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_DEBUG_RESPOND_ERROR,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_debug_respond_error,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_DEVICE_INFO,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_device_info,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_DAEMON_HELLO,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_daemon_hello,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_DAEMON_BYE,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_daemon_bye,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_RESOLVE_COMPLETION,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_resolve_completion,
	  .dumpit = NULL },
};

// Init global object daemon_info. Holds information
// about the connection between the Ovey kernel module and
// Ovey daemon via OCP (netlink). Is also responsible
// for completions. This means if an ibverbs syscall is made
//
struct ocp_sockets ocp_sockets = {
	// Default data for the socket port ids.
	.kernel_daemon_to_sock_pid = -1,
	.daemon_to_kernel_sock_pid = -1,
};

/*
 * Family + Protocol definition for OCP on top of generic netlink.
 */
struct genl_family ovey_gnl_family __ro_after_init = {
	.hdrsize = 0,
	.name = OVEY_NL_FAMILY_NAME,
	.version = 1,
	// maximum number of attributes (without the unspecified attribute (0))
	.maxattr = OVEY_A_MAX,
	.policy = ovey_genl_policy,
	.module = THIS_MODULE,
	.ops = ovey_gnl_ops,
	.n_ops = ARRAY_SIZE(ovey_gnl_ops),
	// allow parallel ops (no lock) is really important, especially during debugging
	// otherwise if we create a completion via OCP we can't complete it from another
	// OCP call, because the netlink lock is locked.. (:
	.parallel_ops = 1,
};

int ocp_init(void)
{
	int res = genl_register_family(&ovey_gnl_family);
	if (res < 0) {
		pr_err("Failed to register netlink family: %d\n", res);
	}

	return res;
}

int ocp_fini(void)
{
	struct sk_buff *msg;
	struct nlmsghdr *hdr;
	int res;

	if (!ocp_daemon_sockets_are_known()) {
		goto out;
	}

	/* Tell daemon that we are gone */
	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	hdr = ocpmsg_put(msg, OVEY_C_KERNEL_MODULE_BYE);
	if (!hdr) {
		goto out;
	}

	/* finalize not needed, because we don't have properties added */
	if (ocp_send_kernel_request(msg)) {
		opr_err("Couldn't send OVEY_C_KERNEL_MODULE_BYE to daemon.\n");
		goto out;
	}

	opr_info("Sent OVEY_C_KERNEL_MODULE_BYE to daemon.\n");

out:
	res = genl_unregister_family(&ovey_gnl_family);
	if (res < 0) {
		opr_err("Failed to unregister netlink family: %d\n", res);
	}
	return res;
}

int ocp_cb_new_device(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *msg_head;
	struct ovey_create_device_info create_info;
	char uuid_str[UUID_STRING_LEN];
	int ret = 0;

	return -EINVAL;

	opr_info("OCP-request: OVEY_C_NEW_DEVICE\n");

	if ((!info->attrs[OVEY_A_VIRT_DEVICE]) ||
		(!info->attrs[OVEY_A_PARENT_DEVICE]) ||
		(!info->attrs[OVEY_A_VIRT_NET_UUID_STR])) {
		opr_err("Need to set all attributes for device creation");
		return -EINVAL;
	}

	nla_strlcpy(create_info.name, info->attrs[OVEY_A_VIRT_DEVICE],
		sizeof(create_info.name));
	nla_strlcpy(create_info.parent, info->attrs[OVEY_A_PARENT_DEVICE],
		sizeof(create_info.parent));
	nla_strlcpy(uuid_str, info->attrs[OVEY_A_VIRT_NET_UUID_STR], sizeof(uuid_str));

	ret = uuid_parse(uuid_str, &create_info.network);
	if (ret) {
		return ret;
	}

	opr_info("Request to create a new Ovey device:\n"
		"    device_name        = %s\n"
		"    parent_device_name = %s\n"
		"    virt_network_id)   = %pUb\n",
		create_info.name, create_info.parent, &create_info.network);

	opr_info("new Ovey device '%s' successfully created\n",
		create_info.name);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM!\n");
		ret = -ENOMEM;
		goto err;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(msg, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM!\n");
		ret = -ENOMEM;
		goto err;
	}

	/* finalize the message */
	genlmsg_end(msg, msg_head);

	opr_info("OCP: replying with success to caller\n");

	// same as genlmsg_unicast(genl_info_net(info), msg, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(msg, info);

err:
	ocp_reply_with_error(info, ret);
	return ret;
};

int ocp_cb_delete_device(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *msg_head;
	int ret = 0;
	char *device_name;

	opr_info("OCP-request: OVEY_C_DELETE_DEVICE\n");

	device_name = ocp_get_string_attribute(info, OVEY_A_VIRT_DEVICE);
	if (!device_name) {
		opr_err("received no valid value for OVEY_A_VIRT_DEVICE!\n");
		goto err;
	}

	opr_info("Request to delete a device: %s\n", device_name);

	ret = ovey_delete_device(device_name);
	if (ret < 0) {
		opr_err("ovey_delete_device() failed\n");
		goto err;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(msg, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* finalize the message */
	genlmsg_end(msg, msg_head);

	// same as genlmsg_unicast(genl_info_net(info), skb, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(msg, info);

err:
	ocp_reply_with_error(info, ret);
	return ret;
};

int ocp_cb_debug_respond_error(struct sk_buff *skb, struct genl_info *info)
{
	opr_info("OCP-request: OVEY_C_DEBUG_RESPOND_ERROR\n");
	ocp_reply_with_error(info, -EINVAL);
	// we expect that this never fails; otherwise we have catastrophic failure
	return 0;
};

int ocp_cb_device_info(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	struct ovey_device_info device_info;
	void *msg_head;
	int ret;

	opr_info("OCP-request: OVEY_C_DEVICE_INFO\n");

	/* For each attribute there is an index in info->attrs which points to a nlattr structure
     * in this structure the data is given
     */

	device_info.device_name =
		ocp_get_string_attribute(info, OVEY_A_VIRT_DEVICE);
	if (!device_info.device_name) {
		opr_err("received no valid value for OVEY_A_VIRT_DEVICE!\n");
		goto err;
	}

	if (!get_device_info_by_name(device_info.device_name, &device_info)) {
		opr_err("get_device_info_by_name failed; does the device %s exist?!\n",
			device_info.device_name);
		goto err;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(msg, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err_free;
	}

	ret = nla_put_string(msg, OVEY_A_VIRT_DEVICE,
			     device_info.device_name);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_VIRT_DEVICE failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_string(msg, OVEY_A_PARENT_DEVICE,
			     device_info.parent_device_name);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_PARENT_DEVICE failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_u64_64bit(msg, OVEY_A_NODE_GUID, device_info.node_guid,
			   0);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_NODE_GUID failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_u64_64bit(msg, OVEY_A_PARENT_NODE_GUID,
			   device_info.parent_node_guid, 0);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_PARENT_NODE_GUID failed because of %d\n",
			ret);
		goto err_free;
	}
#if 0
	ret = nla_put_string(msg, OVEY_A_VIRT_NET_UUID_STR,
			     device_info.virt_network_id);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_VIRT_NET_UUID_STR failed because of %d\n",
			ret);
		goto err_free;
	}
#endif
	/* finalize the message */
	genlmsg_end(msg, msg_head);

	// same as genlmsg_unicast(genl_info_net(info), msg, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(msg, info);

err_free:
	nlmsg_free(msg);

err:
	ocp_reply_with_error(info, EINVAL);
	return ret;
}

int ocp_cb_daemon_hello(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	u32 sending_socket_port_id;
	enum OcpSocketKind received_socket_kind_attribute, netlink_hdr_port_id;
	int ret;

	// Not necessarily the PID of the sending process. The first socket from the process
	// gets the process id assigned (due to my testing) and all further processes
	// get another/random id assigned.
	sending_socket_port_id = info->snd_portid;
	netlink_hdr_port_id = info->nlhdr->nlmsg_pid;

	// This is technically not necessary, but to be more failsafe and check that I do everything right
	// in userland and kernel (knowing what socket a packet came from), I want to ensure that the
	// information is transferred via attribute as well as .nl_pid (of netlink header)

	ret =	ocp_get_u32_attribute(info, OVEY_A_SOCKET_KIND, &received_socket_kind_attribute);
	if (ret) {
		return ret;
	}

	opr_info("OCP-request: OVEY_C_DAEMON_HELLO\n");
	opr_info("    sending_socket_port_id (source socket id)    =%d\n",
		 sending_socket_port_id);
	opr_info(
		"    netlink_hdr_port_id (source socket id)=%d (OcpKindSocket::%s)\n",
		netlink_hdr_port_id,
		ocp_socket_kind_to_string(netlink_hdr_port_id));
	opr_info(
		"    received socket kind attribute        =%d (OcpKindSocket::%s)\n",
		received_socket_kind_attribute,
		ocp_socket_kind_to_string(received_socket_kind_attribute));

	if (netlink_hdr_port_id != received_socket_kind_attribute) {
		opr_err("netlink_hdr_port_id doesn't match the received socket kind attribute!");
		ocp_reply_with_error(info, -EINVAL);
		return -1;
	}

	if (netlink_hdr_port_id == KERNEL_INITIATED_REQUESTS_SOCKET) {
		opr_info("kernel_daemon_to_sock_pid was '%d', new is '%d'\n",
			 ocp_sockets.kernel_daemon_to_sock_pid,
			 sending_socket_port_id);
		ocp_sockets.kernel_daemon_to_sock_pid = sending_socket_port_id;
		ocp_sockets.genl_sock = genl_info_net(info)->genl_sock;
	} else if (netlink_hdr_port_id == DAEMON_INITIATED_REQUESTS_SOCKET) {
		opr_info("daemon_to_kernel_sock_pid was '%d', new is '%d'\n",
			 ocp_sockets.daemon_to_kernel_sock_pid,
			 sending_socket_port_id);
		ocp_sockets.daemon_to_kernel_sock_pid = sending_socket_port_id;
	} else {
		opr_err("netlink_hdr_port_id = %s is not a valid value",
			ocp_socket_kind_to_string(netlink_hdr_port_id));
		ocp_reply_with_error(info, -EINVAL);
		return -1;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	ocp_genlmsg_put_reply(msg, info);
	return genlmsg_reply(msg, info);
};

int ocp_cb_daemon_bye(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	u32 sending_socket_port_id;
	enum OcpSocketKind received_socket_kind_attribute, netlink_hdr_port_id;
	int ret;

	// Not necessarily the PID of the sending process. The first socket from the process
	// gets the process id assigned (due to my testing) and all further processes
	// get another/random id assigned.
	sending_socket_port_id = info->snd_portid;
	netlink_hdr_port_id = info->nlhdr->nlmsg_pid;

	// This is technically not necessary, but to be more failsafe and check that I do everything right
	// in userland and kernel (knowing what socket a packet came from), I want to ensure that the
	// information is transferred via attribute as well as .nl_pid (of netlink header)

	ret =	ocp_get_u32_attribute(info, OVEY_A_SOCKET_KIND, &received_socket_kind_attribute);
	if (ret) {
					return ret;
	}

	opr_info("OCP-request: OVEY_C_DAEMON_BYE\n");
	opr_info("    sending_socket_port_id (source socket id)    =%d\n",
		 sending_socket_port_id);
	opr_info(
		"    netlink_hdr_port_id (source socket id)=%d (OcpKindSocket::%s)\n",
		netlink_hdr_port_id,
		ocp_socket_kind_to_string(netlink_hdr_port_id));
	opr_info(
		"    received socket kind attribute        =%d (OcpKindSocket::%s)\n",
		received_socket_kind_attribute,
		ocp_socket_kind_to_string(received_socket_kind_attribute));

	if (netlink_hdr_port_id != received_socket_kind_attribute) {
		opr_err("netlink_hdr_port_id doesn't match the received socket kind attribute!");
		ocp_reply_with_error(info, -EINVAL);
		return -1;
	}

	if (netlink_hdr_port_id == KERNEL_INITIATED_REQUESTS_SOCKET) {
		opr_info("kernel_daemon_to_sock_pid was '%d', new is '-1'\n",
			 ocp_sockets.kernel_daemon_to_sock_pid);
		ocp_sockets.kernel_daemon_to_sock_pid = -1;
		ocp_sockets.genl_sock = NULL;
	} else if (netlink_hdr_port_id == DAEMON_INITIATED_REQUESTS_SOCKET) {
		opr_info("daemon_to_kernel_sock_pid was '%d', new is '-1'\n",
			 ocp_sockets.daemon_to_kernel_sock_pid);
		ocp_sockets.daemon_to_kernel_sock_pid = -1;
	} else {
		opr_err("netlink_hdr_port_id = %s is not a valid value",
			ocp_socket_kind_to_string(netlink_hdr_port_id));
		ocp_reply_with_error(info, -EINVAL);
		return -1;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	ocp_genlmsg_put_reply(msg, info);
	return genlmsg_reply(msg, info);
};

int ocp_cb_resolve_completion(struct sk_buff *skb, struct genl_info *info)
{
	return -ENOTSUPP;
};

int ocp_daemon_sockets_are_known(void)
{
	return ocp_sockets.genl_sock != NULL &&
	       ocp_sockets.kernel_daemon_to_sock_pid != -1 &&
	       ocp_sockets.daemon_to_kernel_sock_pid != -1;
};
