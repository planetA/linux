// OCP - Ovey Control Protocol
// Defines the functionality of OCP. All OCP functions work on top of
// generic netlink.

#include <linux/module.h>

#include "ovey.h"
#include "ocp.h"
#include "ocp-properties.h"
#include "ocp-util.h"
#include "completions.h"

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

/**
 * Connects each OveyOperation (ocp-properties.h) with a specific callback method.
 */
static const struct genl_ops ovey_gnl_ops[] = {
	{ .cmd = OVEY_C_ECHO,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_echo,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_NEW_DEVICE,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_new_device,
	  .dumpit = NULL },
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
	{ .cmd = OVEY_C_DEBUG_INITIATE_REQUEST,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_debug_initiate_request,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_RESOLVE_COMPLETION,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_resolve_completion,
	  .dumpit = NULL },
	{ .cmd = OVEY_C_DEBUG_RESOLVE_ALL_COMPLETIONS,
	  .validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
	  .flags = 0,
	  .doit = ocp_cb_debug_resolve_all_completions,
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
struct genl_family ovey_gnl_family = {
	.hdrsize = 0,
	.name = OVEY_NL_FAMILY_NAME,
	.version = 1,
	// maximum number of attributes (without the unspecified attribute (0))
	.maxattr = OVEY_A_MAX,
	.policy = ovey_genl_policy,
	.module = THIS_MODULE,
	.ops = ovey_gnl_ops,
	// allow parallel ops (no lock) is really important, especially during debugging
	// otherwise if we create a completion via OCP we can't complete it from another
	// OCP call, because the netlink lock is locked.. (:
	.parallel_ops = 1,
	.n_ops = ARRAY_SIZE(ovey_gnl_ops),
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
	int res;
	if (ocp_daemon_sockets_are_known()) {
		// Tell daemon that we are gone
		struct sk_buff *ocp_msg = ocp_nlmsg_new();
		/*struct nlmsghdr * hdr = */ ocp_kernel_request_put(
			ocp_msg, OVEY_C_KERNEL_MODULE_BYE);
		// finalize not needed, because we don't have properties added
		if (ocp_send_kernel_request(ocp_msg)) {
			opr_err("Couldn't send OVEY_C_KERNEL_MODULE_BYE to daemon.\n");
		} else {
			opr_info("Sent OVEY_C_KERNEL_MODULE_BYE to daemon.\n");
		}
	}

	res = genl_unregister_family(&ovey_gnl_family);
	if (res < 0) {
		opr_err("Failed to unregister netlink family: %d\n", res);
	}
	return res;
}

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_ECHO was received.
 */
int ocp_cb_echo(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	char *recv_msg;
	void *msg_head;
	int ret;

	opr_info("OCP-request: OVEY_C_ECHO\n");
	// the nlhdr->nlmsg_pid (port-id) allows us to use identify multiple sockets
	// from the same process id
	opr_info("snd_portid is: %d\n", info->snd_portid);
	opr_info("info->nlhdr->nlmsg_pid: %d\n", info->nlhdr->nlmsg_pid);

	reply_skb = ocp_nlmsg_new();
	if (reply_skb == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* For each attribute there is an index in info->attrs which points to a nlattr structure
	 * in this structure the data is given
	 */

	recv_msg = ocp_get_string_attribute(info, OVEY_A_MSG);
	if (!recv_msg) {
		opr_err("no OVEY_A_MSG!\n");
		ret = -EINVAL;
		goto err;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(reply_skb, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* add a OVEY_A_MSG attribute to return the message */
	ret = nla_put_string(reply_skb, OVEY_A_MSG, recv_msg);
	if (ret < 0) {
		opr_err("nla_put_string() failed because of %d\n", ret);
		goto err_free;
	}
	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	// same as genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(reply_skb, info);

err_free:
	nlmsg_free(reply_skb);

err:
	ocp_reply_with_error(info, ret);
	return ret;
}

int ocp_cb_new_device(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	void *msg_head;
	int ret = 0;
	struct ib_device *parent;
	struct ovey_device_info ovey_device_info;

	opr_info("OCP-request: OVEY_C_NEW_DEVICE\n");

	// we only get a reference; we don't own the data
	ovey_device_info.device_name =
		ocp_get_string_attribute(info, OVEY_A_VIRT_DEVICE);
	if (!ovey_device_info.device_name) {
		opr_err("received no valid value for OVEY_A_VIRT_DEVICE!\n");
		goto err;
	}
	// we only get a reference; we don't own the data
	ovey_device_info.parent_device_name =
		ocp_get_string_attribute(info, OVEY_A_PARENT_DEVICE);
	if (!ovey_device_info.parent_device_name) {
		opr_err("received no valid value for OVEY_A_PARENT_DEVICE!\n");
		goto err;
	}
	ovey_device_info.virt_network_id =
		ocp_get_string_attribute(info, OVEY_A_VIRT_NET_UUID_STR);
	if (!ovey_device_info.virt_network_id) {
		opr_err("received no valid value for OVEY_A_VIRT_NET_UUID_STR!\n");
		goto err;
	}
	ovey_device_info.node_guid =
		ocp_get_u64_attribute(info, OVEY_A_NODE_GUID);
	if (!ovey_device_info.node_guid) {
		opr_err("received no valid value for OVEY_A_NODE_GUID!\n");
		goto err;
	}

	parent = ib_device_get_by_name(ovey_device_info.parent_device_name,
				       RDMA_DRIVER_UNKNOWN);
	if (!parent) {
		opr_err("parent device '%s'not found by ib_device_get_by_name()\n",
			ovey_device_info.parent_device_name);
		ret = -EINVAL;
		goto err;
	}

	opr_info("Request to create a new Ovey device:\n");
	opr_info("    device_name        = %s\n", ovey_device_info.device_name);
	opr_info("    parent_device_name = %s\n",
		 ovey_device_info.parent_device_name);
	opr_info("    node_guid (be)     = %016llx\n",
		 ovey_device_info.node_guid);
	opr_info("    virt_network_id)   = %s\n",
		 ovey_device_info.virt_network_id);

	if (!ovey_verify_new_device_name(ovey_device_info.device_name)) {
		opr_err("name of new device (%s) doesn't match pattern!\n",
			ovey_device_info.device_name);
		ret = -EINVAL;
		goto err;
	}

	ret = ovey_new_device_if_not_exists(&ovey_device_info, parent);
	if (ret) {
		opr_err("ovey_new_device_if_not_exists() failed because of %d!\n",
			ret);
		goto err_put;
	}

	opr_info("new Ovey device '%s' successfully created\n",
		 ovey_device_info.device_name);

	reply_skb = ocp_nlmsg_new();
	if (reply_skb == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM!\n");
		ret = -ENOMEM;
		goto err_put;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(reply_skb, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM!\n");
		ret = -ENOMEM;
		goto err_put;
	}

	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	opr_info("OCP: replying with success to caller\n");

	// same as genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(reply_skb, info);

err_put:
	ib_device_put(parent);
	goto err;

err:
	ocp_reply_with_error(info, ret);
	return ret;
};

int ocp_cb_delete_device(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
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

	reply_skb = ocp_nlmsg_new();
	if (reply_skb == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(reply_skb, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	// same as genlmsg_unicast(genl_info_net(info), skb, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(reply_skb, info);

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
	struct sk_buff *reply_skb;
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

	reply_skb = ocp_nlmsg_new();
	if (reply_skb == NULL) {
		opr_err("ocp_nlmsg_new() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err;
	}

	/* create the message headers */
	msg_head = ocp_genlmsg_put_reply(reply_skb, info);
	if (msg_head == NULL) {
		opr_err("ocp_genlmsg_put_reply() failed because of ENOMEM\n");
		ret = -ENOMEM;
		goto err_free;
	}

	ret = nla_put_string(reply_skb, OVEY_A_VIRT_DEVICE,
			     device_info.device_name);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_VIRT_DEVICE failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_string(reply_skb, OVEY_A_PARENT_DEVICE,
			     device_info.parent_device_name);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_PARENT_DEVICE failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_be64(reply_skb, OVEY_A_NODE_GUID, device_info.node_guid,
			   0);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_NODE_GUID failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_be64(reply_skb, OVEY_A_PARENT_NODE_GUID,
			   device_info.parent_node_guid, 0);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_PARENT_NODE_GUID failed because of %d\n",
			ret);
		goto err_free;
	}
	ret = nla_put_string(reply_skb, OVEY_A_VIRT_NET_UUID_STR,
			     device_info.virt_network_id);
	if (ret < 0) {
		opr_err("nla_put_string() for OVEY_A_VIRT_NET_UUID_STR failed because of %d\n",
			ret);
		goto err_free;
	}
	/* finalize the message */
	genlmsg_end(reply_skb, msg_head);

	// same as genlmsg_unicast(genl_info_net(info), reply_skb, info->snd_portid)
	// see https://elixir.bootlin.com/linux/v5.8.9/source/include/net/genetlink.h#L326
	return genlmsg_reply(reply_skb, info);

err_free:
	nlmsg_free(reply_skb);

err:
	ocp_reply_with_error(info, EINVAL);
	return ret;
}

int ocp_cb_daemon_hello(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	u32 sending_socket_port_id;
	enum OcpSocketKind received_socket_kind_attribute, netlink_hdr_port_id;

	// Not necessarily the PID of the sending process. The first socket from the process
	// gets the process id assigned (due to my testing) and all further processes
	// get another/random id assigned.
	sending_socket_port_id = info->snd_portid;
	netlink_hdr_port_id = info->nlhdr->nlmsg_pid;

	// This is technically not necessary, but to be more failsafe and check that I do everything right
	// in userland and kernel (knowing what socket a packet came from), I want to ensure that the
	// information is transferred via attribute as well as .nl_pid (of netlink header)

	received_socket_kind_attribute =
		ocp_get_u32_attribute(info, OVEY_A_SOCKET_KIND);

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

	reply_skb = ocp_nlmsg_new();
	ocp_genlmsg_put_reply(reply_skb, info);
	return genlmsg_reply(reply_skb, info);
};

int ocp_cb_daemon_bye(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb;
	u32 sending_socket_port_id;
	enum OcpSocketKind received_socket_kind_attribute, netlink_hdr_port_id;

	// Not necessarily the PID of the sending process. The first socket from the process
	// gets the process id assigned (due to my testing) and all further processes
	// get another/random id assigned.
	sending_socket_port_id = info->snd_portid;
	netlink_hdr_port_id = info->nlhdr->nlmsg_pid;

	// This is technically not necessary, but to be more failsafe and check that I do everything right
	// in userland and kernel (knowing what socket a packet came from), I want to ensure that the
	// information is transferred via attribute as well as .nl_pid (of netlink header)

	received_socket_kind_attribute =
		ocp_get_u32_attribute(info, OVEY_A_SOCKET_KIND);

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

	reply_skb = ocp_nlmsg_new();
	ocp_genlmsg_put_reply(reply_skb, info);
	return genlmsg_reply(reply_skb, info);
};

int ocp_cb_debug_initiate_request(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply_skb_d_to_k_sock;
	struct sk_buff *reply_skb_k_to_d_sock;
	opr_info("OCP-request: OVEY_C_DEBUG_INITIATE_REQUEST\n");
	reply_skb_d_to_k_sock = ocp_nlmsg_new();
	reply_skb_k_to_d_sock = ocp_nlmsg_new();

	// TODO don't be too pity in the userland because
	//  in this case so far nl_pid will show the wrong value
	//  on the other socket
	ocp_genlmsg_put_reply(reply_skb_d_to_k_sock, info);
	ocp_genlmsg_put_reply(reply_skb_k_to_d_sock, info);
	genlmsg_reply(reply_skb_d_to_k_sock, info);

	// address right socket
	info->snd_portid = ocp_sockets.kernel_daemon_to_sock_pid;
	genlmsg_reply(reply_skb_k_to_d_sock, info);
	return 0;
};

int ocp_cb_resolve_completion(struct sk_buff *skb, struct genl_info *info)
{
	u64 completion_id;
	opr_info("OCP-request: OVEY_C_RESOLVE_COMPLETION\n");

	completion_id = ocp_get_u64_attribute(info, OVEY_A_COMPLETION_ID);
	opr_info("Completion ID is %lld\n", completion_id);
	ovey_completion_resolve_by_id(completion_id);
	return 0;
};

int ocp_cb_debug_resolve_all_completions(struct sk_buff *skb,
					 struct genl_info *info)
{
	struct sk_buff *reply_skb;
	struct ovey_completion_chain *curr, *n;

	opr_info("OCP-request: OVEY_C_DEBUG_RESOLVE_ALL_COMPLETIONS\n");

	list_for_each_entry_safe (curr, n, &ovey_completion_list.list_item,
				  list_item) {
		if (!curr->completion_resolved) {
			opr_info(
				"Entry with completion_id=%lld not resolved yet: resolving now\n",
				curr->req_id);
			ovey_completion_resolve_by_id(curr->req_id);
		} else {
opr_info(
				"Entry with completion_id=%lld already resolved\n",
				curr->req_id);
		}
	}

	reply_skb = ocp_nlmsg_new();

	ocp_genlmsg_put_reply(reply_skb, info);

	genlmsg_reply(reply_skb, info);
	return 0;
}

int ocp_daemon_sockets_are_known(void)
{
	return ocp_sockets.genl_sock != NULL &&
	       ocp_sockets.kernel_daemon_to_sock_pid != -1 &&
	       ocp_sockets.daemon_to_kernel_sock_pid != -1;
};
