#include "ovey.h"
#include "ocp-util.h"

void ocp_reply_with_error(struct genl_info *info, int err_code)
{
	struct sk_buff *reply_skb;
	int rc;
	struct nlmsghdr *nlmsghdr;
	struct nlmsgerr *nlmsgerr;
	size_t payload_size;

	// netlink standard expects a negative error code.
	// at this point it can happen that we may receive
	// the positive value. Therefore we negate it.
	if (err_code == 0) {
		opr_err("called send error reply with error_code==0\n");
	}

	if (err_code > 0) {
		err_code = -err_code;
	}

	// that's all the payload that we send
	payload_size = sizeof(struct nlmsgerr);

	opr_info("OCP replying with ERROR(%d) message\n", err_code);

	// just allocates memory
	reply_skb = ocp_nlmsg_new();
	if (reply_skb == NULL) {
		opr_err("ocp_nlmsg_new() failed\n");
		return;
	}

	// We don't send a generic netlink message (netlink header afterwards)
	// we only send a netlink message here!

	// Code similar to https://elixir.bootlin.com/linux/v5.4.86/source/net/netlink/af_netlink.c#L2382

	// puts attributes into netlink header and returns the pointer to the
	// beginning of the netlink header (inside the socket buffer)
	nlmsghdr = nlmsg_put(reply_skb, info->snd_portid, 0, NLMSG_ERROR,
			     payload_size, 0);
	if (nlmsghdr == NULL) {
		opr_err("genlmsg_put() failed because of ENOMEM\n");
		return;
	}

	// returns pointer to head of message payload
	nlmsgerr = nlmsg_data(nlmsghdr);
	// negative status code
	nlmsgerr->error = err_code;
	// netlink header that caused the problem
	// memcpy(&nlmsgerr->msg, info->nlhdr, info->nlhdr->nlmsg_len);
	// for now I only append the pure netlink header of the request and no further data
	// (like gen netlink header or attributes)
	memcpy(&nlmsgerr->msg, info->nlhdr, payload_size);

	// make sure that no userland lib wants to read more data than is available as of now
	// so far we only send the header and not the original attributes
	nlmsgerr->msg.nlmsg_len = sizeof(struct nlmsghdr);

	// update size in netlink header
	nlmsg_end(reply_skb, nlmsghdr);

	// Send the message back to the sender
	rc = nlmsg_unicast(genl_info_net(info)->genl_sock, reply_skb,
			   info->snd_portid);

	if (rc != 0) {
		opr_err("genlmsg_reply() failed because of %d\n", rc);
		return;
	}
}

u64 ocp_get_u64_attribute(struct genl_info *info, enum OveyAttribute attribute)
{
	struct nlattr *na = info->attrs[attribute];
	u64 *value_ptr;
	u64 value;

	if (!na) {
		opr_err("no attribute OveyAttribute::%s in message!\n",
			ovey_a_to_string(attribute));
		return 0; // I assume that we don't use valid "0" values in OCP and we can use 0 as error indicator
	}

	value_ptr = (u64 *)(nla_data(na));
	value = *value_ptr;
	if (value == 0) {
		opr_err("warning: received 0 but we expect 0 to be the error value/indicator of no value. refactor maybe?! OveyAttribute[%d]\n",
			attribute);
	} else {
		opr_info(
			"received u64 value for OveyAttribute::%s is %lld [%#016llx]\n",
			ovey_a_to_string(attribute), value, value);
	}

	return value;
}

u32 ocp_get_u32_attribute(struct genl_info *info, enum OveyAttribute attribute)
{
	struct nlattr *na = info->attrs[attribute];
	u32 *value_ptr;
	u32 value;

	if (!na) {
		opr_err("no attribute OveyAttribute::%s in message!\n",
			ovey_a_to_string(attribute));
		return 0; // I assume that we don't use valid "0" values in OCP and we can use 0 as error indicator
	}

	value_ptr = (u32 *)(nla_data(na));
	value = *value_ptr;

	return value;
}

char *ocp_get_string_attribute(struct genl_info *info,
			       enum OveyAttribute attribute)
{
	struct nlattr *na = info->attrs[attribute];
	char *value = NULL;

	if (!na) {
		opr_err("no attribute OveyAttribute::%s in message!\n",
			ovey_a_to_string(attribute));
		return NULL;
	}

	value = (char *)nla_data(na);
	if (value == NULL) {
		opr_err("received string for OveyAttribute::%s is NULL\n",
			ovey_a_to_string(attribute));
	} else {
		opr_info("received string for OveyAttribute::%s is '%s'\n",
			 ovey_a_to_string(attribute), value);
	}

	return value;
}

int ocp_get_string_attribute_copy(struct genl_info *info,
				  enum OveyAttribute attribute, char *buff,
				  size_t len)
{
	struct nlattr *na = info->attrs[attribute];
	int ret;

	if (!na) {
		opr_err("no attribute OveyAttribute::%s in message!\n",
			ovey_a_to_string(attribute));
		return -EINVAL;
	}

	ret = nla_strlcpy(buff, info->attrs[attribute], len);
	if (ret < 0) {
		opr_err("received string for OveyAttribute::%s is NULL\n",
			ovey_a_to_string(attribute));
		ret = -EINVAL;
	} else {
		opr_info("received string for OveyAttribute::%s is '%s'\n",
			 ovey_a_to_string(attribute), buff);
	}

	return ret;
};

struct sk_buff *ocp_nlmsg_new(void)
{
	return nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
};

struct nlmsghdr *ocp_genlmsg_put_reply(struct sk_buff *skb,
				       struct genl_info *info)
{
	int err;
	struct nlmsghdr *hdr = genlmsg_put(
		skb, // buffer for netlink message: struct sk_buff *
		// this is not used for addressing/routing. I use this
		// only to identify the two sockets inside the same process
		// and distinguish their packets better
		info->nlhdr->nlmsg_pid,
		// I don't use/check sequences
		0,
		// info->snd_seq + 1,  // sequence number: int
		&ovey_gnl_family, // struct genl_family *
		0, // flags: int (for netlink header)
		info->genlhdr->cmd // cmd: u8 (for generic netlink header);
	);
	if (!hdr) {
		opr_err("genlmsg_put() returned null");
	}
	err = PTR_ERR_OR_ZERO(hdr);
	if (err) {
		opr_err("failed because of %d", err);
	}
	return hdr;
}

struct nlmsghdr *ocp_kernel_request_put(struct sk_buff *req_sk_buf,
					enum OveyOperation cmd)
{
	struct nlmsghdr *hdr =
		genlmsg_put(req_sk_buf,
			    // port id in netlink header
			    KERNEL_INITIATED_REQUESTS_SOCKET,
			    // I don't use/check sequences
			    0,
			    &ovey_gnl_family, // struct genl_family *
			    0, // flags: int (for netlink header)
			    cmd // cmd: u8 (for generic netlink header);
		);
	if (hdr == NULL) {
		opr_err("genlmsg_put() returned NULL, ENOMEM?!\n");
	}
	return hdr;
}

int ocp_send_kernel_request(struct sk_buff *req_sk_buf)
{
	int ret;

	if (!ocp_daemon_sockets_are_known()) {
		opr_err("Ovey kernel module has no knowledge about the Ovey daemon OCP sockets. Can't send request.\n");
		return 255;
	}
	ret = nlmsg_unicast(ocp_sockets.genl_sock, req_sk_buf,
				ocp_sockets.kernel_daemon_to_sock_pid);
	if (ret != 0) {
		opr_err("nlmsg_unicast() failed\n");
	}
	return ret;
}
