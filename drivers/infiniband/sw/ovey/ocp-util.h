#ifndef _OCP_UTIL_H
#define _OCP_UTIL_H

/**
 * File used for utility functions like receiving data from a netlink packet
 * or building netlink packets.
 */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "ocp-properties.h"

/**
 * Replies with a error message according to OCP spec and netlink spec.
 * This means property nlmsg_msg of netlink header is NLMSG_ERROR (0x2)
 * instead of family id.
 * Constructs a new generic netlink package.
 *
 * @param info genl header of request that resulted in failure
 * @param err_code positive or negative error code. Will be send as negative to userland.
 */
void ocp_reply_with_error(struct genl_info *info, int err_code);

/**
 * Convenient function to get mandatory null-terminated c-string parameter from netlink attributes.
 *
 * @param info Info of incoming genl request
 * @param attribute OveyAttribute
 * @return NULL or pointer to the data inside info.
 */
char * ocp_get_string_attribute(struct genl_info *info, enum OveyAttribute attribute);

/**
 * Convenient function to get mandatory u64 parameter from netlink attributes.
 *
 * @param info Info of incoming genl request
 * @param attribute OveyAttribute
 * @return NULL or pointer to the data inside info.
 */
u64 ocp_get_u64_attribute(struct genl_info *info, enum OveyAttribute attribute);

/**
 * Convenient function to get mandatory u32 parameter from netlink attributes.
 *
 * @param info Info of incoming genl request
 * @param attribute OveyAttribute
 * @return NULL or pointer to the data inside info.
 */
u32 ocp_get_u32_attribute(struct genl_info *info, enum OveyAttribute attribute);

/**
 * Like ocp_get_string_attribute() but copies the string into a specified buffer.
 *
 * @param info Info of incoming genl request
 * @param attribute OveyAttribute
 * @param buff Destination buffer
 * @param len length of the buffer
 * @return 0 on success or < 0 on error.
 */
int ocp_get_string_attribute_copy(struct genl_info *info, enum OveyAttribute attribute, char * buff, size_t len);

/**
 * Convenient wrapper around nlmsg_new(). Can be used for Kernel OCP replies as well as Kernel OCP requests.
 * @return Buffer to socket.
 */
struct sk_buff * ocp_nlmsg_new(void);

/**
 * Convenient OCP-specific wrapper around genlmsg_put() to store netlink header
 * with generic netlink header as payload in the buffer.
 *
 * @param skb Kernel Buffer
 * @param info Info from last request
 * @return Pointer to valid netlink header inside skb.
 */
struct nlmsghdr *ocp_genlmsg_put_reply(struct sk_buff *skb, struct genl_info *info);

/**
 * Convenient wrapper around genlmsg_put() that should be used for kernel initated OCP requests.
 * @return Pointer to nlmsg_hdr
 */
struct nlmsghdr * ocp_kernel_request_put(struct sk_buff *, enum OveyOperation);

/**
 * Sends a OCP request from the kernel to the daemon via the proper socket.
 * @return
 */
int ocp_send_kernel_request(struct sk_buff *);


#endif /* _OCP_UTIL_H */
