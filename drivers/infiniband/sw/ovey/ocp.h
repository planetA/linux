#ifndef _OCP_H
#define _OCP_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include "ocp-properties.h"

// OCP - Ovey Control Protocol
// Defines the functionality of OCP. All OCP functions work on top of
// generic netlink.

// Make this accessible from other c files
extern struct genl_family ovey_gnl_family;

// This struct is used as intermediate struct for the
// OVEY_C_DEVICE_INFO OCP operation. This is assembled either before it is destructed and send via netlink
// or assembled after the properties where received via OCP.
// It bundles all needed information before it's data can be written into the netlink packet.
// All pointers inside the struct are pointers OWNED BY OTHER FUNCTIONS.
// Don't free them!
struct ovey_device_info {
    // e.g. "ovey0"
    char const * device_name;
    // e.g. "rxe0"
    char const * parent_device_name;
    // the virtual guid that identifies this node. Corresponds with the
    // value inside Ovey Coordinator.
    __be64 node_guid;
    // the guid of the real, physical device.
    __be64 parent_node_guid;
    // the uuid v4 that describes to what virtual network this device belongs.
    // Corresponds with the value inside Ovey Coordinator.
    char const * virt_network_id;
};

struct ocp_sockets {
    /* -1 (=None) or > 0 (valid port id of userland socket) */
    s32 daemon_to_kernel_sock_pid;
    /* -1 (=None) or > 0 (valid port id of userland socket) */
    s32 kernel_daemon_to_sock_pid;
    struct sock		*genl_sock;
};

/**
 * Convenient function that checks if ocp_sockets are in a valid state (i.e. daemon exists)
 * or not.
 * @return 0 or 1
 */
int ocp_daemon_sockets_are_known(void);

// global struct
extern struct ocp_sockets ocp_sockets;

/**
 * I use two sockets in Ovey to distingish between Daemon-to-Kernel communication
 * and Kernel-to-Daemon communication. The first socket is used for Daemon requests
 * and Kernel replies. The latter is used for Kernel initiated requests and Daemon
 * replies.
 *
 * Not it gets a little bit confusing, Netlink doesn't seem to be well designed.
 * On the client side the field `nl_pid` of netlink header message seems pretty
 * useless. On the kernel side, this gets used for routing (targeting back the
 * userland process where the socket is).
 */

/* Global variable to access this information. */
extern struct genl_family ovey_gnl_family;
/**
 * Registers the ovey netlink family with generic netlink.
 * Returns 0 on success. If < 0 then an error happened.
 */
int ocp_init(void);

/**
 * Unregisters the ovey netlink family with generic netlink.
 * Returns 0 on success. If < 0 then an error happened.
 */
int ocp_fini(void);

// #################################################################################
// BEGIN CALLBACK PROTOTYPES

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_ECHO was received.
 */
int ocp_cb_echo(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_NEW_DEVICE was received.
 */
int ocp_cb_new_device(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_DELETE_DEVICE was received.
 */
int ocp_cb_delete_device(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_DEBUG_RESPOND_ERROR was received.
 */
int ocp_cb_debug_respond_error(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_DEVICE_INFO was received.
 */
int ocp_cb_device_info(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_DAEMON_HELLO was received.
 */
int ocp_cb_daemon_hello(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_DAEMON_BYE was received.
 */
int ocp_cb_daemon_bye(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_DEBUG_INITIATE_REQUEST was received.
 */
int ocp_cb_debug_initiate_request(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_RESOLVE_COMPLETION was received.
 */
int ocp_cb_resolve_completion(struct sk_buff *skb, struct genl_info *info);

/**
 * Callback called by generic netlink, if a message with cmd
 * OveyOperation::OVEY_C_RESOLVE_ALL_COMPLETIONS was received.
 */
int ocp_cb_debug_resolve_all_completions(struct sk_buff *skb, struct genl_info *info);

// END CALLBACK PROTOTYPES
// #################################################################################



#endif /* _OCP_H */
