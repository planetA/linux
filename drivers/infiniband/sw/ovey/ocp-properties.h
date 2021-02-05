#ifndef _OVEY_OCP_PROPERTIES_H
#define _OVEY_OCP_PROPERTIES_H

// OCP - Ovey Control Protocol
// This file ONLY describes the common properties of OCP.
//
// This ONLY includes the name of the netlink family, the attributes, and the
// operations on top of (generic) netlink. Concrete functions that implement
// the communication shall be placed in another file.
//
// This file MUST BE KEPT IN SYNC with "ocp-properties.h" in Ovey libibverbs
// userland provider and with the Ovey userland CLI tool.

// Ovey netlink family name.
#define OVEY_NL_FAMILY_NAME "rdma-ovey"

// The possible attributes (kind of payload) of the generic netlink packets.
// Please keep in sync with ovey_a_to_string().
enum OveyAttribute {
    // unspecified / unused
    OVEY_A_UNSPEC,

    // String: used e.g. in echo message
    OVEY_A_MSG,

    // String: used e.g. in OVEY_C_NEW_DEVICE, OVEY_C_DELETE_DEVICE, and OVEY_C_ASK_PARENT_DEVICE
    OVEY_A_VIRT_DEVICE,

    // String: used e.g. in OVEY_C_NEW_DEVICE
    OVEY_A_PARENT_DEVICE,

    // u64 (big endian!): guid of new ovey device
    OVEY_A_NODE_GUID,

    // u64 (big endian!): guid of the parent device of the ovey device
    OVEY_A_PARENT_NODE_GUID,

    // String@36 + \0 (null terminated) that represents a v4 uuid (like 7b36a8ed-24b6-46c7-9a61-ef3c3a39d52e).
    OVEY_A_VIRT_NET_UUID_STR,

    // u32, value from enum OcpSocketKind. Used during DAEMON_HELLO and DAEMON_BYE
    OVEY_A_SOCKET_KIND,

    // u64 value of a completion inside the kernel. This is equal to request id.
    // If the kernel initiates a request from a verbs syscall it creates a new id
    // and sends it to the userland. Ovey Daemon will then return
    OVEY_A_COMPLETION_ID,

    // Value that describes a virtualized value of a u32 value, e.g. port lid.
    // Comes always as pair with OVEY_A_REAL_PROPERTY_U32.
    OVEY_A_VIRT_PROPERTY_U32,

    // Value that describes a real value of a u32 value, e.g. port lid.
    // Comes always as pair with OVEY_A_VIRT_PROPERTY_U32.
    OVEY_A_REAL_PROPERTY_U32,

    // Helper to find count of enum members in code.
    __OVEY_A_MAX,
};
// The number of usable attributes (unspecified is invalid).
#define OVEY_A_MAX (__OVEY_A_MAX - 1)

// The possible operations (callback function) of the generic netlink
// packets when they are received. Please keep in sync with
// ovey_op_to_string().
enum OveyOperation {
    // unspecified / unused
    OVEY_C_UNSPEC,

    /*
     * Description: Sends a string to the receiving side and expects an echo message.
     *              Operation is usually triggered by ovey daemon.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_ECHO(OVEY_A_MSG)
     * Response:    OVEY_C_ECHO(OVEY_A_MSG)
     */
    OVEY_C_ECHO,

    /*
     * Description: Creates a new Ovey ibverbs device and attaches a parent device to it.
     *              Operation is usually triggered by ovey daemon.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_NEW_DEVICE(OVEY_A_VIRT_DEVICE, OVEY_A_PARENT_DEVICE, OVEY_A_NODE_GUID, OVEY_A_VIRT_NET_UUID_STR)
     * Response:    OVEY_C_NEW_DEVICE()
     */
    OVEY_C_NEW_DEVICE,

    /*
     * Description: Deletes a Ovey ibverbs device.
     *              Operation is usually triggered by Ovey deamon.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_DELETE_DEVICE(OVEY_A_VIRT_DEVICE)
     * Response:    OVEY_C_DELETE_DEVICE()
     */
    OVEY_C_DELETE_DEVICE,

    /*
     * Description: Debug command to test to cope with error.
     * According to OCP spec and netlink convention nlmsg_type is set to NLMSG_ERR (0x2) instead
     * of family id.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_DEBUG_RESPOND_ERROR()
     * Response:    OVEY_C_DEBUG_RESPOND_ERROR()
     */
    OVEY_C_DEBUG_RESPOND_ERROR,

    /*
     * Description: Command to ask for device information (like parent device, guid, and virt. network id).
     * Like OVEY_C_PARENT_DEVICE_NAME but with more data.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_DEVICE_INFO(OVEY_A_VIRT_DEVICE)
     * Response:    OVEY_C_DEVICE_INFO(OVEY_A_PARENT_DEVICE, OVEY_A_NODE_GUID, OVEY_A_VIRT_NET_UUID_STR)
     */
    OVEY_C_DEVICE_INFO,

    /*
     * Description: Command that the daemon uses to notify its there. The kernel stores the PID so that
     *              it can reply to the ovey daemon.
     *              Usually this is done twice per application startup where both sockets get registered.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_DAEMON_HELLO(enum OcpSocketKind: u32)
     * Response:    OVEY_C_DAEMON_HELLO(enum OcpSocketKind: u32)
     */
    OVEY_C_DAEMON_HELLO,

    /*
     * Description: Command that the daemon uses to notify a specific socket is gone.
     *              Usually this is done twice per application shutdown where both sockets get unregistered.
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_DAEMON_BYE(enum OcpSocketKind: u32)
     * Response:    OVEY_C_DAEMON_BYE(enum OcpSocketKind: u32)
     */
    OVEY_C_DAEMON_BYE,

    /*
     * Description: Debug command that initiates a Kernel request via OCP.
     *              This should be triggered from the Daemon-to-Kernel socket.
     *
     * Direction:   From daemon to kernel.
     * Request:     OVEY_C_DEBUG_INITIATE_REQUEST()
     * Response:    Kernel to Daemon-Socket: OVEY_C_DEBUG_INITIATE_REQUEST()
     *              Daemon to Kernel-Socket: OVEY_C_DEBUG_INITIATE_REQUEST()
     */
    OVEY_C_DEBUG_INITIATE_REQUEST,

    /*
     * Description: The daemon replies with this over the "kernel to daemon"-socket to answer
     *              a previous request.
     *
     * Direction:   Response from daemon to kernel.
     * Request:     OVEY_C_RESOLVE_COMPLETION(OVEY_A_COMPLETION_ID)
     * Response:    OVEY_C_RESOLVE_COMPLETION()
     */
    OVEY_C_RESOLVE_COMPLETION,

    /*
     * Description: The daemon sends this request to tell the kernel to finish all completions.
     *              Useful during development.
     *
     * Direction:   Request from daemon to kernel.
     * Data:        <None>
     */
    OVEY_C_DEBUG_RESOLVE_ALL_COMPLETIONS,

    /*
     * Description: The kernel sends this request to the daemon during module unload.
     *              This is especially helpful during development when I regular unload
     *              the kernel module.
     *
     * Direction:   Request from kernel to daemon.
     * Data:        <None>
     */
    OVEY_C_KERNEL_MODULE_BYE,

    /*
     * Description: The kernel sends the request to the daemon so that it can save the data in the coordinator.
     *
     * Direction:   Request from kernel to daemon.
     * Data:        <None>
     */
    OVEY_C_STORE_VIRT_PROPERTY_PORT_LID,

    // Helper to find count of enum members in code.
    __OVEY_C_MAX,
};
// The number of usable operations (unspecified is invalid).
#define OVEY_C_MAX (__OVEY_C_MAX - 1)

/**
 * The netlink header has a "nlmsg_pid" field. This field allows us to identify multiple
 * sockets from the same process. We need two kind of communications in OCP.
 */
enum OcpSocketKind {
    /**
     * Socket (with port id) for "daemon->request->kernel->reply->daemon" communication.
     * Userland initiated requests.
     */
    DAEMON_INITIATED_REQUESTS_SOCKET,
    /**
     * Port id for "kernel->request->daemon->reply->kernel" communication.
     * Kernel initiated requests.
     */
    KERNEL_INITIATED_REQUESTS_SOCKET,
};

/**
 * Returns the string/name of the specified Ovey attribute.
 * String is symbol with static lifetime and must not be freed.
 * @param attr
 * @return Name of enum value, that has static lifetime and must not be freed.
 */
__attribute__((unused))
static char * ovey_a_to_string(enum OveyAttribute attr) {
    switch (attr) {
        case OVEY_A_MSG: {
            return "OVEY_A_MSG";
        }
        case OVEY_A_VIRT_DEVICE: {
            return "OVEY_A_VIRT_DEVICE";
        }
        case OVEY_A_PARENT_DEVICE: {
            return "OVEY_A_PARENT_DEVICE";
        }
        case OVEY_A_NODE_GUID: {
            return "OVEY_A_NODE_GUID";
        }
        case OVEY_A_PARENT_NODE_GUID: {
            return "OVEY_A_PARENT_NODE_GUID";
        }
        case OVEY_A_VIRT_NET_UUID_STR: {
            return "OVEY_A_VIRT_NET_UUID_STR";
        }
        default:
            return "<unknown>";
    }
}

/**
 * Returns the string/name of the specified Ovey operation.
 * String is symbol with static lifetime and must not be freed.
 * @param attr
 * @return Name of enum value, that has static lifetime and must not be freed.
 */
__attribute__((unused))
static char * ovey_op_to_string(enum OveyOperation attr) {
    switch (attr) {
        case OVEY_C_ECHO: {
            return "OVEY_C_ECHO";
        }
        case OVEY_C_NEW_DEVICE: {
            return "OVEY_C_NEW_DEVICE";
        }
        case OVEY_C_DELETE_DEVICE: {
            return "OVEY_C_DELETE_DEVICE";
        }
        case OVEY_C_DEBUG_RESPOND_ERROR: {
            return "OVEY_C_DEBUG_RESPOND_ERROR";
        }
        default:
            return "<unknown>";
    }
}

/**
 * Returns the string/name of the specified OcpSocketKind.
 * String is symbol with static lifetime and must not be freed.
 * @param socket
 * @return Name of enum value, that has static lifetime and must not be freed.
 */
__attribute__((unused))
static char * ocp_socket_kind_to_string(enum OcpSocketKind socket) {
    switch (socket) {
        case KERNEL_INITIATED_REQUESTS_SOCKET: {
            return "KERNEL_INITIATED_REQUESTS_SOCKET";
        }
        case DAEMON_INITIATED_REQUESTS_SOCKET: {
            return "DAEMON_INITIATED_REQUESTS_SOCKET";
        }
        default:
            return "<unknown>";
    }
}

#endif /* _OVEY_OCP_PROPERTIES_H */
