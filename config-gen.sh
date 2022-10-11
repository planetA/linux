#!/bin/bash

make defconfig

scripts/config -e GDB_SCRIPTS \
    -e LATENCYTOP \
    -e PROVE_LOCKING \
    -e SOFTLOCKUP_DETECTOR \
    -e HARDLOCKUP_DETECTOR \
    -e DETECT_HUNG_TASK \
    -e WQ_WATCHDOG \
    -e KASAN \
    -e KGDB \
    -e READABLE_ASM \
    -e KGDB_KDB \
    -e GDB_SCRIPTS \
    -e DEBUG_INFO \
    -e DM_MULTIPATH \
    -e DM_MULTIPATH_QL \
    -e DM_MULTIPATH_ST \
    -e BRIDGE \
    -e VXLAN \
    -e VETH \
    -e NLMON \
    -e DYNAMIC_DEBUG \
    -e DEBUG_SLAB \
    -e FUNCTION_TRACER \
    -e OSNOISE_TRACER \
    -e FTRACE_SYSCALLS \
    -e FUNCTION_TRACER \
    -e FUNCTION_GRAPH_TRACER \
    -e FUNCTION_PROFILER \
    -e PREEMPT_NONE \
    -e DEBUG_INFO_DWARF4 \
    \
    -m VIRTIO_PCI \
    -m VIRTIO_MMIO \
    -m VIRTIO_BALLOON \
    -m VIRTIO_INPUT \
    -m VIRTIO_NET \
    -m VIRTIO_BLK \
    -m OPENVSWITCH \
    -m BRIDGE \
    -m OPENVSWITCH \
    -m OPENVSWITCH_VXLAN \
    -m VXLAN \
    -m INFINIBAND \
    -m INFINIBAND_USER_ACCESS \
    -m INFINIBAND_USER_MAD \
    -m RDMA_RXE \
    -m INFINIBAND_MTHCA \
    -m INFINIBAND_MTHCA_DEBUG \
    -m INFINIBAND_IPOIB \
    -m INFINIBAND_IPOIB_DEBUG \
    -m INFINIBAND_EFA \
    -m MLX4_INFINIBAND \
    -m MLX4_CORE \
    -m MLX4_CORE_GEN2 \
    -m MLX5_CORE \
    -m MLX5_CORE_EN \
    -m MLX5_INFINIBAND \
    \
    -d RANDOMIZE_BASE \
    -d CONFIG_PAGE_TABLE_ISOLATION

make olddefconfig