/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 */

#ifndef RXE_H
#define RXE_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/crc32.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include <crypto/hash.h>

#include "rxe_net.h"
#include "rxe_opcode.h"
#include "rxe_hdr.h"
#include "rxe_param.h"
#include "rxe_verbs.h"
#include "rxe_loc.h"

/*
 * Version 1 and Version 2 are identical on 64 bit machines, but on 32 bit
 * machines Version 2 has a different struct layout.
 */
#define RXE_UVERBS_ABI_VERSION		2

#define RXE_ROCE_V2_SPORT		(0xc000)

extern bool rxe_initialized;

static inline u32 rxe_crc32(struct rxe_dev *rxe,
			    u32 crc, void *next, size_t len)
{
	u32 retval;
	int err;

	SHASH_DESC_ON_STACK(shash, rxe->tfm);

	shash->tfm = rxe->tfm;
	*(u32 *)shash_desc_ctx(shash) = crc;
	err = crypto_shash_update(shash, next, len);
	if (unlikely(err)) {
		pr_warn_ratelimited("failed crc calculation, err: %d\n", err);
		return crc32_le(crc, next, len);
	}

	retval = *(u32 *)shash_desc_ctx(shash);
	barrier_data(shash_desc_ctx(shash));
	return retval;
}

void rxe_set_mtu(struct rxe_dev *rxe, unsigned int dev_mtu);

int rxe_add(struct rxe_dev *rxe, unsigned int mtu, const char *ibdev_name);

void rxe_rcv(struct sk_buff *skb);

/* The caller must do a matching ib_device_put(&dev->ib_dev) */
static inline struct rxe_dev *rxe_get_dev_from_net(struct net_device *ndev)
{
	struct ib_device *ibdev =
		ib_device_get_by_netdev(ndev, RDMA_DRIVER_RXE);

	if (!ibdev)
		return NULL;
	return container_of(ibdev, struct rxe_dev, ib_dev);
}

void rxe_port_up(struct rxe_dev *rxe);
void rxe_port_down(struct rxe_dev *rxe);
void rxe_set_port_state(struct rxe_dev *rxe);

#define RXE_DEBUG_QPN_MIN 10
#define RXE_DEBUG_QPN_MAX 256

#define RXE_DEBUG_QPN_ARRAY_SIZE 8

#define RXE_DEBUG_COUNTER(name, suffix) rxe_debug_qp_##name##_##suffix

#define RXE_DEBUG_MODE_DECL	1
#define RXE_DEBUG_MODE_DEF	2
#define RXE_DEBUG_MODE_VAR	3
#define RXE_DEBUG_MODE_INIT	4

#define RXE_DEBUG_MODE RXE_DEBUG_MODE_DECL
#include "rxe_debug_vars.h"

extern int COUNTER_ACTIVE;

#define PRINT_DEBUG 0
#if PRINT_DEBUG
#define RXE_DO_PRINT_DEBUG(...) pr_err_ratelimited(__VA_ARGS__)
#define RXE_DO_PRINT_DEBUG_ALWAYS(...) pr_err(__VA_ARGS__)
#define RXE_COUNTER_ACTIVE COUNTER_ACTIVE
#define COUNTER_FREEZE() ({ wmb(); COUNTER_ACTIVE = 0; RXE_DO_PRINT_DEBUG_ALWAYS("FREEZING\n"); wmb(); })
#else
#define RXE_DO_PRINT_DEBUG(...)
#define RXE_DO_PRINT_DEBUG_ALWAYS(...)
#define RXE_COUNTER_ACTIVE 0
#define COUNTER_FREEZE()
#endif

#define GET_TARGET(qp, name, suffix, type) ({ \
		type *target; \
		int qpn = qp_num(qp); \
		if (qpn < RXE_DEBUG_QPN_MIN || qpn >= RXE_DEBUG_QPN_MAX) { \
			target = NULL; \
			RXE_DO_PRINT_DEBUG("Counter " #name " for qp#%d not defined\n", qpn); \
		} else { \
			target = &RXE_DEBUG_COUNTER(name, suffix)[qpn]; \
		} \
		target; \
	})

#define COUNTER_INC(qp, name) ({ \
	while(RXE_COUNTER_ACTIVE) {\
		atomic_t *target; \
		target	= GET_TARGET(qp, name, var, typeof(*target)); \
		if (target) { \
			atomic_inc(target); \
		} \
		break; \
	} \
	})

#define GET_VALUE(qp, name) ({ \
	atomic_t *target = GET_TARGET(qp, name, var, typeof(*target)); \
	atomic_add_return(0, target); \
	})


#define MINMAX_UPDATE(qp, name, value) ({ \
	while(RXE_COUNTER_ACTIVE) {\
		int __v = value; \
		atomic_t *target; \
		target = GET_TARGET(qp, name, max, typeof(*target)); \
		if (target) { \
			atomic_set(target, max(atomic_add_return(0, target), __v)); \
		} \
		target = GET_TARGET(qp, name, min, typeof(*target)); \
		if (target) { \
			atomic_set(target, min(atomic_add_return(0, target), __v)); \
		} \
		break; \
	} \
	})

#define MINMAX_RESET(qp, name) ({ \
	while (RXE_COUNTER_ACTIVE) { \
		atomic_t *target; \
		target = GET_TARGET(qp, name, max, typeof(*target)); \
		if (target) { \
			atomic_set(target, INT_MIN); \
		} \
		target = GET_TARGET(qp, name, min, typeof(*target)); \
		if (target) { \
			atomic_set(target, INT_MAX); \
		} \
		break; \
	} \
	})

#define ARRAY_PUT(qp, name, value) ({ \
	while (RXE_COUNTER_ACTIVE) { \
		unsigned int i; \
		atomic_t *index_target = \
			GET_TARGET(qp, name, index, typeof(*index_target)); \
		typeof(RXE_DEBUG_COUNTER(name, array)[0]) *elem_target = \
			GET_TARGET(qp, name, array, typeof(*elem_target)); \
		if (!index_target || !elem_target) \
			break; \
		i = atomic_inc_return(index_target) % ARRAY_SIZE(*elem_target); \
		atomic_set(&(*elem_target)[i], value); \
		break; \
	} \
	})

#endif /* RXE_H */
