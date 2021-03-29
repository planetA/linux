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

static inline void rxe_print_skb_v4(const struct sk_buff *skb, const char *func, int line)
{
	struct iphdr *iph = ip_hdr(skb);
#if 0
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;

	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;

	if (iph->protocol == 17) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(udp_header->source);
	} else if (iph->protocol == 6) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(tcp_header->source);
		dest_port = (unsigned int)ntohs(tcp_header->dest);
	}
#endif

	printk(KERN_DEBUG "%s %d IP addres = %pI4  DEST = %pI4\n", func, line, &iph->saddr, &iph->daddr);
}

static inline void rxe_print_skb_v6(const struct sk_buff *skb, const char *func, int line)
{
        struct ipv6hdr *iph = ipv6_hdr(skb);
#if 0
        struct udphdr *udp_header;
        struct tcphdr *tcp_header;

        unsigned int src_ip = (unsigned int)iph->saddr;
        unsigned int dest_ip = (unsigned int)ip_header->daddr;
        unsigned int src_port = 0;
        unsigned int dest_port = 0;
        if (iph->protocol==17) {
                udp_header = (struct udphdr *)skb_transport_header(skb);
                src_port = (unsigned int)ntohs(udp_header->source);
        } else if (iph->protocol == 6) {
                tcp_header = (struct tcphdr *)skb_transport_header(skb);
                src_port = (unsigned int)ntohs(tcp_header->source);
                dest_port = (unsigned int)ntohs(tcp_header->dest);
        }
#endif

        printk(KERN_DEBUG "%s %d IP addres = %pI6  DEST = %pI6\n", func, line, &iph->saddr, &iph->daddr);

}

#define rxe_print_skb(skb) __rxe_print_skb(skb, __FUNCTION__, __LINE__)

static inline void __rxe_print_skb(const struct sk_buff *skb, const char *func, int line)
{
	if (skb->protocol == htons(ETH_P_IPV6)) {
		rxe_print_skb_v6(skb, func, line);
	} else if (skb->protocol == htons(ETH_P_IP)) {
		rxe_print_skb_v4(skb, func, line);
	}
	else {
		pr_warn_ratelimited("bad packet\n");
	}
}

#include "rxe_debug.h"

#endif /* RXE_H */
