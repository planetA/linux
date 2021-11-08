#pragma once

#include "rxe.h"

#define rxe_print_pkt(pkt) __rxe_print_pkt(pkt, __FUNCTION__, __LINE__)

static inline void __rxe_print_pkt(struct rxe_pkt_info *pkt, const char *func,
				   int line)
{
	printk("WAH %s %d pkt: %px psn: %d", func, line, pkt, pkt->psn);
}
