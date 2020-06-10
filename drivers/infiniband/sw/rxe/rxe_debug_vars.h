#if !defined(RXE_DEBUG_MODE)
#error "Need to define mode of the include file"
#endif

#define RXE_DEBUG_VAR_DEF(name, type, suffix) \
	type RXE_DEBUG_COUNTER(name, suffix)[RXE_DEBUG_QPN_MAX]

#define RXE_DEBUG_COUNTER_DEF(name) RXE_DEBUG_VAR_DEF(name, atomic_t, var)

#define RXE_DEBUG_MINMAX_DEF(name) \
	RXE_DEBUG_VAR_DEF(name, atomic_t, max); \
	RXE_DEBUG_VAR_DEF(name, atomic_t, min)

#define RXE_DEBUG_ARRAY_DEF(name) \
	RXE_DEBUG_VAR_DEF(name, atomic_t, array)[RXE_DEBUG_QPN_ARRAY_SIZE]; \
	RXE_DEBUG_VAR_DEF(name, atomic_t, index)

#define RXE_DEBUG_VAR_DECL(name, type, suffix) \
	extern type RXE_DEBUG_COUNTER(name, suffix)[RXE_DEBUG_QPN_MAX]

#define RXE_DEBUG_COUNTER_DECL(name) RXE_DEBUG_VAR_DECL(name, atomic_t, var)

#define RXE_DEBUG_MINMAX_DECL(name) \
	RXE_DEBUG_VAR_DECL(name, atomic_t, max); \
	RXE_DEBUG_VAR_DECL(name, atomic_t, min)

#define RXE_DEBUG_ARRAY_DECL(name) \
	RXE_DEBUG_VAR_DECL(name, atomic_t, array)[RXE_DEBUG_QPN_ARRAY_SIZE]; \
	RXE_DEBUG_VAR_DECL(name, atomic_t, index)

#define RXE_DEBUG_GENERIC_INIT(name, suffix, init_value) ({ \
		int i; \
		for (i = 0; i < RXE_DEBUG_QPN_MAX; i++) { \
			atomic_set(&RXE_DEBUG_COUNTER(name, suffix)[i], init_value); \
		} \
	})

#define RXE_DEBUG_COUNTER_INIT(name) RXE_DEBUG_GENERIC_INIT(name, var, 0)
#define RXE_DEBUG_MINMAX_INIT(name) \
	RXE_DEBUG_GENERIC_INIT(name, max, INT_MIN); \
	RXE_DEBUG_GENERIC_INIT(name, min, INT_MAX)
#define RXE_DEBUG_ARRAY_INIT(name) ({ \
		int i, j; \
		for (i = 0; i < RXE_DEBUG_QPN_MAX; i++) { \
			for (j = 0; j < RXE_DEBUG_QPN_ARRAY_SIZE; j++) { \
				atomic_set(&RXE_DEBUG_COUNTER(name, array)[i][j], 0); \
			} \
		} \
	})


#if RXE_DEBUG_MODE == RXE_DEBUG_MODE_DECL
#define RXE_DEBUG_DO(type, name) RXE_DEBUG_##type##_DECL(name)
#elif RXE_DEBUG_MODE == RXE_DEBUG_MODE_DEF
#define RXE_DEBUG_DO(type, name) RXE_DEBUG_##type##_DEF(name)
#elif RXE_DEBUG_MODE == RXE_DEBUG_MODE_VAR
#error "UNIMPL"
#elif RXE_DEBUG_MODE == RXE_DEBUG_MODE_INIT
#define RXE_DEBUG_DO(type, name) RXE_DEBUG_##type##_INIT(name)
#else
#error "Unknown rxe_debug_mode"
#endif

RXE_DEBUG_DO(COUNTER, send_ack);
RXE_DEBUG_DO(COUNTER, req_1);
RXE_DEBUG_DO(COUNTER, req_2);
RXE_DEBUG_DO(COUNTER, req_3);
RXE_DEBUG_DO(COUNTER, comp_1);
RXE_DEBUG_DO(COUNTER, comp_2);
RXE_DEBUG_DO(COUNTER, comp_3);
RXE_DEBUG_DO(COUNTER, comp_4);
RXE_DEBUG_DO(COUNTER, comp_5);
RXE_DEBUG_DO(COUNTER, comp_error_retry);
RXE_DEBUG_DO(COUNTER, comp_queue_pkt);
RXE_DEBUG_DO(COUNTER, comp_done);
RXE_DEBUG_DO(COUNTER, comp_exit);
RXE_DEBUG_DO(COUNTER, comp_get_wqe);
RXE_DEBUG_DO(MINMAX, rcv_psn);
RXE_DEBUG_DO(MINMAX, rcv_psn_1);
RXE_DEBUG_DO(MINMAX, rcv_psn_2);
RXE_DEBUG_DO(MINMAX, rcv_psn_3);
RXE_DEBUG_DO(MINMAX, rcv_psn_4);
RXE_DEBUG_DO(MINMAX, rcv_psn_5);
RXE_DEBUG_DO(MINMAX, send_ack_psn);
RXE_DEBUG_DO(MINMAX, recv_ack_psn);
RXE_DEBUG_DO(MINMAX, comp_psn);
RXE_DEBUG_DO(MINMAX, comp_psn_1);
RXE_DEBUG_DO(MINMAX, comp_psn_2);
RXE_DEBUG_DO(MINMAX, comp_psn_3);
RXE_DEBUG_DO(MINMAX, comp_psn_5);
RXE_DEBUG_DO(MINMAX, resp_psn);
RXE_DEBUG_DO(MINMAX, resp_psn_1);
RXE_DEBUG_DO(MINMAX, resp_psn_2);
RXE_DEBUG_DO(MINMAX, resp_psn_3);
RXE_DEBUG_DO(MINMAX, resp_psn_4);
RXE_DEBUG_DO(MINMAX, resp_psn_5);
RXE_DEBUG_DO(MINMAX, resp_psn_6);
RXE_DEBUG_DO(MINMAX, req_psn);
RXE_DEBUG_DO(MINMAX, req_psn_1);
RXE_DEBUG_DO(MINMAX, req_psn_2);
RXE_DEBUG_DO(MINMAX, req_psn_3);
RXE_DEBUG_DO(MINMAX, req_psn_4);
RXE_DEBUG_DO(MINMAX, req_psn_5);
RXE_DEBUG_DO(MINMAX, req_psn_6);
RXE_DEBUG_DO(MINMAX, psn_diff);
RXE_DEBUG_DO(MINMAX, send_pkt_psn);
RXE_DEBUG_DO(ARRAY, comp_psn_put);
RXE_DEBUG_DO(ARRAY, comp_psn_get);
RXE_DEBUG_DO(ARRAY, comp_psn_done);
RXE_DEBUG_DO(ARRAY, comp_psn_comp_wqe);
RXE_DEBUG_DO(ARRAY, comp_psn_check_psn);
RXE_DEBUG_DO(ARRAY, comp_psn_error);
RXE_DEBUG_DO(ARRAY, req_retry_posted);

#undef RXE_DEBUG_MODE
#undef RXE_DEBUG_VAR_DECL
#undef RXE_DEBUG_COUNTER_DECL
#undef RXE_DEBUG_ARRAY_DECL
#undef RXE_DEBUG_MINMAX_DECL
#undef RXE_DEBUG_DO
