/*
 *
 * Copyright 2023 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef SKIP_IIP_DEFINITION

#ifndef IIP_CONF_TCP_RX_BUF_CAPACITY
#define IIP_CONF_TCP_RX_BUF_CAPACITY (0x100000)
#endif
#ifndef IIP_CONF_TCP_MSL_SEC
#define IIP_CONF_TCP_MSL_SEC (1) /* RFC specifies more than 2 min, but we keep this short so that we can stop a process after 1 second wait */
#endif
#ifndef II_CONF_IPV4_FRAG_CNT_MAX
#define II_CONF_IPV4_FRAG_CNT_MAX (4)
#endif
#ifndef II_CONF_EXTENT_QUEUE_SIZE
#define II_CONF_EXTENT_QUEUE_SIZE (4)
#endif
#ifndef II_CONF_TCP_RING_SLOT_LEN
#define II_CONF_TCP_RING_SLOT_LEN (8)
#endif
#ifndef II_CONF_IPV4_FRAG_ARRAY_LEN
#define II_CONF_IPV4_FRAG_ARRAY_LEN (2)
#endif
#ifndef II_CONF_POOL_NUM_PB
#define II_CONF_POOL_NUM_PB (512)
#endif
#ifndef II_CONF_POOL_NUM_TCP_CONN
#define II_CONF_POOL_NUM_TCP_CONN (64)
#endif
#ifndef II_CONF_TCP_OPT_TS_OK
#define II_CONF_TCP_OPT_TS_OK (1)
#endif
#ifndef II_CONF_TCP_OPT_SACK_OK
#define II_CONF_TCP_OPT_SACK_OK (1)
#endif
#ifndef IIP_CONF_TCP_CONN_HT_SIZE
#define IIP_CONF_TCP_CONN_HT_SIZE	(829) /* generally bigger is faster at the cost of memory consumption */
#endif

#define II_ETH_HDR_LEN 14
#define II_ETH_ADDR_LEN 6
#define II_ARP_HDR_LEN 8
#define II_IPV4_HDR_LEN_MINIMAL 20
#define II_ICMP_HDR_LEN 8
#define II_TCP_HDR_LEN_MINIMAL 20
#define II_UDP_HDR_LEN 8

#define IIP_PKT_LEN_T uint16_t
#define IIP_PKT_CNT_T uint16_t

enum iip_rc { /* return code */
	IIP_ERR_OK,
	IIP_ERR_INVALID_RX,
	IIP_ERR_AGAIN,
	IIP_ERR_BUF_FULL,
	IIP_ERR_FATAL_USR,
	IIP_ERR_FATAL_SYS,
	IIP_ERR_FATAL_SUB,
	IIP_ERR_FATAL_MEM
};

#define II_TCP_FLAG_FIN 0x01U
#define II_TCP_FLAG_SYN 0x02U
#define II_TCP_FLAG_RST 0x04U
#define II_TCP_FLAG_PSH 0x08U
#define II_TCP_FLAG_ACK 0x10U
#define II_TCP_FLAG_URG 0x20U
#define II_TCP_FLAG_ECE 0x40U
#define II_TCP_FLAG_CWR 0x80U

enum ii_tcp_state {
	II_TCP_STATE_CLOSED = 0,
	II_TCP_STATE_SYN_SENT,
	II_TCP_STATE_SYN_RECVD,
	II_TCP_STATE_ESTABLISHED,
	II_TCP_STATE_CLOSING,
	II_TCP_STATE_FIN_WAIT1,
	II_TCP_STATE_FIN_WAIT2,
	II_TCP_STATE_TIME_WAIT,
	II_TCP_STATE_CLOSE_WAIT,
	II_TCP_STATE_LAST_ACK
};

#define II_PB_FLAGS_TCP_OPT_HAS_TS (1U << 0)
#define II_PB_FLAGS_TCP_URGENT (1U << 1)
#define II_PB_FLAGS_TCP_FASTOPEN_REQUEST (1U << 2)
#define II_PB_FLAGS_TCP_FASTOPEN_VALID (1U << 3)
#define II_PB_FLAGS_TCP_FASTOPEN_INVALID (1U << 4)
#define II_PB_FLAGS_TCP_SACKED (1U << 5)
#define II_PB_FLAGS_TCP_TX_SACKBUF (1U << 6)
#define II_PB_FLAGS_TCP_RX_SACKBUF (1U << 8)

struct ii_pb {
	IIP_PKT_CNT_T cnt;
	IIP_PKT_P part_pkt[II_CONF_IPV4_FRAG_CNT_MAX];
	struct {
		uint16_t info_flags;
		uint32_t seq;
		uint32_t ack_seq;
		uint16_t flags;
		uint16_t win;
		uint16_t payload_len;
		uint16_t sent_bytes;
		uint32_t inc_head;
		uint32_t dec_tail;
		uint32_t urg_p;
		uint8_t sackbuf[28];
		struct {
			uint32_t ts[2];
		} opt;
	} tcp;
};

struct ii_extent_queue {
	uint8_t cnt;
	struct {
		uint32_t v;
		uint16_t l;
	} extent[II_CONF_EXTENT_QUEUE_SIZE];
};

#define II_TCP_CONN_FLAGS_ACK_PENDING (1U << 0)
#define II_TCP_CONN_FLAGS_PEER_RX_FAILED (1U << 1)
#define II_TCP_CONN_FLAGS_SET_PROBE (1U << 2)
#define II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN (1U << 3)
#define II_TCP_CONN_FLAGS_SKIP_TCP_CLOSE_CALLBACK (1U << 4)
#define II_TCP_CONN_FLAGS_CLOSING (1U << 5)
#define II_TCP_CONN_FLAGS_URGENT_SET (1U << 6)
#define II_TCP_CONN_FLAGS_FASTOPEN (1U << 7)
#define II_TCP_CONN_FLAGS_ACK_SENT (1U << 8)
#define II_TCP_CONN_FLAGS_SACK_OK (1U << 9)
#define II_TCP_CONN_FLAGS_KEEPALIVE_ENABLED (1U << 10)
#define II_TCP_CONN_FLAGS_OPT_SET_TS (1U << 11)

#define II_DEFINE_RING(_obj_name, _type, _cnt) \
struct ii_##_obj_name##__ring { \
	uint16_t head; \
	uint16_t tail; \
	_type slot[_cnt]; \
}; \
/*@ \
	requires \valid_read(ring); \
	assigns \nothing; \
	ensures \result == IIP_ERR_OK ==> \
		(ring->head < sizeof(ring->slot) / sizeof(ring->slot[0])) \
		&& (ring->tail < sizeof(ring->slot) / sizeof(ring->slot[0])); \
 */ \
static enum iip_rc ii_##_obj_name##_ring_validation(struct ii_##_obj_name##__ring *ring) \
{ \
	if (ring->head >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->tail >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	return IIP_ERR_OK; \
} \
/*@ \
	requires \valid_read(ring); \
	requires ring->head < sizeof(ring->slot) / sizeof(ring->slot[0]); \
	requires ring->tail < sizeof(ring->slot) / sizeof(ring->slot[0]); \
	assigns \nothing; \
	ensures \result < sizeof(ring->slot) / sizeof(ring->slot[0]); \
 */ \
static uint16_t ii_##_obj_name##_ring_num_used(struct ii_##_obj_name##__ring *ring) \
{ \
	if (ring->tail <= ring->head) \
		return ring->head - ring->tail; \
	else \
		return sizeof(ring->slot) / sizeof(ring->slot[0]) + ring->head - ring->tail; \
} \
/*@ \
	requires \valid_read(ring); \
	requires ring->head < sizeof(ring->slot) / sizeof(ring->slot[0]); \
	requires ring->tail < sizeof(ring->slot) / sizeof(ring->slot[0]); \
	assigns \nothing; \
	ensures \result < sizeof(ring->slot) / sizeof(ring->slot[0]); \
 */ \
static uint16_t ii_##_obj_name##_ring_num_usable(struct ii_##_obj_name##__ring *ring) \
{ \
	return sizeof(ring->slot) / sizeof(ring->slot[0]) - 1 - ii_##_obj_name##_ring_num_used(ring); \
} \
/*@ \
	requires \valid(ring); \
	assigns *ring; \
	ensures \result == IIP_ERR_OK ==> ring->head < sizeof(ring->slot) / sizeof(ring->slot[0]) && ring->tail < sizeof(ring->slot) / sizeof(ring->slot[0]); \
 */ \
static enum iip_rc ii_##_obj_name##_ring_push(struct ii_##_obj_name##__ring *ring, _type _obj_id) \
{ \
	if (ring->tail >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->head >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (!ii_##_obj_name##_ring_num_usable(ring)) { \
		return IIP_ERR_FATAL_MEM; \
	} \
	{ \
		uint16_t next = ring->head + 1; \
		if (next == sizeof(ring->slot) / sizeof(ring->slot[0])) \
			next = 0; \
		ring->slot[ring->head] = _obj_id; \
		ring->head = next; \
		return IIP_ERR_OK; \
	} \
} \
/*@ \
	requires \valid(ring); \
	assigns *ring; \
 */ \
static enum iip_rc ii_##_obj_name##_ring_insert(struct ii_##_obj_name##__ring *ring, _type _obj_id, uint16_t idx) \
{ \
	if (idx >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->tail >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->head >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (!ii_##_obj_name##_ring_num_usable(ring)) { \
		return IIP_ERR_FATAL_MEM; \
	} \
	{ \
		IIP_PKT_CNT_T cnt = (idx <= ring->head ? (uint16_t) (ring->head - idx) : sizeof(ring->slot) / sizeof(ring->slot[0]) + ring->head - idx); \
		{ \
			uint16_t i; \
			/*@ \
				 loop invariant 0 <= i <= cnt; \
				 loop assigns i, ring->slot[0 .. II_CONF_TCP_RING_SLOT_LEN - 1]; \
				 loop variant i; \
			 */ \
			for (i = cnt; i > 0; i--) { \
				uint16_t from = idx + i - 1; \
				uint16_t to = idx + i; \
				if (from >= sizeof(ring->slot) / sizeof(ring->slot[0])) \
					from %= sizeof(ring->slot) / sizeof(ring->slot[0]); \
				if (to >= sizeof(ring->slot) / sizeof(ring->slot[0])) \
					to %= sizeof(ring->slot) / sizeof(ring->slot[0]); \
				ring->slot[to] = ring->slot[from]; \
			} \
		} \
		ring->slot[idx] = _obj_id; \
		ring->head = ring->head + 1 == sizeof(ring->slot) / sizeof(ring->slot[0]) ? 0 : ring->head + 1; \
		return IIP_ERR_OK; \
	} \
} \
/*@ \
	requires \valid(ring); \
	requires \valid(_obj_id); \
	assigns *ring, *_obj_id; \
	ensures \result == IIP_ERR_OK ==> ring->tail == \old(ring->tail); \
	ensures \result == IIP_ERR_OK ==> ring->head == (\old(ring->head) != 0 ? \old(ring->head) - 1 : sizeof(ring->slot) / sizeof(ring->slot[0]) - 1); \
	ensures \result == IIP_ERR_OK ==> (ring->tail <= ring->head ? ring->head - ring->tail : sizeof(ring->slot) / sizeof(ring->slot[0]) + ring->head - ring->tail) + 1 == \
		(\old(ring->tail) <= \old(ring->head) ? \old(ring->head) - \old(ring->tail) : sizeof(ring->slot) / sizeof(ring->slot[0]) + \old(ring->head) - \old(ring->tail)); \
 */ \
static enum iip_rc ii_##_obj_name##_ring_pop(struct ii_##_obj_name##__ring *ring, _type *_obj_id) \
{ \
	if (ring->tail >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->head >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->head == ring->tail) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	{ \
		uint16_t prev = (ring->head ? (uint16_t) (ring->head - 1) : sizeof(ring->slot) / sizeof(ring->slot[0]) - 1); \
		*_obj_id = ring->slot[prev]; \
		ring->head = prev; \
		return IIP_ERR_OK; \
	} \
} \
/*@ \
	requires \valid(ring); \
	requires \valid(_obj_id); \
	assigns *ring, *_obj_id; \
	ensures \result == IIP_ERR_OK ==> ring->head == \old(ring->head); \
	ensures \result == IIP_ERR_OK ==> ring->tail == (\old(ring->tail) != sizeof(ring->slot) / sizeof(ring->slot[0]) - 1 ? \old(ring->tail) + 1 : 0); \
	ensures \result == IIP_ERR_OK ==> (ring->tail <= ring->head ? ring->head - ring->tail : sizeof(ring->slot) / sizeof(ring->slot[0]) + ring->head - ring->tail) + 1 == \
		(\old(ring->tail) <= \old(ring->head) ? \old(ring->head) - \old(ring->tail) : sizeof(ring->slot) / sizeof(ring->slot[0]) + \old(ring->head) - \old(ring->tail)); \
 */ \
static enum iip_rc ii_##_obj_name##_ring_pull(struct ii_##_obj_name##__ring *ring, _type *_obj_id) \
{ \
	if (ring->tail >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->head >= sizeof(ring->slot) / sizeof(ring->slot[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (ring->head == ring->tail) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	{ \
		uint16_t next = (ring->tail == sizeof(ring->slot) / sizeof(ring->slot[0]) - 1 ? 0 : ring->tail + 1); \
		*_obj_id = ring->slot[ring->tail]; \
		ring->tail = next; \
		return IIP_ERR_OK; \
	} \
}

#define II_DEFINE_POOL(_obj_name, _type, _cnt) \
struct ii_##_obj_name##__pool { \
	uint32_t used_cnt; \
	uint32_t queue[_cnt]; \
	_type array[_cnt]; \
}; \
/*@ \
	requires \valid(pool); \
	assigns *pool \from _obj_id; \
	ensures \result == IIP_ERR_OK ==> 0 <= pool->used_cnt < (sizeof(pool->queue) / sizeof(pool->queue[0])); \
 */ \
static enum iip_rc ii_free_##_obj_name(struct ii_##_obj_name##__pool *pool, uint32_t _obj_id) \
{ \
	if (pool->used_cnt > sizeof(pool->queue) / sizeof(pool->queue[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (pool->used_cnt == 0) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (_obj_id >= sizeof(pool->queue) / sizeof(pool->queue[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	pool->used_cnt = pool->used_cnt - 1; \
	pool->queue[pool->used_cnt] = _obj_id; \
	return IIP_ERR_OK; \
} \
/*@ \
	requires \valid(pool); \
	requires \valid(_obj_id); \
	requires \separated(pool, _obj_id); \
	assigns pool->used_cnt, *_obj_id \from pool->queue[pool->used_cnt]; \
	ensures \result == IIP_ERR_OK ==> *_obj_id < (sizeof(pool->queue) / sizeof(pool->queue[0])); \
	ensures \result == IIP_ERR_OK ==> 0 < pool->used_cnt <= (sizeof(pool->queue) / sizeof(pool->queue[0])); \
*/ \
static enum iip_rc ii_alloc_##_obj_name(struct ii_##_obj_name##__pool *pool, uint32_t *_obj_id) \
{ \
	if (pool->used_cnt > sizeof(pool->queue) / sizeof(pool->queue[0])) { \
		return IIP_ERR_FATAL_SYS; \
	} \
	if (pool->used_cnt == sizeof(pool->queue) / sizeof(pool->queue[0])) { \
		return IIP_ERR_FATAL_MEM; \
	} \
	*_obj_id = pool->queue[pool->used_cnt]; \
	pool->used_cnt = pool->used_cnt + 1; \
	if (*_obj_id >= sizeof(pool->queue) / sizeof(pool->queue[0])) { \
		pool->used_cnt = pool->used_cnt - 1; \
		return IIP_ERR_FATAL_SYS; \
	} \
	return IIP_ERR_OK; \
}

II_DEFINE_RING(pb, uint32_t, II_CONF_TCP_RING_SLOT_LEN)
/*@ logic integer f_pb_ring_num_used(struct ii_pb__ring *ring) =
	(ring->tail <= ring->head ? ring->head - ring->tail : sizeof(ring->slot) / sizeof(ring->slot[0]) + ring->head - ring->tail); */

#ifndef IIP_TCP_CONN_STRUCT_EXTRA
#define IIP_TCP_CONN_STRUCT_EXTRA
#endif

struct ii_tcp_conn {
	uint8_t src_mac[II_ETH_ADDR_LEN];
	uint8_t dst_mac[II_ETH_ADDR_LEN];
	uint32_t src_ip[4];
	uint32_t dst_ip[4];
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t flags;
	uint8_t state;
	uint8_t dup_ack_received;
	uint8_t retrans_cnt;
	uint8_t retrans_r1;
	uint8_t retrans_r2;
	uint8_t ws;
	uint8_t diffserv;
	uint16_t mss;
	uint16_t path_mtu;
	uint32_t seq_next_expected;
	uint32_t ack_seq_sent;
	uint32_t iss;
	uint32_t ts;
	uint32_t retx_bytes;
	uint32_t seq;
	uint32_t ack_seq;
	uint32_t acked_seq;
	uint16_t peer_win;
	uint16_t max_peer_win;
	uint32_t sent_seq;
	uint32_t sent_seq_when_loss_detected;
	uint32_t fin_ack_seq;
	uint32_t time_wait_ts_ms;
	uint32_t urgent_ptr;
	uint32_t keepalive_ts;
	uint32_t keepalive_interval_ms;
	uint32_t rto_ms;
	uint32_t rto_expire;
	IIP_TCP_CONN_STRUCT_EXTRA;
	uint32_t probe_ts;
	uint32_t probe_rto_ms;
	struct ii_pb__ring rx_ring;
	struct ii_pb__ring tx_ring;
	struct ii_pb__ring sent_ring;
	struct ii_pb__ring pending_ring;
	struct ii_extent_queue sack;
	struct {
		uint32_t capacity;
		uint32_t used;
		uint32_t adv_cnt;
	} buf;
	struct {
		uint32_t srtt; /* smoothed RTT estimator */
		uint32_t rttvar; /* smoothed mean RTT estimator */
	} rtt;
	struct {
		uint32_t win;
		uint32_t ssthresh;
	} cc;
	struct {
		uint8_t len;
		uint8_t buf[16];
	} fastopen_cookie;
};

#define IIP_TCP_CONN_P uint32_t
#define IIP_TCP_SEQ_INT_T uint32_t

II_DEFINE_POOL(pb, struct ii_pb, II_CONF_POOL_NUM_PB)
II_DEFINE_POOL(tcp_conn, struct ii_tcp_conn, II_CONF_POOL_NUM_TCP_CONN)

struct iip_workspace {
	struct ii_pb__pool pbs;
	struct ii_tcp_conn__pool tcp_conns;
	struct ii_pb ipv4_frag[II_CONF_IPV4_FRAG_ARRAY_LEN];
	uint32_t now_ms;
	struct {
		uint32_t pkt_ts;
		uint32_t iss;
		IIP_TCP_CONN_P conns_ht[IIP_CONF_TCP_CONN_HT_SIZE];
	} tcp;
	struct {
		uint32_t prev_fast;
		uint32_t prev_slow;
		uint32_t prev_very_slow;
	} timer;
};

typedef struct iip_workspace * iip_mem_ptr_t;
#define IIP_MEM_P iip_mem_ptr_t
#define II_PB_P uint32_t

#define II_PB(_pb_id) (w->pbs.array[_pb_id])
#define II_TCP_CONN(_conn_id) (w->tcp_conns.array[_conn_id])

static int iip_run(IIP_MEM_P w, IIP_PKT_P pkt[], IIP_PKT_CNT_T cnt, uint32_t *next_us, IIP_OPAQUE_P opaque);
static int iip_tcp_ipv4_ethernet_connect(IIP_MEM_P w,
		uint8_t src_mac[II_ETH_ADDR_LEN], uint32_t src_ipv4_be, uint16_t src_port_be,
		uint8_t dst_mac[II_ETH_ADDR_LEN], uint32_t dst_ipv4_be, uint16_t dst_port_be,
		IIP_PKT_P *pkt, IIP_PKT_CNT_T cnt, uint8_t *fastopen_cookie_buf, uint8_t fastopen_cookie_len, uint8_t diffserv,
		IIP_OPAQUE_P opaque);
static enum iip_rc iip_tcp_close(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque);
static int iip_tcp_send(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_PKT_P pkts[], IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque);
static int iip_tcp_rxbuf_consumed(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_TCP_SEQ_INT_T consumed, IIP_OPAQUE_P opaque);
static int iip_arp_ethernet_request(IIP_MEM_P w, uint8_t local_mac[II_ETH_ADDR_LEN], uint32_t local_ip4_be, uint32_t target_ip4_be, IIP_OPAQUE_P opaque);

#endif

#ifndef SKIP_IIP_IMPLEMENTATION

#ifndef IIP_OPS_DEBUG_PRINTF
#define IIP_OPS_DEBUG_PRINTF() do { } while (0)
#endif
#ifndef IIP_OPS_ERROR_FATAL_SYS
#define IIP_OPS_ERROR_FATAL_SYS() do { } while (0)
#endif
#ifndef IIP_OPS_ERROR_FATAL_USR
#define IIP_OPS_ERROR_FATAL_USR() do { } while (0)
#endif
#ifndef IIP_OPS_ERROR_FATAL_SUB
#define IIP_OPS_ERROR_FATAL_SUB() do { } while (0)
#endif
#ifndef IIP_OPS_ERROR_FATAL_MEM
#define IIP_OPS_ERROR_FATAL_MEM() do { } while (0)
#endif

#ifndef IIP_OPS_PKT_VALID
#define IIP_OPS_PKT_VALID() do { iip_ret_bool = true; } while (0)
#endif
#ifndef IIP_OPS_PKT_ALLOC
#define IIP_OPS_PKT_ALLOC() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_PKT_FREE
#define IIP_OPS_PKT_FREE() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_PKT_GET_DATA
#define IIP_OPS_PKT_GET_DATA() do { iip_ret_u8_ptr = (uint8_t *) 0; } while (0)
#endif
#ifndef IIP_OPS_PKT_GET_LEN
#define IIP_OPS_PKT_GET_LEN() do { iip_ret_len = 0; } while (0)
#endif
#ifndef IIP_OPS_PKT_SET_LEN
#define IIP_OPS_PKT_SET_LEN() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_PKT_SCATTER_GATHER_APPEND
#define IIP_OPS_PKT_SCATTER_GATHER_APPEND() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_NIC_FEATURE_OFFLOAD_TX_SCATTER_GATHER
#define IIP_OPS_NIC_FEATURE_OFFLOAD_TX_SCATTER_GATHER() do { iip_ret_bool = false; } while (0)
#endif
#ifndef IIP_OPS_PKT_GET_CAPACITY
#define IIP_OPS_PKT_GET_CAPACITY() do { iip_ret_len = 0; } while (0)
#endif
#ifndef IIP_OPS_PKT_CLONE
#define IIP_OPS_PKT_CLONE() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_ETHERNET_ADDR_MATCH
#define IIP_OPS_ETHERNET_ADDR_MATCH() do { iip_ret_bool = true; } while (0)
#endif
#ifndef IIP_OPS_ETHERNET_HDR_CRAFT
#define IIP_OPS_ETHERNET_HDR_CRAFT() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_ETHERNET_PUSH
#define IIP_OPS_ETHERNET_PUSH() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_ETHERNET_FLUSH
#define IIP_OPS_ETHERNET_FLUSH() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_IPV4_ADDR_MATCH
#define IIP_OPS_IPV4_ADDR_MATCH() do { iip_ret_bool = true; } while (0)
#endif

#ifndef IIP_OPS_ARP_ETHERNET_REPLY
#define IIP_OPS_ARP_ETHERNET_REPLY() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_ACCEPT
#define IIP_OPS_TCP_ACCEPT() do { iip_ret_bool = true; } while (0)
#endif
#ifndef IIP_OPS_TCP_CLOSED
#define IIP_OPS_TCP_CLOSED() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_CONNECTED
#define IIP_OPS_TCP_CONNECTED() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_ACCEPTED
#define IIP_OPS_TCP_ACCEPTED() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_URGENT
#define IIP_OPS_TCP_URGENT() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_FASTOPEN_REQUEST
#define IIP_OPS_TCP_FASTOPEN_REQUEST() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_PAYLOAD
#define IIP_OPS_TCP_PAYLOAD() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_STATE_CLOSE_WAIT
#define IIP_OPS_TCP_STATE_CLOSE_WAIT() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_IPV4_FASTOPEN_CHECK
#define IIP_OPS_TCP_IPV4_FASTOPEN_CHECK() do { iip_ret_bool = false; } while (0)
#endif
#ifndef IIP_OPS_TCP_FASTOPEN_REQUEST
#define IIP_OPS_TCP_FASTOPEN_REQUEST() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_UDP_PAYLOAD
#define IIP_OPS_UDP_PAYLOAD() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_TCP_IP_NEGATIVE_ADVICE
#define IIP_OPS_TCP_IP_NEGATIVE_ADVICE() do { iip_ret_int = 0; } while (0)
#endif
#ifndef IIP_OPS_IPV4_RX_CHECKSUM
#define IIP_OPS_IPV4_RX_CHECKSUM() do { (void) opaque; } while (0)
#endif
#ifndef IIP_OPS_IPV4_TX_CHECKSUM
#define IIP_OPS_IPV4_TX_CHECKSUM() do { (void) opaque; } while (0)
#endif
#ifndef IIP_OPS_TCP_RX_CHECKSUM
#define IIP_OPS_TCP_RX_CHECKSUM() do { (void) opaque; } while (0)
#endif
#ifndef IIP_OPS_UDP_RX_CHECKSUM
#define IIP_OPS_UDP_RX_CHECKSUM() do { (void) opaque; } while (0)
#endif
#ifndef IIP_OPS_TCP_TX_SKIP_SW_CHECKSUM
#define IIP_OPS_TCP_TX_SKIP_SW_CHECKSUM() do { iip_ret_bool = false; } while (0)
#endif
#ifndef IIP_OPS_UDP_TX_SKIP_SW_CHECKSUM
#define IIP_OPS_UDP_TX_SKIP_SW_CHECKSUM() do { iip_ret_bool = false; } while (0)
#endif
#ifndef II_HOOK_TX_IPV4_ETHERNET
#define II_HOOK_TX_IPV4_ETHERNET() do { (void) opaque; } while (0)
#endif
#ifndef II_HOOK_TX_IPV4_ETHERNET_ZERO_COPY
#define II_HOOK_TX_IPV4_ETHERNET_ZERO_COPY() do { (void) opaque; } while (0)
#endif

/*@ logic integer f_ntohs{L}(integer x) = (uint16_t)(((uint32_t) x % 256) * 256) | (((uint32_t) x / 256) % 256); */
/*@ logic integer f_htons{L}(integer x) = f_ntohs{L}(x); */
/*@ logic integer f_ntohl{L}(integer x) = (uint32_t)((x & 0xff000000) / 16777216) | (uint32_t)((x & 0xff0000) / 256) | (uint32_t)((x & 0xff00) * 256) | (uint32_t)((x & 0xff) * 16777216); */
/*@ logic integer f_htonl{L}(integer x) = f_ntohl{L}(x); */

/*@ logic integer f_extract_ipv4_version{L}(uint8_t * buf) = buf[0] / 16; */
/*@ logic integer f_extract_ipv4_hdr_len{L}(uint8_t * buf) = (uint8_t)(((uint64_t) buf[0] % 16) * 4); */
/*@ logic integer f_extract_ipv4_more_flag{L}(uint8_t * buf) = (buf[6] & 0x20); */
/*@ logic integer f_extract_ipv4_reserved_flag{L}(uint8_t * buf) = (buf[6] & 0x80); */
/*@ logic integer f_extract_ipv4_proto{L}(uint8_t * buf) = buf[9]; */
/*@ logic integer f_extract_ipv4_tot_len{L}(uint8_t * buf) = f_ntohs((uint16_t)(((uint32_t) buf[3] * 256) | (uint32_t) buf[2])); */
/*@ logic integer f_extract_ipv4_payload_len{L}(uint8_t * buf) = f_extract_ipv4_tot_len{L}(buf) - f_extract_ipv4_hdr_len{L}(buf); */
/*@ logic integer f_extract_ipv4_off{L}(uint8_t * buf) = ((f_ntohs((uint16_t)(((uint32_t) buf[7] * 256) | (uint32_t) buf[6])) % 0x2000) * 8) % 0x10000; */

/*@
	requires \valid(opaque);
	assigns \nothing;
	ensures \result ==> f_iip_ops_pkt_valid(pkt, opaque);
 */
static bool ii_call_pkt_valid(IIP_PKT_P pkt, IIP_OPAQUE_P opaque)
{
	bool iip_ret_bool;
	IIP_OPS_PKT_VALID();
	return iip_ret_bool;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns \result \from opaque;
	ensures \result == f_iip_ops_pkt_get_data(pkt, opaque);
 */
static uint8_t *ii_call_pkt_get_data(IIP_PKT_P pkt, IIP_OPAQUE_P opaque)
{
	uint8_t *iip_ret_u8_ptr;
	IIP_OPS_PKT_GET_DATA();
	return iip_ret_u8_ptr;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns \nothing;
	ensures \result == f_iip_ops_pkt_get_len(pkt, opaque);
 */
static IIP_PKT_LEN_T ii_call_pkt_get_len(IIP_PKT_P pkt, IIP_OPAQUE_P opaque)
{
	IIP_PKT_LEN_T iip_ret_len;
	IIP_OPS_PKT_GET_LEN();
	return iip_ret_len;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns *opaque;
 */
static int ii_call_pkt_set_len(IIP_PKT_P pkt, IIP_PKT_LEN_T len, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_PKT_SET_LEN();
	return iip_ret_int;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(head_pkt, opaque);
	requires f_iip_ops_pkt_valid(tail_pkt, opaque);
	assigns *opaque;
 */
static int ii_call_pkt_scatter_gather_chain_append(IIP_PKT_P head_pkt, IIP_PKT_P tail_pkt, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_PKT_SCATTER_GATHER_APPEND();
	return iip_ret_int;
	{ /* unsused */
		(void) head_pkt;
		(void) tail_pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns \nothing;
	ensures \result == f_iip_ops_pkt_get_capacity(pkt, opaque);
 */
static IIP_PKT_LEN_T ii_call_pkt_get_capacity(IIP_PKT_P pkt, IIP_OPAQUE_P opaque)
{
	IIP_PKT_LEN_T iip_ret_len;
	IIP_OPS_PKT_GET_CAPACITY();
	return iip_ret_len;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(pkt);
	requires \separated(pkt, opaque);
	assigns *pkt, *opaque;
	ensures \result == 0 ==> f_iip_ops_pkt_valid(*pkt, opaque);
 */
static int ii_call_pkt_alloc(IIP_PKT_P *pkt, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_PKT_ALLOC();
	return iip_ret_int;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns *opaque;
 */
static int ii_call_pkt_free(IIP_PKT_P pkt, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_PKT_FREE();
	return iip_ret_int;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(cloned_pkt);
	requires \separated(opaque, cloned_pkt);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns *cloned_pkt, *opaque;
	ensures \result == 0 ==> f_iip_ops_pkt_valid(*cloned_pkt, opaque);
 */
static int ii_call_pkt_clone(IIP_PKT_P pkt, IIP_PKT_P *cloned_pkt, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_PKT_CLONE();
	return iip_ret_int;
	{ /* unsused */
		(void) pkt;
		(void) cloned_pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires f_iip_ops_pkt_valid(pkt, opaque);
	assigns *opaque;
 */
static int ii_call_ethernet_push(IIP_PKT_P pkt, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_ETHERNET_PUSH();
	return iip_ret_int;
	{ /* unsused */
		(void) pkt;
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(buf + (0 .. 13));
	requires \valid_read(dst_addr + (0 .. 5));
	assigns buf[0 .. 13];
 */
static int ii_call_ethernet_hdr_craft(uint8_t *buf, uint8_t dst_addr[], uint16_t proto_be, IIP_OPAQUE_P opaque)
{
	int iip_ret_int;
	IIP_OPS_ETHERNET_HDR_CRAFT();
	return iip_ret_int;
	{ /* unsused */
		(void) buf;
		(void) dst_addr;
		(void) proto_be;
		(void) opaque;
	}
}

/*@
  requires \valid_read(buf + (0 .. 1));
  assigns \nothing;
  ensures \result == (uint16_t)(((uint32_t) buf[1] * 256) | (uint32_t) buf[0]);
 */
static uint16_t ii_read_uint16(const uint8_t *buf)
{
	return (uint16_t)(((uint32_t) buf[1] * 256) | (uint32_t) buf[0]);
}

/*@
	requires \valid(buf + (0 .. 1));
	assigns buf[0 .. 1] \from val;
 */
static void ii_write_uint16(uint8_t *buf, uint16_t val)
{
	buf[1] = val / 256;
	buf[0] = val % 256;
}

/*@
	requires \valid_read(buf + (0 .. 3));
	assigns \nothing;
	ensures \result == (uint32_t)(((uint64_t) buf[3] * 16777216) | ((uint64_t) buf[2] * 65536) | ((uint64_t) buf[1] * 256) | (uint64_t) buf[0]);
 */
static uint32_t ii_read_uint32(const uint8_t *buf)
{
	return (uint32_t)(((uint64_t) buf[3] * 16777216) | ((uint64_t) buf[2] * 65536) | ((uint64_t) buf[1] * 256) | (uint64_t) buf[0]);
}

/*@
	requires \valid(buf + (0 .. 3));
	assigns buf[0 .. 3] \from val;
 */
static void ii_write_uint32(uint8_t *buf, uint32_t val)
{
	buf[3] = val / 16777216;
	buf[2] = (val % 16777216) / 65536;
	buf[1] = (val % 65536) / 256;
	buf[0] = val % 256;
}

/*@
	assigns \nothing;
	ensures \result == f_ntohs(x);
 */
static uint16_t ii_ntohs(uint16_t x)
{
	return (uint16_t)(((uint32_t) x % 256) * 256) | (((uint32_t) x / 256) % 256);
}

/*@
	assigns \nothing;
	ensures \result == f_htons(x);
 */
static uint16_t ii_htons(uint16_t x)
{
	return ii_ntohs(x);
}

/*@
	assigns \nothing;
	ensures \result == f_ntohl(x);
 */
static uint32_t ii_ntohl(uint32_t x)
{
	return ((x & 0xff000000) / 16777216) | ((x & 0xff0000) / 256) | ((x & 0xff00) * 256) | ((x & 0xff) * 16777216);
}

/*@
	assigns \nothing;
	ensures \result == f_htonl(x);
 */
static uint32_t ii_htonl(uint32_t x)
{
	return ii_ntohl(x);
}

/*@ logic integer f_seq_ordered{L}(uint32_t a, uint32_t b) = (b != a && (uint32_t)(b - a) < 0x80000000) ? true : false; */
/*@
	assigns \nothing;
	ensures \result == f_seq_ordered(a, b);
 */
static bool ii_seq_ordered(uint32_t a, uint32_t b)
{
	if (a == b)
		return false;
	if (b - a >= 0x80000000)
		return false;
	else
		return true;
}

/*@
	requires \valid(eq);
	assigns *eq;
 */
static enum iip_rc ii_extent_queue_remove(struct ii_extent_queue *eq, uint8_t idx)
{
	if (!eq->cnt) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (eq->cnt > II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (idx >= eq->cnt) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		if (eq->cnt > 1) {
			uint8_t i;
			/*@
				loop invariant idx <= i <= eq->cnt - 1;
				loop assigns i, eq->extent[idx .. eq->cnt - 2] \from eq->extent[idx + 1 .. eq->cnt - 1];
				loop variant eq->cnt - 1 - i;
				*/
			for (i = idx; i < eq->cnt - 1; i++)
				eq->extent[i] = eq->extent[i + 1];
		}
		eq->cnt--;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(eq);
	assigns *eq;
 */
static enum iip_rc ii_extent_queue_insert(struct ii_extent_queue *eq, uint8_t idx, uint32_t v, uint16_t l)
{
	if (eq->cnt > II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (eq->cnt == II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
	}
	if (idx > eq->cnt) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		if (eq->cnt > 0 && idx != eq->cnt) {
			uint8_t i = eq->cnt - 1;
			/*@
				loop invariant idx <= i <= eq->cnt - 1;
				loop assigns i, eq->extent[idx + 1 .. eq->cnt] \from eq->extent[idx .. eq->cnt - 1];
				loop variant i - idx;
				*/
			while (1) {
				eq->extent[i + 1] = eq->extent[i];
				if (i == idx)
					break;
				i--;
			}
		}
		eq->extent[idx].v = v;
		eq->extent[idx].l = l;
		eq->cnt++;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(eq);
	assigns *eq;
 */
static enum iip_rc ii_extent_queue_add(struct ii_extent_queue *eq, uint32_t val, uint32_t len)
{
	if (eq->cnt > II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (eq->cnt == II_CONF_EXTENT_QUEUE_SIZE)
		return IIP_ERR_BUF_FULL;
	{
		uint32_t v = val;
		uint16_t l = len;
		uint8_t max_loop = eq->cnt + 1, loop_cnt = 0;
		/*@
			loop invariant 0 <= loop_cnt <= max_loop;
			loop assigns v, l, loop_cnt, *eq;
			loop variant max_loop - loop_cnt;
		 */
		do {
			uint8_t i, continue_loop = 0, cnt = eq->cnt;
			if (cnt > II_CONF_EXTENT_QUEUE_SIZE) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			/*@
				loop invariant 0 <= loop_cnt <= max_loop;
				loop invariant 0 <= i <= cnt <= II_CONF_EXTENT_QUEUE_SIZE;
				loop assigns i, continue_loop, v, l, *eq;
				loop variant cnt - i;
			 */
			for (i = 0; i < cnt; i++) {
				if (v == eq->extent[i].v) {
					/*
					 *      v
					 *      |---- l ------
					 *
					 *   eq->v
					 *      |---- eq->l --
					 *
					 */
					if (v + l == eq->extent[i].v + eq->extent[i].l) {
						/* exactly same */
						break;
					} else if (ii_seq_ordered(v + l, eq->extent[i].v + l)) {
						/*
						 *      v
						 *      |---- l ------|
						 *
						 *   eq->v
						 *      |---- eq->l -----|
						 *
						 */
						break;
					} else {
						/*
						 *      v
						 *      |---- l ---------|
						 *
						 *   eq->v
						 *      |---- eq->l ---|
						 *
						 */
						if (ii_extent_queue_remove(eq, i) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						continue_loop = 1;
						continue;
					}
				} else if (ii_seq_ordered(v, eq->extent[i].v)) {
					/*
					 *      v
					 *      |---- l ------
					 *
					 *       eq->v
					 *          |---- eq->l --
					 *
					 */
					if (ii_seq_ordered(v + l, eq->extent[i].v)) {
						/*
						 *      v
						 *      |---- l --|
						 *
						 *                  eq->v
						 *                     |---- eq->l --
						 *
						 */
						if (ii_extent_queue_insert(eq, i, v, l) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						break;
					} else {
						if (ii_seq_ordered(v + l, eq->extent[i].v + eq->extent[i].l)) {
							/*
							 *      v
							 *      |---- l -----|
							 *
							 *         eq->v
							 *            |---- eq->l --|
							 *
							 */
							eq->extent[i].l = eq->extent[i].v + eq->extent[i].l - v;
							eq->extent[i].v = v;
							break;
						} else {
							/*
							 *      v
							 *      |---- l ------------|
							 *
							 *         eq->v
							 *            |-- eq->l --|
							 *
							 */
							if (ii_extent_queue_remove(eq, i) != IIP_ERR_OK) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
							continue_loop = 1;
							break;
						}
					}
				} else {
					/*
					 *         v
					 *         |---- l ------
					 *
					 *   eq->v
					 *      |---- eq->l --
					 *
					 */
					if (ii_seq_ordered(eq->extent[i].v + eq->extent[i].l, v)) {
						/*
						 *                   v
						 *                   |--- l --
						 *
						 *   eq->v
						 *      |- eq->l --|
						 *
						 */
						continue;
					} else {
						/*
						 *            v
						 *            |--- l --|
						 *
						 *   eq->v
						 *      |- eq->l --|
						 *
						 */
						l = v + l - eq->extent[i].v;
						v = eq->extent[i].v;
						if (ii_extent_queue_remove(eq, i) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						continue_loop = 1;
						break;
					}
				}
			}
			if (i == eq->cnt) {
				if (ii_extent_queue_insert(eq, i, v, l) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				break;
			}
			if (!continue_loop)
				break;
			loop_cnt++;
		} while (loop_cnt < max_loop);
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(eq);
	assigns *eq;
 */
static enum iip_rc ii_extent_queue_shrink(struct ii_extent_queue *eq, uint32_t to)
{
	if (eq->cnt > II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t max_loop = eq->cnt, loop_cnt = 0;
		/*@
			loop invariant 0 <= loop_cnt <= max_loop;
			loop assigns loop_cnt, *eq;
			loop variant max_loop - loop_cnt;
		 */
		do {
			uint8_t i, cnt = eq->cnt;
			if (cnt > II_CONF_EXTENT_QUEUE_SIZE) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}	
			/*@
				loop invariant 0 <= loop_cnt <= max_loop;
				loop invariant 0 <= i <= cnt <= II_CONF_EXTENT_QUEUE_SIZE;
				loop assigns i, *eq;
				loop variant cnt - i;
			*/
			for (i = 0; i < cnt; i++) {
				if (ii_seq_ordered(to, eq->extent[i].v)) {
					/*
					 * to
					 *    |--------------|
					 */
					break;
				} else {
					/*
					 *     to
					 *  |----------
					 */
					if (ii_seq_ordered(to, eq->extent[i].v + eq->extent[i].l)) {
						/*
						 *     to
						 *  |----------|
						 */
						eq->extent[i].l = eq->extent[i].v + eq->extent[i].l - to;
						eq->extent[i].v = to;
						break;
					} else {
						/*
						 *                to
						 *  |----------|
						 */
						ii_extent_queue_remove(eq, i);
					}
				}
			}
			loop_cnt++;
		} while (loop_cnt < max_loop);
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(pkts + (0 .. cnt - 1));
	requires \separated(pkts + (0 .. cnt - 1), opaque);
	requires 0 < cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
	assigns *opaque;
 */
static enum iip_rc ii_free_pkts(IIP_PKT_P *pkts, IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque)
{
	enum iip_rc rc = IIP_ERR_OK;
	{
		uint16_t i;
		/*@
			loop invariant 0 <= i <= cnt;
			loop assigns i, rc, *opaque;
			loop variant cnt - i;
			*/
		for (i = 0; i < cnt; i++) {
			if (!ii_call_pkt_valid(pkts[i], opaque))
					rc = IIP_ERR_FATAL_SYS;
			else if (ii_call_pkt_free(pkts[i], opaque)) {
				if (rc == IIP_ERR_OK
						|| rc == IIP_ERR_INVALID_RX
						|| rc == IIP_ERR_AGAIN)
					rc = IIP_ERR_FATAL_SUB;
			}
		}
	}
	return rc;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_free_pb_and_pkt(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_PB(pb_id).cnt && II_PB(pb_id).cnt <= II_CONF_IPV4_FRAG_CNT_MAX)
		ii_free_pkts(II_PB(pb_id).part_pkt, II_PB(pb_id).cnt, opaque);
	if (ii_free_pb(&w->pbs, pb_id) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	return IIP_ERR_OK;
}

/*@
	requires 0 < cnt ==> \valid_read(buf + (0 .. cnt - 1));
	requires 0 < cnt ==> \valid_read(len + (0 .. cnt - 1));
	requires \forall integer i; 0 <= i < cnt ==> 0 < len[i] ==> \valid_read(buf[i] + (0 .. len[i] - 1));
	assigns \nothing;
 */
static uint16_t ii_csum16(const uint8_t *buf[], const uint16_t len[], IIP_PKT_CNT_T cnt, uint16_t base)
{
	uint64_t r = 0; uint16_t n; uint8_t k;
	/*@
		loop invariant 0 <= n <= cnt;
		loop invariant 0 <= k <= 1;
		loop assigns r, n, k;
		loop variant cnt - n;
	 */
	for (n = 0, k = 0; n < cnt; n++) {
		uint16_t i;
		/*@
			loop invariant 0 <= n <= cnt;
			loop invariant 0 <= k <= 1;
			loop invariant 0 <= i <= len[n] + 1;
			loop assigns r, i, k;
			loop variant len[n] - i;
		 */
		for (i = 0; i < len[n]; ) {
			if ((k == 1) || (len[n] - i == 1)) {
				uint16_t v = buf[n][i] & 0x00ff;
				if (k == 0) {
					v = ((uint32_t) v << 8) & 0xffff;
					k = 1;
				} else {
					k = 0;
				}
				r += v;
				i += 1;
			} else {
				uint16_t v = ii_read_uint16(&buf[n][i]);
				r += ii_htons(v);
				i += 2;
			}
		}
	}
	r -= base;
	r = (r >> 16) + (r & 0x0000ffff);
	r = (r >> 16) + r;
	return (uint16_t)~((uint16_t) r);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint16_t ii_extract_tcp_src_be(const uint8_t *buf)
{
	return ii_read_uint16(buf);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint16_t ii_extract_tcp_dst_be(const uint8_t *buf)
{
	return ii_read_uint16(buf + 2);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint32_t ii_extract_tcp_seq_be(const uint8_t *buf)
{
	return ii_read_uint32(buf + 4);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint32_t ii_extract_tcp_ack_seq_be(const uint8_t *buf)
{
	return ii_read_uint32(buf + 8);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint32_t ii_extract_tcp_flags(const uint8_t *buf)
{
	return ii_read_uint16(buf + 12);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint32_t ii_extract_tcp_win_be(const uint8_t *buf)
{
	return ii_read_uint16(buf + 14);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint32_t ii_extract_tcp_csum_be(const uint8_t *buf)
{
	return ii_read_uint16(buf + 16);
}

/*@
	requires \valid_read(buf + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
 */
static uint32_t ii_extract_tcp_urg_p_be(const uint8_t *buf)
{
	return ii_read_uint16(buf + 18);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == f_extract_ipv4_version(buf);
 */
static uint8_t ii_extract_ipv4_version(const uint8_t *buf)
{
	return buf[0] / 16;
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == f_extract_ipv4_hdr_len(buf);
	ensures \result <= 60;
 */
static uint8_t ii_extract_ipv4_hdr_len(const uint8_t *buf)
{
	return (uint8_t)(((uint64_t) buf[0] % 16) * 4);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == f_extract_ipv4_tot_len(buf);
 */
static uint16_t ii_extract_ipv4_tot_len(const uint8_t *buf)
{
	return ii_ntohs(ii_read_uint16(&buf[2]));
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == buf[1];
 */
static uint8_t ii_extract_ipv4_tos(const uint8_t *buf)
{
	return buf[1];
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == f_ntohs((uint16_t)(((uint32_t) buf[5] * 256) | (uint32_t) buf[4]));
 */
static uint16_t ii_extract_ipv4_id(const uint8_t *buf)
{
	return ii_ntohs(ii_read_uint16(&buf[4]));
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == f_extract_ipv4_off(buf);
 */
static uint16_t ii_extract_ipv4_off(const uint8_t *buf)
{
	return ((((uint32_t) ii_ntohs(ii_read_uint16(&buf[6])) % 0x2000 /* & 0x1fff */) * 8) % 0x10000);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == (f_extract_ipv4_more_flag(buf) > 0 ? 1 : 0);
 */
static uint8_t ii_extract_ipv4_more_flag(const uint8_t *buf)
{
	return (buf[6] & 0x20) > 0 ? 1 : 0;
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == (f_extract_ipv4_reserved_flag(buf) > 0 ? 1 : 0);
 */
static uint8_t ii_extract_ipv4_reserved_flag(const uint8_t *buf)
{
	return (buf[6] & 0x80) > 0 ? 1 : 0;
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	requires f_extract_ipv4_tot_len(buf) >= f_extract_ipv4_hdr_len(buf);
	assigns \nothing;
	ensures \result == f_extract_ipv4_payload_len(buf);
 */
static uint16_t ii_extract_ipv4_payload_len(const uint8_t *buf)
{
	return ii_extract_ipv4_tot_len(buf) - ii_extract_ipv4_hdr_len(buf);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == buf[8];
 */
static uint8_t ii_extract_ipv4_ttl(const uint8_t *buf)
{
	return buf[8];
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == f_extract_ipv4_proto(buf);
 */
static uint8_t ii_extract_ipv4_proto(const uint8_t *buf)
{
	return buf[9];
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == (uint16_t)(((uint32_t) buf[11] * 256) | (uint32_t) buf[10]);
 */
static uint16_t ii_extract_ipv4_csum_be(const uint8_t *buf)
{
	return ii_read_uint16(&buf[10]);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == (uint32_t)(((uint64_t) buf[15] * 16777216) | ((uint64_t) buf[14] * 65536) | ((uint64_t) buf[13] * 256) | (uint64_t) buf[12]);
 */
static uint32_t ii_extract_ipv4_src_be(const uint8_t *buf)
{
	return ii_read_uint32(&buf[12]);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == (uint32_t)(((uint64_t) buf[19] * 16777216) | ((uint64_t) buf[18] * 65536) | ((uint64_t) buf[17] * 256) | (uint64_t) buf[16]);
 */
static uint32_t ii_extract_ipv4_dst_be(const uint8_t *buf)
{
	return ii_read_uint32(&buf[16]);
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	requires f_extract_ipv4_hdr_len(buf) >= II_IPV4_HDR_LEN_MINIMAL;
	assigns \nothing;
	ensures \result == f_extract_ipv4_hdr_len(buf) - II_IPV4_HDR_LEN_MINIMAL;
 */
static uint8_t ii_extract_ipv4_opt_len(const uint8_t *buf)
{
	return ii_extract_ipv4_hdr_len(buf) - II_IPV4_HDR_LEN_MINIMAL;
}

/*@
	requires \valid(addr + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(buf + (0 .. II_ETH_ADDR_LEN - 1));
	assigns addr[0] \from buf[ 6];
	assigns addr[1] \from buf[ 7];
	assigns addr[2] \from buf[ 8];
	assigns addr[3] \from buf[ 9];
	assigns addr[4] \from buf[10];
	assigns addr[5] \from buf[11];
 */
static void ii_extract_ethernet_src(uint8_t addr[II_ETH_ADDR_LEN], uint8_t *buf)
{
	addr[0] = buf[ 6];
	addr[1] = buf[ 7];
	addr[2] = buf[ 8];
	addr[3] = buf[ 9];
	addr[4] = buf[10];
	addr[5] = buf[11];
}

/*@
	requires \valid(addr + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(buf + (6 .. 6 + II_ETH_ADDR_LEN - 1));
	assigns addr[0] \from buf[0];
	assigns addr[1] \from buf[1];
	assigns addr[2] \from buf[2];
	assigns addr[3] \from buf[3];
	assigns addr[4] \from buf[4];
	assigns addr[5] \from buf[5];
 */
static void ii_extract_ethernet_dst(uint8_t addr[II_ETH_ADDR_LEN], uint8_t *buf)
{
	addr[0] = buf[0];
	addr[1] = buf[1];
	addr[2] = buf[2];
	addr[3] = buf[3];
	addr[4] = buf[4];
	addr[5] = buf[5];
}

/*@
	logic integer f__pb_ipv4_payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque, integer cnt) =
	cnt <= 0 ? 0 :
	(uint16_t)((uint16_t)f_extract_ipv4_payload_len(f_iip_ops_pkt_get_data(II_PB(pb_id).part_pkt[cnt - 1], opaque) + II_ETH_HDR_LEN) + (uint16_t) f__pb_ipv4_payload_len(w, pb_id, opaque, cnt - 1));
	logic integer f_pb_ipv4_payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque) = f__pb_ipv4_payload_len(w, pb_id, opaque, w->pbs.array[pb_id].cnt);
 */
/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(payload_len);
	requires \separated(w, payload_len, opaque);
	assigns *payload_len;
 */
static enum iip_rc ii_pb_ipv4_payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_PKT_LEN_T *payload_len, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (w->pbs.array[pb_id].cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t len = 0;
		{
			uint16_t i, cnt = w->pbs.array[pb_id].cnt;
			/*@
				loop invariant 0 <= i <= cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
				loop assigns i, len;
				loop variant cnt - i;
			 */
			for (i = 0; i < cnt; i++) {
				if (!ii_call_pkt_valid(w->pbs.array[pb_id].part_pkt[i], opaque)) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_extract_ipv4_tot_len(ii_call_pkt_get_data(w->pbs.array[pb_id].part_pkt[i], opaque) + II_ETH_HDR_LEN) < ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(w->pbs.array[pb_id].part_pkt[i], opaque) + II_ETH_HDR_LEN)) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				len += ii_extract_ipv4_payload_len(ii_call_pkt_get_data(w->pbs.array[pb_id].part_pkt[i], opaque) + II_ETH_HDR_LEN);
			}
			*payload_len = len;
			return IIP_ERR_OK;
		}
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(copied_len);
	requires \valid(buf + (0 .. buf_len - 1));
	requires 0 < buf_len ==> \separated(w, buf + (0 .. buf_len - 1));
	requires 0 < buf_len ==> \separated(buf + (0 .. buf_len - 1), opaque);
	assigns buf[0 .. buf_len - 1], *copied_len;
 */
static enum iip_rc ii_pb_payload_copy(IIP_MEM_P w, II_PB_P pb_id, IIP_PKT_LEN_T skip, uint8_t *buf, IIP_PKT_LEN_T buf_len, IIP_PKT_LEN_T *copied_len, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (w->pbs.array[pb_id].cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_LEN_T len = 0;
		{
			IIP_PKT_CNT_T i, s, cnt = w->pbs.array[pb_id].cnt;
			/*@
				loop invariant 0 <= i <= cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
				loop invariant 0 <= s <= skip;
				loop invariant 0 <= len <= buf_len;
				loop assigns i, s, len, buf[0 .. buf_len - 1];
				loop variant cnt - i;
			 */
			for (i = 0, s = 0; i < cnt; i++) {
				if (!ii_call_pkt_valid(w->pbs.array[pb_id].part_pkt[i], opaque)) {
					IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
				} else {
					IIP_PKT_LEN_T off = skip - s, payload_len = ii_call_pkt_get_len(w->pbs.array[pb_id].part_pkt[i], opaque);
					if (payload_len < off) {
						s += payload_len;
						continue;
					}
					{
						IIP_PKT_CNT_T j, cp_len = payload_len - off;
						/*@
							loop invariant 0 <= i <= cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
							loop invariant 0 <= j <= cp_len;
							loop invariant 0 <= len <= buf_len;
							loop assigns j, len, buf[0 .. buf_len - 1];
							loop variant cp_len - j;
						 */
						for (j = 0; j < cp_len && len < buf_len; j++) {
							if (ii_call_pkt_get_capacity(w->pbs.array[pb_id].part_pkt[i], opaque) <= j + off) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
							buf[len++] = ii_call_pkt_get_data(w->pbs.array[pb_id].part_pkt[i], opaque)[j + off];
						}
					}
					s += off;
				}
			}
		}
		*copied_len = len;
	}
	return IIP_ERR_OK;
}

/*@
	requires 0 < cnt ==> \valid_read(buf + (0 .. cnt - 1));
	requires 0 < cnt ==> \valid_read(buf_len + (0 .. cnt - 1));
	requires \forall integer i; 0 <= i < cnt ==> (0 < buf_len[i] ==> \valid_read(buf[i] + (0 .. buf_len[i] - 1)));
	requires 0 < len ==> \valid(dst + (0 .. len - 1));
	assigns dst[0 .. len - 1];
	ensures \result <= len;
 */
static uint16_t ii_iov_copy(const uint8_t **buf, uint16_t *buf_len, IIP_PKT_CNT_T cnt, uint16_t off, uint8_t *dst, uint16_t len)
{
	uint16_t copied = 0, skip = 0;
	{
		uint16_t i;
		/*@
			loop invariant 0 <= i <= cnt;
			loop invariant copied <= len;
			loop assigns i, copied, skip, dst[0 .. len - 1];
			loop variant cnt - i;
		 */
		for (i = 0; i < cnt && copied < len; i++) {
			uint16_t j;
			/*@
				loop invariant 0 <= j <= buf_len[i];
				loop invariant 0 <= i <= cnt;
				loop invariant copied <= len;
				loop assigns j, copied, skip, dst[0 .. len - 1];
				loop variant buf_len[i] - j;
			 */
			for (j = 0; j < buf_len[i] && copied < len; j++) {
				if (skip == off) {
					dst[copied] = buf[i][j];
					copied++;
				} else
					skip++;
			}
		}
	}
	return copied;
}

/*@
	requires 0 < cnt;
	requires \valid_read(buf_len + (0 .. cnt - 1));
	requires \valid(total_len);
	assigns *total_len \from buf_len[0 .. cnt - 1];
 */
static enum iip_rc ii_iov_total_len(uint16_t *buf_len, IIP_PKT_CNT_T cnt, IIP_PKT_LEN_T *total_len)
{
	uint16_t len = 0;
	{
		uint16_t i;
		/*@
			loop invariant 0 <= i <= cnt;
			loop assigns i, len;
			loop variant cnt - i;
		 */
		for (i = 0; i < cnt; i++) {
			if ((uint32_t) len + buf_len[i] > 0xffff) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			len += buf_len[i];
		}
	}
	*total_len = len;
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns \nothing;
 */
static enum iip_rc ii_ipv4_l4_input__csum_with_pseudo(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t buf_len;
		if (ii_pb_ipv4_payload_len(w, pb_id, &buf_len, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		{
			uint8_t pseudo_hdr_ipv4[12];
			ii_write_uint32(pseudo_hdr_ipv4 + 0, ii_extract_ipv4_src_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN));
			ii_write_uint32(pseudo_hdr_ipv4 + 4, ii_extract_ipv4_dst_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN));
			pseudo_hdr_ipv4[ 8] = 0;
			pseudo_hdr_ipv4[ 9] = ii_extract_ipv4_proto(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN);
			ii_write_uint16(pseudo_hdr_ipv4 + 10, ii_htons(buf_len));
			{
				const uint8_t *buf_ptr[1 + II_CONF_IPV4_FRAG_CNT_MAX];
				uint16_t len[1 + II_CONF_IPV4_FRAG_CNT_MAX];
				buf_ptr[0] = pseudo_hdr_ipv4;
				len[0] = sizeof(pseudo_hdr_ipv4);
				if (II_PB(pb_id).cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				{
					IIP_PKT_CNT_T i, cnt = II_PB(pb_id).cnt;
					/*@
						loop invariant 0 <= i <= cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
						loop invariant buf_ptr[0] == pseudo_hdr_ipv4;
						loop invariant len[0] == sizeof(pseudo_hdr_ipv4);
						loop invariant \valid_read(buf_ptr[0] + (0 .. len[0] - 1));
						loop invariant \forall integer j; 0 <= j < i ==> buf_ptr[1 + j] == f_iip_ops_pkt_get_data(II_PB(pb_id).part_pkt[j], opaque) + II_ETH_HDR_LEN + f_extract_ipv4_hdr_len(f_iip_ops_pkt_get_data(II_PB(pb_id).part_pkt[j], opaque) + II_ETH_HDR_LEN);
						loop invariant \forall integer j; 0 <= j < i ==> len[1 + j] == f_extract_ipv4_payload_len(f_iip_ops_pkt_get_data(II_PB(pb_id).part_pkt[j], opaque) + II_ETH_HDR_LEN);
						loop invariant \forall integer j; 0 <= j < i ==>  f_extract_ipv4_payload_len(f_iip_ops_pkt_get_data(II_PB(pb_id).part_pkt[j], opaque) + II_ETH_HDR_LEN) <= f_iip_ops_pkt_get_capacity(II_PB(pb_id).part_pkt[j], opaque);
						loop invariant \forall integer j; 0 <= j < i ==> \valid_read(buf_ptr[1 + j] + (0 .. len[1 + j] - 1));
						loop invariant \forall integer j; 0 <= j < 1 + i ==> \valid_read(buf_ptr[j] + (0 .. len[j] - 1));
						loop assigns i, buf_ptr[1 .. cnt], len[1 .. cnt];
						loop variant cnt - i;
					 */
					for (i = 0; i < cnt; i++) {
						if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[i], opaque)) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						if (ii_call_pkt_get_len(II_PB(pb_id).part_pkt[i], opaque) < II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN)) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						if (ii_extract_ipv4_tot_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN) < ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN)) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						if (ii_extract_ipv4_payload_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN) > ii_call_pkt_get_capacity(II_PB(pb_id).part_pkt[i], opaque) - II_ETH_HDR_LEN - ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN)) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						buf_ptr[1 + i] = ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN);
						len[1 + i] = ii_extract_ipv4_payload_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque) + II_ETH_HDR_LEN);
					}
				}
				if (ii_csum16(buf_ptr, len, 1 + II_PB(pb_id).cnt, 0))
					return IIP_ERR_INVALID_RX;
				else
					return IIP_ERR_OK;
			}
		}
	}
}

/*
 * ---------------------------------------
 *  icmp
 * ---------------------------------------
 */

/*@
	requires \valid(opaque);
	assigns f_iip_ops_pkt_get_data(tx_pkt, opaque)[off + (10 .. 11)];
 */
static enum iip_rc ii_ipv4_tx_csum(IIP_PKT_P tx_pkt, IIP_PKT_LEN_T off, IIP_PKT_LEN_T len, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(tx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_OPS_IPV4_TX_CHECKSUM();
	}
	if (off + len > ii_call_pkt_get_capacity(tx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (off + 12 > ii_call_pkt_get_capacity(tx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t *buf = ii_call_pkt_get_data(tx_pkt, opaque) + off;
		{
			const uint8_t *buf_ptr[1];
			buf_ptr[0] = buf;
			{
				uint16_t l[1];
				l[0] = len;
				ii_write_uint16(&buf[10], ii_htons(ii_csum16(buf_ptr, l, 1, 0)));
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns buf[ 0 .. 1];
	assigns buf[ 2 .. 3] \from payload_len;
	assigns buf[ 4 .. 5] \from id;
	assigns buf[ 6 .. 7] \from off;
	assigns buf[ 8] \from ttl;
	assigns buf[ 9] \from proto;
	assigns buf[10 .. 11];
	assigns buf[12 .. 15] \from ipv4_src_be;
	assigns buf[16 .. 19] \from ipv4_dst_be;
 */
static void ii_ipv4_hdr_craft_minimal(uint8_t buf[II_IPV4_HDR_LEN_MINIMAL],
		uint8_t tos, uint16_t payload_len, uint16_t id, uint16_t off, uint8_t flags,
		uint8_t ttl, uint8_t proto, uint32_t ipv4_src_be, uint32_t ipv4_dst_be)
{
	buf[0] = (4 /* ivp4 */ << 4) | (II_IPV4_HDR_LEN_MINIMAL / 4);
	buf[1] = tos;
	ii_write_uint16(&buf[2], ii_htons(II_IPV4_HDR_LEN_MINIMAL + payload_len));
	ii_write_uint16(&buf[4], ii_htons(id));
	ii_write_uint16(&buf[6], ii_htons(off / 8));
	buf[ 6] |= flags;
	buf[ 8] = ttl;
	buf[ 9] = proto;
	buf[10] = 0; /* csum_be */
	buf[11] = 0; /* csum_be */
	ii_write_uint32(&buf[12], ipv4_src_be);
	ii_write_uint32(&buf[16], ipv4_dst_be);

}

/*@
	requires \valid(opaque);
	requires \valid(icmp_hdr + (0 .. II_ICMP_HDR_LEN - 1));
	requires f_iip_ops_pkt_valid(rx_pkt, opaque);
	assigns icmp_hdr[0 .. 3];
	assigns icmp_hdr[4] \from f_iip_ops_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + f_extract_ipv4_hdr_len(f_iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 4];
	assigns icmp_hdr[5] \from f_iip_ops_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + f_extract_ipv4_hdr_len(f_iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 5];
	assigns icmp_hdr[6] \from f_iip_ops_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + f_extract_ipv4_hdr_len(f_iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 6];
	assigns icmp_hdr[7] \from f_iip_ops_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + f_extract_ipv4_hdr_len(f_iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 7];
 */
static void ii_icmp_echo_xmit_reply__icmp_hdr_craft_base(uint8_t icmp_hdr[II_ICMP_HDR_LEN], IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	icmp_hdr[0] = 0 /* reply */; /* icmp type */
	icmp_hdr[1] = 0; /* code */
	icmp_hdr[2] = 0; /* csum_be */
	icmp_hdr[3] = 0; /* csum_be */
	icmp_hdr[4] = ii_call_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 4]; /* rest */
	icmp_hdr[5] = ii_call_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 5]; /* rest */
	icmp_hdr[6] = ii_call_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 6]; /* rest */
	icmp_hdr[7] = ii_call_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) + 7]; /* rest */
}

/*@
	requires \valid(icmp_hdr + (0 .. II_ICMP_HDR_LEN - 1));
	requires II_ICMP_HDR_LEN <= buf_len;
	requires \valid_read(buf + (0 .. buf_len - 1));
	assigns icmp_hdr[2 .. 3];
 */
static void ii_icmp_echo_xmit_reply__icmp_hdr_craft_csum(uint8_t icmp_hdr[II_ICMP_HDR_LEN], const uint8_t *buf, uint16_t buf_len)
{
	const uint8_t *buf_ptr[2];
	buf_ptr[0] = icmp_hdr;
	buf_ptr[1] = &buf[II_ICMP_HDR_LEN];
	{
		uint16_t len[2];
		len[0] = II_ICMP_HDR_LEN;
		len[1] = buf_len - II_ICMP_HDR_LEN;
		ii_write_uint16(&icmp_hdr[2], ii_htons(ii_csum16(buf_ptr, len, 2, 0)));
	}
}

/*@
	requires 0 < cnt;
	requires 0 < total_len;
	requires \valid_read(buf + (0 .. cnt - 1));
	requires \valid_read(buf_len + (0 .. cnt - 1));
	requires \valid_read(dst_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \forall integer i; 0 <= i < cnt ==> 0 < buf_len[i] ==> \valid_read(buf[i] + (0 .. buf_len[i] - 1));
	requires \valid(tx_pkts + (0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1));
	requires \valid(tx_len + (0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1));
	requires \valid(tx_pkt_cnt);
	requires \valid(opaque);
	requires \separated(
		buf     + (0 .. cnt - 1),
		buf_len + (0 .. cnt - 1),
		tx_pkts + (0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1),
		tx_len  + (0 .. II_CONF_IPV4_FRAG_CNT_MAX),
		tx_pkt_cnt,
		dst_mac + (0 .. II_ETH_ADDR_LEN - 1),
		opaque);
	assigns tx_pkts[0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1];
	assigns tx_len[0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1];
	assigns *tx_pkt_cnt;
	assigns *opaque;
	ensures 0 <= *tx_pkt_cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
	ensures 0 < *tx_pkt_cnt ==> \valid_read(tx_pkts + (0 .. *tx_pkt_cnt - 1));
	ensures 0 < *tx_pkt_cnt ==> \valid_read(tx_len + (0 .. *tx_pkt_cnt - 1));
 */
static enum iip_rc ipv4_send_ethernet__prepare_tx_pkts(
		const uint8_t **buf, uint16_t *buf_len, IIP_PKT_CNT_T cnt, uint16_t total_len,
		IIP_PKT_P tx_pkts[II_CONF_IPV4_FRAG_CNT_MAX], uint16_t tx_len[II_CONF_IPV4_FRAG_CNT_MAX], uint16_t *tx_pkt_cnt,
		uint8_t dst_mac[II_ETH_ADDR_LEN],
		uint32_t dst_ipv4_be, uint32_t src_ipv4_be,
		uint8_t proto, uint8_t diffserv, IIP_OPAQUE_P opaque)
{
	*tx_pkt_cnt = 0;
	{
		IIP_PKT_CNT_T pkt_cnt = 0, xmit_len = 0;
		uint8_t is_err = 0;
		/*@
			loop invariant 0 <= pkt_cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
			loop invariant 0 <= xmit_len <= total_len;
			loop invariant \forall integer i; 0 <= i < cnt ==> (0 < buf_len[i] ==> \valid_read(buf[i] + (0 .. buf_len[i] - 1)));
			loop invariant \separated(
				buf     + (0 .. cnt - 1),
				buf_len + (0 .. cnt - 1),
				tx_pkts + (0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1),
				tx_len  + (0 .. II_CONF_IPV4_FRAG_CNT_MAX),
				tx_pkt_cnt,
				dst_mac + (0 .. II_ETH_ADDR_LEN - 1),
			opaque);
			loop assigns pkt_cnt;
			loop assigns xmit_len;
			loop assigns is_err;
			loop assigns tx_pkts[0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1];
			loop assigns tx_len[0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1];
			loop assigns *opaque;
			loop variant total_len - xmit_len;
		 */
		while (pkt_cnt < II_CONF_IPV4_FRAG_CNT_MAX && xmit_len < total_len) {
			IIP_PKT_P tx_pkt;
			if (ii_call_pkt_alloc(&tx_pkt, opaque)) {
				is_err = 1;
				break;
			}
			tx_pkts[pkt_cnt] = tx_pkt;
			pkt_cnt++;
			II_HOOK_TX_IPV4_ETHERNET();
			{
				uint16_t tx_bytes;
				if (ii_call_pkt_get_capacity(tx_pkt, opaque) < (II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL)) {
					is_err = 1;
					break;
				}
				tx_bytes = ii_call_pkt_get_capacity(tx_pkt, opaque) - (II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL);
				if (tx_bytes > total_len - xmit_len)
					tx_bytes = total_len - xmit_len;
				else
					tx_bytes = tx_bytes & 0xfff8; /* aligned by 8 for fragmentation */
				if (ii_iov_copy(buf, buf_len, cnt, xmit_len, ii_call_pkt_get_data(tx_pkt, opaque) + II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL, tx_bytes) != tx_bytes) {
					is_err = 1;
					break;
				}
				if (ii_call_ethernet_hdr_craft(ii_call_pkt_get_data(tx_pkt, opaque), dst_mac, ii_htons(0x0800) /* ipv4 */, opaque)) {
					is_err = 1;
					break;
				}
				ii_ipv4_hdr_craft_minimal(ii_call_pkt_get_data(tx_pkt, opaque) + II_ETH_HDR_LEN, diffserv,
						tx_bytes, 0 /* TODO: id randomization  */, xmit_len,
						xmit_len + tx_bytes == total_len ? 0 : 0x20 /* more flag */,
						64, proto,
						src_ipv4_be, dst_ipv4_be);
				if (ii_ipv4_tx_csum(tx_pkt, II_ETH_HDR_LEN, II_IPV4_HDR_LEN_MINIMAL, opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				tx_len[pkt_cnt - 1] = tx_bytes;
				xmit_len += tx_bytes;
			}
		}
		*tx_pkt_cnt = pkt_cnt;
		if (xmit_len < total_len || is_err) {
			IIP_PKT_CNT_T i;
			/*@
				loop invariant 0 <= pkt_cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
				loop invariant 0 <= i <= pkt_cnt;
				loop assigns i, *opaque;
				loop variant pkt_cnt - i;
			 */
			for (i = 0; i < pkt_cnt; i++) {
				if (ii_call_pkt_free(tx_pkts[i], opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
			}
			IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
		} else
			return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid_read(tx_pkts + (0 .. tx_pkt_cnt - 1));
	requires \valid_read(tx_len + (0 .. tx_pkt_cnt - 1));
	requires \valid(xmitted_cnt);
	requires \separated(tx_pkts + (0 .. tx_pkt_cnt - 1),
		tx_len + (0 .. tx_pkt_cnt - 1), xmitted_cnt, opaque);
	assigns *xmitted_cnt, *opaque;
 */
static enum iip_rc ipv4_send_ethernet__xmit_tx_pkts(IIP_PKT_P tx_pkts[II_CONF_IPV4_FRAG_CNT_MAX],
		uint16_t tx_len[II_CONF_IPV4_FRAG_CNT_MAX], uint16_t tx_pkt_cnt,
		uint16_t *xmitted_cnt, IIP_OPAQUE_P opaque)
{
	uint16_t i;
	/*@
		loop invariant 0 <= i <= tx_pkt_cnt;
		loop assigns i, *opaque;
		loop variant tx_pkt_cnt - i;
	 */
	for (i = 0; i < tx_pkt_cnt; i++) {
		if (!ii_call_pkt_valid(tx_pkts[i], opaque)) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ii_call_pkt_set_len(tx_pkts[i], II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL + tx_len[i], opaque))
			break;
		if (ii_call_ethernet_push(tx_pkts[i], opaque))
			break;
	}
	*xmitted_cnt = i;
	if (i != tx_pkt_cnt) {
		IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
	} else
		return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid_read(tx_pkts + (0 .. II_CONF_IPV4_FRAG_CNT_MAX - 1));
	assigns *opaque;
 */
static enum iip_rc ipv4_send_ethernet__cancel_tx_pkts(
		IIP_PKT_P tx_pkts[II_CONF_IPV4_FRAG_CNT_MAX],
		uint16_t from_idx, uint16_t to_idx, IIP_OPAQUE_P opaque)
{
	if (from_idx > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (to_idx > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (from_idx >= to_idx) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t i;
		/*@
			loop invariant from_idx <= i <= to_idx;
			loop assigns i, *opaque;
			loop variant to_idx - i;
		 */
		for (i = from_idx; i < to_idx; i++) {
			if (!ii_call_pkt_valid(tx_pkts[i], opaque)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			if (ii_call_pkt_free(tx_pkts[i], opaque)) {
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
		}
		return IIP_ERR_OK;
	}
}

/* simple copy-based ipv4 send, supporting fragmentation */
/*@
	requires \valid(opaque);
	requires \valid_read(src_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(dst_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires 0 < cnt;
	requires \valid_read(buf + (0 .. cnt - 1));
	requires \valid_read(buf_len + (0 .. cnt - 1));
	requires \forall integer i; 0 <= i < cnt ==> 0 < buf_len[i] ==> \valid_read(buf[i] + (0 .. buf_len[i] - 1));
	requires \separated(
		src_mac + (0 .. II_ETH_ADDR_LEN - 1),
		dst_mac + (0 .. II_ETH_ADDR_LEN - 1),
		buf + (0 .. cnt - 1),
		buf_len + (0 .. cnt - 1),
		opaque);
	assigns *opaque;
 */
static enum iip_rc ii_ipv4_send_ethernet(
		uint8_t src_mac[II_ETH_ADDR_LEN], uint32_t src_ipv4_be,
		uint8_t dst_mac[II_ETH_ADDR_LEN], uint32_t dst_ipv4_be, uint8_t proto, uint8_t diffserv,
		const uint8_t **buf, IIP_PKT_LEN_T *buf_len, IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque)
{
	uint16_t total_len;
	if (ii_iov_total_len(buf_len, cnt, &total_len) != IIP_ERR_OK)
		return IIP_ERR_INVALID_RX;
	if (!total_len)
		return IIP_ERR_INVALID_RX;
	{
		IIP_PKT_P tx_pkts[II_CONF_IPV4_FRAG_CNT_MAX];
		uint16_t tx_len[II_CONF_IPV4_FRAG_CNT_MAX];
		uint16_t tx_pkt_cnt = 0;
		if (ipv4_send_ethernet__prepare_tx_pkts(
					buf, buf_len, cnt, total_len,
					tx_pkts, tx_len, &tx_pkt_cnt,
					dst_mac, dst_ipv4_be, src_ipv4_be,
					proto, diffserv, opaque) != IIP_ERR_OK) {
			if (tx_pkt_cnt)
				return ipv4_send_ethernet__cancel_tx_pkts(tx_pkts, 0, tx_pkt_cnt, opaque);
			else {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		} else {
			uint16_t xmitted_cnt = 0;
			if (ipv4_send_ethernet__xmit_tx_pkts(tx_pkts, tx_len, tx_pkt_cnt, &xmitted_cnt, opaque) != IIP_ERR_OK) {
				if (xmitted_cnt < tx_pkt_cnt)
					return ipv4_send_ethernet__cancel_tx_pkts(tx_pkts, xmitted_cnt, tx_pkt_cnt, opaque);
				else {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			} else
				return IIP_ERR_OK;
		}
	}
	{ /* unused */
		(void) src_mac;
	}
}

/*@
	requires \valid(opaque);
	requires \valid_read(src_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(dst_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires 0 < cnt;
	requires \valid_read(hdr_buf + (0 .. cnt - 1));
	requires \valid_read(hdr_buf_len + (0 .. cnt - 1));
	requires \forall integer i; 0 <= i < cnt ==> 0 < hdr_buf_len[i] ==> \valid_read(hdr_buf[i] + (0 .. hdr_buf_len[i] - 1));
	requires \separated(
		src_mac + (0 .. II_ETH_ADDR_LEN - 1),
		dst_mac + (0 .. II_ETH_ADDR_LEN - 1),
		hdr_buf + (0 .. cnt - 1),
		hdr_buf_len + (0 .. cnt - 1),
		opaque);
	assigns *opaque;
 */
static enum iip_rc ii_ipv4_send_ethernet_zero_copy(
		uint8_t src_mac[II_ETH_ADDR_LEN], uint32_t src_ipv4_be,
		uint8_t dst_mac[II_ETH_ADDR_LEN], uint32_t dst_ipv4_be, uint8_t proto, uint8_t diffserv,
		const uint8_t **hdr_buf, IIP_PKT_LEN_T *hdr_buf_len, IIP_PKT_CNT_T cnt,
		IIP_PKT_P tx_pkt, IIP_PKT_LEN_T payload_len, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(tx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_P cloned_tx_pkt;
		if (ii_call_pkt_clone(tx_pkt, &cloned_tx_pkt, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
		}
		{
			IIP_PKT_P head_pkt;
			if (ii_call_pkt_alloc(&head_pkt, opaque)) {
				if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
			}
			if (ii_call_ethernet_hdr_craft(ii_call_pkt_get_data(head_pkt, opaque), dst_mac, ii_htons(0x0800) /* ipv4 */, opaque)) {
				if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				if (ii_call_pkt_free(head_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
			{
				IIP_PKT_LEN_T hdr_len;
				if (ii_iov_total_len(hdr_buf_len, cnt, &hdr_len) != IIP_ERR_OK) {
					if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					if (ii_call_pkt_free(head_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL + hdr_len > ii_call_pkt_get_capacity(head_pkt, opaque)) {
					if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					if (ii_call_pkt_free(head_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_iov_copy(hdr_buf, hdr_buf_len, cnt, 0, ii_call_pkt_get_data(head_pkt, opaque) + II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL, hdr_len) != hdr_len) {
					if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					if (ii_call_pkt_free(head_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				ii_ipv4_hdr_craft_minimal(ii_call_pkt_get_data(head_pkt, opaque) + II_ETH_HDR_LEN, diffserv,
						hdr_len + payload_len, 0 /* TODO: id randomization  */, 0,
						0, 64, proto,
						src_ipv4_be, dst_ipv4_be);
				if (ii_ipv4_tx_csum(head_pkt, II_ETH_HDR_LEN, II_IPV4_HDR_LEN_MINIMAL, opaque) != IIP_ERR_OK) {
					if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					if (ii_call_pkt_free(head_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_call_pkt_set_len(head_pkt, II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL + hdr_len, opaque)) {
					if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					if (ii_call_pkt_free(head_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				II_HOOK_TX_IPV4_ETHERNET_ZERO_COPY();
			}
			if (ii_call_pkt_scatter_gather_chain_append(head_pkt, cloned_tx_pkt, opaque)) {
				if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				if (ii_call_pkt_free(head_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
			if (ii_call_ethernet_push(head_pkt, opaque)) {
				if (ii_call_pkt_free(cloned_tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				if (ii_call_pkt_free(head_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
		}
	}
	return IIP_ERR_OK;
	{ /* unused */
		(void) src_mac;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid_read(buf + (0 .. buf_len - 1));
	requires II_ICMP_HDR_LEN <= buf_len;
	requires \separated(w, buf + (0 .. buf_len - 1), opaque);
	assigns *opaque;
 */
static enum iip_rc ii_icmp_echo_xmit_reply(IIP_MEM_P w, II_PB_P pb_id, const uint8_t *buf, uint16_t buf_len, IIP_OPAQUE_P opaque)
{
	uint8_t icmp_hdr[II_ICMP_HDR_LEN];
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	ii_icmp_echo_xmit_reply__icmp_hdr_craft_base(icmp_hdr, II_PB(pb_id).part_pkt[0], opaque);
	ii_icmp_echo_xmit_reply__icmp_hdr_craft_csum(icmp_hdr, buf, buf_len);
	{
		const uint8_t *bufs[2];
		IIP_PKT_LEN_T lens[2];
		bufs[0] = icmp_hdr;
		lens[0] = II_ICMP_HDR_LEN;
		if (buf_len > II_ICMP_HDR_LEN) {
			bufs[1] = &buf[II_ICMP_HDR_LEN];
			lens[1] = buf_len - II_ICMP_HDR_LEN;
		}
		{
			uint8_t src_mac[II_ETH_ADDR_LEN], dst_mac[II_ETH_ADDR_LEN]; /* for separation */
			ii_extract_ethernet_src(src_mac, ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque));
			ii_extract_ethernet_dst(dst_mac, ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque));
			/* TODO: support other than ethernet */
			return ii_ipv4_send_ethernet(
					dst_mac,
					ii_extract_ipv4_dst_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN),
					src_mac,
					ii_extract_ipv4_src_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN),
					1 /* icmp */, 0,
					bufs, lens, buf_len > II_ICMP_HDR_LEN ? 2 : 1, opaque);
		}
	}
}

/*@
	requires 0 < buf_len;
	requires \valid_read(buf + (0 .. buf_len - 1));
	assigns \nothing;
 */
static enum iip_rc ii_icmp_validation(const uint8_t *buf, uint16_t buf_len)
{
	if (buf_len < II_ICMP_HDR_LEN)
		return IIP_ERR_INVALID_RX;
	{
		const uint8_t *buf_ptr[1];
		buf_ptr[0] = buf;
		{
			uint16_t len[1];
			len[0] = buf_len;
			if (ii_csum16(buf_ptr, len, 1, 0))
				return IIP_ERR_INVALID_RX;
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_icmp_input(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t buf_len;
		if (ii_pb_ipv4_payload_len(w, pb_id, &buf_len, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (buf_len < II_ICMP_HDR_LEN)
			return IIP_ERR_INVALID_RX;
		{
			uint8_t tmp[0xffff]; /* XXX: assuming sufficiently large stack */
			{
				IIP_PKT_LEN_T copied_len;
				if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_pb_payload_copy(w, pb_id, II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN), tmp, buf_len, &copied_len, opaque) != IIP_ERR_OK)
					return IIP_ERR_INVALID_RX;
				if (copied_len != buf_len)
					return IIP_ERR_INVALID_RX;
			}
			if (ii_icmp_validation(tmp, buf_len) != IIP_ERR_OK)
				return IIP_ERR_INVALID_RX;
			{
				enum iip_rc rc;
				switch (tmp[0]) {
				case 0: /* reply */
				case 3: /* error */
				case 11: /* time exceeded */
				case 12: /* parameter issue */
					rc = IIP_ERR_OK;
					break;
				case 8: /* echo */
					rc = ii_icmp_echo_xmit_reply(w, pb_id, tmp, buf_len, opaque);
					break;
				default:
					rc = IIP_ERR_FATAL_SYS;
					break;
				}
				if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				return rc;
			}
		}
	}
}

/*
 * ---------------------------------------
 *  tcp
 * ---------------------------------------
 */

#define ROUND_UP(_v, _r) ((((_v) / (_r)) + ((_v) % (_r) ? 1 : 0)) * (_r))

/*@
	assigns \nothing;
 */
static uint16_t ii_tcp_compute_win(uint32_t w, uint8_t ws)
{
	uint8_t i;
	/*@
		loop invariant 0 <= i <= ws;
		loop assigns i, w;
		loop variant ws - i;
	 */
	for (i = 0; i < ws; i++)
		w /= 2;
	if (UINT16_MAX <= w)
		w = UINT16_MAX;
	return w;
}

/*@ logic integer f_tcp_hdr_has_fin{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x01U) ? true : false; */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_fin(w, pb_id);
 */
static bool ii_tcp_hdr_has_fin(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x01U) ? true : false;
}

/*@ logic integer f_tcp_hdr_has_syn{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x02U) ? true : false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_syn(w, pb_id);
 */
static bool ii_tcp_hdr_has_syn(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x02U) ? true : false;
}

/*@ logic integer f_tcp_hdr_has_rst{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x04U) ? true : false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_rst(w, pb_id);
 */
static bool ii_tcp_hdr_has_rst(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x04U) ? true : false;
}

/*@ logic integer f_tcp_hdr_has_psh{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x08U) ? true : false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_psh(w, pb_id);
 */
static bool ii_tcp_hdr_has_psh(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x08U) ? true : false;
}

/*@ logic boolean f_tcp_hdr_has_ack{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x10U) ? \true : \false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_ack(w, pb_id);
 */
static bool ii_tcp_hdr_has_ack(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x10U) ? true : false;
}

/*@ logic integer f_tcp_hdr_has_urg{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x20U) ? true : false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_urg(w, pb_id);
 */
static bool ii_tcp_hdr_has_urg(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x20U) ? true : false;
}

/*@ logic integer f_tcp_hdr_has_ece{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x40U) ? true : false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_ece(w, pb_id);
 */
static bool ii_tcp_hdr_has_ece(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x40U) ? true : false;
}

/*@ logic integer f_tcp_hdr_has_cwr{L}(IIP_MEM_P w, II_PB_P pb_id) = (II_PB(pb_id).tcp.flags & 0x80U) ? true : false;  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_hdr_has_cwr(w, pb_id);
 */
static bool ii_tcp_hdr_has_cwr(IIP_MEM_P w, II_PB_P pb_id)
{
	return (II_PB(pb_id).tcp.flags & 0x80U) ? true : false;
}

/*@ logic integer f_tcp_seq_re_raw{L}(IIP_MEM_P w, II_PB_P pb_id) = (uint32_t) ((uint32_t) ((uint32_t) ((uint32_t) (((uint32_t) ((uint32_t) II_PB(pb_id).tcp.seq + (f_tcp_hdr_has_syn(w, pb_id) ? 1 : 0))) + (f_tcp_hdr_has_fin(w, pb_id) ? 1 : 0))) + II_PB(pb_id).tcp.payload_len) - II_PB(pb_id).tcp.dec_tail);  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_seq_re_raw(w, pb_id);
 */
static uint32_t ii_tcp_seq_re_raw(IIP_MEM_P w, II_PB_P pb_id)
{
	return II_PB(pb_id).tcp.seq
		+ (ii_tcp_hdr_has_syn(w, pb_id) ? 1 : 0)
		+ (ii_tcp_hdr_has_fin(w, pb_id) ? 1 : 0)
		+ II_PB(pb_id).tcp.payload_len
		- II_PB(pb_id).tcp.dec_tail;
}

/*@ logic integer f_tcp_seq_le_raw{L}(IIP_MEM_P w, II_PB_P pb_id) = (uint32_t) (II_PB(pb_id).tcp.seq + II_PB(pb_id).tcp.inc_head);  */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_tcp_seq_le_raw(w, pb_id);
 */
static uint32_t ii_tcp_seq_le_raw(IIP_MEM_P w, II_PB_P pb_id)
{
	return II_PB(pb_id).tcp.seq
		+ II_PB(pb_id).tcp.inc_head; 
}

/*@ logic integer f_tcp_seq_re{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) = (uint32_t)(f_tcp_seq_re_raw(w, pb_id) - II_TCP_CONN(conn_id).seq_next_expected); */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns \nothing;
	ensures \result == f_tcp_seq_re(w, conn_id, pb_id);
 */
static uint32_t ii_tcp_seq_re(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	return ii_tcp_seq_re_raw(w, pb_id) - II_TCP_CONN(conn_id).seq_next_expected;
}

/*@ logic integer f_tcp_seq_le{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) = (uint32_t)(f_tcp_seq_le_raw(w, pb_id) - II_TCP_CONN(conn_id).seq_next_expected); */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns \nothing;
	ensures \result == f_tcp_seq_le(w, conn_id, pb_id);
 */
static uint32_t ii_tcp_seq_le(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	return ii_tcp_seq_le_raw(w, pb_id) - II_TCP_CONN(conn_id).seq_next_expected;
}

/*@ logic integer f_seq_in_between{L}(uint32_t a, uint32_t b, uint32_t c) = (f_seq_ordered(a, b) && f_seq_ordered(b, c)) ? true : false; */
/*@
	assigns \nothing;
	ensures \result == f_seq_in_between(a, b, c);
 */
static bool ii_tcp_seq_in_between(uint32_t a, uint32_t b, uint32_t c)
{
	if (ii_seq_ordered(a, b) && ii_seq_ordered(b, c))
		return true;
	else
		return false;
}

/*@ logic integer f_tcp_seq_expected{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) = (f_tcp_seq_le_raw(w, pb_id) == II_TCP_CONN(conn_id).seq_next_expected) ? true : false; */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns \nothing;
	ensures \result == f_tcp_seq_expected(w, conn_id, pb_id);
 */
static bool ii_tcp_seq_expected(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	return ii_tcp_seq_le(w, conn_id, pb_id) == 0 ? true : false;
}

/* XXX: overflow complexity, bug of ordered */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns \nothing;
	ensures \result == true ==> (f_tcp_seq_re_raw(w, pb_id) == II_TCP_CONN(conn_id).seq_next_expected) || (f_seq_ordered((uint32_t) f_tcp_seq_re_raw(w, pb_id), II_TCP_CONN(conn_id).seq_next_expected));
 */
static bool ii_tcp_seq_entirely_acked(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (!II_PB(pb_id).tcp.payload_len && (ii_tcp_seq_re_raw(w, pb_id) == II_TCP_CONN(conn_id).seq_next_expected))
		return false;
	if (ii_tcp_seq_re_raw(w, pb_id) == II_TCP_CONN(conn_id).seq_next_expected
			|| ii_seq_ordered(ii_tcp_seq_re_raw(w, pb_id), II_TCP_CONN(conn_id).seq_next_expected)) {
		/*
		 *  le          re
		 *   |-----------|
		 *                  |
		 *                 next expected
		 */
		return true;
	} else
		return false;
}

/*@ logic integer f_tcp_seq_partially_acked{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) = f_seq_in_between((uint32_t) f_tcp_seq_le_raw(w, pb_id), II_TCP_CONN(conn_id).seq_next_expected, (uint32_t) f_tcp_seq_re_raw(w, pb_id)) ? true : false; */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns \nothing;
	ensures \result == f_tcp_seq_partially_acked(w, conn_id, pb_id);
 */
static bool ii_tcp_seq_partially_acked(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (ii_tcp_seq_in_between(ii_tcp_seq_le_raw(w, pb_id),
				II_TCP_CONN(conn_id).seq_next_expected,
				ii_tcp_seq_re_raw(w, pb_id))) {
		/*
		 *  le          re
		 *   |-----------|
		 *      |
		 *     next expected
		 */
		return true;
	} else
		return false;
}

/*@
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns II_TCP_CONN(conn_id).rto_ms;
	assigns II_TCP_CONN(conn_id).rto_expire;
 */
static void ii_tcp_conn_update_rto(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, bool loss)
{
	if (!loss)
		II_TCP_CONN(conn_id).rto_ms = (II_TCP_CONN(conn_id).rtt.srtt + 4 * II_TCP_CONN(conn_id).rtt.rttvar) * 200; /* tick is incremented every 200 ms by fast timer */
	else
		II_TCP_CONN(conn_id).rto_ms *= 2;
	if (!II_TCP_CONN(conn_id).rto_ms)
		II_TCP_CONN(conn_id).rto_ms = 200U;
	if (60000U /* 60 sec */ < II_TCP_CONN(conn_id).rto_ms)
		II_TCP_CONN(conn_id).rto_ms = 60000U;
	II_TCP_CONN(conn_id).rto_expire = w->now_ms + II_TCP_CONN(conn_id).rto_ms;
}

/*@
	requires \valid(w);
	assigns II_PB(pb_id).tcp.info_flags, II_PB(pb_id).tcp.sackbuf[0 .. 27];
 */
static enum iip_rc ii_tcp_craft_sackbuf(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).pending_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SACK_OK))
		return IIP_ERR_OK;
	if (II_TCP_CONN(conn_id).pending_ring.head != II_TCP_CONN(conn_id).pending_ring.tail) {
		struct ii_extent_queue eq;
		eq.cnt = 0;
		{
			IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).pending_ring);
			{
				uint16_t i;
				/*@
				  loop invariant 0 <= i <= cnt;
				  loop assigns i, eq;
				  loop variant cnt - i;
				 */
				for (i = 0; i < cnt; i++) {
					uint16_t slot_idx = II_TCP_CONN(conn_id).pending_ring.tail + i;
					if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
						slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
					if (II_TCP_CONN(conn_id).pending_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					{
						II_PB_P pb_id = II_TCP_CONN(conn_id).pending_ring.slot[slot_idx];
						if (ii_extent_queue_add(&eq, ii_tcp_seq_le_raw(w, pb_id), ii_tcp_seq_re_raw(w, pb_id) - ii_tcp_seq_le_raw(w, pb_id)) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
					}
				}
			}
		}
		{
			uint8_t i, eq_cnt = eq.cnt;
			/*@
			  loop invariant 0 <= i <= eq_cnt;
			  loop assigns i, II_PB(pb_id).tcp.sackbuf[0 .. 27];
			  loop variant eq_cnt - i;
			 */
			for (i = 0; i < eq_cnt && 2 + i * 8  + 8 <= 28 /* we do not try to send all acked range */; i++) {
				ii_write_uint32(II_PB(pb_id).tcp.sackbuf + 2 + i * 8 + 0, ii_htonl(eq.extent[i].v));
				ii_write_uint32(II_PB(pb_id).tcp.sackbuf + 2 + i * 8 + 4, ii_htonl(eq.extent[i].v + eq.extent[i].l));
			}
			II_PB(pb_id).tcp.sackbuf[0] = 5;
			II_PB(pb_id).tcp.sackbuf[1] = 2 + i * 8;
		}
	}
	II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_TX_SACKBUF;
	return IIP_ERR_OK;
}

/*@
	requires \valid(w);
	assigns w->pbs, II_TCP_CONN(conn_id).tx_ring, II_TCP_CONN(conn_id).seq, II_TCP_CONN(conn_id).ack_seq_sent, II_TCP_CONN(conn_id).flags;
	assigns II_TCP_CONN(conn_id).rto_ms;
	assigns II_TCP_CONN(conn_id).rto_expire;
 */
static enum iip_rc ii_tcp_tx_push_control(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint16_t flags)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		II_PB_P pb_id;
		{
			enum iip_rc rc = ii_alloc_pb(&w->pbs, &pb_id);
			if (rc != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		}
		{
			II_PB(pb_id).tcp.info_flags = 0;
			II_PB(pb_id).tcp.seq = II_TCP_CONN(conn_id).seq;
			II_PB(pb_id).tcp.ack_seq = II_TCP_CONN(conn_id).ack_seq;
			II_PB(pb_id).tcp.flags = flags;
			II_PB(pb_id).tcp.payload_len = 0;
			II_PB(pb_id).tcp.sent_bytes = 0;
			II_PB(pb_id).tcp.urg_p = 0;
			II_PB(pb_id).tcp.opt.ts[0] = w->tcp.pkt_ts;
			II_PB(pb_id).tcp.opt.ts[1] = II_TCP_CONN(conn_id).ts;
			II_PB(pb_id).tcp.inc_head = 0;
			II_PB(pb_id).tcp.dec_tail = 0;
			II_PB(pb_id).cnt = 0;
			if (ii_tcp_craft_sackbuf(w, conn_id, pb_id) != IIP_ERR_OK) {
				if (ii_free_pb(&w->pbs, pb_id) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		}
		{
			II_TCP_CONN(conn_id).seq += ((flags & 0x3fU) & 0x01U /* fin */ ? 1 : 0) + ((flags & 0x3fU) & 0x02U /* syn */ ? 1 : 0);
			if ((flags & 0x3fU) & 0x10U /* ack */) {
				II_TCP_CONN(conn_id).ack_seq_sent = II_PB(pb_id).tcp.ack_seq;
				II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_ACK_SENT;
				II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_PENDING;
			}
		}
		if (II_TCP_CONN(conn_id).seq != II_TCP_CONN(conn_id).acked_seq)
			ii_tcp_conn_update_rto(w, conn_id, false);
		{
			enum iip_rc rc = ii_pb_ring_push(&II_TCP_CONN(conn_id).tx_ring, pb_id);
			if (rc != IIP_ERR_OK) {
				if (ii_free_pb(&w->pbs, pb_id) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				} else if (rc == IIP_ERR_FATAL_MEM) {
					IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
				}
				return rc;
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires 0 < cnt ==> \valid_read(pkts + (0 .. cnt - 1));
	requires 0 < cnt ==> \separated(w, pkts + (0 .. cnt - 1), opaque);
	requires cnt == 0 ==> \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_send(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint16_t flags, IIP_PKT_P pkts[], IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		II_PB_P pb_id;
		{
			enum iip_rc rc = ii_alloc_pb(&w->pbs, &pb_id);
			if (rc != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		}
		{
			II_PB(pb_id).tcp.info_flags = 0;
			II_PB(pb_id).tcp.seq = II_TCP_CONN(conn_id).seq;
			II_PB(pb_id).tcp.ack_seq = II_TCP_CONN(conn_id).ack_seq;
			II_PB(pb_id).tcp.flags = flags;
			II_PB(pb_id).tcp.urg_p = 0;
			II_PB(pb_id).tcp.payload_len = 0;
			II_PB(pb_id).tcp.opt.ts[0] = w->tcp.pkt_ts;
			II_PB(pb_id).tcp.opt.ts[1] = II_TCP_CONN(conn_id).ts;
			II_PB(pb_id).tcp.inc_head = 0;
			II_PB(pb_id).tcp.dec_tail = 0;
			{
				uint16_t i;
				/*@
					loop invariant 0 <= i <= cnt;
					loop assigns i, II_PB(pb_id).tcp.payload_len, II_PB(pb_id).part_pkt[0 .. cnt - 1];
					loop variant cnt - i;
				 */
				for (i = 0; i < cnt; i++) {
					if (!ii_call_pkt_valid(pkts[i], opaque)) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					II_PB(pb_id).tcp.payload_len += ii_call_pkt_get_len(pkts[i], opaque);
					II_PB(pb_id).part_pkt[i] = pkts[i];
				}
			}
			II_PB(pb_id).cnt = cnt;
			if (ii_tcp_craft_sackbuf(w, conn_id, pb_id) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		}
		{
			II_TCP_CONN(conn_id).seq += II_PB(pb_id).tcp.payload_len;
			II_TCP_CONN(conn_id).ack_seq_sent = II_PB(pb_id).tcp.ack_seq;
			II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_ACK_SENT;
			II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_PENDING;
		}
		if (II_TCP_CONN(conn_id).seq != II_TCP_CONN(conn_id).acked_seq)
			ii_tcp_conn_update_rto(w, conn_id, false);
		{
			enum iip_rc rc = ii_pb_ring_push(&II_TCP_CONN(conn_id).tx_ring, pb_id);
			if (rc != IIP_ERR_OK) {
				if (ii_free_pb(&w->pbs, pb_id) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				return rc;
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires 0 < cnt ==> \valid_read(pkts + (0 .. cnt - 1));
	requires 0 < cnt ==> \separated(w, pkts + (0 .. cnt - 1), opaque);
	requires cnt == 0 ==> \separated(w, opaque);
	assigns *w, *opaque;
 */
static int iip_tcp_send(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_PKT_P pkts[], IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque)
{
	if (ii_tcp_send(w, conn_id, 0x3fU & 0x10U /* ack */, pkts, cnt, opaque) == IIP_ERR_OK)
		return 0;
	else
		return -1;
}

/*@ logic integer f_pb_tcp_hdr_len(IIP_MEM_P w, II_PB_P pb_id) = (uint16_t)((uint16_t) (II_PB(pb_id).tcp.flags / 4096) * 4); */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns \nothing;
	ensures \result == f_pb_tcp_hdr_len(w, pb_id);
	ensures \result <= 60;
 */
static uint16_t ii_pb_tcp_hdr_len(IIP_MEM_P w, II_PB_P pb_id)
{
	return ((II_PB(pb_id).tcp.flags / 4096) * 4);
}

/*@ logic integer f_pb_tcp_payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque) = (uint16_t)((uint16_t) f_pb_ipv4_payload_len(w, pb_id, opaque) - (uint16_t) f_pb_tcp_hdr_len(w, pb_id)); */
/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(payload_len);
	requires \separated(w, payload_len, opaque);
	assigns *payload_len;
 */
static enum iip_rc ii_pb_tcp_payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_PKT_LEN_T *payload_len, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_LEN_T ipv4_payload_len;
		if (ii_pb_ipv4_payload_len(w, pb_id, &ipv4_payload_len, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ipv4_payload_len < ii_pb_tcp_hdr_len(w, pb_id)) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		*payload_len = ipv4_payload_len - ii_pb_tcp_hdr_len(w, pb_id);
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(w);
	assigns w->tcp.conns_ht[0 .. IIP_CONF_TCP_CONN_HT_SIZE - 1];
 */
static IIP_TCP_CONN_P ii_ipv4_tcp_conn_lookup(IIP_MEM_P w,
		uint32_t src_ipv4_be, uint16_t src_port_be,
		uint32_t dst_ipv4_be, uint16_t dst_port_be)
{
	{
		IIP_TCP_CONN_P r = w->tcp.conns_ht[(dst_ipv4_be + src_port_be + dst_port_be) % IIP_CONF_TCP_CONN_HT_SIZE];
		if (r < II_CONF_POOL_NUM_TCP_CONN) {
			if (src_ipv4_be == ii_htonl(w->tcp_conns.array[r].src_ip[0])
					&& src_port_be == ii_htons(w->tcp_conns.array[r].src_port)
					&& dst_ipv4_be == ii_htonl(w->tcp_conns.array[r].dst_ip[0])
					&& dst_port_be == ii_htons(w->tcp_conns.array[r].dst_port)
					&& II_TCP_CONN(r).state != II_TCP_STATE_CLOSED) {
				return r;
			}
		}
	}
	{
		IIP_TCP_CONN_P i;
		/*@
			loop invariant 0 <= i <= II_CONF_POOL_NUM_TCP_CONN;
			loop assigns i;
			loop variant II_CONF_POOL_NUM_TCP_CONN - i;
		 */
		for (i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
			if (src_ipv4_be == ii_htonl(w->tcp_conns.array[i].src_ip[0])
					&& src_port_be == ii_htons(w->tcp_conns.array[i].src_port)
					&& dst_ipv4_be == ii_htonl(w->tcp_conns.array[i].dst_ip[0])
					&& dst_port_be == ii_htons(w->tcp_conns.array[i].dst_port)
					&& II_TCP_CONN(i).state != II_TCP_STATE_CLOSED)
				break;
		}
		if (i < II_CONF_POOL_NUM_TCP_CONN)
			w->tcp.conns_ht[(dst_ipv4_be + src_port_be + dst_port_be) % IIP_CONF_TCP_CONN_HT_SIZE] = i;
		return i;
	}
}

/*@ logic integer f_tcp_rx_window{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id) = (uint32_t)(II_TCP_CONN(conn_id).buf.capacity - II_TCP_CONN(conn_id).buf.used); */
/*@
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	requires II_TCP_CONN(conn_id).buf.used <= II_TCP_CONN(conn_id).buf.capacity;
	assigns \nothing;
	ensures \result == f_tcp_rx_window(w, conn_id);
 */
static uint32_t ii_tcp_rx_window(IIP_MEM_P w, IIP_TCP_CONN_P conn_id)
{
	return II_TCP_CONN(conn_id).buf.capacity - II_TCP_CONN(conn_id).buf.used;
}

/*@ logic integer f_tcp_seq_entirely_exceed_win{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) = ((f_tcp_rx_window(w, conn_id) == 0) || (f_seq_ordered((uint32_t) f_tcp_rx_window(w, conn_id), (uint32_t) f_tcp_seq_le(w, conn_id, pb_id)))) ? true : false; */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	requires II_TCP_CONN(conn_id).buf.used <= II_TCP_CONN(conn_id).buf.capacity;
	assigns \nothing;
	ensures \result == f_tcp_seq_entirely_exceed_win(w, conn_id, pb_id);
 */
static bool ii_tcp_seq_entirely_exceed_win(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (ii_tcp_rx_window(w, conn_id) == 0
			|| ii_seq_ordered(ii_tcp_rx_window(w, conn_id), ii_tcp_seq_le(w, conn_id, pb_id))) {
		/*
		 *      le          re
		 *       |-----------|
		 *   |
		 *  adv win
		 */
		return true;
	} else
		return false;
}

/*@ logic integer f_tcp_seq_partially_exceed_win{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) = f_seq_in_between((uint32_t) f_tcp_seq_le(w, conn_id, pb_id), (uint32_t) f_tcp_rx_window(w, conn_id), (uint32_t) f_tcp_seq_re(w, conn_id, pb_id)) ? true : false; */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	requires II_TCP_CONN(conn_id).buf.used <= II_TCP_CONN(conn_id).buf.capacity;
	assigns \nothing;
	ensures \result == f_tcp_seq_partially_exceed_win(w, conn_id, pb_id);
 */
static bool ii_tcp_seq_partially_exceed_win(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (ii_tcp_seq_in_between(ii_tcp_seq_le(w, conn_id, pb_id),
				ii_tcp_rx_window(w, conn_id),
				ii_tcp_seq_re(w, conn_id, pb_id))) {
		/*
		 *  le          re
		 *   |-----------|
		 *        |
		 *       adv win
		 */
		return true;
	} else
		return false;
}

/*@ logic integer f_tcp_retransmitted_syn_ack{L}(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id) =
			(f_tcp_hdr_has_syn(w, pb_id)
			&& f_tcp_hdr_has_ack(w, pb_id)
			&& II_TCP_CONN(conn_id).state == II_TCP_STATE_ESTABLISHED
			&& II_PB(pb_id).tcp.ack_seq == (uint32_t)((uint32_t) II_TCP_CONN(conn_id).iss + 1)) ? true : false; */
/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	requires II_TCP_CONN(conn_id).buf.used <= II_TCP_CONN(conn_id).buf.capacity;
	assigns \nothing;
	ensures \result == f_tcp_retransmitted_syn_ack(w, conn_id, pb_id);
 */
static bool ii_tcp_retransmitted_syn_ack(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (ii_tcp_hdr_has_syn(w, pb_id)
			&& ii_tcp_hdr_has_ack(w, pb_id)
			&& II_TCP_CONN(conn_id).state == II_TCP_STATE_ESTABLISHED
			&& II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).iss + 1)
		return true;
	else
		return false;
}

/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	requires II_TCP_CONN(conn_id).buf.used <= II_TCP_CONN(conn_id).buf.capacity;
	assigns \nothing;
 */
static bool ii_tcp_paws(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (II_CONF_TCP_OPT_TS_OK
			&& II_TCP_CONN(conn_id).state == II_TCP_STATE_ESTABLISHED
			&& !(II_PB(pb_id).tcp.flags & II_TCP_FLAG_SYN)
			&& !(II_PB(pb_id).tcp.flags & II_TCP_FLAG_RST)
			&& II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_OPT_SET_TS
			&& II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_OPT_HAS_TS) { /* PAWS */
		uint32_t t = II_TCP_CONN(conn_id).ts - II_PB(pb_id).tcp.opt.ts[0];
		if (t && t < 2147483648U)
			return true;
	}
	return false;
}

/*@
	requires \valid(w);
	assigns II_PB(pb_id).tcp.inc_head, II_PB(pb_id).tcp.dec_tail, II_TCP_CONN(conn_id).flags;
 */
static enum iip_rc ii_tcp_check_input_seq(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).buf.used > II_TCP_CONN(conn_id).buf.capacity) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!ii_tcp_rx_window(w, conn_id))
		return IIP_ERR_INVALID_RX;
	if (ii_tcp_seq_entirely_acked(w, conn_id, pb_id))
		return IIP_ERR_INVALID_RX;
	if (ii_tcp_seq_entirely_exceed_win(w, conn_id, pb_id))
		return IIP_ERR_INVALID_RX;
	if (ii_tcp_paws(w, conn_id, pb_id))
		return IIP_ERR_INVALID_RX;
	if (ii_tcp_seq_partially_acked(w, conn_id, pb_id)) {
		/*
		 *  le          re
		 *   |-----------|
		 *        |
		 *       next
		 */
		II_PB(pb_id).tcp.inc_head += II_TCP_CONN(conn_id).seq_next_expected - ii_tcp_seq_le_raw(w, pb_id);
		/*
		 *       le     re
		 *        |------|
		 *        |
		 *       next
		 */
		/*@ assert II_TCP_CONN(conn_id).seq_next_expected == f_tcp_seq_le_raw(w, pb_id); */
	}
	if (ii_tcp_seq_partially_exceed_win(w, conn_id, pb_id)) {
		/*
		 *  le          re
		 *   |-----------|
		 *       |
		 *      win
		 */
		II_PB(pb_id).tcp.dec_tail += ii_tcp_seq_re(w, conn_id, pb_id) - ii_tcp_rx_window(w, conn_id);
		/*
		 *  le  re
		 *   |---|
		 *       |
		 *      win
		 */
		/*@ assert f_tcp_rx_window(w, conn_id) == f_tcp_seq_re(w, conn_id, pb_id); */
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w;
 */
static enum iip_rc ii_tcp_rx_push__pending(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint32_t le = ii_tcp_seq_le_raw(w, pb_id);
		{
			if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).pending_ring) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			{
				bool queue_full = false;
				{
					IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).pending_ring);
					{
						uint16_t i;
						/*@
							loop invariant 0 <= i <= cnt;
							loop assigns i, *w;
							loop variant cnt - i;
						 */
						for (i = 0; i < cnt; i++) {
							uint16_t slot_idx = II_TCP_CONN(conn_id).pending_ring.tail + i;
							if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
								slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
							if (II_TCP_CONN(conn_id).pending_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
							{
								uint32_t _le = ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).pending_ring.slot[slot_idx]);
								if (le == _le || ii_seq_ordered(le, _le)) {
									enum iip_rc rc = ii_pb_ring_insert(&II_TCP_CONN(conn_id).pending_ring, pb_id, slot_idx);
									if (rc != IIP_ERR_OK) {
										if (rc == IIP_ERR_FATAL_SYS) {
											IIP_OPS_DEBUG_PRINTF("[%s:%u]: IPv4 pending queue fatal error\n", __func__, __LINE__);
											IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
										} else if (rc == IIP_ERR_FATAL_MEM)
											queue_full = true;
									}
									break;
								}
							}
						}
						if (!queue_full && i == cnt) {
							enum iip_rc rc = ii_pb_ring_insert(&II_TCP_CONN(conn_id).pending_ring, pb_id, II_TCP_CONN(conn_id).pending_ring.head);
							if (rc != IIP_ERR_OK) {
								if (rc == IIP_ERR_FATAL_SYS) {
									IIP_OPS_DEBUG_PRINTF("[%s:%u]: IPv4 pending queue fatal error\n", __func__, __LINE__);
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								} else if (rc == IIP_ERR_FATAL_MEM)
									queue_full = true;
							}
						}
					}
				}
				if (queue_full) {
					IIP_OPS_DEBUG_PRINTF("[%s:%u]: IPv4 pending queue is full (%u), so discard all entries\n", __func__, __LINE__, II_CONF_TCP_RING_SLOT_LEN);
					{
						IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).pending_ring);
						{
							IIP_PKT_CNT_T i;
							/*@
								loop invariant 0 <= i <= cnt;
								loop assigns i, *opaque;
								loop variant cnt - i;
							 */
							for (i = 0; i < cnt; i++) {
								uint16_t slot_idx = II_TCP_CONN(conn_id).pending_ring.tail + i;
								if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
									slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
								if (II_TCP_CONN(conn_id).pending_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								if (ii_free_pkts(II_PB(II_TCP_CONN(conn_id).pending_ring.slot[slot_idx]).part_pkt, II_PB(II_TCP_CONN(conn_id).pending_ring.slot[slot_idx]).cnt, opaque)) {
									IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
								}
							}
						}
						II_TCP_CONN(conn_id).pending_ring.head = II_TCP_CONN(conn_id).pending_ring.tail = 0;
						return IIP_ERR_INVALID_RX; /* XXX: better error code? */
					}
				}
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(w);
	requires \valid(out_of_order_p);
	requires \valid(valid_ack_p);
	requires \separated(w, out_of_order_p, valid_ack_p);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *out_of_order_p, *valid_ack_p, II_TCP_CONN(conn_id).dup_ack_received;
 */
static void ii_tcp_check_input_ack(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint8_t *out_of_order_p, uint8_t *valid_ack_p)
{
	uint8_t out_of_order = 0, valid_ack = 0;
	if (!ii_tcp_hdr_has_syn(w, pb_id) && !ii_tcp_hdr_has_fin(w, pb_id) && !ii_tcp_hdr_has_rst(w, pb_id)) {
		/*
		 * ACK number check:
		 *
		 * check whether the packet is dup ack (patten B +alpha) or not
		 *
		 *        conn->acked_seq              conn->seq_be
		 *                  |                        |
		 *  ----- acked ----|------- unacked --------|
		 *              |   |   |
		 *              |   |   |
		 *              A   B   C
		 */
		/* 1. doesn't ack for new data */
		if (II_TCP_CONN(conn_id).sent_seq - II_TCP_CONN(conn_id).acked_seq <= II_TCP_CONN(conn_id).sent_seq - II_PB(pb_id).tcp.ack_seq) { /* pattern A or B */
			/*
			 *        conn->acked_seq              conn->seq_be
			 *                  |                        |
			 *  ----- acked ----|------- unacked --------|
			 *              |   |
			 *              |   |
			 *              A   B
			 */
			/* 2. no payload */
			if (!II_PB(pb_id).tcp.payload_len) {
				/* 3. window size isn't updated */
				if (II_TCP_CONN(conn_id).peer_win == II_PB(pb_id).tcp.win) {
					/* 4. some data is not acked yet */
					if (II_TCP_CONN(conn_id).sent_seq != II_TCP_CONN(conn_id).acked_seq) {
						/*
						 *        conn->acked_seq              conn->seq_be
						 *                  |                        |
						 *  ----- acked ----|------- unacked --------|
						 */
						/* 5. packet ack number is the biggest ack number seen ever */
						if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).acked_seq) { /* pattern B */
							/*
							 *        conn->acked_seq              conn->seq_be
							 *                  |                        |
							 *  ----- acked ----|------- unacked --------|
							 *                  |
							 *                  |
							 *                  B
							 */
							/* this is dup ack */
							if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SET_PROBE))
								II_TCP_CONN(conn_id).dup_ack_received++;
							if (ii_tcp_hdr_has_ack(w, pb_id))
								valid_ack = 1; /* valid but same */
						} else { /* pattern A */
							/*
							 *        conn->acked_seq              conn->seq_be
							 *                  |                        |
							 *  ----- acked ----|------- unacked --------|
							 *              |
							 *              |
							 *              A
							 */
						}
						out_of_order = 1;
					} else { /* all data is acked */
						/*
						 *        conn->acked_seq
						 *            conn->seq_be
						 *                  |
						 *  ----- acked ----|
						 *                  |
						 *                  |
						 *                  B
						 */
						if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).acked_seq) { /* pattern B */
							/*
							 *        conn->acked_seq
							 *            conn->seq_be
							 *                  |
							 *  ----- acked ----|
							 *                  |
							 *                  |
							 *                  B
							 */
							/* we will send a keep-alive ack */
							if (ii_tcp_hdr_has_ack(w, pb_id))
								valid_ack = 1; /* valid but same */
						} else {
							/*
							 *        conn->acked_seq
							 *            conn->seq_be
							 *                  |
							 *  ----- acked ----|
							 *              |
							 *              |
							 *              A
							 */
							out_of_order = 1;
						}
					}
				} else {
					if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).acked_seq) { /* pattern B */
						if (ii_tcp_hdr_has_ack(w, pb_id))
							valid_ack = 1; /* valid but same */
					} else { /* pattern A */
						/* invalid */
					}
				}
			} else { /* packet has the payload */
				if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).acked_seq) { /* pattern B */
					/* this is valid */
					if (ii_tcp_hdr_has_ack(w, pb_id))
						valid_ack = 1; /* valid but same */
				} else
					out_of_order = 2;
			}
		} else { /* pattern C */
			/*
			 *        conn->acked_seq              conn->seq_be
			 *                  |                        |
			 *  ----- acked ----|------- unacked --------|
			 *                      |
			 *                      |
			 *                      C
			 */
			/* this is valid */
			if (ii_tcp_hdr_has_ack(w, pb_id))
				valid_ack = 2; /* advance */
		}
	} else {
		if (ii_tcp_hdr_has_ack(w, pb_id)) {
			if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).acked_seq)
				valid_ack = 1; /* valid but same */
			else if (II_PB(pb_id).tcp.ack_seq - II_TCP_CONN(conn_id).acked_seq <= II_TCP_CONN(conn_id).sent_seq - II_TCP_CONN(conn_id).acked_seq)
				valid_ack = 2; /* advance */
		}
	}
	*out_of_order_p = out_of_order;
	*valid_ack_p = valid_ack;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn_update_info(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint8_t out_of_order, uint8_t valid_ack, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!out_of_order) {
		II_TCP_CONN(conn_id).peer_win = II_PB(pb_id).tcp.win;
		if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED) && ii_tcp_hdr_has_ack(w, pb_id)) {
			uint32_t nticks;
			if (II_CONF_TCP_OPT_TS_OK && (II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_OPT_HAS_TS))
				nticks = w->tcp.pkt_ts - II_PB(pb_id).tcp.opt.ts[1];
			else
				nticks = w->tcp.pkt_ts - II_TCP_CONN(conn_id).ts;
			if (II_TCP_CONN(conn_id).state == II_TCP_STATE_SYN_SENT || II_TCP_CONN(conn_id).state == II_TCP_STATE_SYN_RECVD) {
				II_TCP_CONN(conn_id).rtt.srtt = nticks;
				II_TCP_CONN(conn_id).rtt.rttvar = nticks / 2;
			} else {
				uint32_t delta = (nticks < II_TCP_CONN(conn_id).rtt.srtt ? II_TCP_CONN(conn_id).rtt.srtt - nticks : nticks - II_TCP_CONN(conn_id).rtt.srtt);
				if (nticks < II_TCP_CONN(conn_id).rtt.srtt)
					II_TCP_CONN(conn_id).rtt.srtt -= delta / 8;
				else
					II_TCP_CONN(conn_id).rtt.srtt += delta / 8;
				{
					uint32_t d2 = (delta < II_TCP_CONN(conn_id).rtt.rttvar ? II_TCP_CONN(conn_id).rtt.rttvar - delta : delta - II_TCP_CONN(conn_id).rtt.rttvar);
					if (delta < II_TCP_CONN(conn_id).rtt.rttvar)
						II_TCP_CONN(conn_id).rtt.rttvar -= d2 / 4;
					else
						II_TCP_CONN(conn_id).rtt.rttvar += d2 / 4;
				}
			}
		}
		if (II_CONF_TCP_OPT_TS_OK && (II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_OPT_HAS_TS))
			II_TCP_CONN(conn_id).ts = II_PB(pb_id).tcp.opt.ts[0];
		else
			II_TCP_CONN(conn_id).ts = w->tcp.pkt_ts;
	}
	if (!out_of_order && valid_ack /* advance or same */) {
		II_TCP_CONN(conn_id).peer_win = II_PB(pb_id).tcp.win;
		if (II_TCP_CONN(conn_id).max_peer_win < II_TCP_CONN(conn_id).peer_win)
			II_TCP_CONN(conn_id).max_peer_win = II_TCP_CONN(conn_id).peer_win;
	}
	if (valid_ack == 2 /* advance */) {
		II_TCP_CONN(conn_id).retrans_cnt = 0;
		II_TCP_CONN(conn_id).acked_seq = II_PB(pb_id).tcp.ack_seq;
		II_TCP_CONN(conn_id).dup_ack_received = 0;
		if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED) {
			if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).sent_seq_when_loss_detected || ii_seq_ordered(II_PB(pb_id).tcp.ack_seq, II_TCP_CONN(conn_id).sent_seq_when_loss_detected)) {
				II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_PEER_RX_FAILED;
				II_TCP_CONN(conn_id).cc.ssthresh = II_TCP_CONN(conn_id).cc.win;
				II_TCP_CONN(conn_id).retx_bytes = 0;
			}
		}
	}
	if (!out_of_order && valid_ack /* advance or same */ && ii_seq_ordered(II_TCP_CONN(conn_id).acked_seq, II_TCP_CONN(conn_id).seq))
		ii_tcp_conn_update_rto(w, conn_id, false);
	II_TCP_CONN(conn_id).ack_seq = II_PB(pb_id).tcp.seq + (ii_tcp_hdr_has_syn(w, pb_id) ? 1 : 0) + (ii_tcp_hdr_has_fin(w, pb_id) ? 1 : 0) + II_PB(pb_id).tcp.payload_len - II_PB(pb_id).tcp.dec_tail;
	return IIP_ERR_OK;
	{ /* unused */
		(void) opaque;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn_close_check(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_CLOSING) {
		int iip_ret_int;
		IIP_OPS_TCP_CLOSED();
		if (iip_ret_int) {
			IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
		}
		II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_CLOSING;
		ii_free_tcp_conn(&w->tcp_conns, conn_id);
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns II_TCP_CONN(conn_id).state \from state;
 */
static void ii_tcp_conn_set_state(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint8_t state)
{
	II_TCP_CONN(conn_id).state = state;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc iip_tcp_close(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).state == II_TCP_STATE_ESTABLISHED
			|| II_TCP_CONN(conn_id).state == II_TCP_STATE_CLOSE_WAIT) {
		if (II_TCP_CONN(conn_id).state == II_TCP_STATE_ESTABLISHED)
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_FIN_WAIT1);
		else
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_LAST_ACK);
		{
			enum iip_rc rc = ii_tcp_tx_push_control(w, conn_id, II_TCP_FLAG_FIN | II_TCP_FLAG_ACK);
			if (rc != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			II_TCP_CONN(conn_id).fin_ack_seq = II_TCP_CONN(conn_id).seq;
		}
	}
	return IIP_ERR_OK;
	{ /* unused */
		(void) opaque;
	}
}

/*@
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns II_TCP_CONN(conn_id).flags;
 */
static void ii_tcp_conn_enter_close_phase(IIP_MEM_P w, IIP_TCP_CONN_P conn_id)
{
	II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_CLOSING;
}

/*@
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns II_TCP_CONN(conn_id).state;
	assigns II_TCP_CONN(conn_id).flags;
 */
static void ii_tcp_conn_handle_rst(IIP_MEM_P w, IIP_TCP_CONN_P conn_id)
{
	if (II_TCP_CONN(conn_id).state == II_TCP_STATE_SYN_RECVD
			&& !(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN)) /* passive open */
		II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_SKIP_TCP_CLOSE_CALLBACK;
	if (II_TCP_CONN(conn_id).state != II_TCP_STATE_CLOSED) {
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_CLOSED);
		ii_tcp_conn_enter_close_phase(w, conn_id);
	}
}

/*@
	requires \valid(w);
	requires \valid(ack);
	requires \valid(rst);
	requires \separated(w, ack, rst);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w;
	assigns *ack, *rst;
 */
static void ii_tcp_conn_handle_in_order__fin_wait1(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint8_t *ack, uint8_t *rst)
{
	if (ii_tcp_hdr_has_ack(w, pb_id)) {
		if (II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).fin_ack_seq) {
			if (ii_tcp_hdr_has_fin(w, pb_id)) {
				*ack = 1;
				ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_TIME_WAIT);
				II_TCP_CONN(conn_id).time_wait_ts_ms = w->now_ms;
			} else
				ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_FIN_WAIT2);
		} else if (ii_tcp_hdr_has_fin(w, pb_id)) {
			/*
			 * this is the case where the peer also sent fin mostly at the same time,
			 * and especially here is for close initiators sending fin-ack
			 * rather than than only fin
			 */
			*ack = 1;
			*rst = 1;
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_TIME_WAIT);
			II_TCP_CONN(conn_id).time_wait_ts_ms = w->now_ms;
		}
	} else {
		if (ii_tcp_hdr_has_fin(w, pb_id)) {
			*ack = 1;
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_CLOSING);
		}
	}
}

/*@
	requires \valid(w);
	requires \valid(ack);
	requires \separated(w, ack);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w, *ack;
 */
static void ii_tcp_conn_handle_in_order__fin_wait2(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint8_t *ack)
{
	if (ii_tcp_hdr_has_fin(w, pb_id)) {
		*ack = 1;
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_TIME_WAIT);
		II_TCP_CONN(conn_id).time_wait_ts_ms = w->now_ms;
	}
}

/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w;
 */
static void ii_tcp_conn_handle_in_order__closing(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (ii_tcp_hdr_has_ack(w, pb_id)) {
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_TIME_WAIT);
		II_TCP_CONN(conn_id).time_wait_ts_ms = w->now_ms;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(syn);
	requires \valid(ack);
	requires \separated(w, syn, ack, opaque);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w, *syn, *ack;
 */
static enum iip_rc ii_tcp_conn_handle_in_order__syn_sent(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint8_t *syn, uint8_t *ack, IIP_OPAQUE_P opaque)
{
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).tx_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).sent_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_tcp_hdr_has_syn(w, pb_id)) {
		if (ii_tcp_hdr_has_ack(w, pb_id)) {
			if (II_TCP_CONN(conn_id).fastopen_cookie.len /* active fast open */
					&& II_TCP_CONN(conn_id).acked_seq != II_TCP_CONN(conn_id).seq /* some data is not acked */
					&& II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).iss + 1 /* peer did not accept fast open */) { /* resend payload */
				/*
				 * remove syn and reconstruct the first packet
				 * since syn will not be sent anymore, we directly overwrite the original packet for further retransmissions
				 */
#if 0
				/*@ assert II_TCP_CONN(conn_id).sent_ring.head != II_TCP_CONN(conn_id).sent_ring.tail; */
#endif
				{ /* assuming only the first packet has syn */
					II_PB_P syn_pb_id = II_TCP_CONN(conn_id).sent_ring.slot[II_TCP_CONN(conn_id).sent_ring.tail];
					if (syn_pb_id >= II_CONF_POOL_NUM_PB) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
#if 0
					/*@ assert II_PB(syn_pb_id).tcp.flags & II_TCP_FLAG_SYN; */
#endif
					II_PB(syn_pb_id).tcp.flags &= ~II_TCP_FLAG_SYN;
					II_PB(syn_pb_id).tcp.seq += 1; /* forward for the accepted syn */
				}
				{ /* retransmit all */
					/* move all packets to sent_ring first to preserve the order of the packet  */
					uint16_t i, cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).tx_ring);
					/*@
						loop invariant 0 <= i <= cnt;
						loop assigns i, *w;
						loop variant cnt - i;
					 */
					for (i = 0; i < cnt; i++) {
						uint32_t p;
						if (ii_pb_ring_pull(&II_TCP_CONN(conn_id).tx_ring, &p) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						if (ii_pb_ring_push(&II_TCP_CONN(conn_id).sent_ring, p) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM; /* XXX: can we improve this? */
						}
					}
					/* copy all from sent_ring to tx_ring */
					II_TCP_CONN(conn_id).tx_ring = II_TCP_CONN(conn_id).sent_ring;
					/* clear sent_ring */
					II_TCP_CONN(conn_id).sent_ring.head = II_TCP_CONN(conn_id).sent_ring.tail = 0;
				}
			}
			*ack = 1;
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_ESTABLISHED);
			{
				II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_SENT;
				{
					int iip_ret_int;
					IIP_OPS_TCP_CONNECTED();
					if (iip_ret_int) {
						IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
					}
				}
				if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_ACK_SENT)
					*ack = 0;
			}
		} else { /* simultaneous open */
			*syn = *ack = 1;
			II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN; /* to trigger connect callback when accepted */
			II_TCP_CONN(conn_id).sent_seq = II_TCP_CONN(conn_id).seq = II_TCP_CONN(conn_id).acked_seq = II_TCP_CONN(conn_id).iss;
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_SYN_RECVD);
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(fallthrough);
	requires \valid(syn);
	requires \valid(ack);
	requires \valid(fastopen_cookie);
	requires \separated(w, fallthrough, syn, ack, fastopen_cookie, opaque);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w, *opaque;
	assigns *fallthrough, *syn, *ack, *fastopen_cookie;
 */
static enum iip_rc ii_tcp_conn_handle_in_order__syn_recvd(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, bool *fallthrough, uint8_t *syn, uint8_t *ack, uint8_t *fastopen_cookie, IIP_OPAQUE_P opaque)
{
	*fallthrough = false;
	if (ii_tcp_hdr_has_ack(w, pb_id)) {
		*ack = 1;
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_ESTABLISHED);
		if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN) {
			II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_SIMULTANEOUS_OPEN;
			{
				II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_SENT;
				{
					int iip_ret_int;
					IIP_OPS_TCP_CONNECTED();
					if (iip_ret_int) {
						IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
					}
				}
				if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_ACK_SENT)
					*ack = 0;
			}
		} else {
			if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_FASTOPEN)) {
				II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_SENT;
				{
					int iip_ret_int;
					IIP_OPS_TCP_ACCEPTED();
					if (iip_ret_int) {
						IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
					}
				}
				if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_ACK_SENT)
					*ack = 0;
			}
		}
		if (II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_URGENT) {
			uint32_t up = II_PB(pb_id).tcp.seq + II_PB(pb_id).tcp.urg_p;
			if ((II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_URGENT_SET
						&& up - II_TCP_CONN(conn_id).urgent_ptr < 2147483648U
						&& up != II_TCP_CONN(conn_id).urgent_ptr)
					|| !(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_URGENT_SET)) {
				II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_URGENT_SET;
				II_TCP_CONN(conn_id).urgent_ptr = up;
				{
					int iip_ret_int;
					IIP_OPS_TCP_URGENT();
					if (iip_ret_int) {
						IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
					}
				}
			}
			II_PB(pb_id).tcp.info_flags &= ~II_PB_FLAGS_TCP_URGENT;
		}
		if (II_TCP_CONN(conn_id).state == II_TCP_STATE_FIN_WAIT1 /* updated by close called in callback */
				&& ii_tcp_hdr_has_fin(w, pb_id)) {
			ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_CLOSING);
			return IIP_ERR_OK;
		}
		*fallthrough = true;
		return IIP_ERR_OK;
	} else if (ii_tcp_hdr_has_syn(w, pb_id)) {
		*syn = *ack = 1;
		II_TCP_CONN(conn_id).sent_seq = II_TCP_CONN(conn_id).seq = II_TCP_CONN(conn_id).acked_seq = II_TCP_CONN(conn_id).iss;
		if (II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_FASTOPEN_REQUEST) {
			{
				int iip_ret_int;
				IIP_OPS_TCP_FASTOPEN_REQUEST();
				if (iip_ret_int) {
					IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
				}
			}
			if (II_TCP_CONN(conn_id).fastopen_cookie.len >= 4 && II_TCP_CONN(conn_id).fastopen_cookie.len <= 16)
				*fastopen_cookie = 1;
		} else if (II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_FASTOPEN_VALID
				&& !(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_FASTOPEN)
				&& II_PB(pb_id).tcp.payload_len - II_PB(pb_id).tcp.inc_head - II_PB(pb_id).tcp.dec_tail) {
			if (ii_tcp_tx_push_control(w, conn_id, II_TCP_FLAG_SYN | II_TCP_FLAG_ACK) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_FASTOPEN;
			{
				int iip_ret_int;
				IIP_OPS_TCP_ACCEPTED();
				if (iip_ret_int) {
					IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
				}
			}
			II_TCP_CONN(conn_id).buf.used += II_PB(pb_id).tcp.payload_len - II_PB(pb_id).tcp.inc_head - II_PB(pb_id).tcp.dec_tail;
			{
				int iip_ret_int;
				IIP_OPS_TCP_PAYLOAD();
				if (iip_ret_int) {
					IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
				}
			}
		}
		return IIP_ERR_OK;
	} else
		return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(ack);
	requires \separated(w, ack, opaque);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w, *opaque, *ack;
 */
static enum iip_rc ii_tcp_conn_handle_in_order__established(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint8_t *ack, IIP_OPAQUE_P opaque)
{
	II_TCP_CONN(conn_id).keepalive_ts = w->now_ms;
	if (II_TCP_CONN(conn_id).state == II_TCP_STATE_ESTABLISHED /* state can be updated in callback before fall through */
			&& ii_tcp_hdr_has_ack(w, pb_id) && II_PB(pb_id).tcp.payload_len) {
		II_TCP_CONN(conn_id).buf.used += II_PB(pb_id).tcp.payload_len - II_PB(pb_id).tcp.inc_head - II_PB(pb_id).tcp.dec_tail;
		II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_SENT;
		{
			int iip_ret_int;
			IIP_OPS_TCP_PAYLOAD();
			if (iip_ret_int) {
				IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
			}
		}
		if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_ACK_SENT))
			*ack = 1;
	}
	if (ii_tcp_hdr_has_fin(w, pb_id)) {
		*ack = 1;
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_CLOSE_WAIT);
		II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_ACK_SENT;
		{
			int iip_ret_int;
			IIP_OPS_TCP_STATE_CLOSE_WAIT();
			if (iip_ret_int) {
				IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
			}
		}
		if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_ACK_SENT)
			*ack = 0;
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns *w;
 */
static void ii_tcp_conn_handle_in_order__last_ack(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)
{
	if (ii_tcp_hdr_has_ack(w, pb_id) && II_PB(pb_id).tcp.ack_seq == II_TCP_CONN(conn_id).fin_ack_seq) {
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_CLOSED);
		ii_tcp_conn_enter_close_phase(w, conn_id);
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn_handle_in_order(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t syn = 0, ack = 0, rst = 0, fastopen_cookie = 0;
		switch (II_TCP_CONN(conn_id).state) {
		case II_TCP_STATE_FIN_WAIT1:
			ii_tcp_conn_handle_in_order__fin_wait1(w, conn_id, pb_id, &ack, &rst);
			break;
		case II_TCP_STATE_FIN_WAIT2:
			ii_tcp_conn_handle_in_order__fin_wait2(w, conn_id, pb_id, &ack);
			break;
		case II_TCP_STATE_CLOSING:
			ii_tcp_conn_handle_in_order__closing(w, conn_id, pb_id);
			break;
		case II_TCP_STATE_TIME_WAIT:
			/* wait 2 MSL timeout */
			break;
		case II_TCP_STATE_SYN_SENT:
			{
				enum iip_rc rc = ii_tcp_conn_handle_in_order__syn_sent(w, conn_id, pb_id, &syn, &ack, opaque);
				if (rc != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
			break;
		case II_TCP_STATE_SYN_RECVD:
			{
				bool fallthrough = false;
				{
					enum iip_rc rc = ii_tcp_conn_handle_in_order__syn_recvd(w, conn_id, pb_id, &fallthrough, &syn, &ack, &fastopen_cookie, opaque);
					if (rc != IIP_ERR_OK) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
				}
				if (!fallthrough)
					break;
			}
		/* fall through */
		case II_TCP_STATE_ESTABLISHED:
			{
				enum iip_rc rc = ii_tcp_conn_handle_in_order__established(w, conn_id, pb_id, &ack, opaque);
				if (rc != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
			break;
		case II_TCP_STATE_CLOSE_WAIT:
			break;
		case II_TCP_STATE_LAST_ACK:
			ii_tcp_conn_handle_in_order__last_ack(w, conn_id, pb_id);
			break;
		case II_TCP_STATE_CLOSED:
			/* do nothing */
			break;
		default:
			break;
		}
		if (syn || ack || rst) {
			enum iip_rc rc = ii_tcp_tx_push_control(w, conn_id,
					(syn ? II_TCP_FLAG_SYN : 0) | (ack ? II_TCP_FLAG_ACK : 0) | (rst ? II_TCP_FLAG_RST : 0));
			if (rc != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_release_acked(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).sent_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).sent_ring);
		{
			uint16_t i;
			/*@
				loop invariant 0 <= i <= cnt < II_CONF_TCP_RING_SLOT_LEN;
				loop assigns i, *w, *opaque;
				loop variant cnt - i;
			 */
			for (i = 0; i < cnt; i++) {
				uint16_t slot_idx = II_TCP_CONN(conn_id).sent_ring.tail + i;
				if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
					slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
				if (II_TCP_CONN(conn_id).sent_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				{
					/*
					 *        conn->acked_seq             conn->seq_be
					 *                  |                        |
					 *  ----- acked ----|------- unacked --------|
					 *              |   |   |
					 *              |   |   |
					 *              A   B   C
					 */
					II_PB_P pb_id = II_TCP_CONN(conn_id).sent_ring.slot[slot_idx];
					if (II_TCP_CONN(conn_id).sent_seq - II_TCP_CONN(conn_id).acked_seq
							<= II_TCP_CONN(conn_id).sent_seq - (II_PB(pb_id).tcp.seq + (ii_tcp_hdr_has_syn(w, pb_id) ? 1 : 0) + (ii_tcp_hdr_has_fin(w, pb_id) ? 1 : 0) + II_PB(pb_id).tcp.payload_len)) { /* A or B */
						if (II_PB(pb_id).tcp.payload_len) {
							if (!(II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_SACKED)) { /* increase window size for congestion control */
								if (II_TCP_CONN(conn_id).cc.ssthresh <= II_TCP_CONN(conn_id).cc.win)
									II_TCP_CONN(conn_id).cc.win = (II_TCP_CONN(conn_id).cc.win < 65535U ? II_TCP_CONN(conn_id).cc.win + 1 : II_TCP_CONN(conn_id).cc.win);
								else
									II_TCP_CONN(conn_id).cc.win = (II_TCP_CONN(conn_id).cc.win < 65535U / 2 ? II_TCP_CONN(conn_id).cc.win * 2 : 65535U);
							}
						}
						ii_free_pb_and_pkt(w, pb_id, opaque);
					} else
						break;
				}
			}
			II_TCP_CONN(conn_id).sent_ring.tail += i;
			if (II_TCP_CONN(conn_id).sent_ring.tail >= II_CONF_TCP_RING_SLOT_LEN)
				II_TCP_CONN(conn_id).sent_ring.tail -= II_CONF_TCP_RING_SLOT_LEN;
		}
#if 0
		/*@ assert II_TCP_CONN(conn_id).sent_ring.tail < II_CONF_TCP_RING_SLOT_LEN; */
#endif
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(w);
	requires \valid(emss);
	requires \separated(w, emss);
	assigns *emss;
 */
static enum iip_rc ii_tcp_ipv4_ethernet_emss(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint16_t tcp_opt_len, uint16_t *emss)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).mss < tcp_opt_len) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	} else {
		uint16_t m = II_TCP_CONN(conn_id).mss - tcp_opt_len;
		{
			uint16_t hdr_len = II_IPV4_HDR_LEN_MINIMAL + 0 /* XXX: assuming no ipv4 option */ + II_TCP_HDR_LEN_MINIMAL + tcp_opt_len;
			if (hdr_len >= II_TCP_CONN(conn_id).path_mtu) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			{
				uint16_t path_len = II_TCP_CONN(conn_id).path_mtu - hdr_len;
				if (m > path_len)
					m = path_len;
			}
		}
		*emss = m;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(w);
	requires \valid(tcp_opt + (0 .. 39));
	requires \valid(tcp_opt_len_p);
	requires \separated(w, tcp_opt, tcp_opt_len_p);
	assigns tcp_opt[0 .. 39], *tcp_opt_len_p;
	ensures \result == IIP_ERR_OK ==> *tcp_opt_len_p <= 40;
 */
static enum iip_rc ii_tcp_xmit_queued_data_one__craft_opt(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id,
		uint16_t tcp_flags, uint16_t info_flags, uint8_t tcp_opt[40], uint8_t *tcp_opt_len_p)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t tcp_opt_len = 0;
		if (tcp_flags & II_TCP_FLAG_SYN) { /* mss */
			uint8_t opt_len = 4;
			tcp_opt[tcp_opt_len + 0] = 2;
			tcp_opt[tcp_opt_len + 1] = opt_len;
			ii_write_uint16(tcp_opt + tcp_opt_len + 2, ii_htons(II_TCP_CONN(conn_id).mss));
			tcp_opt_len += opt_len;
		}
		if (tcp_flags & II_TCP_FLAG_SYN) { /* window scale */
			uint8_t opt_len = 3;
			tcp_opt[tcp_opt_len + 0] = 3;
			tcp_opt[tcp_opt_len + 1] = 3;
			tcp_opt[tcp_opt_len + 2] = II_TCP_CONN(conn_id).ws;
			tcp_opt_len += opt_len;
		}
		if (II_CONF_TCP_OPT_SACK_OK
				&& (tcp_flags & II_TCP_FLAG_SYN)) { /* sack ok */
			uint8_t opt_len = 2;
			tcp_opt[tcp_opt_len + 0] = 4;
			tcp_opt[tcp_opt_len + 1] = 2;
			tcp_opt_len += opt_len;
		}
		if (info_flags & II_PB_FLAGS_TCP_TX_SACKBUF) { /* sack */
			uint8_t opt_len = II_PB(pb_id).tcp.sackbuf[1];
			if (tcp_opt_len + opt_len > 40) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			if (opt_len > sizeof(II_PB(pb_id).tcp.sackbuf)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			{
				uint8_t i;
				/*@
				  loop invariant 0 <= i <= opt_len;
				  loop assigns i, tcp_opt[tcp_opt_len .. tcp_opt_len + opt_len - 1] \from II_PB(pb_id).tcp.sackbuf[0 .. opt_len - 1];
				  loop variant opt_len - i;
				 */
				for (i = 0; i < opt_len; i++)
					tcp_opt[tcp_opt_len + i] = II_PB(pb_id).tcp.sackbuf[i];
			}
			tcp_opt_len += opt_len;
		}
		if (II_CONF_TCP_OPT_TS_OK
				&& ((tcp_flags & II_TCP_FLAG_SYN)
				|| (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_OPT_SET_TS))) { /* time stamp */
			uint8_t opt_len = 10;
			if (tcp_opt_len + opt_len + 2 > 40) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			tcp_opt[tcp_opt_len + 0] = 1; /* nop */
			tcp_opt[tcp_opt_len + 1] = 1; /* nop */
			tcp_opt[tcp_opt_len + 2] = 8;
			tcp_opt[tcp_opt_len + 3] = opt_len;
			ii_write_uint32(tcp_opt + tcp_opt_len + 4, ii_htonl(II_PB(pb_id).tcp.opt.ts[0]));
			ii_write_uint32(tcp_opt + tcp_opt_len + 8, ii_htonl(II_PB(pb_id).tcp.opt.ts[1]));
			tcp_opt_len += opt_len + 2;
		}
		if (II_TCP_CONN(conn_id).fastopen_cookie.len) { /* fast open cookie */
			if (II_TCP_CONN(conn_id).fastopen_cookie.len > sizeof(II_TCP_CONN(conn_id).fastopen_cookie.buf)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			{
				uint8_t opt_len = 2 + II_TCP_CONN(conn_id).fastopen_cookie.len;
				if (tcp_opt_len + opt_len > 40) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				tcp_opt[tcp_opt_len + 0] = 34; /* fast open */
				tcp_opt[tcp_opt_len + 1] = opt_len;
				{
					uint8_t i;
					/*@
					  loop invariant 0 <= i <= II_TCP_CONN(conn_id).fastopen_cookie.len;
					  loop assigns i, tcp_opt[tcp_opt_len + 2 .. tcp_opt_len + 2 + II_TCP_CONN(conn_id).fastopen_cookie.len - 1] \from II_TCP_CONN(conn_id).fastopen_cookie.buf[0 .. II_TCP_CONN(conn_id).fastopen_cookie.len - 1];
					  loop variant II_TCP_CONN(conn_id).fastopen_cookie.len - i;
					 */
					for (i = 0; i < II_TCP_CONN(conn_id).fastopen_cookie.len; i++)
						tcp_opt[tcp_opt_len + 2 + i] = II_TCP_CONN(conn_id).fastopen_cookie.buf[i];
				}
				tcp_opt_len += opt_len;
			}
		}
		/*@ assert tcp_opt_len <= 40; */
		if (tcp_opt_len % 4) {
			/*@ assert tcp_opt_len < 40; */
			uint8_t l = ((tcp_opt_len / 4) + 1) * 4 - tcp_opt_len, i;
			/*@
			  loop invariant 0 <= i <= l;
			  loop assigns i, tcp_opt[tcp_opt_len .. tcp_opt_len + l - 1];
			  loop variant l - i;
			 */
			for (i = 0; i < l; i++)
				tcp_opt[tcp_opt_len + i] = 1; /* nop */
			tcp_opt_len += l;
			/*@ assert tcp_opt_len <= 40; */
		}
		*tcp_opt_len_p = tcp_opt_len;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(head_forwarded);
	requires \valid(xmitted_len);
	requires \separated(w, head_forwarded, xmitted_len, opaque);
	assigns *w, *head_forwarded, *xmitted_len, *opaque;
	ensures \result == IIP_ERR_OK ==> *head_forwarded <= head_off;
	ensures \result == IIP_ERR_OK ==> *xmitted_len <= tx_len;
	ensures \result == IIP_ERR_OK ==> (0 < tx_len ==> 0 < *xmitted_len);
 */
static enum iip_rc ii_tcp_xmit_queued_data_one__trigger(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id,
		uint16_t tcp_flags, uint16_t info_flags,
		uint16_t head_off, uint16_t tx_len, uint16_t seq_off, uint16_t *head_forwarded, uint16_t *xmitted_len, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t tcp_opt_len = 0;
		uint8_t tcp_opt[40];
		if (ii_tcp_xmit_queued_data_one__craft_opt(w, conn_id, pb_id, tcp_flags, info_flags, tcp_opt, &tcp_opt_len) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		{
			uint16_t xmit_len = tx_len;
			{
				uint16_t emss;
				if (ii_tcp_ipv4_ethernet_emss(w, conn_id, tcp_opt_len, &emss) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (!emss) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (xmit_len > emss)
					xmit_len = emss;
				{
					uint8_t tcp_hdr[II_TCP_HDR_LEN_MINIMAL];
					ii_write_uint16(tcp_hdr +  0, ii_htons(II_TCP_CONN(conn_id).src_port));
					ii_write_uint16(tcp_hdr +  2, ii_htons(II_TCP_CONN(conn_id).dst_port));
					ii_write_uint32(tcp_hdr +  4, ii_htonl(II_PB(pb_id).tcp.seq + seq_off));
					ii_write_uint32(tcp_hdr +  8, ii_htonl(II_PB(pb_id).tcp.ack_seq));
					ii_write_uint16(tcp_hdr + 12, ii_htons(tcp_flags | (((II_TCP_HDR_LEN_MINIMAL + tcp_opt_len) / 4) * 4096)));
					ii_write_uint16(tcp_hdr + 14, ii_htons(ii_tcp_compute_win(II_TCP_CONN(conn_id).buf.capacity - II_TCP_CONN(conn_id).buf.used, 7)));
					ii_write_uint16(tcp_hdr + 16, 0); /* csum */
					ii_write_uint16(tcp_hdr + 18, ii_htons(II_PB(pb_id).tcp.urg_p));
					{
						uint8_t pseudo_hdr_ipv4[12];
						ii_write_uint32(pseudo_hdr_ipv4 + 0, ii_htonl(II_TCP_CONN(conn_id).src_ip[0]));
						ii_write_uint32(pseudo_hdr_ipv4 + 4, ii_htonl(II_TCP_CONN(conn_id).dst_ip[0]));
						pseudo_hdr_ipv4[8] = 0;
						pseudo_hdr_ipv4[9] = 6;
						ii_write_uint16(pseudo_hdr_ipv4 + 10, ii_htons(II_TCP_HDR_LEN_MINIMAL + tcp_opt_len + xmit_len));
						{
							const uint8_t *buf_ptr[3 + II_CONF_IPV4_FRAG_CNT_MAX];
							IIP_PKT_LEN_T len[3 + II_CONF_IPV4_FRAG_CNT_MAX];
							buf_ptr[0] = pseudo_hdr_ipv4;
							len[0] = sizeof(pseudo_hdr_ipv4);
							buf_ptr[1] = tcp_hdr;
							len[1] = sizeof(tcp_hdr);
							buf_ptr[2] = tcp_opt;
							len[2] = tcp_opt_len;
							if (II_PB(pb_id).cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
							/*@ assert \forall integer j; 0 <= j < 3 ==> 0 < len[j] ==> \valid_read(buf_ptr[j] + (0 .. len[j] - 1)); */
							{
								IIP_PKT_LEN_T i, l = 0, head_fwd = head_off;
								/*@
								  loop invariant 0 <= i <= II_PB(pb_id).cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
								  loop invariant 0 <= head_fwd <= head_off;
								  loop invariant 0 <= l <= xmit_len;
								  loop invariant \forall integer j; 0 <= j < i ==> len[3 + j] <= f_iip_ops_pkt_get_capacity(II_PB(pb_id).part_pkt[j], opaque);
								  loop invariant \forall integer j; 0 <= j < 3 + i ==> 0 < len[j] ==> \valid_read(buf_ptr[j] + (0 .. len[j] - 1));
								  loop assigns i, head_fwd, l, buf_ptr[3 .. 3 + II_CONF_IPV4_FRAG_CNT_MAX - 1], len[3 .. 3 + II_CONF_IPV4_FRAG_CNT_MAX - 1];
								  loop variant II_PB(pb_id).cnt - i;
								 */
								for (i = 0; i < II_PB(pb_id).cnt && l < xmit_len; i++) {
									if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[i], opaque)) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									buf_ptr[3 + i] = ii_call_pkt_get_data(II_PB(pb_id).part_pkt[i], opaque);
									len[3 + i] = ii_call_pkt_get_len(II_PB(pb_id).part_pkt[i], opaque);
									{
										uint16_t fwd = head_fwd;
										if (fwd) {
											if (fwd > len[3 + i])
												fwd = len[3 + i];
											buf_ptr[3 + i] += fwd;
											len[3 + i] -= fwd;
											head_fwd -= fwd;
										}
										if (len[3 + i] > ii_call_pkt_get_capacity(II_PB(pb_id).part_pkt[i], opaque) - fwd) {
											IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
										}
									}
									if (xmit_len < l + len[3 + i])
										len[3 + i] = xmit_len - l;
									l += len[3 + i];
								}
								if (l != xmit_len) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								*head_forwarded = head_fwd;
								{
									bool iip_ret_bool;
									IIP_OPS_TCP_TX_SKIP_SW_CHECKSUM();
									if (!iip_ret_bool)
										ii_write_uint16(tcp_hdr + 16, ii_htons(ii_csum16(buf_ptr, len, 3 + i, 0)));
								}
								{
									bool iip_ret_bool;
									IIP_OPS_NIC_FEATURE_OFFLOAD_TX_SCATTER_GATHER();
									if (iip_ret_bool && II_PB(pb_id).cnt == 1 && xmit_len == ii_call_pkt_get_len(II_PB(pb_id).part_pkt[0], opaque)) {
										if (ii_ipv4_send_ethernet_zero_copy(II_TCP_CONN(conn_id).src_mac, ii_htonl(II_TCP_CONN(conn_id).src_ip[0]),
													II_TCP_CONN(conn_id).dst_mac, ii_htonl(II_TCP_CONN(conn_id).dst_ip[0]), 6 /* tcp */, II_TCP_CONN(conn_id).diffserv,
													&buf_ptr[1], &len[1], 2, II_PB(pb_id).part_pkt[0], II_PB(pb_id).tcp.payload_len, opaque) != IIP_ERR_OK) {
											IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
										}
									} else {
										if (ii_ipv4_send_ethernet(II_TCP_CONN(conn_id).src_mac, ii_htonl(II_TCP_CONN(conn_id).src_ip[0]),
													II_TCP_CONN(conn_id).dst_mac, ii_htonl(II_TCP_CONN(conn_id).dst_ip[0]), 6 /* tcp */, II_TCP_CONN(conn_id).diffserv,
													&buf_ptr[1], &len[1], 2 + i, opaque) != IIP_ERR_OK) {
											IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
										}
									}
								}
							}
						}
					}
				}
			}
			*xmitted_len = xmit_len;
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_xmit_queued_data_one(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, uint16_t head_off, uint16_t req_len, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_PB(pb_id).tcp.payload_len < head_off || II_PB(pb_id).tcp.payload_len < head_off + req_len) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!req_len && !II_PB(pb_id).tcp.payload_len) {
		/* control packet */
		uint16_t head_forwarded, xmitted_len;
		if (ii_tcp_xmit_queued_data_one__trigger(w, conn_id, pb_id,
					II_PB(pb_id).tcp.flags, II_PB(pb_id).tcp.info_flags, head_off, 0, 0,
					&head_forwarded, &xmitted_len, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
	} else {
		uint16_t sent_len = 0;
		uint16_t head_fwd = head_off;
		uint16_t tcp_flags = II_PB(pb_id).tcp.flags;
		uint16_t info_flags = II_PB(pb_id).tcp.info_flags;
		/*@
		  loop invariant 0 <= sent_len <= req_len;
		  loop assigns sent_len, head_fwd, tcp_flags, info_flags, *w, *opaque;
		  loop variant req_len - sent_len;
		  */
		while (sent_len < req_len) {
			uint16_t head_forwarded, xmitted_len;
			if (ii_tcp_xmit_queued_data_one__trigger(w, conn_id, pb_id,
						tcp_flags, info_flags,
						head_off + sent_len, req_len - sent_len, head_off + sent_len,
						&head_forwarded, &xmitted_len, opaque) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			head_fwd -= head_forwarded;
			sent_len += xmitted_len;
			tcp_flags &= ~(II_TCP_FLAG_SYN);
			info_flags = 0;
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn_xmit_queued_data(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint32_t tx_space, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!tx_space)
		return IIP_ERR_OK;
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).tx_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).sent_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).tx_ring), sent_ring_space = ii_pb_ring_num_usable(&II_TCP_CONN(conn_id).sent_ring);
		if (sent_ring_space < cnt) {
			IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM; /* TODO */
		}
		{
			uint32_t sent = 0;
			uint16_t i;
			/*@
				loop invariant 0 <= i <= cnt <= II_CONF_TCP_RING_SLOT_LEN;
				loop assigns i, sent, *w, *opaque;
				loop variant cnt - i;
			 */
			for (i = 0; i < cnt && sent < tx_space; i++) {
				uint16_t slot_idx = II_TCP_CONN(conn_id).tx_ring.tail + i;
				if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
					slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
				if (II_TCP_CONN(conn_id).tx_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.payload_len < II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				{
					uint16_t l = II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.payload_len - II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes;
					if (tx_space - sent < l)
						l = tx_space - sent;
					if (ii_tcp_xmit_queued_data_one(w, conn_id, II_TCP_CONN(conn_id).tx_ring.slot[slot_idx],
								II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes, l, opaque) != IIP_ERR_OK)
						return IIP_ERR_OK;
					if (II_TCP_CONN(conn_id).tx_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes += l;
					sent += l;
				}
				II_TCP_CONN(conn_id).sent_seq = II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.seq
					+ (II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_FIN ? 1 : 0)
					+ (II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_SYN ? 1 : 0)
					+ II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes;
				if (II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.payload_len == II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes) {
					II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.sent_bytes = 0; /* reuse for retransmission */
					if (ii_pb_ring_push(&II_TCP_CONN(conn_id).sent_ring, II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]) != IIP_ERR_OK) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS; /* TODO */
					}
				} else {
					if (sent == tx_space)
						break; /* do not forward i */
				}
			}
			II_TCP_CONN(conn_id).tx_ring.tail += i;
			if (II_TCP_CONN(conn_id).tx_ring.tail >= II_CONF_TCP_RING_SLOT_LEN)
				II_TCP_CONN(conn_id).tx_ring.tail -= II_CONF_TCP_RING_SLOT_LEN;
		}
#if 0
		/*@ assert II_TCP_CONN(conn_id).tx_ring.tail < II_CONF_TCP_RING_SLOT_LEN; */
#endif
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns II_TCP_CONN(conn_id);
 */
static void ii_tcp_conn_input_one__check_dup_ack(IIP_MEM_P w, IIP_TCP_CONN_P conn_id)
{
	if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED)) {
		if (II_TCP_CONN(conn_id).dup_ack_received == 3) {
			II_TCP_CONN(conn_id).dup_ack_received = 0;
			II_TCP_CONN(conn_id).cc.ssthresh = (II_TCP_CONN(conn_id).cc.win / 2 < 1 ? 2 : II_TCP_CONN(conn_id).cc.win / 2);
			II_TCP_CONN(conn_id).cc.win = 1;
			II_TCP_CONN(conn_id).sent_seq_when_loss_detected = II_TCP_CONN(conn_id).seq;
			II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_PEER_RX_FAILED;
			IIP_OPS_DEBUG_PRINTF("[%s:%u]: loss detected because of dup ack\n", __func__, __LINE__);
		}
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn_input_one(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t out_of_order, valid_ack;
		ii_tcp_check_input_ack(w, conn_id, pb_id, &out_of_order, &valid_ack);
		ii_tcp_conn_input_one__check_dup_ack(w, conn_id);
		if (out_of_order == 1)
			return IIP_ERR_INVALID_RX;
		{
			enum iip_rc rc = ii_tcp_conn_update_info(w, conn_id, pb_id, out_of_order, valid_ack, opaque);
			if (rc != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
		}
	}
	if (ii_tcp_hdr_has_rst(w, pb_id)) {
		ii_tcp_conn_handle_rst(w, conn_id);
		return IIP_ERR_OK;
	} else
		return ii_tcp_conn_handle_in_order(w, conn_id, pb_id, opaque);
}

/* XXX: this takes time */
/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(payload + (0 .. len - 1));
	requires \valid(payload_len);
	requires \valid(fin);
	requires \valid(syn);
	requires \valid(ack);
	requires \separated(w, payload + (0 .. len - 1), payload_len, syn, fin, opaque);
	requires 0 < len;
	assigns payload[0 .. len - 1], *payload_len, *fin, *syn, *ack;
 */
static enum iip_rc ii_tcp_conn_copy_sent_payload(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint32_t le, uint16_t len,
		uint8_t *payload, uint16_t *payload_len, uint8_t *fin, uint8_t *syn, uint8_t *ack, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).sent_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).sent_ring);
		{
			uint8_t found_fin = 0, found_syn = 0, found_ack = 0;
			uint16_t i, buf_off = 0;
			/*@
				loop invariant 0 <= i <= cnt < II_CONF_TCP_RING_SLOT_LEN;
				loop assigns i, buf_off, payload[0 .. len - 1], found_fin, found_syn, found_ack;
				loop variant cnt - i;
			 */
			for (i = 0; i < cnt; i++) {
				uint16_t slot_idx = II_TCP_CONN(conn_id).sent_ring.tail + i;
				if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
					slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
				if (II_TCP_CONN(conn_id).sent_ring.slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (le == ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]) || ii_seq_ordered(le, ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]))) {
					/*
					 *  le
					 *   |
					 *     seq
					 *      |
					 */
					if (ii_seq_ordered(le + len, ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]))) {
						/*
						 *  le
						 *   |----|
						 *          seq
						 *           |--------|
						 */
#if 0
						/*@ assert \false; */
#endif
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					} else {
						/*
						 *  le
						 *   |----------
						 *          seq
						 *           |--
						 */
						if (ii_seq_ordered(le + len, ii_tcp_seq_re_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]))) {
							/*
							 *  le
							 *   |-----------|
							 *          seq
							 *           |-----|
							 */
							uint16_t l = le + len - ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]);
							if (l) {
								if (len < buf_off + l) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								{
									IIP_PKT_LEN_T copied_len;
									if (ii_pb_payload_copy(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx], 0, &payload[buf_off], l, &copied_len, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (copied_len != l) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
								}
								buf_off += l;
							}
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_FIN)
								found_fin = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_SYN)
								found_syn = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_ACK)
								found_ack = 1;
							break;
						} else {
							/*
							 *  le
							 *   |---------------|
							 *          seq
							 *           |-----|
							 */
							uint16_t l = II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.payload_len;
							if (l) {
								if (len < buf_off + l) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								{
									IIP_PKT_LEN_T copied_len;
									if (ii_pb_payload_copy(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx], 0, &payload[buf_off], l, &copied_len, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (copied_len != l) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
								}
								buf_off += l;
							}
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_FIN)
								found_fin = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_SYN)
								found_syn = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_ACK)
								found_ack = 1;
						}
					}
				} else {
					/*
					 *      le
					 *       |
					 *  seq
					 *   |
					 */
					if (ii_seq_ordered(ii_tcp_seq_re_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]), le)) {
					/*
					 *          le
					 *           |
					 *  seq
					 *   |----|
					 */
					} else {
						/*
						 *       le
						 *        |
						 *  seq
						 *   |--------|
						 */
						if (ii_seq_ordered(le + len, ii_tcp_seq_re_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]))) {
							/*
							 *       le
							 *        |--|
							 *  seq
							 *   |--------|
							 */
							uint16_t l = len, s = le - ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]);
							if (l) {
								if (len < buf_off + l) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								{
									IIP_PKT_LEN_T copied_len;
									if (ii_pb_payload_copy(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx], s, &payload[buf_off], l, &copied_len, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (copied_len != l) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
								}
								buf_off += l;
							}
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_FIN)
								found_fin = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_SYN)
								found_syn = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_ACK)
								found_ack = 1;
							break;
						} else  {
							/*
							 *       le
							 *        |------|
							 *  seq
							 *   |--------|
							 */
							uint16_t l = ii_tcp_seq_re_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]) - le, s = le - ii_tcp_seq_le_raw(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]);
							if (l) {
								if (len < buf_off + l) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								{
									IIP_PKT_LEN_T copied_len;
									if (ii_pb_payload_copy(w, II_TCP_CONN(conn_id).sent_ring.slot[slot_idx], s, &payload[buf_off], l, &copied_len, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (copied_len != l) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
								}
								buf_off += l;
							}
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_FIN)
								found_fin = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_SYN)
								found_syn = 1;
							if (II_PB(II_TCP_CONN(conn_id).sent_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_ACK)
								found_ack = 1;
						}
					}
				}
			}
			*fin = found_fin;
			*syn = found_syn;
			*ack = found_ack;
			*payload_len = buf_off;
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid_read(eq);
	requires \valid(retx_bytes);
	requires \separated(w, eq, retx_bytes, opaque);
	assigns *w, *retx_bytes, *opaque;
	ensures \result == IIP_ERR_OK ==> *retx_bytes <= tx_space;
 */
static enum iip_rc ii_tcp_conn_queue_retx_data__trigger(IIP_MEM_P w, struct ii_extent_queue *eq, uint8_t eq_cnt, IIP_TCP_CONN_P conn_id, uint32_t tx_space, uint32_t *retx_bytes, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (eq_cnt > II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint32_t le = II_TCP_CONN(conn_id).acked_seq, retx_b = 0;
		uint8_t i;
		/*@
			loop invariant 0 <= i <= eq_cnt <= II_CONF_EXTENT_QUEUE_SIZE;
			loop invariant 0 <= retx_b <= tx_space;
			loop assigns i, le, retx_b, *w, *opaque;
			loop variant eq_cnt - i;
		 */
		for (i = 0; i < eq_cnt && retx_b < tx_space; i++) {
			if (le != eq->extent[i].v && !ii_seq_ordered(le, eq->extent[i].v)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			IIP_OPS_DEBUG_PRINTF("[%s:%u]: TCP (conn %u) retransmission seq %u (len %u)\n", __func__, __LINE__, conn_id, eq->extent[i].v, eq->extent[i].v - le);
			{
				uint32_t len = eq->extent[i].v - le;
				if (len > tx_space - retx_b)
					len = tx_space - retx_b;
				/*@ assert len + retx_b <= tx_space; */
				{
					uint32_t l = 0;
					/*@
					  loop invariant 0 <= l <= len;
					  loop assigns l, *w, *opaque;
					  loop variant len - l;
					 */
					while (l < len) {
						IIP_PKT_P new_pkt;
						if (ii_call_pkt_alloc(&new_pkt, opaque)) {
							IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
						}
						{
							uint16_t tx_len;
							{
								uint16_t hdr_len = II_ETH_HDR_LEN + 60 + 60; /* XXX: assuming full ipv4 and tcp hdr sizes */
								if (ii_call_pkt_get_capacity(new_pkt, opaque) <= hdr_len) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								tx_len = ii_call_pkt_get_capacity(new_pkt, opaque) - hdr_len;
								if (tx_len > len - l)
									tx_len = len - l;
							}
							{
								uint16_t payload_len = 0;
								uint8_t fin = 0, syn = 0, ack = 0;
								if (tx_len) {
									uint8_t payload[0xffff]; /* XXX: for separation, assuming sufficiently large stack */
									if (ii_tcp_conn_copy_sent_payload(w, conn_id, le + l, tx_len,
												payload, &payload_len, &fin, &syn, &ack, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									{
										uint16_t copied_len;
										/*@
											loop invariant 0 <= copied_len <= tx_len;
											loop assigns copied_len, f_iip_ops_pkt_get_data(new_pkt, opaque)[0 .. tx_len - 1];
											loop variant tx_len - copied_len;
										 */
										for (copied_len = 0; copied_len < tx_len; copied_len++)
											ii_call_pkt_get_data(new_pkt, opaque)[copied_len] = payload[copied_len];
									}
								}
								{
									II_PB_P pb_id;
									{
										enum iip_rc rc = ii_alloc_pb(&w->pbs, &pb_id);
										if (rc != IIP_ERR_OK) {
											if (ii_call_pkt_free(new_pkt, opaque)) {
												IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
											}
											return rc;
										}
									}
									II_PB(pb_id).part_pkt[0] = new_pkt;
									II_PB(pb_id).cnt = 1;
									II_PB(pb_id).tcp.info_flags = 0;
									II_PB(pb_id).tcp.seq = le + l;
									II_PB(pb_id).tcp.ack_seq = II_TCP_CONN(conn_id).ack_seq;
									II_PB(pb_id).tcp.flags = (ack ? II_TCP_FLAG_ACK : 0) | (fin ? II_TCP_FLAG_FIN : 0) | (syn ? II_TCP_FLAG_SYN : 0);
									II_PB(pb_id).tcp.payload_len = payload_len;
									II_PB(pb_id).tcp.urg_p = 0;
									II_PB(pb_id).tcp.opt.ts[0] = w->tcp.pkt_ts;
									II_PB(pb_id).tcp.opt.ts[1] = II_TCP_CONN(conn_id).ts;
									if (ii_call_pkt_set_len(new_pkt, payload_len, opaque)) {
										if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK) {
											IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
										}
										IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
									}
									if (ii_tcp_xmit_queued_data_one(w, conn_id, pb_id, 0, II_PB(pb_id).tcp.payload_len, opaque) != IIP_ERR_OK) {
										if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK) {
											IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
										}
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
								}
							}
							l += tx_len;
						}
					}
				}
				/*@ assert len + retx_b <= tx_space; */
				retx_b += len;
				/*@ assert retx_b <= tx_space; */
			}
			le = eq->extent[i].v + eq->extent[i].l;
		}
		*retx_bytes = retx_b;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(retx_bytes);
	requires \separated(w, retx_bytes, opaque);
	assigns *w, *retx_bytes, *opaque;
 */
static enum iip_rc ii_tcp_conn_retx(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint32_t tx_space, uint32_t *retx_bytes, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).sent_ring.head != II_TCP_CONN(conn_id).sent_ring.tail) {
		struct ii_extent_queue eq;
		if (II_TCP_CONN(conn_id).sack.cnt)
			eq = II_TCP_CONN(conn_id).sack;
		else {
			eq.cnt = 1;
			eq.extent[0].v = II_TCP_CONN(conn_id).acked_seq + (II_TCP_CONN(conn_id).seq - II_TCP_CONN(conn_id).acked_seq > tx_space ? tx_space : II_TCP_CONN(conn_id).seq - II_TCP_CONN(conn_id).acked_seq);
			eq.extent[0].l = 0;
		}
		return ii_tcp_conn_queue_retx_data__trigger(w, &eq, eq.cnt, conn_id, tx_space, retx_bytes, opaque);
	} else {
		*retx_bytes = 0;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(w);
	requires \valid(on_wire_bytes);
	requires \separated(w, on_wire_bytes);
	assigns *on_wire_bytes;
 */
static enum iip_rc ii_tcp_conn_on_wire_bytes(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint32_t *on_wire_bytes)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).sack.cnt > II_CONF_EXTENT_QUEUE_SIZE) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint32_t b;
		if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED)
			b = 0;
		else {
			b = II_TCP_CONN(conn_id).sent_seq - II_TCP_CONN(conn_id).acked_seq;
			if (II_TCP_CONN(conn_id).sack.cnt) {
				uint32_t le = II_TCP_CONN(conn_id).sack.extent[0].v;
				uint32_t re = II_TCP_CONN(conn_id).sack.extent[II_TCP_CONN(conn_id).sack.cnt - 1].v + II_TCP_CONN(conn_id).sack.extent[II_TCP_CONN(conn_id).sack.cnt - 1].l;
				if (ii_seq_ordered(re, le)) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				{
					uint32_t sacked_range = re - le;
					if (b < sacked_range) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					b -= sacked_range;
				}
			}
		}
		b += II_TCP_CONN(conn_id).retx_bytes;
		*on_wire_bytes = b;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(w);
	requires \valid(space);
	requires \separated(w, space);
	assigns *space;
 */
static enum iip_rc ii_tcp_conn_tx_space(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, uint32_t *space)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).ws >= 15) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint32_t flow_win = (uint32_t) II_TCP_CONN(conn_id).peer_win << II_TCP_CONN(conn_id).ws;
		uint32_t cc_win = (uint32_t) II_TCP_CONN(conn_id).cc.win * II_TCP_CONN(conn_id).mss;
		{
			uint32_t win;
			if (flow_win < cc_win)
				win = flow_win;
			else
				win = cc_win;
			{
				uint32_t on_wire;
				if (ii_tcp_conn_on_wire_bytes(w, conn_id, &on_wire) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (win < on_wire)
					*space = 0;
				else
					*space = win - on_wire;
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(w);
	assigns *w;
 */
static enum iip_rc ii_tcp_conn_retx_timeout_check(IIP_MEM_P w, IIP_TCP_CONN_P conn_id)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SET_PROBE)
		return IIP_ERR_OK;
	if (ii_seq_ordered(II_TCP_CONN(conn_id).acked_seq, II_TCP_CONN(conn_id).sent_seq)) {
		if (w->now_ms - II_TCP_CONN(conn_id).rto_expire /* XXX: properly set? */ < UINT32_MAX / 2) {
			if (II_TCP_CONN(conn_id).retrans_cnt < II_TCP_CONN(conn_id).retrans_r2) {
				ii_tcp_conn_update_rto(w, conn_id, true);
				II_TCP_CONN(conn_id).sack.cnt = 0; /* clear sack info */
				II_TCP_CONN(conn_id).retx_bytes = 0; /* no data is on wire */
				II_TCP_CONN(conn_id).retrans_cnt++;
				if (II_TCP_CONN(conn_id).retrans_cnt == II_TCP_CONN(conn_id).retrans_r1) {
					int iip_ret_int;
					IIP_OPS_TCP_IP_NEGATIVE_ADVICE();
					if (iip_ret_int) {
						IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
					}
				}
				if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED)) {
					II_TCP_CONN(conn_id).cc.ssthresh = (II_TCP_CONN(conn_id).cc.win / 2 < 1 ? 2 : II_TCP_CONN(conn_id).cc.win / 2);
					II_TCP_CONN(conn_id).cc.win = 1;
					II_TCP_CONN(conn_id).sent_seq_when_loss_detected = II_TCP_CONN(conn_id).sent_seq;
					II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_PEER_RX_FAILED;
					IIP_OPS_DEBUG_PRINTF("[%s:%u]: loss detected because of timeout\n", __func__, __LINE__);
				}
			} else {
				ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_CLOSED);
				ii_tcp_conn_enter_close_phase(w, conn_id);
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, sent, opaque);
	requires \valid(sent);
	assigns *w, *opaque, *sent;
 */
static enum iip_rc ii_tcp_conn__zero_window_probe_send(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, bool is_tx_ring, bool *sent, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		struct ii_pb__ring *ring;
		if (is_tx_ring)
			ring = &II_TCP_CONN(conn_id).tx_ring;
		else
			ring = &II_TCP_CONN(conn_id).sent_ring;
		if (ii_pb_ring_validation(ring) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		{
			uint32_t new_sent_seq = 0;
			bool probe_sent = false, new_seq_set = false;
			{
				IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(ring);
				{
					uint16_t i;
					/*@
						loop invariant 0 <= i <= cnt < II_CONF_TCP_RING_SLOT_LEN;
						loop assigns i, probe_sent, new_sent_seq, new_seq_set, *w, *opaque;
						loop variant cnt - i;
					 */
					for (i = 0; i < cnt; i++) {
						uint16_t slot_idx = ring->tail + i;
						if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
							slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
						if (ring->slot[slot_idx] >= II_CONF_POOL_NUM_PB) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
						{
							II_PB_P probe_pb_id = ring->slot[slot_idx];
							if (!II_PB(probe_pb_id).tcp.payload_len) {
								if (II_PB(probe_pb_id).tcp.flags & II_TCP_FLAG_FIN) {
									uint16_t head_forwarded, xmitted_len;
									if (ii_tcp_xmit_queued_data_one__trigger(w, conn_id, probe_pb_id, II_TCP_FLAG_FIN | II_TCP_FLAG_ACK,
												0, 0, 0, 0, &head_forwarded, &xmitted_len, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (is_tx_ring) {
										if (ii_seq_ordered(II_TCP_CONN(conn_id).sent_seq, II_PB(probe_pb_id).tcp.seq + 1)) {
											new_sent_seq = II_PB(probe_pb_id).tcp.seq + 1;
											new_seq_set = true;
										}
									}
									probe_sent = true;
									break;
								}
							} else if (II_PB(probe_pb_id).tcp.payload_len == II_TCP_CONN(conn_id).acked_seq - II_PB(probe_pb_id).tcp.seq) {
								if (II_PB(probe_pb_id).tcp.flags & II_TCP_FLAG_FIN) {
									uint16_t head_forwarded, xmitted_len;
									if (ii_tcp_xmit_queued_data_one__trigger(w, conn_id, probe_pb_id, II_TCP_FLAG_FIN | II_TCP_FLAG_ACK,
												II_PB(probe_pb_id).tcp.payload_len, 0, 0, II_PB(probe_pb_id).tcp.payload_len, &head_forwarded, &xmitted_len, opaque) != IIP_ERR_OK) {
										IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
									}
									if (is_tx_ring) {
										if (ii_seq_ordered(II_TCP_CONN(conn_id).sent_seq, II_PB(probe_pb_id).tcp.seq + II_PB(probe_pb_id).tcp.payload_len + 1)) {
											new_sent_seq = II_PB(probe_pb_id).tcp.seq + II_PB(probe_pb_id).tcp.payload_len + 1;
											new_seq_set = true;
										}
									}
									probe_sent = true;
									break;
								}
							} else if (II_PB(probe_pb_id).tcp.payload_len > II_TCP_CONN(conn_id).acked_seq - II_PB(probe_pb_id).tcp.seq) {
								uint16_t head_forwarded, xmitted_len;
								if (ii_tcp_xmit_queued_data_one__trigger(w, conn_id, probe_pb_id, II_TCP_FLAG_ACK,
											II_TCP_CONN(conn_id).acked_seq - II_PB(probe_pb_id).tcp.seq, 0,
											1, II_TCP_CONN(conn_id).acked_seq - II_PB(probe_pb_id).tcp.seq, &head_forwarded, &xmitted_len, opaque) != IIP_ERR_OK) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								if (is_tx_ring) {
									if (ii_seq_ordered(II_TCP_CONN(conn_id).sent_seq, II_PB(probe_pb_id).tcp.seq + II_TCP_CONN(conn_id).acked_seq - II_PB(probe_pb_id).tcp.seq + 1)) {
										new_sent_seq = II_PB(probe_pb_id).tcp.seq + II_TCP_CONN(conn_id).acked_seq - II_PB(probe_pb_id).tcp.seq + 1;
										new_seq_set = true;
									}
								}
								probe_sent = true;
								break;
							}
						}
					}
				}
			}
			if (probe_sent && new_seq_set)
				II_TCP_CONN(conn_id).sent_seq = new_sent_seq;
			*sent = probe_sent;
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn__zero_window_probe_check(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		bool clear = false;
		if ((II_TCP_CONN(conn_id).tx_ring.head != II_TCP_CONN(conn_id).tx_ring.tail)
				|| (II_TCP_CONN(conn_id).sent_ring.head != II_TCP_CONN(conn_id).sent_ring.tail)) {
			if (II_TCP_CONN(conn_id).peer_win && (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SET_PROBE))
				clear = true;
			else {
				if (!II_TCP_CONN(conn_id).peer_win && !(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SET_PROBE)) {
					II_TCP_CONN(conn_id).probe_rto_ms = (II_TCP_CONN(conn_id).rtt.srtt + 4 * II_TCP_CONN(conn_id).rtt.rttvar) * 200;
					if (!II_TCP_CONN(conn_id).probe_rto_ms)
						II_TCP_CONN(conn_id).probe_rto_ms = 200U;
					if (60000U /* 60 sec */ < II_TCP_CONN(conn_id).probe_rto_ms)
						II_TCP_CONN(conn_id).probe_rto_ms = 60000U;
					II_TCP_CONN(conn_id).probe_ts = w->now_ms;
					II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_SET_PROBE;
				}
				if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_SET_PROBE) {
					if (II_TCP_CONN(conn_id).probe_rto_ms < w->now_ms - II_TCP_CONN(conn_id).probe_ts) {
						bool sent;
						if (II_TCP_CONN(conn_id).sent_ring.head != II_TCP_CONN(conn_id).sent_ring.tail) {
							if (ii_tcp_conn__zero_window_probe_send(w, conn_id, 0, &sent, opaque) != IIP_ERR_OK) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
							if (!sent) {
								if (ii_tcp_conn__zero_window_probe_send(w, conn_id, 1, &sent, opaque) != IIP_ERR_OK) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
							}
						} else {
							if (ii_tcp_conn__zero_window_probe_send(w, conn_id, 1, &sent, opaque) != IIP_ERR_OK) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
						}
						if (sent) {
							II_TCP_CONN(conn_id).probe_rto_ms *= 2;
							if (60000U /* 60 sec */ < II_TCP_CONN(conn_id).probe_rto_ms)
								II_TCP_CONN(conn_id).probe_rto_ms = 60000U;
							II_TCP_CONN(conn_id).probe_ts = w->now_ms;
						} else
							clear = true;
					}
				}
			}
		} else
			clear = true;
		if (clear) {
			II_TCP_CONN(conn_id).flags &= ~II_TCP_CONN_FLAGS_SET_PROBE;
			ii_tcp_conn_update_rto(w, conn_id, false);
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_conn_work(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_ACK_PENDING) {
		if (ii_tcp_tx_push_control(w, conn_id, II_TCP_FLAG_ACK) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
	}
	if (ii_pb_ring_validation(&II_TCP_CONN(conn_id).rx_ring) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_CNT_T cnt = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).rx_ring);
		{
			uint16_t i;
			/*@
				loop invariant 0 <= i <= cnt < II_CONF_TCP_RING_SLOT_LEN;
				loop assigns i, *w, *opaque;
				loop variant cnt - i;
			 */
			for (i = 0; i < cnt; i++) {
				uint16_t slot_idx = II_TCP_CONN(conn_id).rx_ring.tail + i;
				if (slot_idx >= II_CONF_TCP_RING_SLOT_LEN)
					slot_idx %= II_CONF_TCP_RING_SLOT_LEN;
				{
					II_PB_P pb_id = II_TCP_CONN(conn_id).rx_ring.slot[slot_idx];
					if (pb_id >= II_CONF_POOL_NUM_PB) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					{
						enum iip_rc rc = ii_tcp_conn_input_one(w, conn_id, pb_id, opaque);
						switch (rc) {
						case IIP_ERR_FATAL_SYS:
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						case IIP_ERR_FATAL_USR:
								IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
						case IIP_ERR_FATAL_SUB:
								IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
						default:
							break;
						}
					}
					if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
				}
			}
		}
		II_TCP_CONN(conn_id).rx_ring.tail = II_TCP_CONN(conn_id).rx_ring.head;
		ii_tcp_release_acked(w, conn_id, opaque);
		ii_extent_queue_shrink(&II_TCP_CONN(conn_id).sack, II_TCP_CONN(conn_id).acked_seq);
		if (ii_tcp_conn__zero_window_probe_check(w, conn_id, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ii_tcp_conn_retx_timeout_check(w, conn_id) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if ((II_TCP_CONN(conn_id).tx_ring.head != II_TCP_CONN(conn_id).tx_ring.tail)
				|| (II_TCP_CONN(conn_id).sent_ring.head != II_TCP_CONN(conn_id).sent_ring.tail)) {
			uint32_t tx_space;
			if (ii_tcp_conn_tx_space(w, conn_id, &tx_space) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			if (II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED) {
				uint32_t retx_bytes;
				if (ii_tcp_conn_retx(w, conn_id, tx_space, &retx_bytes, opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (tx_space < retx_bytes) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				II_TCP_CONN(conn_id).retx_bytes = retx_bytes;
			} else {
				if (ii_tcp_conn_xmit_queued_data(w, conn_id, tx_space, opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
		}
		ii_tcp_conn_close_check(w, conn_id, opaque);
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_tcp_rx_push(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint32_t push_pb_id = pb_id;
		if (II_TCP_CONN(conn_id).pending_ring.head >= II_CONF_TCP_RING_SLOT_LEN || II_TCP_CONN(conn_id).pending_ring.tail >= II_CONF_TCP_RING_SLOT_LEN) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		} else {
			uint16_t i, loop_max = ii_pb_ring_num_used(&II_TCP_CONN(conn_id).pending_ring) + 1;
			/*@
				loop invariant 0 <= i <= loop_max;
				loop invariant push_pb_id < II_CONF_POOL_NUM_PB;
				loop assigns i, push_pb_id, *w, *opaque;
				loop variant loop_max - i;
			 */
			for (i = 0; i < loop_max; i++) {
				if (II_TCP_CONN(conn_id).buf.used > II_TCP_CONN(conn_id).buf.capacity) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_tcp_retransmitted_syn_ack(w, conn_id, pb_id))
					II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_ACK_PENDING; /* send ack */
				if (ii_tcp_check_input_seq(w, conn_id, push_pb_id) != IIP_ERR_OK)
					return IIP_ERR_INVALID_RX;
				if (II_TCP_CONN(conn_id).seq_next_expected == ii_tcp_seq_le_raw(w, push_pb_id)) {
					II_TCP_CONN(conn_id).seq_next_expected = ii_tcp_seq_re_raw(w, push_pb_id);
					{
						enum iip_rc rc = ii_pb_ring_push(&II_TCP_CONN(conn_id).rx_ring, push_pb_id);
						if (rc != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
					}
				} else {
					IIP_OPS_DEBUG_PRINTF("[%s:%u]: TCP unexpected seq %u (expected %u)\n", __func__, __LINE__, II_TCP_CONN(conn_id).seq_next_expected, ii_tcp_seq_le_raw(w, push_pb_id));
					II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_ACK_PENDING; /* send ack for packet loss detection */
					return ii_tcp_rx_push__pending(w, conn_id, push_pb_id, opaque);
				}
				if (II_TCP_CONN(conn_id).pending_ring.head != II_TCP_CONN(conn_id).pending_ring.tail) {
					if (ii_pb_ring_pull(&II_TCP_CONN(conn_id).pending_ring, &push_pb_id) != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					if (push_pb_id >= II_CONF_POOL_NUM_PB) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
				} else
					break;
			}
			return IIP_ERR_OK;
		}
	}
}

/*@
	requires \separated(w, tcp_hdr);
	requires \valid_read(tcp_hdr + (0 .. II_TCP_HDR_LEN_MINIMAL - 1));
	requires \valid(w);
	requires pb_id < II_CONF_POOL_NUM_PB;
	assigns II_PB(pb_id).tcp;
 */
static void ii_tcp_pb_init__base(IIP_MEM_P w, II_PB_P pb_id, uint8_t tcp_hdr[II_TCP_HDR_LEN_MINIMAL])
{
	{
		struct ii_pb clear_pb = { 0 };
		II_PB(pb_id).tcp = clear_pb.tcp;
	}
	II_PB(pb_id).tcp.seq = ii_ntohl(ii_read_uint32(&tcp_hdr[4]));
	II_PB(pb_id).tcp.ack_seq = ii_ntohl(ii_read_uint32(&tcp_hdr[8]));
	II_PB(pb_id).tcp.flags = ii_ntohs(ii_read_uint16(&tcp_hdr[12]));
	II_PB(pb_id).tcp.win = ii_ntohs(ii_read_uint16(&tcp_hdr[14]));
	II_PB(pb_id).tcp.urg_p = ii_ntohs(ii_read_uint16(&tcp_hdr[18]));
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns II_PB(pb_id).tcp.payload_len;
 */
static enum iip_rc ii_tcp_pb_init__payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_LEN_T ipv4_payload_len;
		if (ii_pb_ipv4_payload_len(w, pb_id, &ipv4_payload_len, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ipv4_payload_len < ii_pb_tcp_hdr_len(w, pb_id))
			return IIP_ERR_INVALID_RX;
		{
			IIP_PKT_LEN_T len;
			if (ii_pb_tcp_payload_len(w, pb_id, &len, opaque) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			II_PB(pb_id).tcp.payload_len = len;
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_tcp_input__parse_opt(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_pb_tcp_hdr_len(w, pb_id) < II_TCP_HDR_LEN_MINIMAL)
		return IIP_ERR_INVALID_RX;
	{
		uint8_t tcp_opt_len = ii_pb_tcp_hdr_len(w, pb_id) - II_TCP_HDR_LEN_MINIMAL;
		if (tcp_opt_len) {
			uint8_t tcp_opt[40];
			{
				IIP_PKT_LEN_T copied_len;
				if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_pb_payload_copy(w, pb_id, II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN) + II_TCP_HDR_LEN_MINIMAL, tcp_opt, tcp_opt_len, &copied_len, opaque) != IIP_ERR_OK)
					return IIP_ERR_INVALID_RX;
				if (copied_len != tcp_opt_len)
					return IIP_ERR_INVALID_RX;
			}
			{ /* parse tcp option */
				uint8_t l = 0;
				/*@
					loop invariant 0 <= l <= tcp_opt_len;
					loop assigns l, *w, *opaque;
					loop variant tcp_opt_len - l;
				 */
				while (l < tcp_opt_len) {
					switch (tcp_opt[l]) {
					case 0: /* eol */
						l = tcp_opt_len; /* stop loop */
						break;
					case 1: /* nop */
						l++;
						break;
					default:
						if (tcp_opt_len - l < 2) {
							l = tcp_opt_len; /* stop loop */
							break;
						}
						/*@ assert l < tcp_opt_len - 1; */
						switch (tcp_opt[l]) {
						case 2: /* mss */
							if (tcp_opt[l + 1] == 4
									&& tcp_opt_len - l >= 4) {
								if (II_PB(pb_id).tcp.flags & II_TCP_FLAG_SYN) { /* accept only with syn */
									uint16_t mss = ii_ntohs(ii_read_uint16(tcp_opt + l + 2));
									if (!mss) {
										/* ignore mss 0 */
									} else {
										II_TCP_CONN(conn_id).mss = mss;
										if (536 < II_TCP_CONN(conn_id).mss) /* TODO: mss */
											II_TCP_CONN(conn_id).mss = 536;
									}
								}
							} else
								return IIP_ERR_INVALID_RX;
							break;
						case 3: /* window scale */
							if (tcp_opt[l + 1] == 3
									&& tcp_opt_len - l >= 3) {
								if (II_PB(pb_id).tcp.flags & II_TCP_FLAG_SYN) /* accept only with syn */
									II_TCP_CONN(conn_id).ws = tcp_opt[l + 2];
							} else
								return IIP_ERR_INVALID_RX;
							break;
						case 4: /* sack permitted */
#if 0
							if (tcp_opt[l + 1] == 2
									&& tcp_opt_len - l >= 2) {
#endif
								if (II_PB(pb_id).tcp.flags & II_TCP_FLAG_SYN) /* accept only with syn */
									II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_SACK_OK;
#if 0
							} else
								return IIP_ERR_INVALID_RX;
#endif
							break;
						case 5: /* sack */
							if (tcp_opt[l + 1] >= (2 + 8)
									&& tcp_opt[l + 1] <= tcp_opt_len - l
									&& (tcp_opt[l + 1] - 2) % 8 == 0) {
								uint8_t sackbuf_len = tcp_opt[l + 1] - 2;
								if (sackbuf_len) {
									uint8_t i;
									/*@
										loop invariant 0 <= i <= sackbuf_len;
										loop invariant i % 8 == 0;
										loop invariant sackbuf_len % 8 == 0;
										loop assigns i, II_TCP_CONN(conn_id).sack;
										loop variant sackbuf_len - i;
									 */
									for (i = 0; i < sackbuf_len; i += 8) {
										uint32_t sle = ii_ntohl(ii_read_uint32(tcp_opt + l + 2 + i + 0));
										uint32_t sre = ii_ntohl(ii_read_uint32(tcp_opt + l + 2 + i + 4));
										if (ii_seq_ordered(sle, sre)) {
											enum iip_rc rc = ii_extent_queue_add(&II_TCP_CONN(conn_id).sack, sle, sre - sle);
											if (rc != IIP_ERR_OK) {
												if (rc == IIP_ERR_BUF_FULL) {
													II_TCP_CONN(conn_id).sack.cnt = 0; /* XXX: clear sack extent because it's full */
													break;
												} else {
													IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
												}
											}
										} else
											break;
									}
									if (i == sackbuf_len) {
										II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_RX_SACKBUF;
										if (ii_seq_ordered(II_TCP_CONN(conn_id).acked_seq, II_TCP_CONN(conn_id).seq)) {
											if (!(II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED)) {
												II_TCP_CONN(conn_id).cc.ssthresh = (II_TCP_CONN(conn_id).cc.win / 2 < 1 ? 2 : II_TCP_CONN(conn_id).cc.win / 2);
												II_TCP_CONN(conn_id).cc.win = 1;
												II_TCP_CONN(conn_id).sent_seq_when_loss_detected = II_TCP_CONN(conn_id).seq;
												II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_PEER_RX_FAILED;
												IIP_OPS_DEBUG_PRINTF("[%s:%u]: loss detected because of sack\n", __func__, __LINE__);
											}
										}
									}
								}
							} else
								return IIP_ERR_INVALID_RX;
							break;
						case 8: /* timestamp */
							if (tcp_opt[l + 1] == 10
									&& tcp_opt_len - l >= 10) {
								II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_OPT_HAS_TS;
								II_PB(pb_id).tcp.opt.ts[0] = ii_ntohl(ii_read_uint32(tcp_opt + l + 2));
								II_PB(pb_id).tcp.opt.ts[1] = ii_ntohl(ii_read_uint32(tcp_opt + l + 6));
								II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_OPT_SET_TS;
							} else
								return IIP_ERR_INVALID_RX;
							break;
						case 34: /* fast open */
							if (II_PB(pb_id).tcp.info_flags & (II_PB_FLAGS_TCP_FASTOPEN_REQUEST | II_PB_FLAGS_TCP_FASTOPEN_VALID | II_PB_FLAGS_TCP_FASTOPEN_INVALID)) {
								II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_FASTOPEN_INVALID;
								II_PB(pb_id).tcp.info_flags &= ~(II_PB_FLAGS_TCP_FASTOPEN_REQUEST | II_PB_FLAGS_TCP_FASTOPEN_VALID);
							} else if (II_PB(pb_id).tcp.flags & II_TCP_FLAG_SYN) {
								if (tcp_opt_len - l >= tcp_opt[l + 1]) {
									if (tcp_opt[l + 1] == 2) /* request */
										II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_FASTOPEN_REQUEST;
									else if (tcp_opt[l + 1] >= 2 + 4 && tcp_opt[l + 1] <= 2 + 16) { /* has cookie */
										bool iip_ret_bool;
										IIP_OPS_TCP_IPV4_FASTOPEN_CHECK();
										if (iip_ret_bool)
											II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_FASTOPEN_VALID;
									}
								}
								if (!(II_PB(pb_id).tcp.info_flags & (II_PB_FLAGS_TCP_FASTOPEN_REQUEST | II_PB_FLAGS_TCP_FASTOPEN_VALID)))
									II_PB(pb_id).tcp.info_flags |= II_PB_FLAGS_TCP_FASTOPEN_INVALID;
							}
							break;
						default:
							break;
						}
						if (!tcp_opt[l + 1]) {
							l = tcp_opt_len; /* stop loop */
							break;
						}
						if (tcp_opt_len - l < tcp_opt[l + 1])
							l = tcp_opt_len; /* stop loop */
						else
							l += tcp_opt[l + 1];
						break;
					}
				}
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \separated(w, src_mac, dst_mac);
	requires \valid_read(src_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(dst_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid(w);
	requires conn_id < II_CONF_POOL_NUM_TCP_CONN;
	assigns II_TCP_CONN(conn_id);
 */
static void ii_ipv4_tcp_conn_init(IIP_MEM_P w, IIP_TCP_CONN_P conn_id,
		uint8_t src_mac[II_ETH_ADDR_LEN], uint32_t src_ipv4_be, uint16_t src_port_be,
		uint8_t dst_mac[II_ETH_ADDR_LEN], uint32_t dst_ipv4_be, uint16_t dst_port_be,
		uint32_t seq_next_expected_be)
{
	{
		struct ii_tcp_conn clear_conn = { 0 };
		II_TCP_CONN(conn_id) = clear_conn;
	}
	II_TCP_CONN(conn_id).src_mac[0] = src_mac[0];
	II_TCP_CONN(conn_id).src_mac[1] = src_mac[1];
	II_TCP_CONN(conn_id).src_mac[2] = src_mac[2];
	II_TCP_CONN(conn_id).src_mac[3] = src_mac[3];
	II_TCP_CONN(conn_id).src_mac[4] = src_mac[4];
	II_TCP_CONN(conn_id).src_mac[5] = src_mac[5];
	II_TCP_CONN(conn_id).dst_mac[0] = dst_mac[0];
	II_TCP_CONN(conn_id).dst_mac[1] = dst_mac[1];
	II_TCP_CONN(conn_id).dst_mac[2] = dst_mac[2];
	II_TCP_CONN(conn_id).dst_mac[3] = dst_mac[3];
	II_TCP_CONN(conn_id).dst_mac[4] = dst_mac[4];
	II_TCP_CONN(conn_id).dst_mac[5] = dst_mac[5];
	II_TCP_CONN(conn_id).src_ip[0] = ii_ntohl(src_ipv4_be);
	II_TCP_CONN(conn_id).dst_ip[0] = ii_ntohl(dst_ipv4_be);
	II_TCP_CONN(conn_id).src_port = ii_ntohs(src_port_be);
	II_TCP_CONN(conn_id).dst_port = ii_ntohs(dst_port_be);
	II_TCP_CONN(conn_id).state = II_TCP_STATE_SYN_RECVD;
	II_TCP_CONN(conn_id).mss = 536; /* TODO */
	II_TCP_CONN(conn_id).path_mtu = 1360; /* TODO */
	II_TCP_CONN(conn_id).seq_next_expected = ii_ntohl(seq_next_expected_be);
	II_TCP_CONN(conn_id).iss = w->tcp.iss;
	II_TCP_CONN(conn_id).sent_seq = II_TCP_CONN(conn_id).seq = II_TCP_CONN(conn_id).acked_seq = II_TCP_CONN(conn_id).iss;
	II_TCP_CONN(conn_id).keepalive_interval_ms = 7200000;
	II_TCP_CONN(conn_id).buf.capacity = IIP_CONF_TCP_RX_BUF_CAPACITY;
	II_TCP_CONN(conn_id).sack.cnt = 0;
	II_TCP_CONN(conn_id).cc.win = 10;
	II_TCP_CONN(conn_id).cc.ssthresh = 65535;
	II_TCP_CONN(conn_id).retrans_r1 = 3;
	II_TCP_CONN(conn_id).retrans_r2 = 4;
	II_TCP_CONN(conn_id).rto_ms = 0;
	II_TCP_CONN(conn_id).rto_expire = UINT16_MAX;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid_read(src_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(dst_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires 0 < cnt ==> \valid(pkt + (0 .. cnt - 1));
	requires 0 < fastopen_cookie_len ==> \valid_read(fastopen_cookie_buf + (0 .. fastopen_cookie_len - 1));
	requires 0 < cnt && 0 < fastopen_cookie_len ==>
		\separated(w, src_mac, dst_mac, pkt + (0 .. cnt - 1), fastopen_cookie_buf + (0 .. fastopen_cookie_len - 1), opaque);
	requires 0 < cnt && 0 == fastopen_cookie_len ==>
		\separated(w, src_mac, dst_mac, pkt + (0 .. cnt - 1), opaque);
	requires 0 == cnt && 0 < fastopen_cookie_len ==>
		\separated(w, src_mac, dst_mac, fastopen_cookie_buf + (0 .. fastopen_cookie_len - 1), opaque);
	requires 0 == cnt && 0 == fastopen_cookie_len ==>
		\separated(w, src_mac, dst_mac, opaque);
	assigns *w, *opaque;
	*/
static int iip_tcp_ipv4_ethernet_connect(IIP_MEM_P w,
		uint8_t src_mac[II_ETH_ADDR_LEN], uint32_t src_ipv4_be, uint16_t src_port_be,
		uint8_t dst_mac[II_ETH_ADDR_LEN], uint32_t dst_ipv4_be, uint16_t dst_port_be,
		IIP_PKT_P *pkt, IIP_PKT_CNT_T cnt, uint8_t *fastopen_cookie_buf, uint8_t fastopen_cookie_len, uint8_t diffserv,
		IIP_OPAQUE_P opaque)
{
	IIP_TCP_CONN_P conn_id;
	{
		enum iip_rc rc = ii_alloc_tcp_conn(&w->tcp_conns, &conn_id);
		if (rc != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		ii_ipv4_tcp_conn_init(w, conn_id,
				src_mac,
				src_ipv4_be,
				src_port_be,
				dst_mac,
				dst_ipv4_be,
				dst_port_be,
				0);
		II_TCP_CONN(conn_id).diffserv = diffserv;
		II_TCP_CONN(conn_id).peer_win = 0xffff;
		if (fastopen_cookie_len) {
			if (fastopen_cookie_len > sizeof(II_TCP_CONN(conn_id).fastopen_cookie.buf))
				return -1;
			{
				uint8_t i;
				/*@
				  loop invariant 0 <= i <= fastopen_cookie_len <= sizeof(II_TCP_CONN(conn_id).fastopen_cookie.buf);
				  loop assigns i, II_TCP_CONN(conn_id).fastopen_cookie.buf[0 .. sizeof(II_TCP_CONN(conn_id).fastopen_cookie.buf) - 1];
				  loop variant fastopen_cookie_len - i;
				 */
				for (i = 0; i < fastopen_cookie_len; i++)
					II_TCP_CONN(conn_id).fastopen_cookie.buf[i] = fastopen_cookie_buf[i];
				II_TCP_CONN(conn_id).fastopen_cookie.len = fastopen_cookie_len;
				if (cnt > II_CONF_IPV4_FRAG_CNT_MAX)
					return -1;
				if (ii_tcp_send(w, conn_id, II_TCP_FLAG_SYN, pkt, cnt, opaque) != IIP_ERR_OK) {
					II_TCP_CONN(conn_id).state = 0;
					return -1;
				}
			}
		} else {
			if (ii_tcp_tx_push_control(w, conn_id, II_TCP_FLAG_SYN) != IIP_ERR_OK) {
				II_TCP_CONN(conn_id).state = 0;
				return -1;
			}
		}
		ii_tcp_conn_set_state(w, conn_id, II_TCP_STATE_SYN_SENT);
		return 0;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns \nothing;
 */
static enum iip_rc ii_tcp_rx_csum_check(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_OPS_TCP_RX_CHECKSUM();
	}
	return ii_ipv4_l4_input__csum_with_pseudo(w, pb_id, opaque);
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_tcp_input(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_tcp_rx_csum_check(w, pb_id, opaque) != IIP_ERR_OK) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint32_t src_ipv4_be = ii_extract_ipv4_src_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN);
		uint32_t dst_ipv4_be = ii_extract_ipv4_dst_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN);
		{
			uint8_t tcp_hdr[II_TCP_HDR_LEN_MINIMAL];
			{
				IIP_PKT_LEN_T copied_len;
				if (ii_pb_payload_copy(w, pb_id, II_ETH_HDR_LEN + ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN), tcp_hdr, sizeof(tcp_hdr), &copied_len, opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (copied_len != sizeof(tcp_hdr)) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
			ii_tcp_pb_init__base(w, pb_id, tcp_hdr);
			if (ii_tcp_pb_init__payload_len(w, pb_id, opaque) != IIP_ERR_OK)
				return IIP_ERR_INVALID_RX;
			{
				IIP_TCP_CONN_P conn_id = ii_ipv4_tcp_conn_lookup(w,
							ii_extract_ipv4_dst_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN),
							ii_extract_tcp_dst_be(tcp_hdr),
							ii_extract_ipv4_src_be(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN),
							ii_extract_tcp_src_be(tcp_hdr));
				if (conn_id > II_CONF_POOL_NUM_TCP_CONN) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (conn_id < II_CONF_POOL_NUM_TCP_CONN && II_TCP_CONN(conn_id).state == II_TCP_STATE_CLOSED)
					return IIP_ERR_OK; /* do nothing */
				if (ii_tcp_hdr_has_syn(w, pb_id)) {
					if (ii_tcp_hdr_has_fin(w, pb_id) && !ii_tcp_hdr_has_rst(w, pb_id))
						return IIP_ERR_INVALID_RX;
					if (conn_id < II_CONF_POOL_NUM_TCP_CONN) {
						if (II_TCP_CONN(conn_id).state == II_TCP_STATE_SYN_SENT
								&& ii_tcp_hdr_has_rst(w, pb_id)
								&& !ii_tcp_hdr_has_ack(w, pb_id))
							return IIP_ERR_OK;
					} else { /* not found */
						if (ii_tcp_hdr_has_rst(w, pb_id))
							return IIP_ERR_OK; /* do nothing */
						else if (ii_tcp_hdr_has_ack(w, pb_id)) {
							IIP_OPS_DEBUG_PRINTF("WARNING: got syn-ack for non-existing connection, maybe RSS sterring would be wrong\n");
							return IIP_ERR_INVALID_RX; /* do nothing */
						} else {
							bool iip_ret_bool;
							IIP_OPS_TCP_ACCEPT();
							if (iip_ret_bool) {
								enum iip_rc rc = ii_alloc_tcp_conn(&w->tcp_conns, &conn_id);
								if (rc != IIP_ERR_OK) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
									IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
								}
								ii_ipv4_tcp_conn_init(w, conn_id,
										ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + 0,
										dst_ipv4_be,
										ii_read_uint16(&tcp_hdr[2]),
										ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + 6,
										src_ipv4_be,
										ii_read_uint16(&tcp_hdr[0]),
										ii_read_uint32(&tcp_hdr[4]));
							}
						}
					}
					if (conn_id < II_CONF_POOL_NUM_TCP_CONN)
						II_TCP_CONN(conn_id).seq_next_expected = ii_tcp_seq_le_raw(w, pb_id);
				}
				if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
					IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
				}
				if (ii_ipv4_tcp_input__parse_opt(w, conn_id, pb_id, opaque) != IIP_ERR_OK)
					return IIP_ERR_INVALID_RX;
				return ii_tcp_rx_push(w, conn_id, pb_id, opaque);
			}
		}
	}
}

/*
 * ---------------------------------------
 *  udp
 * ---------------------------------------
 */

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns \nothing;
 */
static enum iip_rc ii_udp_rx_csum_check(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_OPS_UDP_RX_CHECKSUM();
	}
	return ii_ipv4_l4_input__csum_with_pseudo(w, pb_id, opaque);
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_udp_input(IIP_MEM_P w, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_udp_rx_csum_check(w, pb_id, opaque) != IIP_ERR_OK)
		return IIP_ERR_INVALID_RX;
	{
		int iip_ret_int;
		IIP_OPS_UDP_PAYLOAD();
		if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		else if (iip_ret_int) {
			IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
		}
		else
			return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid_read(src_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \valid_read(dst_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires 0 < buf_len ==> \valid_read(buf + (0 .. buf_len - 1));
	requires 0 < buf_len ==> \separated(w,
		src_mac + (0 .. II_ETH_ADDR_LEN - 1),
		dst_mac + (0 .. II_ETH_ADDR_LEN - 1),
		buf + (0 .. buf_len - 1),
		opaque);
	requires buf_len == 0 ==> \separated(w,
		src_mac + (0 .. II_ETH_ADDR_LEN - 1),
		dst_mac + (0 .. II_ETH_ADDR_LEN - 1),
		opaque);
	assigns *w, *opaque;
 */
static enum iip_rc iip_udp_ipv4_ethernet_send_copy(IIP_MEM_P w,
		uint8_t src_mac[II_ETH_ADDR_LEN], uint32_t src_ipv4_be, uint16_t src_port_be,
		uint8_t dst_mac[II_ETH_ADDR_LEN], uint32_t dst_ipv4_be, uint16_t dst_port_be,
		uint8_t diffserv,
		uint8_t *buf, uint16_t buf_len, IIP_OPAQUE_P opaque)
{
	uint8_t udp_hdr[II_UDP_HDR_LEN];
	ii_write_uint16(udp_hdr + 0, src_port_be);
	ii_write_uint16(udp_hdr + 2, dst_port_be);
	ii_write_uint16(udp_hdr + 4, ii_htons(II_UDP_HDR_LEN + buf_len));
	udp_hdr[6] = 0;
	udp_hdr[7] = 0;
	{
		uint8_t pseudo_hdr_ipv4[12];
		ii_write_uint32(pseudo_hdr_ipv4 + 0, src_ipv4_be);
		ii_write_uint32(pseudo_hdr_ipv4 + 4, dst_ipv4_be);
		pseudo_hdr_ipv4[8] = 0;
		pseudo_hdr_ipv4[9] = 17;
		ii_write_uint16(pseudo_hdr_ipv4 + 10, ii_htons(II_UDP_HDR_LEN + buf_len));
		{
			const uint8_t *buf_ptr[3];
			IIP_PKT_LEN_T len[3];
			buf_ptr[0] = pseudo_hdr_ipv4;
			len[0] = sizeof(pseudo_hdr_ipv4);
			buf_ptr[1] = udp_hdr;
			len[1] = II_UDP_HDR_LEN;
			buf_ptr[2] = buf;
			len[2] = buf_len;
			{
				bool iip_ret_bool;
				IIP_OPS_UDP_TX_SKIP_SW_CHECKSUM();
				if (!iip_ret_bool)
					ii_write_uint16(&udp_hdr[6], ii_htons(ii_csum16(buf_ptr, len, 3, 0)));
			}
			{
				return ii_ipv4_send_ethernet(src_mac, src_ipv4_be, dst_mac, dst_ipv4_be, 17 /* udp */, diffserv, &buf_ptr[1], &len[1], 2, opaque);
			}
		}
	}
	{ /* unused */
		(void) w;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns II_TCP_CONN(conn_id);
 */
static int iip_tcp_rxbuf_consumed(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_TCP_SEQ_INT_T consumed, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	II_TCP_CONN(conn_id).buf.adv_cnt += consumed;
	{
		uint32_t l;
		{
			uint16_t emss;
			if (ii_tcp_ipv4_ethernet_emss(w, conn_id, 40, &emss) != IIP_ERR_OK)
				return -1;
			l = emss;
		}
		if (l > II_TCP_CONN(conn_id).buf.capacity / 2)
			l = II_TCP_CONN(conn_id).buf.capacity / 2;
		if (l <= II_TCP_CONN(conn_id).buf.adv_cnt) {
			II_TCP_CONN(conn_id).buf.used -= II_TCP_CONN(conn_id).buf.adv_cnt;
			II_TCP_CONN(conn_id).buf.adv_cnt = 0;
			II_TCP_CONN(conn_id).flags |= II_TCP_CONN_FLAGS_ACK_PENDING;
		}
	}
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

/*
 * ---------------------------------------
 *  ipv4
 * ---------------------------------------
 */

/*@
	requires \valid(opaque);
	requires \valid(frag);
	assigns \nothing;
	ensures \result == IIP_ERR_OK ==> 0 <= frag->cnt <= II_CONF_IPV4_FRAG_CNT_MAX;
	ensures \result == IIP_ERR_OK ==> (\forall integer i; 0 < frag->cnt && 0 <= i < frag->cnt ==> f_iip_ops_pkt_valid(frag->part_pkt[i], opaque));
 */
static enum iip_rc ii_ipv4_frag_validation(struct ii_pb *frag, IIP_OPAQUE_P opaque)
{
	if (frag->cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t i;
		/*@
			loop invariant 0 <= i <= frag->cnt;
			loop invariant \forall integer j; 0 <= j < i ==> f_iip_ops_pkt_valid(frag->part_pkt[j], opaque);
			loop assigns i;
			loop variant frag->cnt - i;
		 */
		for (i = 0; i < frag->cnt; i++) {
			if (!ii_call_pkt_valid(frag->part_pkt[i], opaque))
				return IIP_ERR_INVALID_RX;
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == 0 || \result == 1;
 */
static int ii_ipv4_should_ignore(const uint8_t *buf)
{
	uint32_t src = ii_ntohl(ii_extract_ipv4_src_be(buf));
	if (src == 0xffffffff) /* limited broadcast */
		return 1;
	if (src >> 24 == 0) /* 0.0.0.0/8 */
		return 1;
	if (src >> 28 == 0xe) /* 224.0.0.0/4 */
		return 1;
	if (src >> 28 == 0xf) /* Class E */
		return 1;
	/* TODO: subnet-directed broadcast  */
	return 0;
}

/*@
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	assigns \nothing;
	ensures \result == IIP_ERR_OK;
 */
static enum iip_rc ii_ipv4_received_invalid_option(const uint8_t *buf)
{
	if (ii_extract_ipv4_off(buf)) /* skip fragment */
		return IIP_ERR_OK;
	if (ii_ipv4_should_ignore(buf)) /* skip particular ip addresses */
		return IIP_ERR_OK;
	if (ii_extract_ipv4_proto(buf) == 1 /* icmp */) {
	}
	/* TODO: send icmp error */
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(frag);
	requires \separated(frag, opaque);
	assigns frag->cnt, *opaque;
 */
static enum iip_rc ii_ipv4_frag_push__discard_slot(struct ii_pb *frag, IIP_OPAQUE_P opaque)
{
	if (frag->cnt > II_CONF_IPV4_FRAG_CNT_MAX) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_CNT_T i, cnt = frag->cnt;
		/*@
		  loop invariant 0 <= i <= cnt;
		  loop assigns i, *opaque;
		  loop variant cnt - i;
		  */
		for (i = 0; i < cnt; i++) {
			if (!ii_call_pkt_valid(frag->part_pkt[i], opaque)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			if (ii_call_pkt_free(frag->part_pkt[i], opaque)) {
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
		}
		frag->cnt = 0;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid_read(buf + (0 .. II_IPV4_HDR_LEN_MINIMAL - 1));
	requires \valid_read(ipv4_frag + (0 .. II_CONF_IPV4_FRAG_ARRAY_LEN - 1));
	requires \valid(slot);
	assigns *slot \from buf, ipv4_frag[0 .. II_CONF_IPV4_FRAG_ARRAY_LEN - 1];
	ensures \result == IIP_ERR_OK ==> *slot < II_CONF_IPV4_FRAG_ARRAY_LEN;
 */
static enum iip_rc ii_ipv4_frag_push__slot(const uint8_t *buf, struct ii_pb ipv4_frag[II_CONF_IPV4_FRAG_ARRAY_LEN], uint16_t *slot, IIP_OPAQUE_P opaque)
{
	int32_t i, unused = -1;
	/*@
		loop invariant 0 <= i <= II_CONF_IPV4_FRAG_ARRAY_LEN;
		loop invariant -1 <= unused < II_CONF_IPV4_FRAG_ARRAY_LEN;
		loop assigns i, unused;
		loop variant II_CONF_IPV4_FRAG_ARRAY_LEN - i;
	 */
	for (i = 0; i < II_CONF_IPV4_FRAG_ARRAY_LEN; i++) {
		if (!ipv4_frag[i].cnt)
			unused = i;
		else {
			if (!ii_call_pkt_valid(ipv4_frag[i].part_pkt[0], opaque)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			} else {
				uint8_t *buf2 = ii_call_pkt_get_data(ipv4_frag[i].part_pkt[0], opaque) + II_ETH_HDR_LEN;
				if (ii_extract_ipv4_src_be(buf) == ii_extract_ipv4_src_be(buf2)
						&& ii_extract_ipv4_dst_be(buf) == ii_extract_ipv4_dst_be(buf2)
						&& ii_extract_ipv4_id(buf) == ii_extract_ipv4_id(buf2)
						&& ii_extract_ipv4_proto(buf) == ii_extract_ipv4_proto(buf2))
					break;
			}
		}
	}
	if (i == II_CONF_IPV4_FRAG_ARRAY_LEN) {
		if (unused == -1) {
			IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
		} else {
			*slot = unused;
			return IIP_ERR_OK;
		}
	} else {
		*slot = i;
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(part_pkt + (0 .. cnt - 1));
	requires \separated(part_pkt, opaque);
	assigns part_pkt[0 .. cnt - 1] \from part_pkt[0 .. cnt - 1];
 */
static enum iip_rc ii_ipv4_frag_push__ordering(IIP_PKT_P part_pkt[II_CONF_IPV4_FRAG_CNT_MAX], IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque)
{
	uint16_t j;
	/*@
		loop invariant 0 <= j <= cnt;
		loop assigns j, part_pkt[0 .. cnt - 1];
		loop variant cnt - j;
	 */
	for (j = 0; j < cnt; j++) {
		uint16_t i;
		/*@
			loop invariant 0 <= i <= cnt - 1 - j;
			loop assigns i, part_pkt[0 .. cnt - 1];
			loop variant cnt - 1 - j - i;
		 */
		for (i = 0; i < cnt - 1 - j; i++) {
			if (!ii_call_pkt_valid(part_pkt[i], opaque)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			if (!ii_call_pkt_valid(part_pkt[i + 1], opaque)) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			if (ii_extract_ipv4_off(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN) >
					ii_extract_ipv4_off(ii_call_pkt_get_data(part_pkt[i + 1], opaque) + II_ETH_HDR_LEN)) {
				IIP_PKT_P tmp = part_pkt[i];
				part_pkt[i] = part_pkt[i + 1];
				part_pkt[i + 1] = tmp;
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid_read(part_pkt + (0 .. cnt - 1));
	assigns \nothing;
 */
static enum iip_rc ii_ipv4_frag_push__check_complete(IIP_PKT_P part_pkt[II_CONF_IPV4_FRAG_CNT_MAX], IIP_PKT_CNT_T cnt, IIP_OPAQUE_P opaque)
{
	uint16_t i, off;
	/*@
		loop invariant 0 <= i <= cnt;
		loop invariant 0 <= off <= 0xffff;
		loop invariant 0 == i ==> off == 0;
		loop assigns i, off;
		loop variant cnt - i;
	 */
	for (i = 0, off = 0; i < cnt; i++) {
		if (!ii_call_pkt_valid(part_pkt[i], opaque)) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ii_extract_ipv4_tot_len(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN) < ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN)) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (off != ii_extract_ipv4_off(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN)) { /* not contiguous */
			if (cnt == II_CONF_IPV4_FRAG_CNT_MAX)
				return IIP_ERR_INVALID_RX; /* incomplete and no extra space, so discard all */
			else
				return IIP_ERR_AGAIN; /* wait more */
		} else { /* contiguous */
			if ((uint32_t) off + ii_extract_ipv4_payload_len(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN) > 0xffff)
				return IIP_ERR_INVALID_RX; /* invalid length, discard all */
			else {
				off += ii_extract_ipv4_payload_len(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN);
				if (!ii_extract_ipv4_more_flag(ii_call_pkt_get_data(part_pkt[i], opaque) + II_ETH_HDR_LEN)) {
					if (i != cnt - 1)
						return IIP_ERR_INVALID_RX;
					else
						return IIP_ERR_OK;
				} else
					continue;
			}
		}
	}
	/* all has more flags */
	if (cnt == II_CONF_IPV4_FRAG_CNT_MAX)
		return IIP_ERR_INVALID_RX; /* no extra space, so discard all */
	else
		return IIP_ERR_AGAIN; /* wait more */
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_rx_push(IIP_MEM_P w, uint16_t pb_id, IIP_OPAQUE_P opaque)
{
	if (pb_id >= II_CONF_POOL_NUM_PB) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (!ii_call_pkt_valid(II_PB(pb_id).part_pkt[0], opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		enum iip_rc rc;
		switch (ii_extract_ipv4_proto(ii_call_pkt_get_data(II_PB(pb_id).part_pkt[0], opaque) + II_ETH_HDR_LEN)) {
		case 1: /* icmp */
			{
				rc = ii_icmp_input(w, pb_id, opaque);
			}
			break;
		case 6: /* tcp */ 
			{
				rc = ii_ipv4_tcp_input(w, pb_id, opaque);
				if (rc != IIP_ERR_OK) {
					if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK)
						rc = IIP_ERR_FATAL_SYS;
				}
			}
			break;
		case 17: /* udp */ 
			{
				rc = ii_ipv4_udp_input(w, pb_id, opaque);
			}
			break;
		default:
			{
				rc = IIP_ERR_INVALID_RX;
				if (ii_free_pb_and_pkt(w, pb_id, opaque) != IIP_ERR_OK)
					rc = IIP_ERR_FATAL_SYS;
			}
			break;
		}
		return rc;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_frag_push(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
	}
	{
		uint8_t *buf = ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN;
		uint16_t slot;
		if (ii_ipv4_frag_push__slot(buf, w->ipv4_frag, &slot, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ii_ipv4_frag_validation(&w->ipv4_frag[slot], opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}

		if (w->ipv4_frag[slot].cnt >= II_CONF_IPV4_FRAG_CNT_MAX) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		{
			IIP_PKT_P cloned_rx_pkt;
			if (ii_call_pkt_clone(rx_pkt, &cloned_rx_pkt, opaque)) {
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
			if (!w->ipv4_frag[slot].cnt)
				w->ipv4_frag[slot].tcp.opt.ts[0] = w->now_ms; /* XXX: reusing the field for tcp */
			w->ipv4_frag[slot].part_pkt[w->ipv4_frag[slot].cnt++] = cloned_rx_pkt;
			if (w->ipv4_frag[slot].cnt < 2)
				return IIP_ERR_OK;
			if (ii_ipv4_frag_push__ordering(w->ipv4_frag[slot].part_pkt, w->ipv4_frag[slot].cnt, opaque) != IIP_ERR_OK) {
				IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
			}
			switch (ii_ipv4_frag_push__check_complete(w->ipv4_frag[slot].part_pkt, w->ipv4_frag[slot].cnt, opaque)) {
			case IIP_ERR_OK: /* complete */
				{
					II_PB_P pb_id;
					{
						enum iip_rc rc = ii_alloc_pb(&w->pbs, &pb_id);
						if (rc != IIP_ERR_OK) {
							IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
						}
					}
					II_PB(pb_id) = w->ipv4_frag[slot];
					w->ipv4_frag[slot].cnt = 0;
					{
						enum iip_rc rc = ii_ipv4_rx_push(w, pb_id, opaque);
						if (rc != IIP_ERR_OK) {
							if (ii_free_pb(&w->pbs, pb_id)) {
								IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
							}
							return rc;
						}
					}
					return IIP_ERR_OK;
				}
			case IIP_ERR_AGAIN: /* wait */
				return IIP_ERR_OK;
			case IIP_ERR_INVALID_RX: /* discard */
				ii_ipv4_frag_push__discard_slot(&w->ipv4_frag[slot], opaque);
				return IIP_ERR_INVALID_RX;
			default:
				{
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
		}
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_push_one(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_PKT_P cloned_rx_pkt;
		if (ii_call_pkt_clone(rx_pkt, &cloned_rx_pkt, opaque)) {
			IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
		}
		{
			II_PB_P pb_id;
			{
				enum iip_rc rc = ii_alloc_pb(&w->pbs, &pb_id);
				if (rc != IIP_ERR_OK) {
					if (ii_call_pkt_free(cloned_rx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					return rc;
				}
			}
			II_PB(pb_id).part_pkt[0] = cloned_rx_pkt;
			II_PB(pb_id).cnt = 1;
			{
				enum iip_rc rc = ii_ipv4_rx_push(w, pb_id, opaque);
				if (rc != IIP_ERR_OK) {
					if (ii_free_pb_and_pkt(w, pb_id, opaque)) {
						IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
					}
					return rc;
				}
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	assigns \nothing;
 */
static enum iip_rc ii_ipv4_validation(IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t *buf = ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN;
		IIP_PKT_LEN_T buf_len = ii_call_pkt_get_len(rx_pkt, opaque);

		if (buf_len < II_ETH_HDR_LEN)
			return IIP_ERR_INVALID_RX;
		buf_len -= II_ETH_HDR_LEN;

		if (buf_len < II_IPV4_HDR_LEN_MINIMAL)
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_version(buf) != 4) /* ipv4 version */
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_hdr_len(buf) < II_IPV4_HDR_LEN_MINIMAL) /* header is smaller than 20 */
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_hdr_len(buf) > buf_len) /* given buffer is smaller than header size */
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_hdr_len(buf) > ii_extract_ipv4_tot_len(buf)) /* total length is smaller than header */
			return IIP_ERR_INVALID_RX;
		/*@ assert f_extract_ipv4_hdr_len(f_iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) <= f_extract_ipv4_tot_len(f_iip_ops_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN); */
		if (ii_extract_ipv4_tot_len(buf) > buf_len) /* total length is smaller than received buf */
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_reserved_flag(buf))
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_more_flag(buf) && (ii_extract_ipv4_payload_len(buf) % 8)) /* not aligned by 8 */
			return IIP_ERR_INVALID_RX;
		if ((uint32_t) ii_extract_ipv4_off(buf) + ii_extract_ipv4_payload_len(buf) > (uint32_t) 0xffff - II_IPV4_HDR_LEN_MINIMAL /* XXX: need recheck */) /* entire data exceeds 64 KiB */
			return IIP_ERR_INVALID_RX;
		switch (ii_extract_ipv4_proto(buf)) {
		case 1: /* icmp */
		case 6: /* tcp */ 
		case 17: /* udp */ 
			break;
		default:
			return IIP_ERR_INVALID_RX;
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns \nothing;
 */
static enum iip_rc ii_ipv4_rx_csum_check(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		IIP_OPS_IPV4_RX_CHECKSUM();
	}
	{
		uint8_t *buf = ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN;
		{
			const uint8_t *buf_ptr[1];
			buf_ptr[0] = buf;
			{
				uint16_t len[1];
				len[0] = ii_extract_ipv4_hdr_len(buf);
				if (ii_csum16(buf_ptr, len, 1, 0))
					return IIP_ERR_INVALID_RX;
			}
		}
	}
	return IIP_ERR_OK;
	{ /* unused */
		(void) w;
	}
}

/*@
	requires 0 < buf_len ==> \valid_read(buf + (0 .. buf_len - 1));
	assigns \nothing;
 */
static enum iip_rc ii_ipv4_opt_validation(uint8_t *buf, uint16_t buf_len, uint16_t ipv4_opt_len)
{
	if (ipv4_opt_len > buf_len || ipv4_opt_len > 40)
		return IIP_ERR_INVALID_RX;
	{
		uint16_t i, is_err;
		/*@
			loop invariant 0 <= i <= ipv4_opt_len;
			loop invariant 0 <= is_err <= 1;
			loop assigns i, is_err;
			loop variant ipv4_opt_len - i;
		 */
		for (i = 0, is_err = 0; i < ipv4_opt_len && !is_err; i++) {
			switch (buf[i]) {
			case 0x00: /* eol */
				i = ipv4_opt_len - 1;
				break;
			case 0x01: /* nop */
				break;
			default:
				if ((uint32_t) i + 1 < ipv4_opt_len) {
					uint8_t opt_len = buf[i + 1];
					if (opt_len < 2 || i + opt_len > ipv4_opt_len)
						is_err = 1;
					else
						i = i + opt_len - 1;
				} else
					is_err = 1;
			}
		}
		if (is_err) {
			/* TODO: send icmp error */
			return IIP_ERR_INVALID_RX;
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ipv4_input(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint16_t buf_len = ii_call_pkt_get_len(rx_pkt, opaque);
		if (buf_len > ii_call_pkt_get_capacity(rx_pkt, opaque)) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (!(buf_len > II_ETH_HDR_LEN
					&& ii_ipv4_validation(rx_pkt, opaque) == IIP_ERR_OK))
			return IIP_ERR_INVALID_RX;
		if (ii_ipv4_rx_csum_check(w, rx_pkt, opaque) != IIP_ERR_OK)
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_hdr_len(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) < II_IPV4_HDR_LEN_MINIMAL) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (!(buf_len > II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL
					&& ii_ipv4_opt_validation(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN + II_IPV4_HDR_LEN_MINIMAL, buf_len - II_ETH_HDR_LEN - II_IPV4_HDR_LEN_MINIMAL, ii_extract_ipv4_opt_len(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN)) == IIP_ERR_OK))
			return IIP_ERR_INVALID_RX;
		if (ii_extract_ipv4_off(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN) || ii_extract_ipv4_more_flag(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN))
			return ii_ipv4_frag_push(w, rx_pkt, opaque);
		else
			return ii_ipv4_push_one(w, rx_pkt, opaque);
	}
}

/*
 * ---------------------------------------
 *  arp
 * ---------------------------------------
 */

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid_read(local_mac + (0 .. II_ETH_ADDR_LEN - 1));
	requires \separated(w, local_mac, opaque);
	assigns *opaque;
 */
static int iip_arp_ethernet_request(IIP_MEM_P w, uint8_t local_mac[II_ETH_ADDR_LEN], uint32_t local_ip4_be, uint32_t target_ip4_be, IIP_OPAQUE_P opaque)
{
	{
		IIP_PKT_P out_pkt;
		if (ii_call_pkt_alloc(&out_pkt, opaque))
			return -1;
		if (ii_call_pkt_get_capacity(out_pkt, opaque) < II_ETH_HDR_LEN + II_ARP_HDR_LEN + 20) {
			ii_call_pkt_free(out_pkt, opaque);
			return -1;
		}
		{
			uint8_t *txbuf = ii_call_pkt_get_data(out_pkt, opaque);
			{
				uint8_t bc_mac[II_ETH_ADDR_LEN];
				bc_mac[0] = 0xff;
				bc_mac[1] = 0xff;
				bc_mac[2] = 0xff;
				bc_mac[3] = 0xff;
				bc_mac[4] = 0xff;
				bc_mac[5] = 0xff;
				ii_call_ethernet_hdr_craft(txbuf, bc_mac, ii_htons(0x0806 /* arp */), opaque);
			}
			ii_write_uint16(txbuf + II_ETH_HDR_LEN + 0, ii_htons(0x0001)); /* hw */
			ii_write_uint16(txbuf + II_ETH_HDR_LEN + 2, ii_htons(0x0800)); /* protocol ipv4 */
			txbuf[II_ETH_HDR_LEN + 4] = 6; /* hw addr len */
			txbuf[II_ETH_HDR_LEN + 5] = 4; /* ipv4 protocol addr len */
			ii_write_uint16(txbuf + II_ETH_HDR_LEN + 6, ii_htons(0x0001)); /* op */
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 0] = local_mac[0];
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 1] = local_mac[1];
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 2] = local_mac[2];
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 3] = local_mac[3];
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 4] = local_mac[4];
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 5] = local_mac[5];
			ii_write_uint32(txbuf + II_ETH_HDR_LEN + II_ARP_HDR_LEN + 6, local_ip4_be);
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10] = 0;
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 11] = 0;
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 12] = 0;
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 13] = 0;
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 14] = 0;
			txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 15] = 0;
			ii_write_uint32(txbuf + II_ETH_HDR_LEN + II_ARP_HDR_LEN + 16, target_ip4_be);
		}
		ii_call_pkt_set_len(out_pkt, II_ETH_HDR_LEN + II_ARP_HDR_LEN + 20, opaque);
		if (ii_call_ethernet_push(out_pkt, opaque)) {
			ii_call_pkt_free(out_pkt, opaque);
			return -1;
		}
	}
	{
		int iip_ret_int;
		IIP_OPS_ETHERNET_FLUSH();
		if (iip_ret_int)
			return -1;
	}
	return 0;
	{ /* unused */
		(void) w;
		(void) local_mac;
	}
}

/*@
	requires \valid(opaque);
	assigns *opaque;
 */
static enum iip_rc ii_arp_input__ipv4_request(IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		bool iip_ret_bool;
		IIP_OPS_IPV4_ADDR_MATCH();
		if (iip_ret_bool) {
			IIP_PKT_P tx_pkt;
			if (ii_call_pkt_alloc(&tx_pkt, opaque)) {
				IIP_OPS_ERROR_FATAL_MEM(); return IIP_ERR_FATAL_MEM;
			}
			if (ii_call_pkt_get_capacity(tx_pkt, opaque) < II_ETH_HDR_LEN + II_ARP_HDR_LEN + 20) {
				if (ii_call_pkt_free(tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
			{
				uint8_t *rxbuf = ii_call_pkt_get_data(rx_pkt, opaque);
				uint8_t *txbuf = ii_call_pkt_get_data(tx_pkt, opaque);
				if (ii_call_ethernet_hdr_craft(txbuf, rxbuf + 6, ii_htons(0x0806) /* arp */, opaque)) {
					if (ii_call_pkt_free(tx_pkt, opaque)) {
						IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
					}
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				/* arp hdr common */
				ii_write_uint16(txbuf + II_ETH_HDR_LEN + 0, ii_htons(0x0001)); /* ethernet */
				ii_write_uint16(txbuf + II_ETH_HDR_LEN + 2, ii_htons(0x0800)); /* protocol */
				txbuf[II_ETH_HDR_LEN + 4] = 6; /* ethernet addr len */
				txbuf[II_ETH_HDR_LEN + 5] = 4; /* ipv4 addr len */
				ii_write_uint16(txbuf + II_ETH_HDR_LEN + 6, ii_htons(0x0002)); /* operation reply */
				/* hw sender */
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  0 + 0] = txbuf[ 6];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  0 + 1] = txbuf[ 7];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  0 + 2] = txbuf[ 8];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  0 + 3] = txbuf[ 9];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  0 + 4] = txbuf[10];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  0 + 5] = txbuf[11];
				/* hw target */
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10 + 0] = txbuf[ 0];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10 + 1] = txbuf[ 1];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10 + 2] = txbuf[ 2];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10 + 3] = txbuf[ 3];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10 + 4] = txbuf[ 4];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 10 + 5] = txbuf[ 5];
				/* l3 addr sender */
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  6 + 0] = rxbuf[II_ETH_HDR_LEN + 8 + 16 + 0];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  6 + 1] = rxbuf[II_ETH_HDR_LEN + 8 + 16 + 1];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  6 + 2] = rxbuf[II_ETH_HDR_LEN + 8 + 16 + 2];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN +  6 + 3] = rxbuf[II_ETH_HDR_LEN + 8 + 16 + 3];
				/* l3 addr target */
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 16 + 0] = rxbuf[II_ETH_HDR_LEN + 8 +  6 + 0];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 16 + 1] = rxbuf[II_ETH_HDR_LEN + 8 +  6 + 1];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 16 + 2] = rxbuf[II_ETH_HDR_LEN + 8 +  6 + 2];
				txbuf[II_ETH_HDR_LEN + II_ARP_HDR_LEN + 16 + 3] = rxbuf[II_ETH_HDR_LEN + 8 +  6 + 3];
			}
			if (ii_call_pkt_set_len(tx_pkt, II_ETH_HDR_LEN + II_ARP_HDR_LEN + 20, opaque)) {
				if (ii_call_pkt_free(tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
			if (ii_call_ethernet_push(tx_pkt, opaque)) {
				if (ii_call_pkt_free(tx_pkt, opaque)) {
					IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
				}
				IIP_OPS_ERROR_FATAL_SUB(); return IIP_ERR_FATAL_SUB;
			}
			return IIP_ERR_OK;
		} else
			return IIP_ERR_INVALID_RX;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_arp_input__ipv4_reply(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		int iip_ret_int;
		IIP_OPS_ARP_ETHERNET_REPLY();
		if (iip_ret_int) {
			IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
		}
		return IIP_ERR_OK;
	}
	{ /* unused */
		(void) w;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_arp_input__ipv4(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	if (ii_call_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + 4] != 6) /* ethenet addr len */
		return IIP_ERR_INVALID_RX;
	if (ii_call_pkt_get_data(rx_pkt, opaque)[II_ETH_HDR_LEN + 5] != 4) /* ipv4 addr len */
		return IIP_ERR_INVALID_RX;
	switch (ii_ntohs(ii_read_uint16(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN + 6))) { /* operation */
	case 0x0001: /* request */
		return ii_arp_input__ipv4_request(rx_pkt, opaque);
	case 0x0002: /* reply */
		return ii_arp_input__ipv4_reply(w, rx_pkt, opaque);
	default:
		return IIP_ERR_INVALID_RX;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_arp_input(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
	}
	{
		uint16_t buf_len = ii_call_pkt_get_len(rx_pkt, opaque);
		if (buf_len > ii_call_pkt_get_capacity(rx_pkt, opaque)) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (buf_len < II_ETH_HDR_LEN + II_ARP_HDR_LEN + 20)
			return IIP_ERR_INVALID_RX;
		switch (ii_ntohs(ii_read_uint16(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN))) {
		case 0x0001: /* ethernet */
			switch (ii_ntohs(ii_read_uint16(ii_call_pkt_get_data(rx_pkt, opaque) + II_ETH_HDR_LEN + 2))) {
			case 0x0800: /* ipv4 */
				return ii_arp_input__ipv4(w, rx_pkt, opaque);
			default:
				return IIP_ERR_INVALID_RX;
			}
		default:
			return IIP_ERR_INVALID_RX;
		}
	}
}

/*
 * ---------------------------------------
 *  ethernet
 * ---------------------------------------
 */

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_ethernet_input(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t *buf = ii_call_pkt_get_data(rx_pkt, opaque);
		if (ii_call_pkt_get_len(rx_pkt, opaque) < II_ETH_HDR_LEN)
			return IIP_ERR_INVALID_RX;
		switch (ii_ntohs(ii_read_uint16(&buf[12]))) {
		case 0x0800: /* ipv4 */
			{
				bool iip_ret_bool;
				IIP_OPS_ETHERNET_ADDR_MATCH();
				if (iip_ret_bool)
					return ii_ipv4_input(w, rx_pkt, opaque);
				else
					return IIP_ERR_INVALID_RX;
			}
		case 0x0806: /* arp */
			{
				bool iip_ret_bool;
				IIP_OPS_ETHERNET_ADDR_MATCH();
				if (iip_ret_bool
						|| ( /* broadcast */
							buf[0] == 0xff
							&& buf[1] == 0xff
							&& buf[2] == 0xff
							&& buf[3] == 0xff
							&& buf[4] == 0xff
							&& buf[5] == 0xff))
					return ii_arp_input(w, rx_pkt, opaque);
				else
					return IIP_ERR_INVALID_RX;
			}
		default:
			return IIP_ERR_INVALID_RX;
		}
	}
}

/*
 * ---------------------------------------
 *  periodic timer
 * ---------------------------------------
 */

/*@
	requires \valid(w);
	assigns *w;
 */
static enum iip_rc ii_periodic_timer__delayed_ack(IIP_MEM_P w)
{
	uint16_t i;
	/*@
		loop invariant 0 <= i <= II_CONF_POOL_NUM_TCP_CONN;
		loop assigns i, *w;
		loop variant II_CONF_POOL_NUM_TCP_CONN - i;
	 */
	for (i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
		if (II_TCP_CONN(i).state == II_TCP_STATE_ESTABLISHED
				&& !(II_TCP_CONN(i).flags & II_TCP_CONN_FLAGS_PEER_RX_FAILED)) {
			if ((II_TCP_CONN(i).ack_seq) != II_TCP_CONN(i).ack_seq_sent) { /* we got payload, but ack is not pushed by the app */
				if (ii_tcp_tx_push_control(w, i, II_TCP_FLAG_ACK) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_periodic_timer__keep_alive_xmit(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	if (conn_id >= II_CONF_POOL_NUM_TCP_CONN) {
		IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
	}
	{
		uint8_t xmit_len = 0;
		uint8_t tcp_opt_len = 0;
		uint8_t tcp_hdr[II_TCP_HDR_LEN_MINIMAL];
		ii_write_uint16(tcp_hdr +  0, ii_htons(II_TCP_CONN(conn_id).src_port));
		ii_write_uint16(tcp_hdr +  2, ii_htons(II_TCP_CONN(conn_id).dst_port));
		ii_write_uint32(tcp_hdr +  4, ii_htonl(II_TCP_CONN(conn_id).seq));
		ii_write_uint32(tcp_hdr +  8, ii_htonl(II_TCP_CONN(conn_id).ack_seq));
		ii_write_uint16(tcp_hdr + 12, ii_htons(II_TCP_FLAG_ACK | (((II_TCP_HDR_LEN_MINIMAL + tcp_opt_len) / 4) * 4096)));
		ii_write_uint16(tcp_hdr + 14, ii_htons(ii_tcp_compute_win(II_TCP_CONN(conn_id).buf.capacity - II_TCP_CONN(conn_id).buf.used, 7)));
		ii_write_uint16(tcp_hdr + 16, 0); /* csum */
		ii_write_uint16(tcp_hdr + 18, 0); /* urg_p */
		{
			uint8_t pseudo_hdr_ipv4[12];
			ii_write_uint32(pseudo_hdr_ipv4 + 0, ii_htonl(II_TCP_CONN(conn_id).src_ip[0]));
			ii_write_uint32(pseudo_hdr_ipv4 + 4, ii_htonl(II_TCP_CONN(conn_id).dst_ip[0]));
			pseudo_hdr_ipv4[8] = 0;
			pseudo_hdr_ipv4[9] = 6;
			ii_write_uint16(pseudo_hdr_ipv4 + 10, ii_htons(II_TCP_HDR_LEN_MINIMAL + tcp_opt_len + xmit_len));
			{
				const uint8_t *buf_ptr[3 + II_CONF_IPV4_FRAG_CNT_MAX];
				IIP_PKT_LEN_T len[3 + II_CONF_IPV4_FRAG_CNT_MAX];
				buf_ptr[0] = pseudo_hdr_ipv4;
				len[0] = sizeof(pseudo_hdr_ipv4);
				buf_ptr[1] = tcp_hdr;
				len[1] = sizeof(tcp_hdr);
				ii_write_uint16(tcp_hdr + 16, ii_htons(ii_csum16(buf_ptr, len, 2, 0)));
				if (ii_ipv4_send_ethernet(II_TCP_CONN(conn_id).src_mac, ii_htonl(II_TCP_CONN(conn_id).src_ip[0]),
							II_TCP_CONN(conn_id).dst_mac, ii_htonl(II_TCP_CONN(conn_id).dst_ip[0]), 6 /* tcp */, II_TCP_CONN(conn_id).diffserv,
							&buf_ptr[1], &len[1], 1, opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
		}
		return IIP_ERR_OK;
	}
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_periodic_timer__keep_alive(IIP_MEM_P w, IIP_OPAQUE_P opaque)
{
	uint16_t i;
	/*@
		loop invariant 0 <= i <= II_CONF_POOL_NUM_TCP_CONN;
		loop assigns i, *w, *opaque;
		loop variant II_CONF_POOL_NUM_TCP_CONN - i;
	 */
	for (i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
		if (II_TCP_CONN(i).flags & II_TCP_CONN_FLAGS_KEEPALIVE_ENABLED
				&& II_TCP_CONN(i).keepalive_interval_ms
				&& II_TCP_CONN(i).keepalive_interval_ms < w->now_ms - II_TCP_CONN(i).keepalive_ts
				&& !(II_TCP_CONN(i).flags & II_TCP_CONN_FLAGS_SET_PROBE)
				&& II_TCP_CONN(i).state == II_TCP_STATE_ESTABLISHED) {
			if (ii_periodic_timer__keep_alive_xmit(w, i, opaque) != IIP_ERR_OK)
				return IIP_ERR_OK;
			II_TCP_CONN(i).keepalive_ts = w->now_ms;
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(w);
	assigns *w;
 */
static enum iip_rc ii_periodic_timer__tcp_close_check(IIP_MEM_P w)
{
	uint16_t i;
	/*@
		loop invariant 0 <= i <= II_CONF_POOL_NUM_TCP_CONN;
		loop assigns i, *w;
		loop variant II_CONF_POOL_NUM_TCP_CONN - i;
	 */
	for (i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++) {
		if (II_TCP_CONN(i).state == II_TCP_STATE_TIME_WAIT) {
			if (IIP_CONF_TCP_MSL_SEC * 1000U * 2 < w->now_ms - II_TCP_CONN(i).time_wait_ts_ms) {
				ii_tcp_conn_set_state(w, i, II_TCP_STATE_CLOSED);
				ii_tcp_conn_enter_close_phase(w, i);
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_periodic_timer__ipv4_fragment_expiration(IIP_MEM_P w, IIP_OPAQUE_P opaque)
{
	uint8_t i;
	/*@
		loop invariant 0 <= i <= II_CONF_IPV4_FRAG_ARRAY_LEN;
		loop assigns i, *w, *opaque;
		loop variant II_CONF_IPV4_FRAG_ARRAY_LEN - i;
	 */
	for (i = 0; i < II_CONF_IPV4_FRAG_ARRAY_LEN; i++) {
		if (w->ipv4_frag[i].cnt) {
			if (60000 /* 60 sec */ <= w->now_ms - w->ipv4_frag[i].tcp.opt.ts[0] /* XXX: reusing the field for tcp */) {
				if (ii_ipv4_frag_validation(&w->ipv4_frag[i], opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
				if (ii_ipv4_frag_push__discard_slot(&w->ipv4_frag[i], opaque) != IIP_ERR_OK) {
					IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
				}
			}
		}
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_preiodic_timer(IIP_MEM_P w, IIP_OPAQUE_P opaque)
{
	if (200 <= w->now_ms - w->timer.prev_fast){ /* fast timer every 200 ms */
		if (ii_periodic_timer__delayed_ack(w) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		w->tcp.pkt_ts++; /* incrment tcp packet timestamp counter */
		w->timer.prev_fast = w->now_ms;
	}
	if (500 <= w->now_ms - w->timer.prev_slow){ /* slow timer every 500 ms */
		if (ii_periodic_timer__keep_alive(w, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		if (ii_periodic_timer__tcp_close_check(w) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		w->tcp.iss++; /* incrment initial send sequence number */
		w->timer.prev_slow = w->now_ms;
	}
	if (1000 <= w->now_ms - w->timer.prev_very_slow) { /* slow timer every 1000 ms */
		if (ii_periodic_timer__ipv4_fragment_expiration(w, opaque) != IIP_ERR_OK) {
			IIP_OPS_ERROR_FATAL_SYS(); return IIP_ERR_FATAL_SYS;
		}
		w->timer.prev_very_slow = w->now_ms;
	}
	return IIP_ERR_OK;
}

/*
 * ---------------------------------------
 *  packet input
 * ---------------------------------------
 */

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_packet_input_round1(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
	}
	if (ii_call_pkt_get_len(rx_pkt, opaque) > ii_call_pkt_get_capacity(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
	} else
		return ii_ethernet_input(w, rx_pkt, opaque);
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static enum iip_rc ii_work(IIP_MEM_P w, IIP_OPAQUE_P opaque)
{
	uint16_t i;
	/*@
		loop invariant 0 <= i <= II_CONF_POOL_NUM_TCP_CONN;
		loop assigns i, *w, *opaque;
		loop variant II_CONF_POOL_NUM_TCP_CONN - i;
	 */
	for (i = 0; i < II_CONF_POOL_NUM_TCP_CONN; i++)
		ii_tcp_conn_work(w, i, opaque);
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \separated(w, opaque);
	assigns *w, *opaque;
 */
static int iip_input(IIP_MEM_P w, IIP_PKT_P rx_pkt, IIP_OPAQUE_P opaque)
{
	if (!ii_call_pkt_valid(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
	}
	ii_packet_input_round1(w, rx_pkt, opaque);
	if (ii_call_pkt_free(rx_pkt, opaque)) {
		IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
	}
	return IIP_ERR_OK;
}

/*@
	requires \valid(opaque);
	requires \valid(w);
	requires \valid(next_us);
	requires 0 < cnt ==> \valid_read(pkt + (0 .. cnt - 1));
	requires cnt == 0 ==> \separated(w, opaque);
	requires 0 < cnt ==> \separated(w, pkt + (0 .. cnt - 1), opaque);
	assigns *w, *opaque, *next_us;
 */
static int iip_run(IIP_MEM_P w, IIP_PKT_P pkt[], IIP_PKT_CNT_T cnt, uint32_t *next_us, IIP_OPAQUE_P opaque)
{
	ii_preiodic_timer(w, opaque);
	{
		IIP_PKT_CNT_T i;
		/*@
			loop invariant 0 <= i <= cnt;
			loop assigns i, *w, *opaque;
			loop variant cnt - i;
		 */
		for (i = 0; i < cnt; i++)
			iip_input(w, pkt[i], opaque);
	}
	ii_work(w, opaque);
	{
		int iip_ret_int;
		IIP_OPS_ETHERNET_FLUSH();
		if (iip_ret_int) {
			IIP_OPS_ERROR_FATAL_USR(); return IIP_ERR_FATAL_USR;
		}
	}
	*next_us = 0;
	return 0;
	{ /* unused */
		(void) ii_ipv4_received_invalid_option;
		(void) ii_ipv4_received_invalid_option;
		(void) ii_tcp_seq_expected;
		(void) ii_tcp_hdr_has_cwr;
		(void) ii_tcp_hdr_has_ece;
		(void) ii_tcp_hdr_has_urg;
		(void) ii_tcp_hdr_has_psh;
		(void) ii_extract_ipv4_csum_be;
		(void) ii_extract_ipv4_ttl;
		(void) ii_extract_ipv4_tos;
		(void) ii_extract_tcp_urg_p_be;
		(void) ii_extract_tcp_csum_be;
		(void) ii_extract_tcp_win_be;
		(void) ii_extract_tcp_flags;
		(void) ii_extract_tcp_ack_seq_be;
		(void) ii_extract_tcp_seq_be;
		(void) ii_pb_ring_pop;
		(void) iip_udp_ipv4_ethernet_send_copy;
	}
}

#endif
