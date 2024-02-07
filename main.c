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

/* configuration */

#ifndef IIP_CONF_ENDIAN
#define IIP_CONF_ENDIAN (1) /* little 1, big 2 */
#endif

/* TODO: properly configure them */
#ifndef IIP_CONF_IP4_TTL
#define IIP_CONF_IP4_TTL		(64)
#endif
#ifndef IIP_CONF_TCP_OPT_WS
#define IIP_CONF_TCP_OPT_WS		(7U) /* RFC 7323 : between 0 ~ 14 */ /* TODO: how to determine this ? */
#endif
#ifndef IIP_CONF_TCP_OPT_MSS
#define IIP_CONF_TCP_OPT_MSS		(1460U)
#endif
#ifndef IIP_CONF_TCP_OPT_SACK_OK
#define IIP_CONF_TCP_OPT_SACK_OK	(1U)
#endif
#ifndef IIP_CONF_TCP_RX_BUF_CNT
#define IIP_CONF_TCP_RX_BUF_CNT		(512U) /* should be smaller than 735439 (1GB with 1460 mss) : limit by RFC 7323 */
#endif
#ifndef IIP_CONF_TCP_WIN_INIT
#define IIP_CONF_TCP_WIN_INIT		(1)
#endif
#ifndef IIP_CONF_TCP_MSL_SEC
#define IIP_CONF_TCP_MSL_SEC		(1) /* maximum segment lifetime, in second : RFC 793 recommends 2 min, but we can choose as we wish */
#endif
#ifndef IIP_CONF_TCP_RETRANS_CNT
#define IIP_CONF_TCP_RETRANS_CNT	(4) /* maximum retransmission count */
#endif
#ifndef IIP_CONF_TCP_SSTHRESH_INIT
#define IIP_CONF_TCP_SSTHRESH_INIT	(256)
#endif
#ifndef IIP_CONF_TCP_CONN_HT_SIZE
#define IIP_CONF_TCP_CONN_HT_SIZE	(829) /* generally bigger is faster at the cost of memory consumption */
#endif
#ifndef IIP_CONF_TCP_TIMESTAMP_ENABLE
#define IIP_CONF_TCP_TIMESTAMP_ENABLE	(1)
#endif
#ifndef IIP_CONF_L2ADDR_LEN_MAX
#define IIP_CONF_L2ADDR_LEN_MAX		(6)
#endif

/* functions implemented by app and io subsystems */

static void *iip_ops_pkt_alloc(void *);
static void iip_ops_pkt_free(void *, void *);
static void *iip_ops_pkt_get_data(void *, void *);
static uint16_t iip_ops_pkt_get_len(void *, void *);
static void iip_ops_pkt_set_len(void *, uint16_t, void *);
static void iip_ops_pkt_increment_head(void *, uint16_t, void *);
static void iip_ops_pkt_decrement_tail(void *, uint16_t, void *);
static void *iip_ops_pkt_clone(void *, void *); /* assuming the entire packet chain is cloned while reference counts to the payload buffers are also incremented */
static void iip_ops_pkt_scatter_gather_chain_append(void *, void *, void *);
static void *iip_ops_pkt_scatter_gather_chain_get_next(void *, void *);
static uint16_t iip_ops_l2_hdr_len(void *, void *);
static uint8_t *iip_ops_l2_hdr_src_ptr(void *, void *);
static uint8_t *iip_ops_l2_hdr_dst_ptr(void *, void *);
static uint16_t iip_ops_l2_ethertype_be(void *, void *);
static uint16_t iip_ops_l2_addr_len(void *);
static void iip_ops_l2_broadcast_addr(uint8_t [], void *);
static void iip_ops_l2_hdr_craft(void *, uint8_t [], uint8_t [], uint16_t, void *);
static uint8_t iip_ops_l2_skip(void *, void *);
static void iip_ops_l2_flush(void *);
static void iip_ops_l2_push(void *, void *); /* assuming packet object is released by app */
static uint8_t iip_ops_arp_lhw(void *);
static uint8_t iip_ops_arp_lproto(void *);
static void iip_ops_arp_reply(void *, void *, void *);
static void iip_ops_icmp_reply(void *, void *, void *);
static uint8_t iip_ops_tcp_accept(void *, void *, void *);
static void *iip_ops_tcp_accepted(void *, void *, void *, void *);
static void *iip_ops_tcp_connected(void *, void *, void *, void *);
static void iip_ops_tcp_closed(void *, void *, void *);
static void iip_ops_tcp_payload(void *, void *, void *, void *, uint16_t, uint16_t, void *);
static void iip_ops_tcp_acked(void *, void *, void *, void *, void *);
static void iip_ops_udp_payload(void *, void *, void *);
static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *);
static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *);
static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *);
static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *);
static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *, void *);
static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *, void *);
static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *, void *);
static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *, void *);
static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *, void *);
static void iip_ops_nic_offload_tcp_tx_tso_mark(void *, void *);
static void iip_ops_nic_offload_udp_tx_checksum_mark(void *, void *);
static void iip_ops_nic_offload_udp_tx_tso_mark(void *, void *);
static void iip_ops_util_now_ns(uint32_t [3], void *);

/* utilities */

#define __iip_bsw16(_n) ((((_n) >> 8) | ((_n) << 8)) & 0xffff)
#define __iip_bsw32(_n) (((((_n) >> 24) & 0xff) | (((_n) >> 8) & 0xff00) | (((_n) << 8) & 0xff0000) | (((_n) << 24) & 0xff000000)) & 0xffffffff)

#if IIP_CONF_ENDIAN == 1
#define __iip_htons(_n) __iip_bsw16(_n)
#define __iip_htonl(_n) __iip_bsw32(_n)
#define __iip_ntohs(_n) __iip_bsw16(_n)
#define __iip_ntohl(_n) __iip_bsw32(_n)
#elif IIP_CONF_ENDIAN == 2
#define __iip_htons(_n) (_n)
#define __iip_htonl(_n) (_n)
#define __iip_ntohs(_n) (_n)
#define __iip_ntohl(_n) (_n)
#else
#error "invalid IIP_CONF_ENDIAN: it should be either 1 (little) or 2 (big)"
#endif

#ifndef __iip_memcpy
#define __iip_memcpy(__dest, __src, __n) \
	do { \
		uint32_t __i; \
		for (__i = 0; __i < (uint32_t)(__n); __i++) \
			((uint8_t *) __dest)[__i] = ((uint8_t *) __src)[__i]; \
	} while (0)
#endif

#ifndef __iip_memset
#define __iip_memset(__s, __c, __n) \
	do { \
		uint32_t __i; \
		for (__i = 0; __i < (uint32_t)(__n); __i++) \
			((uint8_t *) __s)[__i] = __c; \
	} while (0)
#endif

#ifndef __iip_memcmp
static uint32_t __iip_memcmp_impl(void *__s1, void *__s2, uint32_t __n)
{
	uint32_t __i = 0, ret = 0;
	for (__i = 0; __i < (uint32_t)(__n); __i++) {
		if (((uint8_t *) __s1)[__i] != ((uint8_t *) __s2)[__i]) {
			ret = __i + 1;
			break;
		}
	}
	return ret;
}
#define __iip_memcmp(__s1, __s2, __n) __iip_memcmp_impl(__s1, __s2, __n)
#endif

#ifndef __iip_memmove
#define __iip_memmove(__dst, __src, __n) \
	do { \
		if ((uintptr_t) (__dst) > (uintptr_t) (__src)) { \
			uint32_t __i = 0; \
			for (__i = (uint32_t)(__n) - 1; __i != (uint32_t) -1; __i--) { \
				((uint8_t *) (__dst))[__i] = ((uint8_t *) (__src))[__i]; \
			} \
		} else if ((uintptr_t) (__dst) < (uintptr_t) (__src)) { \
			uint32_t __i = 0; \
			for (__i = 0; __i < (uint32_t)(__n); __i++) { \
				((uint8_t *) (__dst))[__i] = ((uint8_t *) (__src))[__i]; \
			} \
		} \
	} while (0)
#endif

#ifndef __iip_assert
#define __iip_assert(_cond) \
	do { \
		if (!(_cond))  { \
			IIP_OPS_DEBUG_PRINTF("[%s:%u]: assertion fail\n", __FILE__, __LINE__); \
			while (1) ; \
		} \
	} while (0)
#endif

static uint16_t __iip_netcsum16(uint8_t *__b[], uint16_t __l[], uint16_t __c, uint16_t __m)
{
	uint32_t __r = 0; uint16_t __n; uint8_t __k;
	for (__n = 0, __k = 0; __n < (__c); __n++) {
		uint32_t __i, __o = __k;
		for (__i = __k; __i < (__l)[__n]; ) {
			if ((__k == 1) || ((__l)[__n] - __i == 1)) {
				uint16_t __v = ((uint8_t *)((__b)[__n]))[__i] & 0x00ff;
				if (__k == 0) {
					__v <<= 8;
					__k = 1;
				} else {
					__k = 0;
				}
				__r += __v;
				__i += 1;
			} else {
				uint16_t __v = ((uint16_t *)((__b)[__n]))[__i / 2 + __o];
				__r += __iip_htons(__v);
				__i += 2;
			}
		}
	}
	__r -= (__m);
	__r = (__r >> 16) + (__r & 0x0000ffff);
	__r = (__r >> 16) + __r;
	return (uint16_t)~((uint16_t) __r);
}

#define __iip_round_up(_v, _r) ((((_v) / (_r)) + ((_v) % (_r) ? 1 : 0)) * (_r))

#define __iip_dequeue_obj(__queue, __obj, __x) \
	do { \
		if ((__queue)[0] == (__obj)) \
			(__queue)[0] = (__obj)->next[__x]; \
		if ((__queue)[1] == (__obj)) \
			(__queue)[1] = (__obj)->prev[__x]; \
		if ((__obj)->prev[__x]) \
			(__obj)->prev[__x]->next[__x] = (__obj)->next[__x]; \
		if ((__obj)->next[__x]) \
			(__obj)->next[__x]->prev[__x] = (__obj)->prev[__x]; \
		(__obj)->prev[__x] = (__obj)->next[__x] = NULL; \
	} while (0)

#define __iip_enqueue_obj(__queue, __obj, __x) \
	do { \
		(__obj)->prev[__x] = (__obj)->next[__x] = NULL; \
		if (!((__queue)[0])) { \
			(__queue)[0] = (__queue)[1] = (__obj); \
		} else { \
			(__obj)->next[__x] = NULL; \
			(__obj)->prev[__x] = (__queue)[1]; \
			(__queue)[1]->next[__x] = (__obj); \
			(__queue)[1] = (__obj); \
		} \
	} while (0)

#define __iip_q_for_each_safe(__queue, _i, _n, __x) \
	for ((_i) = (__queue)[0], _n = ((_i) ? _i->next[__x] : (NULL)); (_i); (_i) = _n, _n = ((_i) ? (_i)->next[__x] : (NULL)))

/* protocol headers */

struct iip_ip4_hdr {
	uint8_t vl;
	uint8_t tos;
	uint16_t len_be;
	uint16_t id_be;
	uint16_t off_be;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum_be;
	uint32_t src_be;
	uint32_t dst_be;
};

struct iip_arp_hdr {
	uint16_t hw_be;
	uint16_t proto_be;
	uint8_t lhw;
	uint8_t lproto;
	uint16_t op_be;
};

struct iip_icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t csum_be;
	struct {
		uint16_t id_be;
		uint16_t seq_be;
	} echo;
};

struct iip_l4_ip4_pseudo_hdr {
	uint32_t ip4_src_be;
	uint32_t ip4_dst_be;
	uint8_t pad;
	uint8_t proto;
	uint16_t len_be;
};

struct iip_tcp_hdr {
	uint16_t src_be;
	uint16_t dst_be;
	uint32_t seq_be;
	uint32_t ack_seq_be;
	uint16_t flags;
	uint16_t win_be;
	uint16_t csum_be;
	uint16_t urg_p_be;
};

struct iip_udp_hdr {
	uint16_t src_be;
	uint16_t dst_be;
	uint16_t len_be;
	uint16_t csum_be;
};

#define PB_IP4(__b) ((struct iip_ip4_hdr *)((uintptr_t) (__b) + iip_ops_l2_hdr_len(__b, opaque)))
#define PB_ARP(__b) ((struct iip_arp_hdr *)(PB_IP4(__b)))
#define PB_ARP_HW_SENDER(__b) ((uint8_t *)((uintptr_t) PB_ARP(__b) + sizeof(struct iip_arp_hdr)))
#define PB_ARP_IP_SENDER(__b) ((uint8_t *)((uintptr_t) PB_ARP_HW_SENDER(__b) + PB_ARP(__b)->lhw))
#define PB_ARP_HW_TARGET(__b) ((uint8_t *)((uintptr_t) PB_ARP_IP_SENDER(__b) + PB_ARP(__b)->lproto))
#define PB_ARP_IP_TARGET(__b) ((uint8_t *)((uintptr_t) PB_ARP_HW_TARGET(__b) + PB_ARP(__b)->lhw))
#define PB_ICMP(__b) ((struct iip_icmp_hdr *)((uintptr_t) PB_IP4(__b) + (PB_IP4(__b)->vl & 0x0f) * 4))
#define PB_ICMP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_ICMP(__b) + sizeof(struct iip_icmp_hdr)))
#define PB_ICMP_PAYLOAD_LEN(__b) ((uint16_t)(__iip_htons(PB_IP4(__b)->len_be) - (PB_IP4(__b)->vl & 0x0f) * 4 - sizeof(struct iip_icmp_hdr)))
#define PB_TCP(__b) ((struct iip_tcp_hdr *)((uintptr_t) PB_IP4(__b) + (PB_IP4(__b)->vl & 0x0f) * 4))
#define PB_TCP_HDR_LEN(__b) ((uint16_t) __iip_ntohs(PB_TCP(__b)->flags) >> 12)
#define PB_TCP_HDR_HAS_FIN(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x01U) ? 1 : 0)
#define PB_TCP_HDR_HAS_SYN(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x02U) ? 1 : 0)
#define PB_TCP_HDR_HAS_RST(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x04U) ? 1 : 0)
#define PB_TCP_HDR_HAS_PSH(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x08U) ? 1 : 0)
#define PB_TCP_HDR_HAS_ACK(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x10U) ? 1 : 0)
#define PB_TCP_HDR_HAS_URG(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x20U) ? 1 : 0)
#define PB_TCP_HDR_HAS_ECE(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x40U) ? 1 : 0)
#define PB_TCP_HDR_HAS_CWR(__b) ((((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)) & 0x80U) ? 1 : 0)
#define PB_TCP_HDR_SET_LEN(__b, __l) do { PB_TCP(__b)->flags = (__iip_htons(((__l) << 12) | ((uint8_t)(__iip_ntohs(PB_TCP(__b)->flags) & 0x3fU)))); } while (0)
#define PB_TCP_HDR_SET_FLAGS(__b, __f) do { PB_TCP(__b)->flags = (PB_TCP(__b)->flags & __iip_htons(~0x3fU)) | __iip_htons(__f); } while (0)
#define PB_TCP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_TCP(__b) + PB_TCP_HDR_LEN(__b) * 4))
#define PB_TCP_PAYLOAD_LEN(__b) ((uint16_t)(__iip_htons(PB_IP4(__b)->len_be) - (PB_IP4(__b)->vl & 0x0f) * 4 - PB_TCP_HDR_LEN(__b) * 4))
#define PB_TCP_OPT(__b) ((uint8_t *)((uintptr_t) PB_TCP(__b) + sizeof(struct iip_tcp_hdr)))
#define PB_TCP_OPTLEN(__b) (PB_TCP_HDR_LEN(__b) * 4 - sizeof(struct iip_tcp_hdr))
#define PB_UDP(__b) ((struct iip_udp_hdr *)((uintptr_t) PB_IP4(__b) + (PB_IP4(__b)->vl & 0x0f) * 4))
#define PB_UDP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_UDP(__b) + sizeof(struct iip_udp_hdr)))
#define PB_UDP_PAYLOAD_LEN(__b) ((uint16_t)(__iip_ntohs(PB_UDP(__b)->len_be)))

/* data structures */

struct pb {
	void *pkt;
	void *buf;
	void *ack_cb_pkt;
	uint8_t flags;
#define __IIP_PB_FLAGS_NEED_ACK_CB_PKT_FREE	(1U << 2)
#define __IIP_PB_FLAGS_OPT_HAS_TS		(1U << 3)
#define __IIP_PB_FLAGS_SACKED			(1U << 4)
#define __IIP_PB_FLAGS_SACK_REPLY_SEND_ALL	(1U << 5)
	void *orig_pkt; /* for no scatter gather mode */

	uint32_t ts;
	uint32_t a_cnt; /* arrival count */

	struct {
		uint32_t rto_ms;
		uint16_t inc_head;
		uint16_t dec_tail;
		struct {
			uint16_t sack_opt_off;
			uint32_t ts[2];
		} opt;
	} tcp;

	struct {
		uint16_t to_be_updated;
		struct {
			uint16_t increment_head;
			uint16_t decrement_tail;
		} range[0xffff /* max frame size*/ / 512 /* minimum mtu */];
	} clone;

	struct pb *prev[1];
	struct pb *next[1];
};

#define __IIP_TCP_STATE_CLOSED	    (1)
#define __IIP_TCP_STATE_SYN_SENT    (2)
#define __IIP_TCP_STATE_SYN_RECVD   (3)
#define __IIP_TCP_STATE_ESTABLISHED (4)
#define __IIP_TCP_STATE_CLOSING	    (5)
#define __IIP_TCP_STATE_FIN_WAIT1   (6)
#define __IIP_TCP_STATE_FIN_WAIT2   (7)
#define __IIP_TCP_STATE_TIME_WAIT   (8)
#define __IIP_TCP_STATE_CLOSE_WAIT  (9)
#define __IIP_TCP_STATE_LAST_ACK    (10)

struct iip_tcp_conn {
	uint8_t state;

	uint16_t local_port_be;
	uint16_t peer_port_be;
	uint32_t local_ip4_be;
	uint32_t peer_ip4_be;
	uint8_t local_mac[IIP_CONF_L2ADDR_LEN_MAX];
	uint8_t peer_mac[IIP_CONF_L2ADDR_LEN_MAX];

	uint32_t seq_be;
	uint32_t ack_seq_be;
	uint16_t win_be;

	/* management */
	uint32_t acked_seq;
	uint32_t ts; /* latest timestamp of peer host */
	uint16_t peer_win;
	uint32_t ack_seq_sent;
	uint32_t seq_next_expected;
	uint8_t dup_ack_received;
	uint8_t dup_ack_sent;
	uint32_t time_wait_ts_ms;
	uint32_t retrans_cnt;

	uint8_t flags;
#define __IIP_TCP_CONN_FLAGS_PEER_RX_FAILED	(1U << 5)

	uint32_t sent_seq_when_loss_detected;
	uint32_t dupack_ts_ms;

	uint32_t fin_ack_seq_be;

	uint8_t ws;
	uint8_t sack_ok;
	uint16_t mss;

	uint32_t a_cnt; /* arrival count */

	struct { /* number of packet buffer (not in byte) for rx */
		uint32_t limit; /* we should have 1GB (735439) as the max : 1GB / 1460 (mss) = 735439.6.. */
		uint32_t used;
	} rx_buf_cnt;

	struct {
		uint16_t ssthresh;
		uint16_t win;
	} cc; /* congestion control */

	struct {
		uint32_t srtt; /* smoothed RTT estimator */
		uint32_t rttvar; /* smoothed mean RTT estimator */
	} rtt;

	void *opaque;

	struct pb *tcp_sack_rx[2];

	struct pb *head[6][2]; /* 0: rx, 1: tx, 2: tx sent, 3: tx retrans, 4: rx out-of-order, 5: tx urgent */

	struct iip_tcp_conn *prev[2];
	struct iip_tcp_conn *next[2];
};

struct workspace {
	struct {
		struct pb *ip4_rx_fragment[2];
	} queue;
	struct {
		uint32_t p_cnt;
		struct pb *p[2];
		struct iip_tcp_conn *conn[2];
	} pool;
	struct {
		uint32_t prev_fast;
		uint32_t prev_slow;
		uint32_t prev_very_slow;
	} timer;
	struct {
		uint32_t iss; /* initial send sequence number */
		uint32_t pkt_ts;
		struct iip_tcp_conn *conns[2];
		struct iip_tcp_conn *conns_ht[IIP_CONF_TCP_CONN_HT_SIZE][2];
		struct iip_tcp_conn *closed_conns[2];
	} tcp;

	struct {
		uint32_t prev_print_ts;
		struct {
			uint32_t rx_pkt;
			uint32_t rx_pkt_dupack;
			uint32_t rx_pkt_keepalive;
			uint32_t rx_pkt_winupdate;
			uint32_t tx_pkt;
			uint32_t tx_pkt_re;
			uint32_t fc_stop;
			uint32_t cc_stop;
			uint32_t th_stop;
		} tcp;
	} monitor;
};

/* pb allocator */

static void __iip_free_pb(struct workspace *s, struct pb *p, void *opaque)
{
	if (p->flags & __IIP_PB_FLAGS_NEED_ACK_CB_PKT_FREE)
		iip_ops_pkt_free(p->ack_cb_pkt, opaque);
	iip_ops_pkt_free(p->pkt, opaque);
	if (p->orig_pkt)
		iip_ops_pkt_free(p->orig_pkt, opaque);
	__iip_memset(p, 0, sizeof(struct pb));
#define __iip_enqueue_obj_top(__queue, __obj, __x) \
	do { \
		(__obj)->prev[__x] = (__obj)->next[__x] = NULL; \
		if (!((__queue)[0])) { \
			(__queue)[0] = (__queue)[1] = (__obj); \
		} else { \
			(__queue)[0]->prev[__x] = (__obj); \
			(__obj)->next[__x] = (__queue)[0]; \
			(__queue)[0] = (__obj); \
		} \
	} while (0)
	__iip_enqueue_obj_top(s->pool.p, p, 0);
#undef __iip_enqueue_obj_top
	s->pool.p_cnt++;
}

static struct pb *__iip_alloc_pb(struct workspace *s, void *pkt, void *opaque)
{
	struct pb *p = s->pool.p[0];
	__iip_assert(p);
	__iip_assert(pkt);
	__iip_dequeue_obj(s->pool.p, p, 0);
	p->pkt = pkt;
	p->buf = iip_ops_pkt_get_data(p->pkt, opaque);
	s->pool.p_cnt--;
	return p;
}

static struct pb *__iip_clone_pb(struct workspace *s, struct pb *orig, void *opaque)
{
	struct pb *p = s->pool.p[0];
	__iip_assert(p);
	__iip_dequeue_obj(s->pool.p, p, 0);
	p->pkt = iip_ops_pkt_clone(orig->pkt, opaque);
	__iip_assert(p->pkt);
	if (orig->ack_cb_pkt) {
		p->ack_cb_pkt = iip_ops_pkt_clone(orig->ack_cb_pkt, opaque);
		__iip_assert(p->ack_cb_pkt);
	}
	if (orig->orig_pkt) {
		p->orig_pkt = iip_ops_pkt_clone(orig->orig_pkt, opaque);
		__iip_assert(p->orig_pkt);
	}
	p->buf = orig->buf;
	p->flags = orig->flags;
	p->ts = orig->ts;
	p->a_cnt = orig->a_cnt;
	__iip_memcpy(&p->tcp, &orig->tcp, sizeof(p->tcp));
	__iip_memcpy(&p->clone, &orig->clone, sizeof(p->clone));
	/* we do not touch queue entity */
	s->pool.p_cnt--;
	return p;
}

/* exported utilitiy functions */

static uint32_t iip_workspace_size(void)
{
	return sizeof(struct workspace);
}

static uint32_t iip_pb_size(void)
{
	return sizeof(struct pb);
}

static uint32_t iip_tcp_conn_size(void)
{
	return sizeof(struct iip_tcp_conn);
}

static void iip_add_pb(void *_mem, void *_p)
{
	__iip_enqueue_obj(((struct workspace *) _mem)->pool.p, (struct pb *) _p, 0);
	((struct workspace *) _mem)->pool.p_cnt++;
}

static void iip_add_tcp_conn(void *_mem, void *_conn)
{
	__iip_enqueue_obj(((struct workspace *) _mem)->pool.conn, (struct iip_tcp_conn *) _conn, 0);
}

/* protocol stack implementation */

static void iip_arp_request(void *_mem,
			    uint8_t local_mac[],
			    uint32_t local_ip4_be,
			    uint32_t target_ip4_be,
			    void *opaque)
{
	void *out_pkt = iip_ops_pkt_alloc(opaque);
	__iip_assert(out_pkt);
	{
		uint8_t bc_mac[IIP_CONF_L2ADDR_LEN_MAX];
		iip_ops_l2_broadcast_addr(bc_mac, opaque);
		iip_ops_l2_hdr_craft(out_pkt, local_mac, bc_mac, __iip_htons(0x0806), opaque);
	}
	{
		struct iip_arp_hdr *arph = PB_ARP(iip_ops_pkt_get_data(out_pkt, opaque));
		arph->hw_be = __iip_htons(0x0001);
		arph->proto_be = __iip_htons(0x0800);
		arph->lhw = iip_ops_arp_lhw(opaque);
		arph->lproto = iip_ops_arp_lproto(opaque);
		arph->op_be = __iip_htons(0x0001);
		__iip_memcpy(PB_ARP_HW_SENDER(iip_ops_pkt_get_data(out_pkt, opaque)), local_mac, 6);
		__iip_memset(PB_ARP_HW_TARGET(iip_ops_pkt_get_data(out_pkt, opaque)), 0, 6);
		__iip_memcpy(PB_ARP_IP_SENDER(iip_ops_pkt_get_data(out_pkt, opaque)), (uint8_t *) &local_ip4_be, 4);
		__iip_memcpy(PB_ARP_IP_TARGET(iip_ops_pkt_get_data(out_pkt, opaque)), (uint8_t *) &target_ip4_be, 4);
		iip_ops_pkt_set_len(out_pkt, iip_ops_l2_hdr_len(out_pkt, opaque) + sizeof(struct iip_arp_hdr) + arph->lhw * 2 + arph->lproto * 2, opaque);
	}
	iip_ops_l2_push(out_pkt, opaque);
	{ /* unused */
		(void) _mem;
	}
}

static uint16_t __iip_tcp_push(struct workspace *s,
			       struct iip_tcp_conn *conn, void *_pkt,
			       uint8_t syn, uint8_t ack, uint8_t fin, uint8_t rst,
			       uint8_t *sackbuf, void *opaque)
{
	void *pkt;
	struct pb *out_p;
	uint16_t total_payload_len = (_pkt ? iip_ops_pkt_get_len(_pkt, opaque) : 0), payload_len = total_payload_len, pushed_payload_len = 0, frag_cnt = 0;
again:
	frag_cnt++;
	pkt = _pkt;
	out_p = __iip_alloc_pb(s, iip_ops_pkt_alloc(opaque), opaque);
	if (!iip_ops_nic_feature_offload_tcp_tx_tso(opaque)) {
		uint16_t l = (conn->mss < 536 ? 536 : conn->mss) - (0 /* size of ip option */ + __iip_round_up((syn ? 4 + 3 + (IIP_CONF_TCP_OPT_SACK_OK ? 2 : 0) : 0) + (sackbuf ? sackbuf[1] : 0) + (IIP_CONF_TCP_TIMESTAMP_ENABLE ? 10 : 0), 4)) /* size of tcp option */;
		payload_len = (l < (uint16_t) (total_payload_len - pushed_payload_len) ? l : total_payload_len - pushed_payload_len);
		if (payload_len != total_payload_len) {
			__iip_assert((pkt = iip_ops_pkt_clone(_pkt, opaque)) != NULL);
			iip_ops_pkt_increment_head(pkt, pushed_payload_len, opaque);
			iip_ops_pkt_set_len(pkt, payload_len, opaque);
		}
	}
	iip_ops_l2_hdr_craft(out_p->pkt, conn->local_mac, conn->peer_mac, __iip_htons(0x0800), opaque);
	{
		struct iip_ip4_hdr *ip4h = PB_IP4(out_p->buf);
		ip4h->vl = (4 /* ver ipv4 */ << 4) | (sizeof(struct iip_ip4_hdr) / 4 /* len in octet */);
		ip4h->len_be = __iip_htons(sizeof(struct iip_ip4_hdr) + __iip_round_up(sizeof(struct iip_tcp_hdr) + (syn ? 4 + 3 + (IIP_CONF_TCP_OPT_SACK_OK ? 2 : 0) : 0) + (sackbuf ? sackbuf[1] : 0) + (IIP_CONF_TCP_TIMESTAMP_ENABLE ? 10 : 0), 4) + payload_len);
		ip4h->tos = 0;
		ip4h->id_be = 0; /* no ip4 fragment */
		ip4h->off_be = 0; /* no ip4 fragment */
		ip4h->ttl = IIP_CONF_IP4_TTL;
		ip4h->proto = 6; /* tcp */
		ip4h->src_be = conn->local_ip4_be;
		ip4h->dst_be = conn->peer_ip4_be;
		ip4h->csum_be = 0;
		if (!iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)) { /* ip4 csum */
			uint8_t *_b[1]; _b[0] = (uint8_t *) ip4h;
			{
				uint16_t _l[1]; _l[0] = (uint16_t) ((ip4h->vl & 0x0f) * 4);
				ip4h->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 1, 0));
			}
		} else
			iip_ops_nic_offload_ip4_tx_checksum_mark(out_p->pkt, opaque);
	}
	__iip_assert(conn->rx_buf_cnt.limit < (1U << 30) /* 1GB limit : RFC 7323 */ / IIP_CONF_TCP_OPT_MSS);
	{
		struct iip_tcp_hdr *tcph = PB_TCP(out_p->buf);
		tcph->src_be = conn->local_port_be;
		tcph->dst_be = conn->peer_port_be;
		tcph->seq_be = conn->seq_be;
		tcph->ack_seq_be = conn->ack_seq_be;
		tcph->flags = 0;
		PB_TCP_HDR_SET_LEN(out_p->buf, __iip_round_up(sizeof(struct iip_tcp_hdr) + (syn ? 4 + 3 + (IIP_CONF_TCP_OPT_SACK_OK ? 2 : 0) : 0) + (sackbuf ? sackbuf[1] : 0) + (IIP_CONF_TCP_TIMESTAMP_ENABLE ? 10 : 0), 4) / 4);
		PB_TCP_HDR_SET_FLAGS(out_p->buf, (syn ? 0x02U : 0) | (ack ? 0x10U : 0) | (rst ? 0x04U : 0) | (fin ? 0x01U : 0));
		tcph->win_be = __iip_htons((uint16_t) (((conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * IIP_CONF_TCP_OPT_MSS) >> IIP_CONF_TCP_OPT_WS));
		tcph->urg_p_be = 0;
		tcph->csum_be = 0;
		{
			uint8_t *optbuf = PB_TCP_OPT(out_p->buf), optlen = 0;
			{
				if (syn) { /* mss */
					optbuf[optlen + 0] = 2;
					optbuf[optlen + 1] = 4;
					*((uint16_t *) &(optbuf[optlen + 2])) = __iip_htons(IIP_CONF_TCP_OPT_MSS);
					optlen += optbuf[optlen + 1];
				}
				if (syn) { /* window scale */
					optbuf[optlen + 0] = 3;
					optbuf[optlen + 1] = 3;
					__iip_assert(IIP_CONF_TCP_OPT_WS < 15); /* RFC 7323 */
					optbuf[optlen + 2] = IIP_CONF_TCP_OPT_WS;
					optlen += optbuf[optlen + 1];
				}
				if (syn && IIP_CONF_TCP_OPT_SACK_OK) { /* sack ok */
					optbuf[optlen + 0] = 4;
					optbuf[optlen + 1] = 2;
					optlen += optbuf[optlen + 1];
				}
				if (sackbuf) { /* sack */
					__iip_memcpy(&optbuf[optlen], sackbuf, sackbuf[1]);
					optlen += sackbuf[1];
				}
				if (IIP_CONF_TCP_TIMESTAMP_ENABLE) { /* time stamp */
					optbuf[optlen + 0] = 8;
					optbuf[optlen + 1] = 10;
					((uint32_t *) &optbuf[optlen + 2])[0] = __iip_htonl(s->tcp.pkt_ts);
					((uint32_t *) &optbuf[optlen + 2])[1] = __iip_htonl(conn->ts);
					optlen += optbuf[optlen + 1];
				}
				__iip_assert(PB_TCP_HDR_LEN(out_p->buf) == __iip_round_up(sizeof(struct iip_tcp_hdr) + optlen, 4) / 4); /* we already have configured */
			}
			__iip_memset(&optbuf[optlen], 0, PB_TCP_HDR_LEN(out_p->buf) * 4 - optlen);
		}
		if (!iip_ops_nic_feature_offload_tcp_tx_checksum(opaque)) {
			struct iip_l4_ip4_pseudo_hdr _pseudo;
			_pseudo.ip4_src_be = conn->local_ip4_be;
			_pseudo.ip4_dst_be = conn->peer_ip4_be;
			_pseudo.pad = 0;
			_pseudo.proto = 6;
			_pseudo.len_be = __iip_htons(PB_TCP_HDR_LEN(out_p->buf) * 4 + payload_len);
			{
				uint8_t *_b[3]; _b[0] = (uint8_t *) &_pseudo; _b[1] = (uint8_t *) tcph; _b[2] = (pkt ? (uint8_t *) iip_ops_pkt_get_data(pkt, opaque) : NULL);
				{
					uint16_t _l[3]; _l[0] = sizeof(_pseudo); _l[1] = (uint16_t) (PB_TCP_HDR_LEN(out_p->buf) * 4); _l[2] = payload_len;
					tcph->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 3, 0));
				}
			}
		} else
			iip_ops_nic_offload_tcp_tx_checksum_mark(out_p->pkt, opaque); /* relies on the value of tcp hdr len on packet buf */
	}

	if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
		if (pkt) iip_ops_pkt_scatter_gather_chain_append(out_p->pkt, pkt, opaque);
		iip_ops_pkt_set_len(out_p->pkt, iip_ops_l2_hdr_len(out_p->pkt, opaque) + (PB_IP4(out_p->buf)->vl & 0x0f) * 4 + PB_TCP_HDR_LEN(out_p->buf) * 4, opaque);
	} else {
		if (pkt) __iip_memcpy(PB_TCP_PAYLOAD(out_p->buf), iip_ops_pkt_get_data(pkt, opaque), payload_len);
		iip_ops_pkt_set_len(out_p->pkt, iip_ops_l2_hdr_len(out_p->pkt, opaque) + (PB_IP4(out_p->buf)->vl & 0x0f) * 4 + PB_TCP_HDR_LEN(out_p->buf) * 4 + payload_len, opaque);
		if (pkt) out_p->orig_pkt = pkt;
	}

	conn->seq_be = __iip_htonl(__iip_ntohl(conn->seq_be) + payload_len + syn + fin);
	if (ack)
		conn->ack_seq_sent = __iip_ntohl(PB_TCP(out_p->buf)->ack_seq_be);

	if (iip_ops_nic_feature_offload_tcp_tx_tso(opaque))
		iip_ops_nic_offload_tcp_tx_tso_mark(out_p->pkt, opaque);

	__iip_enqueue_obj(conn->head[1], out_p, 0);

	pushed_payload_len += payload_len;
	if (pushed_payload_len != total_payload_len)
		goto again;
	else {
		out_p->ack_cb_pkt = _pkt;
		if (1 < frag_cnt)
			out_p->flags |= __IIP_PB_FLAGS_NEED_ACK_CB_PKT_FREE;
	}

	return 0;
}

static uint16_t iip_tcp_send(void *_mem, void *_handle, void *pkt, void *opaque)
{
	struct iip_tcp_conn *conn = (struct iip_tcp_conn *) _handle;
	if (conn->state != __IIP_TCP_STATE_ESTABLISHED)
		return 0;
	return __iip_tcp_push((struct workspace *) _mem, conn, pkt, 0, 1, 0, 0, NULL, opaque);
}

static uint16_t iip_tcp_close(void *_mem, void *_handle, void *opaque)
{
	struct iip_tcp_conn *conn = (struct iip_tcp_conn *) _handle;
	if (conn->state == __IIP_TCP_STATE_ESTABLISHED) {
		conn->state = __IIP_TCP_STATE_FIN_WAIT1;
		IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_FIN_WAIT1\n", (void *) conn);
		{
			uint16_t ret = __iip_tcp_push((struct workspace *) _mem, conn, NULL, 0, 1, 1, 0, NULL, opaque);
			conn->fin_ack_seq_be = conn->seq_be;
			return ret;
		}
	} else
		return 0;
}

static void iip_tcp_rxbuf_consumed(void *_mem, void *_handle, uint16_t cnt, void *opaque)
{
	struct iip_tcp_conn *conn = (struct iip_tcp_conn *) _handle;
	__iip_assert(cnt <= conn->rx_buf_cnt.used);
	conn->rx_buf_cnt.used -= cnt;
	{ /* unused */
		(void) _mem;
		(void) opaque;
	}
}

static void __iip_tcp_conn_init(struct workspace *s, struct iip_tcp_conn *conn,
				uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
				uint8_t state, void *opaque)
{
	__iip_memset(conn, 0, sizeof(*conn));
	__iip_memcpy(conn->local_mac, local_mac, sizeof(conn->local_mac));
	conn->local_ip4_be = local_ip4_be;
	conn->local_port_be = local_port_be;
	__iip_memcpy(conn->peer_mac, peer_mac, sizeof(conn->peer_mac));
	conn->peer_ip4_be = peer_ip4_be;
	conn->peer_port_be = peer_port_be;
	conn->seq_be = __iip_htonl(s->tcp.iss);
	conn->ack_seq_be = 0;
	conn->acked_seq = 0xffff; /* to differentiate from ack number for Dup ACK detection */
	conn->state = state;
	conn->rx_buf_cnt.limit = IIP_CONF_TCP_RX_BUF_CNT;
	conn->cc.win = IIP_CONF_TCP_WIN_INIT;
	conn->cc.ssthresh = IIP_CONF_TCP_SSTHRESH_INIT;
	conn->rtt.srtt = 0;
	conn->rtt.rttvar = 24;
	__iip_assert(conn->rx_buf_cnt.limit * IIP_CONF_TCP_OPT_MSS < (1U << 30));
	conn->win_be = __iip_htons((conn->rx_buf_cnt.limit * IIP_CONF_TCP_OPT_MSS) >> IIP_CONF_TCP_OPT_WS);
	__iip_enqueue_obj(s->tcp.conns, conn, 0);
	__iip_enqueue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
	__iip_assert(conn->rx_buf_cnt.used < conn->rx_buf_cnt.limit);
	{ /* unused */
		(void) opaque;
	}
}

static uint16_t iip_tcp_connect(void *_mem,
				uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
				void *opaque)
{
	struct workspace *s = (struct workspace *) _mem;
	struct iip_tcp_conn *conn = s->pool.conn[0];
	__iip_assert(conn);
	__iip_dequeue_obj(s->pool.conn, conn, 0);
	__iip_tcp_conn_init(s, conn, local_mac, local_ip4_be, local_port_be, peer_mac, peer_ip4_be, peer_port_be, __IIP_TCP_STATE_SYN_SENT, opaque);
	return __iip_tcp_push(s, conn, NULL, 1, 0, 0, 0, NULL, opaque);
}

static uint16_t iip_udp_send(void *_mem,
			     uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			     uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			     void *pkt, void *opaque)
{
	void *out_pkt = iip_ops_pkt_alloc(opaque);
	uint16_t payload_len = (pkt ? iip_ops_pkt_get_len(pkt, opaque) : 0);
	__iip_assert(out_pkt);
	iip_ops_l2_hdr_craft(out_pkt, local_mac, peer_mac, __iip_htons(0x0800), opaque);
	{
		struct iip_ip4_hdr *ip4h = PB_IP4(iip_ops_pkt_get_data(out_pkt, opaque));
		ip4h->vl = (4 /* ver ipv4 */ << 4) | (sizeof(struct iip_ip4_hdr) / 4 /* len in octet */);
		ip4h->len_be = __iip_htons((ip4h->vl & 0x0f) * 4 + sizeof(struct iip_udp_hdr) + payload_len);
		ip4h->tos = 0;
		ip4h->id_be = 0; /* no ip4 fragment */
		ip4h->off_be = 0; /* no ip4 fragment */
		ip4h->ttl = IIP_CONF_IP4_TTL;
		ip4h->proto = 17; /* udp */
		ip4h->src_be = local_ip4_be;
		ip4h->dst_be = peer_ip4_be;
		ip4h->csum_be = 0;
		if (!iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)) { /* ip4 csum */
			uint8_t *_b[1]; _b[0] = (uint8_t *) ip4h;
			{
				uint16_t _l[1]; _l[0] = (uint16_t) ((ip4h->vl & 0x0f) * 4);
				ip4h->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 1, 0));
			}
		} else
			iip_ops_nic_offload_ip4_tx_checksum_mark(out_pkt, opaque);
		{
			struct iip_udp_hdr *udph = PB_UDP(iip_ops_pkt_get_data(out_pkt, opaque));
			udph->src_be = local_port_be;
			udph->dst_be = peer_port_be;
			udph->len_be = __iip_htons(sizeof(struct iip_udp_hdr) + payload_len);
			udph->csum_be = 0;
			if (!iip_ops_nic_feature_offload_udp_tx_checksum(opaque)) { /* udp csum */
				struct iip_l4_ip4_pseudo_hdr _pseudo;
				_pseudo.ip4_src_be = local_ip4_be;
				_pseudo.ip4_dst_be = peer_ip4_be;
				_pseudo.pad = 0;
				_pseudo.proto = 17;
				_pseudo.len_be = __iip_htons(sizeof(struct iip_udp_hdr) + payload_len);
				{
					uint8_t *_b[3]; _b[0] = (uint8_t *) &_pseudo; _b[1] = (uint8_t *) udph; _b[2] = (pkt ? (uint8_t *) iip_ops_pkt_get_data(pkt, opaque) : NULL);
					{
						uint16_t _l[3]; _l[0] = sizeof(_pseudo); _l[1] = sizeof(struct iip_udp_hdr); _l[2] = payload_len;
						udph->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 3, 0));
					}
				}
			} else
				iip_ops_nic_offload_udp_tx_checksum_mark(out_pkt, opaque);

			if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
				if (pkt) iip_ops_pkt_scatter_gather_chain_append(out_pkt, pkt, opaque);
				iip_ops_pkt_set_len(out_pkt, iip_ops_l2_hdr_len(out_pkt, opaque) + (ip4h->vl & 0x0f) * 4 + sizeof(struct iip_udp_hdr), opaque);
			} else {
				if (pkt) __iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[iip_ops_l2_hdr_len(out_pkt, opaque) + (ip4h->vl & 0x0f) * 4 + sizeof(struct iip_udp_hdr)], iip_ops_pkt_get_data(pkt, opaque), payload_len);
				iip_ops_pkt_set_len(out_pkt, iip_ops_l2_hdr_len(out_pkt, opaque) + (ip4h->vl & 0x0f) * 4 + __iip_ntohs(udph->len_be), opaque);
				if (pkt) iip_ops_pkt_free(pkt, opaque);
			}
		}
	}

	if (iip_ops_nic_feature_offload_udp_tx_tso(opaque))
		iip_ops_nic_offload_udp_tx_tso_mark(out_pkt, opaque);

	iip_ops_l2_push(out_pkt, opaque);

	return 0;

	{ /* unused */
		(void) _mem;
	}
}

static uint16_t iip_run(void *_mem, uint8_t mac[], uint32_t ip4_be, void *pkt[], uint16_t cnt, uint32_t *next_us, void *opaque)
{
	struct workspace *s = (struct workspace *) _mem;
	uint16_t ret = 0;
	uint32_t _next_us = 1000000UL; /* 1 sec */
	uint32_t now_ms;
	{
		uint32_t t[3];
		iip_ops_util_now_ns(t, opaque);
		now_ms = (t[1] * 1000UL + t[2] / 1000000UL);
	}
	{ /* periodic timer */
		if (200 <= now_ms - s->timer.prev_fast){ /* fast timer every 200 ms */
			/* send delayed ack */
			{
				struct iip_tcp_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					if (conn->state == __IIP_TCP_STATE_ESTABLISHED && !conn->head[3][0] && !conn->head[5][0]) {
						if ((__iip_ntohl(conn->ack_seq_be) != conn->ack_seq_sent)) /* we got payload, but ack is not pushed by the app */
							__iip_tcp_push(s, conn, NULL, 0, 1, 0, 0, NULL, opaque);
					}
				}
			}
			{ /* incrment tcp packet timestamp counter */
				s->tcp.pkt_ts++;
			}
			s->timer.prev_fast = now_ms;
		}
		if (500 <= now_ms - s->timer.prev_slow){ /* slow timer every 500 ms */
			{ /* incrment initial send sequence number */
				s->tcp.iss++; /* while RFC 793 specifies to increment every 4 us */
			}
			s->timer.prev_slow = now_ms;
		}
		if (1000 <= now_ms - s->timer.prev_very_slow) { /* slow timer every 1000 ms */
			{ /* close connections */
				struct iip_tcp_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					switch (conn->state) {
					case __IIP_TCP_STATE_TIME_WAIT:
						if (IIP_CONF_TCP_MSL_SEC * 1000U * 2 < now_ms - conn->time_wait_ts_ms) {
							conn->state = __IIP_TCP_STATE_CLOSED;
							__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
							__iip_dequeue_obj(s->tcp.conns, conn, 0);
							__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
							IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_TIME_WAIT - TCP_STATE_CLOSED (%u %u (%u %u))\n", (void *) conn, IIP_CONF_TCP_MSL_SEC * 1000U * 2, (now_ms - conn->time_wait_ts_ms) * 1000U, now_ms, conn->time_wait_ts_ms);
						}
						break;
					default:
						break;
					}
				}
			}
			s->timer.prev_very_slow = now_ms;
		}
		{
			_next_us = (s->timer.prev_fast + 200U - now_ms < _next_us * 1000U ? (s->timer.prev_fast + 200U - now_ms) * 1000U : _next_us);
			_next_us = (s->timer.prev_slow + 500U - now_ms < _next_us * 1000U ? (s->timer.prev_slow + 500U - now_ms) * 1000U : _next_us);
			_next_us = (s->timer.prev_very_slow + 1000U - now_ms < _next_us * 1000U ? (s->timer.prev_very_slow + 1000U - now_ms) * 1000U : _next_us);
		}
	}
	{ /* steer packet to an ip4_rx queue or discard after executing callback  */
		struct pb *ip4_rx[2] = { 0 };
		{
			uint16_t i;
			for (i = 0; i < cnt; i++) {
				if (iip_ops_l2_skip(pkt[i], opaque))
					iip_ops_pkt_free(pkt[i], opaque);
				else {
					uint8_t pkt_used = 0;
					struct pb *p = __iip_alloc_pb(s, pkt[i], opaque);
					switch (__iip_ntohs(iip_ops_l2_ethertype_be(p->pkt, opaque))) {
					case 0x0800: /* ip */
						if (!__iip_memcmp(mac, iip_ops_l2_hdr_dst_ptr(p->pkt, opaque), iip_ops_l2_addr_len(opaque))) {
							/*IIP_OPS_DEBUG_PRINTF("ip4-in : src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u v %u, l %u, proto %u\n",
									(PB_IP4(p->buf)->src_be >>  0) & 0x0ff,
									(PB_IP4(p->buf)->src_be >>  8) & 0x0ff,
									(PB_IP4(p->buf)->src_be >> 16) & 0x0ff,
									(PB_IP4(p->buf)->src_be >> 24) & 0x0ff,
									(PB_IP4(p->buf)->dst_be >>  0) & 0x0ff,
									(PB_IP4(p->buf)->dst_be >>  8) & 0x0ff,
									(PB_IP4(p->buf)->dst_be >> 16) & 0x0ff,
									(PB_IP4(p->buf)->dst_be >> 24) & 0x0ff,
									PB_IP4(p->buf)->vl >> 4, PB_IP4(p->buf)->l,
									PB_IP4(p->buf)->proto);*/
							if ((PB_IP4(p->buf)->vl >> 4) != 4) { /* ip version*/
								IIP_OPS_DEBUG_PRINTF("this is not ipv4 (%u)\n", PB_IP4(p->buf)->vl >> 4);
								break;
							}
							if ((PB_IP4(p->buf)->vl & 0x0f) * 4 > iip_ops_pkt_get_len(pkt[i], opaque)) {
								IIP_OPS_DEBUG_PRINTF("ip4 hdr invalid length (%u)\n", (PB_IP4(p->buf)->vl & 0x0f) * 4);
								break;
							}
							if (iip_ops_nic_feature_offload_ip4_rx_checksum(opaque)) {
								if (!iip_ops_nic_offload_ip4_rx_checksum(p->pkt, opaque)) {
									IIP_OPS_DEBUG_PRINTF("pkt %p: invalid ip4 csum computed by NIC\n", p->pkt);
									break;
								}
							} else {
								uint8_t *_b[1]; _b[0] = (uint8_t *) PB_IP4(p->buf);
								{
									uint16_t _l[1]; _l[0] = (uint16_t) ((PB_IP4(p->buf)->vl & 0x0f) * 4);
									if (__iip_ntohs(PB_IP4(p->buf)->csum_be) != __iip_netcsum16(_b, _l, 1, __iip_ntohs(PB_IP4(p->buf)->csum_be))) {
										IIP_OPS_DEBUG_PRINTF("invalid ip4 csum (hdr val %x, computed %x)\n",
												__iip_ntohs(PB_IP4(p->buf)->csum_be),
												__iip_netcsum16(_b, _l, 1, __iip_ntohs(PB_IP4(p->buf)->csum_be)));
										break;
									}
								}
							}
							if (PB_IP4(p->buf)->dst_be != ip4_be) {
								IIP_OPS_DEBUG_PRINTF("ip4 but not for me (dst %u.%u.%u.%u)\n",
										(PB_IP4(p->buf)->dst_be >>  0) & 0x0ff,
										(PB_IP4(p->buf)->dst_be >>  8) & 0x0ff,
										(PB_IP4(p->buf)->dst_be >> 16) & 0x0ff,
										(PB_IP4(p->buf)->dst_be >> 24) & 0x0ff);
								break;
							}
							/* TODO: handling ip options */
							if (__iip_ntohs(PB_IP4(p->buf)->off_be) & (0x2000 /* more packet flag */ | 0x1fff /* offset */)) {
								IIP_OPS_DEBUG_PRINTF("fragmented ip4 (%u)\n", __iip_ntohs(PB_IP4(p->buf)->off_be) & (0x2000 /* more packet flag */ | 0x1fff /* offset */));
								__iip_enqueue_obj(s->queue.ip4_rx_fragment, p, 0);
							} else
								__iip_enqueue_obj(ip4_rx, p, 0);
							pkt_used = 1;
						}
						break;
					case 0x0806: /* arp */
						{
							uint8_t bc_mac[IIP_CONF_L2ADDR_LEN_MAX];
							iip_ops_l2_broadcast_addr(bc_mac, opaque);
							if (!__iip_memcmp(mac, iip_ops_l2_hdr_dst_ptr(p->pkt, opaque), iip_ops_l2_addr_len(opaque))
									|| !__iip_memcmp(bc_mac, iip_ops_l2_hdr_dst_ptr(p->pkt, opaque), iip_ops_l2_addr_len(opaque))) {
								switch (__iip_ntohs(PB_ARP(p->buf)->hw_be)) {
								case 0x0001: /* ethernet */
									switch (__iip_ntohs(PB_ARP(p->buf)->proto_be)) {
									case 0x0800: /* ipv4 */
										if (PB_ARP(p->buf)->lhw != 6) {
											IIP_OPS_DEBUG_PRINTF("unknown hardawre addr size %u\n", PB_ARP(p->buf)->lhw);
											break;
										}
										if (PB_ARP(p->buf)->lproto != 4) {
											IIP_OPS_DEBUG_PRINTF("unknown ip addr size %u\n", PB_ARP(p->buf)->lproto);
											break;
										}
										switch (__iip_ntohs(PB_ARP(p->buf)->op_be)) {
										case 0x0001: /* request */
											if (ip4_be == *((uint32_t *) PB_ARP_IP_TARGET(p->buf))) { /* arp response */
												void *out_pkt = iip_ops_pkt_alloc(opaque);
												__iip_assert(out_pkt);
												iip_ops_l2_hdr_craft(out_pkt, mac, PB_ARP_HW_SENDER(p->buf), __iip_htons(0x0806), opaque);
												{
													struct iip_arp_hdr *arph = PB_ARP(iip_ops_pkt_get_data(out_pkt, opaque));
													arph->hw_be = __iip_htons(0x0001);
													arph->proto_be = __iip_htons(0x0800);
													arph->lhw = iip_ops_arp_lhw(opaque);
													arph->lproto = iip_ops_arp_lproto(opaque);
													arph->op_be = __iip_htons(0x0002);
													__iip_memcpy(PB_ARP_HW_SENDER(iip_ops_pkt_get_data(out_pkt, opaque)), mac, 6);
													__iip_memcpy(PB_ARP_HW_TARGET(iip_ops_pkt_get_data(out_pkt, opaque)), PB_ARP_HW_SENDER(p->buf), 6);
													__iip_memcpy(PB_ARP_IP_SENDER(iip_ops_pkt_get_data(out_pkt, opaque)), PB_ARP_IP_TARGET(p->buf), 4);
													__iip_memcpy(PB_ARP_IP_TARGET(iip_ops_pkt_get_data(out_pkt, opaque)), PB_ARP_IP_SENDER(p->buf), 4);
													iip_ops_pkt_set_len(out_pkt, iip_ops_l2_hdr_len(out_pkt, opaque) + sizeof(struct iip_arp_hdr) + arph->lhw * 2 + arph->lproto * 2, opaque);
												}
												iip_ops_l2_push(out_pkt, opaque);
											}
											break;
										case 0x0002: /* reply */
											if (ip4_be == *((uint32_t *) PB_ARP_IP_TARGET(p->buf)))
												iip_ops_arp_reply(s, pkt[i], opaque);
											break;
										default:
											IIP_OPS_DEBUG_PRINTF("unknown arp op 0x%x\n", __iip_ntohs(PB_ARP(p->buf)->op_be));
											break;
										}
										break;
									default:
										IIP_OPS_DEBUG_PRINTF("unknown protocol type 0x%x\n", __iip_ntohs(PB_ARP(p->buf)->proto_be));
										break;
									}
									break;
								default:
									IIP_OPS_DEBUG_PRINTF("unknown hardware type 0x%x\n", __iip_ntohs(PB_ARP(p->buf)->hw_be));
									break;
								}
							} else {
								IIP_OPS_DEBUG_PRINTF("arp but not for me (dst %02x:%02x:%02x:%02x:%02x:%02x)\n",
										iip_ops_l2_hdr_dst_ptr(p->pkt, opaque)[0],
										iip_ops_l2_hdr_dst_ptr(p->pkt, opaque)[1],
										iip_ops_l2_hdr_dst_ptr(p->pkt, opaque)[2],
										iip_ops_l2_hdr_dst_ptr(p->pkt, opaque)[3],
										iip_ops_l2_hdr_dst_ptr(p->pkt, opaque)[4],
										iip_ops_l2_hdr_dst_ptr(p->pkt, opaque)[5]);
							}
							break;
						}
					default:
						IIP_OPS_DEBUG_PRINTF("unknown ether type 0x%x\n", __iip_ntohs(iip_ops_l2_ethertype_be(p->pkt, opaque)));
						break;
					}
					if (!pkt_used)
						__iip_free_pb(s, p, opaque);
				}
			}
			ret = i;
		}
		{ /* steer ip4 packets to a queue of tcp connection or discard after executing callback for icmp and udp */
			{
				struct pb *p, *_n;
				__iip_q_for_each_safe(ip4_rx, p, _n, 0) {
					__iip_dequeue_obj(ip4_rx, p, 0);
					{
						uint8_t pkt_used = 0;
						switch (PB_IP4(p->buf)->proto) {
						case 1: /* icmp */
							{
								switch (PB_ICMP(p->buf)->type) {
								case 0: /* reply */
									iip_ops_icmp_reply(s, p->pkt, opaque);
									break;
								case 8: /* echo */
									IIP_OPS_DEBUG_PRINTF("icmp echo (id %u, seq %u)\n",
											__iip_ntohs(PB_ICMP(p->buf)->echo.id_be),
											__iip_ntohs(PB_ICMP(p->buf)->echo.seq_be));
									{
										void *out_pkt = iip_ops_pkt_alloc(opaque);
										__iip_assert(out_pkt);
										iip_ops_l2_hdr_craft(out_pkt, iip_ops_l2_hdr_dst_ptr(p->pkt, opaque), iip_ops_l2_hdr_src_ptr(p->pkt, opaque), __iip_htons(0x0800), opaque);
										{
											struct iip_ip4_hdr *ip4h = PB_IP4(iip_ops_pkt_get_data(out_pkt, opaque));
											ip4h->vl = (4 /* ver ipv4 */ << 4) | (sizeof(struct iip_ip4_hdr) / 4 /* len in octet */);
											ip4h->len_be = __iip_htons((ip4h->vl & 0x0f) * 4 + sizeof(struct iip_icmp_hdr) + (PB_ICMP_PAYLOAD_LEN(p->buf)));
											ip4h->tos = 0;
											ip4h->id_be = 0; /* no ip4 fragment */
											ip4h->off_be = 0; /* no ip4 fragment */
											ip4h->ttl = IIP_CONF_IP4_TTL;
											ip4h->proto = 1; /* icmp */
											ip4h->src_be = PB_IP4(p->buf)->dst_be;
											ip4h->dst_be = PB_IP4(p->buf)->src_be;
											ip4h->csum_be = 0;
											if (!iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)) { /* ip4 csum */
												uint8_t *_b[1]; _b[0] = (uint8_t *) ip4h;
												{
													uint16_t _l[1]; _l[0] = (uint16_t) ((ip4h->vl & 0x0f) * 4);
													ip4h->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 1, 0));
												}
											} else
												iip_ops_nic_offload_ip4_tx_checksum_mark(out_pkt, opaque);
										}
										{
											struct iip_icmp_hdr *icmph = PB_ICMP(iip_ops_pkt_get_data(out_pkt, opaque));
											icmph->type = 0; /* icmp reply */
											icmph->code = 0;
											icmph->csum_be = 0;
											icmph->echo.id_be = PB_ICMP(p->buf)->echo.id_be;
											icmph->echo.seq_be = PB_ICMP(p->buf)->echo.seq_be;
											__iip_memcpy(PB_ICMP_PAYLOAD(iip_ops_pkt_get_data(out_pkt, opaque)), PB_ICMP_PAYLOAD(p->buf), PB_ICMP_PAYLOAD_LEN(p->buf));
											/* TODO: large icmp packet */
											{ /* icmp csum */
												uint8_t *_b[2]; _b[0] = (uint8_t *) icmph; _b[1] = (uint8_t *) PB_ICMP_PAYLOAD(p->buf);
												{
													uint16_t _l[2]; _l[0] = sizeof(struct iip_icmp_hdr); _l[1] = PB_ICMP_PAYLOAD_LEN(p->buf);
													icmph->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 2, 0));
												}
											}
										}
										iip_ops_pkt_set_len(out_pkt, iip_ops_l2_hdr_len(out_pkt, opaque) + __iip_htons(PB_IP4(p->buf)->len_be), opaque);
										iip_ops_l2_push(out_pkt, opaque);
									}
									break;
								default: /* TODO */
									IIP_OPS_DEBUG_PRINTF("unsupported icmp type %u\n", PB_ICMP(p->buf)->type);
									break;
								}
							}
							break;
						case 6: /* tcp */
							if (iip_ops_nic_feature_offload_tcp_rx_checksum(opaque)) {
								if (!iip_ops_nic_offload_tcp_rx_checksum(p->pkt, opaque)) {
									IIP_OPS_DEBUG_PRINTF("pkt %p: invalid tcp checksum hdr commputed by NIC\n", p->pkt);
									break;
								}
							} else {
								struct iip_l4_ip4_pseudo_hdr _pseudo;
								_pseudo.ip4_src_be = PB_IP4(p->buf)->src_be;
								_pseudo.ip4_dst_be = PB_IP4(p->buf)->dst_be;
								_pseudo.pad = 0;
								_pseudo.proto = PB_IP4(p->buf)->proto;
								_pseudo.len_be = __iip_htons(__iip_ntohs(PB_IP4(p->buf)->len_be) - (PB_IP4(p->buf)->vl & 0x0f) * 4);
								{
									uint8_t *_b[3]; _b[0] = (uint8_t *) &_pseudo; _b[1] = (uint8_t *) PB_TCP(p->buf); _b[2] = PB_TCP_PAYLOAD(p->buf);
									{
										uint16_t _l[3]; _l[0] = sizeof(_pseudo); _l[1] = (uint16_t) (PB_TCP_HDR_LEN(p->buf) * 4); _l[2] = PB_TCP_PAYLOAD_LEN(p->buf);
										{
											uint16_t p_csum = __iip_ntohs(PB_TCP(p->buf)->csum_be), c_csum = __iip_netcsum16(_b, _l, 3, __iip_ntohs(PB_TCP(p->buf)->csum_be));
											if ((p_csum == 0xffff ? 0 : p_csum) != (c_csum == 0xffff ? 0 : c_csum)) { /* 0xffff is 0 */
												IIP_OPS_DEBUG_PRINTF("invalid tcp checksum hdr: %u %u : payload len %u\n", p_csum, c_csum, PB_TCP_PAYLOAD_LEN(p->buf));
												break;
											}
										}
									}
								}
							}
							__iip_assert(PB_TCP_HDR_LEN(p->buf));
							{ /* find tcp conneciton and push the packet to its queue */
								struct iip_tcp_conn *conn = (NULL);
								{ /* connection lookup */
									struct iip_tcp_conn *c, *_n;
									__iip_q_for_each_safe(s->tcp.conns_ht[(PB_IP4(p->buf)->src_be + PB_TCP(p->buf)->src_be + PB_TCP(p->buf)->dst_be) % IIP_CONF_TCP_CONN_HT_SIZE], c, _n, 0) {
										if (c->local_port_be == PB_TCP(p->buf)->dst_be
												&& c->peer_port_be == PB_TCP(p->buf)->src_be
												&& c->peer_ip4_be == PB_IP4(p->buf)->src_be) {
											conn = c;
											break;
										}
									}
								}
								if (PB_TCP_HDR_HAS_SYN(p->buf)) {
									if (conn) { /* connect */
										if (!PB_TCP_HDR_HAS_ACK(p->buf)) /* invalid, just ignore */
											conn = NULL;
									} else { /* accept */
										if (iip_ops_tcp_accept(s, p->pkt, opaque)) {
											if (PB_TCP_HDR_HAS_ACK(p->buf)) {
												IIP_OPS_DEBUG_PRINTF("WARNING: got syn-ack for non-existing connection, maybe RSS sterring would be wrong\n");
											} else { /* got a new connection request, so allocate conn obj */
												conn = s->pool.conn[0];
												__iip_assert(conn);
												__iip_dequeue_obj(s->pool.conn, conn, 0);
												__iip_tcp_conn_init(s, conn,
														iip_ops_l2_hdr_dst_ptr(p->pkt, opaque), PB_IP4(p->buf)->dst_be, PB_TCP(p->buf)->dst_be,
														iip_ops_l2_hdr_src_ptr(p->pkt, opaque), PB_IP4(p->buf)->src_be, PB_TCP(p->buf)->src_be,
														__IIP_TCP_STATE_SYN_RECVD, opaque);
											}
										}
									}
									if (conn)
										conn->seq_next_expected = __iip_ntohl(PB_TCP(p->buf)->seq_be);
								}
								if (conn) {
									pkt_used = 1; /* we release p by ourselves */
									if (!conn->a_cnt)
										conn->a_cnt = 1;
									p->a_cnt = conn->a_cnt++;
									if (PB_TCP_OPTLEN(p->buf)) { /* parse tcp option */
										uint32_t l = 0;
										while (l < PB_TCP_OPTLEN(p->buf)) {
											switch (PB_TCP_OPT(p->buf)[l]) {
											case 0: /* eol */
												l = PB_TCP_OPTLEN(p->buf); /* stop loop */
												break;
											case 1: /* nop */
												l++;
												break;
											default:
												if (PB_TCP_OPTLEN(p->buf) - l <= 2) {
													l = PB_TCP_OPTLEN(p->buf); /* stop loop */
													break;
												}
												switch (PB_TCP_OPT(p->buf)[l]) {
												case 2: /* mss */
													if (PB_TCP_OPT(p->buf)[l + 1] == 4) {
														if (PB_TCP_HDR_HAS_SYN(p->buf)) { /* accept only with syn */
															conn->mss = (uint16_t) __iip_ntohs(*((uint16_t *) &PB_TCP_OPT(p->buf)[l + 2]));
															if (IIP_CONF_TCP_OPT_MSS < conn->mss)
																conn->mss = IIP_CONF_TCP_OPT_MSS;
														}
													}
													break;
												case 3: /* window scale */
													if (PB_TCP_OPT(p->buf)[l + 1] == 3) {
														if (PB_TCP_HDR_HAS_SYN(p->buf)) /* accept only with syn */
															conn->ws = PB_TCP_OPT(p->buf)[l + 2];
													}
													break;
												case 4: /* sack permitted */
													if (PB_TCP_OPT(p->buf)[l + 1] == 2) {
														if (PB_TCP_HDR_HAS_SYN(p->buf)) { /* accept only with syn */
															if (IIP_CONF_TCP_OPT_SACK_OK)
																conn->sack_ok = 1;
														}
													}
													break;
												case 5: /* sack */
													if (PB_TCP_OPT(p->buf)[l + 1] >= (2 + 8))
														p->tcp.opt.sack_opt_off = l + 1; /* pointing to the length, to diffrenciate sack starting at opt[0] */
													if (p->tcp.opt.sack_opt_off) { /* debug */
														uint16_t c = 2;
														while (c < PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off]) {
															IIP_OPS_DEBUG_PRINTF("rx sack: %2u/%2u: sle %u sre %u (len %u)\n",
																	c, PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off],
																	__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 0]))),
																	__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 4]))),
																	__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 4]))) - __iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 0]))));
															c += 8;
														}
													}
													break;
												case 8: /* timestamp */
													if (PB_TCP_OPT(p->buf)[l + 1] == 10) {
														p->flags |= __IIP_PB_FLAGS_OPT_HAS_TS;
														p->tcp.opt.ts[0] = __iip_ntohl(*(uint32_t *) &PB_TCP_OPT(p->buf)[l + 2]);
														p->tcp.opt.ts[1] = __iip_ntohl(*(uint32_t *) &PB_TCP_OPT(p->buf)[l + 6]);
													}
													break;
												default:
													IIP_OPS_DEBUG_PRINTF("unknown tcp option %u\n", PB_TCP_OPT(p->buf)[l]);
													break;
												}
												l += PB_TCP_OPT(p->buf)[l + 1];
												break;
											}
										}
									}
									{ /* check seq num of the packet, and push it to in-order receive queue head[0], pending receive queue head[4], or discard the packet */
#define SEQ_LE_RAW(__pb) (__iip_ntohl(PB_TCP((__pb)->buf)->seq_be) + (__pb)->tcp.inc_head) /* left edge */
#define SEQ_RE_RAW(__pb) (__iip_ntohl(PB_TCP((__pb)->buf)->seq_be) + PB_TCP_HDR_HAS_SYN((__pb)->buf) + PB_TCP_HDR_HAS_FIN((__pb)->buf) + PB_TCP_PAYLOAD_LEN((__pb)->buf) - (__pb)->tcp.dec_tail) /* right edge */
#define SEQ_LE(__pb) (SEQ_LE_RAW(__pb) - conn->seq_next_expected) /* left edge, relative */
#define SEQ_RE(__pb) (SEQ_RE_RAW(__pb) - conn->seq_next_expected) /* right edge, relative */
										struct pb *_p = p;
										uint8_t do_dup_ack = 0, do_immediate_ack = 0;
										while (1) {
											__iip_assert(_p);
											__iip_assert(_p->buf);
											__iip_assert(!_p->prev[0]);
											__iip_assert(!_p->next[0]);
											if (conn->seq_next_expected != SEQ_LE_RAW(_p)) { /* sequence number is different from expected one, but keep in head[4] */
												if ((conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * conn->mss < SEQ_LE(_p)) { /* exceeding advertised window size, so, discard _p */
													IIP_OPS_DEBUG_PRINTF("tcp-in D src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u (window %u diff %u)\n",
															(PB_IP4(_p->buf)->src_be >>  0) & 0x0ff,
															(PB_IP4(_p->buf)->src_be >>  8) & 0x0ff,
															(PB_IP4(_p->buf)->src_be >> 16) & 0x0ff,
															(PB_IP4(_p->buf)->src_be >> 24) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >>  0) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >>  8) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >> 16) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >> 24) & 0x0ff,
															__iip_ntohs(PB_TCP(_p->buf)->src_be),
															__iip_ntohs(PB_TCP(_p->buf)->dst_be),
															PB_TCP_HDR_HAS_SYN(_p->buf), PB_TCP_HDR_HAS_ACK(_p->buf), PB_TCP_HDR_HAS_FIN(_p->buf), PB_TCP_HDR_HAS_RST(_p->buf),
															__iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->ack_seq_be),
															PB_TCP_PAYLOAD_LEN(_p->buf),
															(conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * IIP_CONF_TCP_OPT_MSS,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be) - conn->seq_next_expected);
													__iip_free_pb(s, _p, opaque);
													if (p == _p) {
														/* send ack */
														do_immediate_ack = 1;
													}
													if (p != _p && conn->head[4][0]) {
														/*
														 * we continue the loop to cope with the following case
														 *
														 * head[4] has ( ) ( ) ( ) 4 5 6 7 8
														 * seq_next_expected is 1 and currently missing 1 2 3
														 *
														 * afterward, we received 1 2 3 4 5 in order
														 *
														 * in this case, seq_next_expected will be updated to 6
														 * and, 4 and 5 in head[4] has to be removed
														 *
														 * to do this remove in head[4], we continue the loop
														 */
														__iip_assert(conn->head[4][1]);
														_p = conn->head[4][0];
														__iip_assert(_p->buf);
														__iip_dequeue_obj(conn->head[4], _p, 0);
														continue;
													}
												} else if (conn->sack_ok) { /* range of seq is fine, does not exceed advertised window size */
													if (p == _p)
														do_dup_ack = 1;
													/*IIP_OPS_DEBUG_PRINTF("tcp-in O src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u\n",
															(PB_IP4(_p->buf)->src_be >>  0) & 0x0ff,
															(PB_IP4(_p->buf)->src_be >>  8) & 0x0ff,
															(PB_IP4(_p->buf)->src_be >> 16) & 0x0ff,
															(PB_IP4(_p->buf)->src_be >> 24) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >>  0) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >>  8) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >> 16) & 0x0ff,
															(PB_IP4(_p->buf)->dst_be >> 24) & 0x0ff,
															__iip_ntohs(PB_TCP(_p->buf)->src_be),
															__iip_ntohs(PB_TCP(_p->buf)->dst_be),
															PB_TCP_HDR_HAS_SYN(_p->buf), PB_TCP_HDR_HAS_ACK(_p->buf), PB_TCP_HDR_HAS_FIN(_p->buf), PB_TCP_HDR_HAS_RST(_p->buf),
															__iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->ack_seq_be),
															PB_TCP_PAYLOAD_LEN(_p->buf))*/
													/* push packet to out-of-order queue, sorted by sequence number */
													if (!conn->head[4][0]) { /* head[4] is empty, just add _p to it */
														__iip_assert(!conn->head[4][1]);
														__iip_enqueue_obj(conn->head[4], _p, 0);
													} else { /* insert _p in a sorted manner, and keep newer data if overlap exists */
														uint8_t p_discard = 0, p_replaced = 0;
														{ /* insert _p to head[4] and check overlap with the previous packet */
															struct pb *__p = conn->head[4][1];
															__iip_assert(_p);
															__iip_assert(__p);
															__iip_assert(_p->buf);
															__iip_assert(__p->buf);
															__iip_assert(conn);
															while (__p && SEQ_LE(_p) <= SEQ_LE(__p))
																__p = __p->prev[0];
															if (__p) { /* add _p next to __p */
																__iip_assert(_p->a_cnt);
																__iip_assert(__p->a_cnt);
																if (SEQ_RE(__p) <= SEQ_LE(_p)) {
																	/*
																	 * no overlap
																	 * |--- __p ---|
																	 *               |--- _p ----|
																	 * or
																	 * |--- __p ---|
																	 *             |--- _p ----|
																	 * do nothing
																	 */
																	/*IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: no overlap: __p %u %u _p %u %u\n",
																			__LINE__,
																			SEQ_LE_RAW(__p),
																			SEQ_RE_RAW(__p),
																			SEQ_LE_RAW(_p),
																			SEQ_RE_RAW(_p));*/
																} else if ((SEQ_LE(_p) == SEQ_LE(__p)) && (SEQ_RE(_p) == SEQ_RE(__p))) {
																	/*
																	 * _p has the exact same range as __p
																	 */
																	if (_p->a_cnt - __p->a_cnt < 2147483648U) {
																		/*
																		 * _p is newer than __p
																		 * replace __p with _p
																		 */
																		IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: replace __p with _p: __p %u %u _p %u %u\n",
																				__LINE__,
																				SEQ_LE_RAW(__p),
																				SEQ_RE_RAW(__p),
																				SEQ_LE_RAW(_p),
																				SEQ_RE_RAW(_p));
																		_p->prev[0] = __p->prev[0];
																		_p->next[0] = __p->next[0];
																		if (conn->head[4][0] == __p)
																			conn->head[4][0] = _p;
																		if (conn->head[4][1] == __p)
																			conn->head[4][1] = _p;
																		if (_p->prev[0])
																			_p->prev[0]->next[0] = _p;
																		if (_p->next[0])
																			_p->next[0]->prev[0] = _p;
																		__iip_free_pb(s, __p, opaque);
																		__p = NULL; /* for easier assertion */
																		p_replaced = 1;
																	} else {
																		/*
																		 * __p is newer than _p
																		 * discard _p
																		 */
																		IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard _p: __p %u %u _p %u %u\n",
																				__LINE__,
																				SEQ_LE_RAW(__p),
																				SEQ_RE_RAW(__p),
																				SEQ_LE_RAW(_p),
																				SEQ_RE_RAW(_p));
																		__iip_free_pb(s, _p, opaque);
																		_p = NULL; /* for easier assertion */
																		p_discard = 1;
																	}
																} else {
																	/*
																	 * _p and __p have overlapping part
																	 *
																	 * pattern A
																	 * |--- __p ---|
																	 * |-------- _p -------|
																	 * or
																	 * |------- __p -------|
																	 * |---- _p ---|
																	 * or
																	 * pattern B
																	 * |--- __p ---|
																	 *         |--- _p ----|
																	 * or
																	 * |--- __p -----------|
																	 *         |--- _p ----|
																	 * or
																	 * pattern C
																	 * |---------- __p --------------|
																	 *         |--- _p ----|
																	 */
																	if (SEQ_LE(_p) == SEQ_LE(__p)) {
																		/* pattern A
																		 * |--- __p ---|
																		 * |-------- _p -------|
																		 * or
																		 * |------- __p -------|
																		 * |---- _p ---|
																		 */
																		if (SEQ_RE(_p) <= SEQ_RE(__p)) {
																			/*
																			 * |------- __p -------|
																			 * |---- _p ---|
																			 */
																			if (_p->a_cnt - __p->a_cnt < 2147483648U) {
																				/*
																				 * _p is newer than __p
																				 *             |- __p --|
																				 * |---- _p ---|
																				 * shrink __p head
																				 */
																				IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment __p head BEFORE: _p %u %u __p %u %u\n",
																						__LINE__,
																						SEQ_LE_RAW(_p),
																						SEQ_RE_RAW(_p),
																						SEQ_LE_RAW(__p),
																						SEQ_RE_RAW(__p));

																				__p->tcp.inc_head += PB_TCP_HDR_HAS_SYN(_p->buf) + PB_TCP_HDR_HAS_FIN(_p->buf) + PB_TCP_PAYLOAD_LEN(_p->buf) - _p->tcp.dec_tail;
																				IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment __p head AFTER : _p %u %u __p %u %u\n",
																						__LINE__,
																						SEQ_LE_RAW(_p),
																						SEQ_RE_RAW(_p),
																						SEQ_LE_RAW(__p),
																						SEQ_RE_RAW(__p));
																				__iip_assert(SEQ_RE(_p) == SEQ_LE(__p));
																			} else {
																				/*
																				 * __p is newer than _p
																				 * discard _p
																				 */
																				IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard _p: __p %u %u _p %u %u\n",
																						__LINE__,
																						SEQ_LE_RAW(__p),
																						SEQ_RE_RAW(__p),
																						SEQ_LE_RAW(_p),
																						SEQ_RE_RAW(_p));
																				__iip_free_pb(s, _p, opaque);
																				_p = NULL; /* for easier assertion */
																				p_discard = 1;
																			}
																		}
																	} else if (SEQ_RE(_p) <= SEQ_RE(__p)) {
																		/*
																		 * pattern B
																		 * |--- __p ---|
																		 *         |--- _p ----|
																		 * or
																		 * |--- __p -----------|
																		 *         |--- _p ----|
																		 */
																		if (_p->a_cnt - __p->a_cnt < 2147483648U) {
																			/*
																			 * _p is newer than __p
																			 * |- __p -|
																			 *         |--- _p ----|
																			 * shrink __p tail
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: decrement __p tail BEFORE: __p %u %u _p %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__p),
																					SEQ_RE_RAW(__p),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p));

																			__p->tcp.dec_tail += (SEQ_RE_RAW(__p)) - SEQ_LE_RAW(_p);
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: decrement __p tail AFTER : __p %u %u _p %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__p),
																					SEQ_RE_RAW(__p),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p));
																			__iip_assert(SEQ_RE(__p) == SEQ_LE(_p));
																		} else {
																			/*
																			 * __p is newer than _p
																			 */
																			if (SEQ_RE(_p) == SEQ_RE(__p)) {
																				/*
																				 *                same edge
																				 * |--- __p -----------|
																				 *         |--- _p ----|
																				 * to
																				 * |--- __p -----------|
																				 * discard _p
																				 */
																				IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard _p: __p %u %u _p %u %u\n",
																						__LINE__,
																						SEQ_LE_RAW(__p),
																						SEQ_RE_RAW(__p),
																						SEQ_LE_RAW(_p),
																						SEQ_RE_RAW(_p));
																				__iip_free_pb(s, _p, opaque);
																				_p = NULL; /* for easier assertion */
																				p_discard = 1;
																			} else {
																				/*
																				 * |--- __p ---|
																				 *         |--- _p ----|
																				 * to
																				 * |--- __p ---|
																				 *             |- _p --|
																				 * shrink _p head
																				 */
																				IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment _p head BEFORE: __p %u %u _p %u %u\n",
																						__LINE__,
																						SEQ_LE_RAW(__p),
																						SEQ_RE_RAW(__p),
																						SEQ_LE_RAW(_p),
																						SEQ_RE_RAW(_p));
																				_p->tcp.inc_head += (SEQ_RE_RAW(__p)) - SEQ_LE_RAW(_p);
																				IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment _p head AFTER : __p %u %u _p %u %u\n",
																						__LINE__,
																						SEQ_LE_RAW(__p),
																						SEQ_RE_RAW(__p),
																						SEQ_LE_RAW(_p),
																						SEQ_RE_RAW(_p));
																			__iip_assert(SEQ_RE(__p) == SEQ_LE(_p));
																			}
																		}
																	} else {
																		/*
																		 * pattern C
																		 * |---------- __p --------------|
																		 *         |--- _p ----|
																		 */
																		if (_p->a_cnt - __p->a_cnt < 2147483648U) {
																			/*
																			 * _p is newer than __p
																			 * |--__p1--|           |-__p2--|
																			 *          |--- _p ----|
																			 * divide __p into two
																			 * and put _p in between the two
																			 */
																			struct pb *__p2 = __iip_clone_pb(s, __p, opaque);
																			__iip_assert(__p2);
																			__p2->tcp.inc_head += (SEQ_RE_RAW(_p)) - SEQ_LE_RAW(__p);
																			__p->tcp.dec_tail += (SEQ_RE_RAW(__p)) - SEQ_LE_RAW(_p);
																			__p2->prev[0] = __p;
																			__p2->next[0] = __p->next[0];
																			__p->next[0] = __p2;
																			if (__p2->next[0])
																				__p2->next[0]->prev[0] = __p2;
																			else
																				conn->head[4][1] = __p2;
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: split __p and put _p in between: __p1 %u %u _p %u %u __p2 %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__p),
																					SEQ_RE_RAW(__p),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__p2),
																					__iip_ntohl(PB_TCP(__p2->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(__p2->buf) + PB_TCP_HDR_HAS_FIN(__p2->buf) + PB_TCP_PAYLOAD_LEN(__p2->buf) - __p2->tcp.dec_tail);
																			__iip_assert(SEQ_RE(__p) == SEQ_LE(_p));
																			__iip_assert(SEQ_RE(_p) == SEQ_LE(__p2));
																		} else {
																			/*
																			 * __p is newer than _p
																			 *
																			 * discard _p
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard _p: __p %u %u _p %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__p),
																					SEQ_RE_RAW(__p),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p));
																			__iip_free_pb(s, _p, opaque);
																			_p = NULL; /* for easier assertion */
																			p_discard = 1;
																		}
																	}
																}
																if (!p_discard && !p_replaced) { /* do insert to head[4] */
																	_p->prev[0] = __p;
																	_p->next[0] = __p->next[0];
																	__p->next[0] = _p;
																	if (_p->next[0])
																		_p->next[0]->prev[0] = _p;
																	else
																		conn->head[4][1] = _p;
																}
															} else { /* this is the head of head[4] */
																_p->next[0] = conn->head[4][0];
																__iip_assert(!conn->head[4][0]->prev[0]);
																conn->head[4][0]->prev[0] = _p;
																conn->head[4][0] = _p;
															}
														}
														/* now _p is in head[4] or discarded */
														if (!p_discard && !p_replaced && _p->next[0]) { /* overlap check with the next packets */
															struct pb *__next = _p->next[0];
															while (__next) {
																/*
																 * this should never happen
																 * |--- __next ---...
																 *    |--- _p ----...
																 */
																__iip_assert(SEQ_LE(_p) <= SEQ_LE(__next));
																if (SEQ_RE(_p) <= SEQ_LE(__next)) {
																	/*
																	 * no overlap
																	 *               |--- __next ---|
																	 * |--- _p ------|
																	 * or
																	 *               |--- __next ---|
																	 * |--- _p ----|
																	 * nothing to do for this case
																	 */
																	/*IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: no overlap: _p %u %u __next %u %u\n",
																			__LINE__,
																			SEQ_LE_RAW(_p),
																			SEQ_RE_RAW(_p),
																			SEQ_LE_RAW(__next),
																			SEQ_RE_RAW(__next));*/
																	break;
																} else if (SEQ_LE(_p) == SEQ_LE(__next))  {
																	/*
																	 * |--- __next ---...
																	 * |--- _p ----...
																	 */
																	if (_p->a_cnt - __next->a_cnt < 2147483648U) {
																		/*
																		 * _p is newer than __next
																		 */
																		if (SEQ_RE(_p) == SEQ_RE(__next)) {
																			/*
																			 * |- __next -|
																			 * |--- _p ---|
																			 * replace __next with _p
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: replace __next with _p: __next %u %u _p %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p));
																			__iip_dequeue_obj(conn->head[4], _p, 0); /* dequeue _p first */
																			_p->prev[0] = __next->prev[0];
																			_p->next[0] = __next->next[0];
																			if (conn->head[4][0] == __next)
																				conn->head[4][0] = _p;
																			if (conn->head[4][1] == __next)
																				conn->head[4][1] = _p;
																			if (_p->prev[0])
																				_p->prev[0]->next[0] = _p;
																			if (_p->next[0])
																				_p->next[0]->prev[0] = _p;
																			__iip_free_pb(s, __next, opaque);
																			__next = NULL; /* for easier assertion */
																			__iip_assert(conn->head[4][0] && conn->head[4][1]);
																			__iip_assert(conn->head[4][0]->buf);
																			break;
																		} else if (SEQ_RE(_p) < SEQ_RE(__next)) {
																			/*
																			 * |------ __next ------|
																			 * |--- _p ---|
																			 * to
																			 *            |-__next--|
																			 * |--- _p ---|
																			 * shrink __next head
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment __next head BEFORE: _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			__next->tcp.inc_head += (SEQ_RE_RAW(_p)) - SEQ_LE_RAW(__next);
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment __next head AFTER : _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			__iip_assert(SEQ_RE(_p) == SEQ_LE(__next));
																			break;
																		} else {
																			/*
																			 * |-- __next ----|
																			 * |-------- _p -------|
																			 * discard __next,
																			 * and continue to check __next->next
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard __next: _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			{
																				struct pb *__next_tmp = __next;
																				__next = __next->next[0];
																				__iip_dequeue_obj(conn->head[4], __next_tmp, 0);
																				__iip_free_pb(s, __next_tmp, opaque);
																				__next_tmp = NULL; /* for easier assertion */
																			}
																		}
																	} else {
																		/*
																		 * __next is newer than __p
																		 */
																		if (SEQ_RE(_p) <= SEQ_RE(__next)) {
																			/*
																			 * |- __next -|
																			 * |--- _p ---|
																			 * or
																			 * |------ __next ------|
																			 * |--- _p ---|
																			 * discard _p
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard _p: _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			__iip_dequeue_obj(conn->head[4], _p, 0);
																			__iip_free_pb(s, _p, opaque);
																			_p = NULL; /* for easier assertion */
																			break;
																		} else {
																			/*
																			 * |-- __next ----|
																			 * |-------- _p --------|
																			 * to
																			 * |-- __next ----|
																			 *                |-_p -|
																			 * shrink _p head,
																			 * swap position of __next and _p
																			 * and continue to check __next->next
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment _p head BEFORE: __next %u %u _p %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p));
																			_p->tcp.inc_head += PB_TCP_HDR_HAS_SYN(__next->buf) + PB_TCP_HDR_HAS_FIN(__next->buf) + PB_TCP_PAYLOAD_LEN(__next->buf) - __next->tcp.dec_tail;
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: incrment _p head AFTER : __next %u %u _p %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next),
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p));
																			__iip_assert(SEQ_RE(__next) == SEQ_LE(_p));
																			/* swap _p and __next */
																			__iip_dequeue_obj(conn->head[4], _p, 0); /* dequeue _p first */
																			/* add _p next to __next */
																			_p->prev[0] = __next;
																			_p->next[0] = __next->next[0];
																			__next->next[0] = _p;
																			if (_p->next[0])
																				_p->next[0]->prev[0] = _p;
																			/* swap complete */
																			__next = _p->next[0]; /* continue the loop */
																		}
																	}
																} else {
																	/*
																	 *           |--- __next ---|
																	 * |----- _p ----|
																	 * or
																	 *           |--- __next ---|--- __next->next --|
																	 * |----------- _p ---------|
																	 * or
																	 *           |--- __next ---|--- __next->next --|
																	 * |----------- _p ----------------|
																	 */
																	if (_p->a_cnt - __next->a_cnt < 2147483648U) {
																		/*
																		 * _p is newer than __next
																		 */
																		if (SEQ_RE(__next) <= SEQ_RE(_p)) {
																			/*
																			 *           |--- __next ---|--- __next->next --|
																			 * |----------- _p ---------|
																			 * or
																			 *           |--- __next ---|--- __next->next --|
																			 * |----------- _p ----------------|
																			 * discard __next
																			 * and continue the loop to check __next->next
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: discard __next: _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			{
																				struct pb *__next_tmp = __next;
																				__next = __next->next[0];
																				__iip_dequeue_obj(conn->head[4], __next_tmp, 0);
																				__iip_free_pb(s, __next_tmp, opaque);
																				__next_tmp = NULL; /* for easier assertion */
																			}
																		} else {
																			/*
																			 *           |--- __next ---|
																			 * |----- _p ----|
																			 * to
																			 *               |- __next -|
																			 * |----- _p ----|
																			 * shrink __next head
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment __next head BEFORE: _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			__next->tcp.inc_head += (SEQ_RE_RAW(_p)) - SEQ_LE_RAW(__next);
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: increment __next head AFTER : _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			__iip_assert(SEQ_RE(_p) == SEQ_LE(__next));
																			break;
																		}
																	} else {
																		/*
																		 * __next is newer than _p
																		 */
																		if (SEQ_RE(__next) < SEQ_RE(_p)) {
																			/*
																			 *           |--- __next ---|--- __next->next --|
																			 * |----------- _p ----------------|
																			 * to
																			 *           |--- __next ---|--- __next->next --|
																			 * |-- _p1 --|              |-_p2--|
																			 * divide _p into _p1 and _p2 and
																			 * continue check for _p2 as _p
																			 */
																			struct pb *_p2 = __iip_clone_pb(s, _p, opaque);
																			__iip_assert(_p2);
																			_p2->tcp.inc_head += (SEQ_RE_RAW(__next)) - SEQ_LE_RAW(_p);
																			_p->tcp.dec_tail += (SEQ_RE_RAW(_p)) - SEQ_LE_RAW(__next);
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: split _p and put __next in between: _p1 %u %u __next %u %u _p2 %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next),
																					SEQ_LE_RAW(_p2),
																					SEQ_RE_RAW(_p2));
																			__iip_assert(SEQ_RE(_p) == SEQ_LE(__next));
																			__iip_assert(SEQ_RE(__next) == SEQ_LE(_p2));
																			_p = _p2;
																		} else {
																			/*
																			 *           |--- __next ---|--- __next->next --|
																			 * |----------- _p ---------|
																			 * or
																			 *           |--- __next ---|
																			 * |----- _p ----|
																			 * to
																			 *           |--- __next ---|
																			 * |-- _p ---|
																			 * shrink _p tail
																			 */
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: decrement _p tail BEFORE: _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			_p->tcp.dec_tail += (SEQ_RE_RAW(_p)) - SEQ_LE_RAW(__next);
																			IIP_OPS_DEBUG_PRINTF("%4u pending tcp rx queue insert: decrement _p tail AFTER : _p %u %u __next %u %u\n",
																					__LINE__,
																					SEQ_LE_RAW(_p),
																					SEQ_RE_RAW(_p),
																					SEQ_LE_RAW(__next),
																					SEQ_RE_RAW(__next));
																			__iip_assert(SEQ_RE(_p) == SEQ_LE(__next));
																			break;
																		}
																	}
																}
															}
														}
													}
													/* IIP_OPS_DEBUG_PRINTF("out-of-order: %u %u\n", __iip_ntohl(PB_TCP(_p->buf)->seq_be), conn->seq_next_expected); */
												} else {
													__iip_assert(p == _p);
													__iip_free_pb(s, _p, opaque);
													_p = NULL; /* for easier assertion */
													do_dup_ack = 1;
												}
												/*
												 * _p is not pushed to head[0], therefore,
												 * there will be no need to move packets in head[4] to head[0],
												 * so stop this loop
												 */
												break;
											} else { /* seq is expected one */
												if (/* PAWS */ ((p->flags & __IIP_PB_FLAGS_OPT_HAS_TS) && !PB_TCP_HDR_HAS_SYN(p->buf) && !PB_TCP_HDR_HAS_RST(p->buf)) && (2147483648U <= (p->tcp.opt.ts[0] < conn->ts ? conn->ts - p->tcp.opt.ts[0] : p->tcp.opt.ts[0] - conn->ts))) {
													__iip_free_pb(s, _p, opaque);
													_p = NULL; /* for easier assertion */
												} else { /* seq is fine, push _p to sorted receive queue head[0] */
													__iip_enqueue_obj(conn->head[0], _p, 0);
													s->monitor.tcp.rx_pkt++;
													conn->seq_next_expected += PB_TCP_HDR_HAS_SYN(_p->buf) + PB_TCP_HDR_HAS_FIN(_p->buf) + PB_TCP_PAYLOAD_LEN(_p->buf) - _p->tcp.dec_tail;
													if (conn->head[4][0]) {
														__iip_assert(conn->head[4][1]);
														/*
														 * here, _p is pushed to head[0], and
														 * there would be the possibility that
														 * the missing segment was filled by _p and
														 * head[4][0] may also can be pushed to head[0],
														 * so, we continue the check in the same loop
														 */
														_p = conn->head[4][0];
														__iip_assert(_p->buf);
														/*IIP_OPS_DEBUG_PRINTF("recheck expected %u", conn->seq_next_expected);*/
														__iip_dequeue_obj(conn->head[4], _p, 0);
														continue;
													}
												}
												break;
											}
										}
										if ((do_dup_ack || do_immediate_ack) && (now_ms - conn->dupack_ts_ms > 1U /* dup ack throttling : 1 ms */)) {
											uint8_t sackbuf[(15 * 4) - sizeof(struct iip_tcp_hdr) - 19] = { 5, 2, };
											if (do_dup_ack && conn->sack_ok) {
												struct pb *__p = conn->head[4][1];
												__iip_assert(__p);
												while (sackbuf[1] < (sizeof(sackbuf) - 2 - 8) && __p) {
													if (sackbuf[1] == 2) {
														*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)]) = __iip_htonl(SEQ_RE_RAW(__p));
													} else if (*((uint32_t *) &sackbuf[sackbuf[1]]) != __iip_htonl(SEQ_RE_RAW(__p))) { /* add new entry */
														if (__iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1]])) - conn->seq_next_expected != __iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)])) - conn->seq_next_expected) {
															/* we only add entry when the entry has the length */
															sackbuf[1] += 8;
															*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)]) = __iip_htonl(SEQ_RE_RAW(__p));
														}
													}
													*((uint32_t *) &sackbuf[sackbuf[1]]) = __iip_htonl(SEQ_LE_RAW(__p));
													__iip_assert(__iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1]])) - conn->seq_next_expected <= /* accept no payload length packet */ __iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)])) - conn->seq_next_expected);
													__p = __p->prev[0];
												}
												if (__iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1]])) - conn->seq_next_expected != __iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)])) - conn->seq_next_expected) {
													/* we only add entry when the entry has the length */
													sackbuf[1] += 8;
												}
												{ /* debug */
													uint8_t __i;
													for (__i = 2; __i < sackbuf[1]; __i += 8) {
														IIP_OPS_DEBUG_PRINTF("SACK %2u-%2u/%2u: sle %u sre %u (len %u) expected seq %u\n",
																__i, __i + 8, sackbuf[1],
																__iip_ntohl(*((uint32_t *) &sackbuf[__i +                0])),
																__iip_ntohl(*((uint32_t *) &sackbuf[__i + sizeof(uint32_t)])),
																__iip_ntohl(*((uint32_t *) &sackbuf[__i + sizeof(uint32_t)])) - __iip_ntohl(*((uint32_t *) &sackbuf[__i + 0])),
																conn->seq_next_expected);
													}
												}
											}
											{ /* send dup ack */
												__iip_tcp_push(s, conn, NULL, 0, 1, 0, 0, (sackbuf[1] == 2 ? NULL : sackbuf), opaque);
												{ /* workaround to bypass the ordered queue */
													struct pb *dup_ack_p = conn->head[1][1];
													__iip_dequeue_obj(conn->head[1], dup_ack_p, 0);
													__iip_enqueue_obj(conn->head[5], dup_ack_p, 0);
												}
											}
											if (do_dup_ack) {
												conn->dup_ack_sent++;
												if (conn->dup_ack_sent == 3)
													conn->dup_ack_sent = 0;
											}
											conn->dupack_ts_ms = now_ms;
										}
#undef SEQ_LE
#undef SEQ_RE
									}
								} else {
									IIP_OPS_DEBUG_PRINTF("NO CONNECTION FOUND: src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u\n",
											(PB_IP4(p->buf)->src_be >>  0) & 0x0ff,
											(PB_IP4(p->buf)->src_be >>  8) & 0x0ff,
											(PB_IP4(p->buf)->src_be >> 16) & 0x0ff,
											(PB_IP4(p->buf)->src_be >> 24) & 0x0ff,
											(PB_IP4(p->buf)->dst_be >>  0) & 0x0ff,
											(PB_IP4(p->buf)->dst_be >>  8) & 0x0ff,
											(PB_IP4(p->buf)->dst_be >> 16) & 0x0ff,
											(PB_IP4(p->buf)->dst_be >> 24) & 0x0ff,
											__iip_ntohs(PB_TCP(p->buf)->src_be),
											__iip_ntohs(PB_TCP(p->buf)->dst_be),
											PB_TCP_HDR_HAS_SYN(p->buf), PB_TCP_HDR_HAS_ACK(p->buf), PB_TCP_HDR_HAS_FIN(p->buf), PB_TCP_HDR_HAS_RST(p->buf),
											__iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->ack_seq_be),
											PB_TCP_PAYLOAD_LEN(p->buf));
									/* we send rst as a reply */
									{
										struct iip_tcp_conn _conn;
										__iip_tcp_conn_init(s, &_conn,
												iip_ops_l2_hdr_dst_ptr(p->pkt, opaque), PB_IP4(p->buf)->dst_be, PB_TCP(p->buf)->dst_be,
												iip_ops_l2_hdr_src_ptr(p->pkt, opaque), PB_IP4(p->buf)->src_be, PB_TCP(p->buf)->src_be,
												__IIP_TCP_STATE_SYN_RECVD, opaque);
										_conn.ack_seq_be = __iip_ntohl(PB_TCP(p->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(p->buf) + PB_TCP_HDR_HAS_FIN(p->buf) + PB_TCP_PAYLOAD_LEN(p->buf);
										__iip_tcp_push(s, &_conn, NULL, 0, 0, 0, 1, NULL, opaque);
										{
											struct pb *out_p = _conn.head[1][1];
											__iip_dequeue_obj(_conn.head[1], out_p, 0);
											{
												void *clone_pkt = iip_ops_pkt_clone(out_p->pkt, opaque);
												__iip_assert(clone_pkt);
												iip_ops_l2_push(clone_pkt, opaque);
											}
											__iip_free_pb(s, out_p, opaque);
										}
										__iip_dequeue_obj(s->tcp.conns_ht[(_conn.peer_ip4_be + _conn.local_port_be + _conn.peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], &_conn, 1);
										__iip_dequeue_obj(s->tcp.conns, &_conn, 0);
									}
								}
							}
							break;
						case 17: /* udp */
							if (iip_ops_nic_feature_offload_udp_rx_checksum(opaque)) {
								if (!iip_ops_nic_offload_udp_rx_checksum(p->pkt, opaque)) {
									IIP_OPS_DEBUG_PRINTF("pkt %p: invalid udp checksum hdr computed by NIC\n", p->pkt);
									break;
								}
							} else {
								struct iip_l4_ip4_pseudo_hdr _pseudo;
								_pseudo.ip4_src_be = PB_IP4(p->buf)->src_be;
								_pseudo.ip4_dst_be = PB_IP4(p->buf)->dst_be;
								_pseudo.pad = 0;
								_pseudo.proto = 17;
								_pseudo.len_be = PB_UDP(p->buf)->len_be;
								{
									uint8_t *_b[2]; _b[0] = (uint8_t *) &_pseudo; _b[1] = (uint8_t *) PB_UDP(p->buf);
									{
										uint16_t _l[2]; _l[0] = sizeof(_pseudo); _l[1] = (uint16_t) __iip_ntohs(PB_UDP(p->buf)->len_be);
										{
											uint16_t p_csum = __iip_ntohs(PB_UDP(p->buf)->csum_be), c_csum = __iip_netcsum16(_b, _l, 2, __iip_ntohs(PB_UDP(p->buf)->csum_be));
											if ((p_csum == 0xffff ? 0 : p_csum) != (c_csum == 0xffff ? 0 : c_csum)) { /* 0xffff is 0 */
												IIP_OPS_DEBUG_PRINTF("invalid udp checksum hdr: %u %u : payload len %u\n", p_csum, c_csum, __iip_ntohs(PB_UDP(p->buf)->len_be));
												break;
											}
										}
									}
								}
							}
							iip_ops_udp_payload(s, p->pkt, opaque);
							break;
						default:
							IIP_OPS_DEBUG_PRINTF("unsupported l4 protocol %u\n", PB_IP4(p->buf)->proto);
							break;
						}
						if (!pkt_used)
							__iip_free_pb(s, p, opaque);
					}
				}
			}

			{ /* iterate all tcp connections */
				struct iip_tcp_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					do {
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->head[0], p, _n, 0) {
							__iip_dequeue_obj(conn->head[0], p, 0);
							{ /* validate ack number */
								uint8_t out_of_order = 0;
								if (!PB_TCP_HDR_HAS_SYN(p->buf) && !PB_TCP_HDR_HAS_FIN(p->buf) && !PB_TCP_HDR_HAS_RST(p->buf)) {
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
									if (__iip_ntohl(conn->seq_be) - conn->acked_seq <= __iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(p->buf)->ack_seq_be)) { /* pattern A or B */
										/*
										 *        conn->acked_seq              conn->seq_be
										 *                  |                        |
										 *  ----- acked ----|------- unacked --------|
										 *              |   |
										 *              |   |
										 *              A   B
										 */
										/* 2. no payload */
										if (!PB_TCP_PAYLOAD_LEN(p->buf)) {
											/* 3. window size isn't updated */
											if (conn->peer_win == __iip_ntohs(PB_TCP(p->buf)->win_be)) {
												/* 4. some data is not acked yet */
												if (__iip_ntohl(conn->seq_be) != conn->acked_seq) {
													/*
													 *        conn->acked_seq              conn->seq_be
													 *                  |                        |
													 *  ----- acked ----|------- unacked --------|
													 */
													/* 5. packet ack number is the biggest ack number seen ever */
													if (__iip_ntohl(PB_TCP(p->buf)->ack_seq_be) == conn->acked_seq) { /* pattern B */
														/*
														 *        conn->acked_seq              conn->seq_be
														 *                  |                        |
														 *  ----- acked ----|------- unacked --------|
														 *                  |
														 *                  |
														 *                  B
														 */
														/* this is dup ack */
														s->monitor.tcp.rx_pkt_dupack++;
														if (conn->dup_ack_received <= 3) {
															conn->dup_ack_received++;
															IIP_OPS_DEBUG_PRINTF("%p Received Dup ACK (cnt %u) %u (has sack %u) (win %u sent %u)\n",
																	(void *) conn, conn->dup_ack_received, conn->acked_seq, p->tcp.opt.sack_opt_off,
																	((uint32_t) conn->peer_win << conn->ws),
																	__iip_ntohl(conn->seq_be) + PB_TCP_PAYLOAD_LEN(p->buf) - conn->acked_seq /* len to be filled on the rx side */);
														}
													} else { /* pattern A */
														/*
														 *        conn->acked_seq              conn->seq_be
														 *                  |                        |
														 *  ----- acked ----|------- unacked --------|
														 *              |
														 *              |
														 *              A
														 */
														IIP_OPS_DEBUG_PRINTF("%p Weird, ack to already acked packet (acked %u pkt-ack %u)\n",
																(void *) conn, conn->acked_seq, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
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
													if (__iip_ntohl(PB_TCP(p->buf)->ack_seq_be) == conn->acked_seq) { /* pattern B */
														/*
														 *        conn->acked_seq
														 *            conn->seq_be
														 *                  |
														 *  ----- acked ----|
														 *                  |
														 *                  |
														 *                  B
														 */
														s->monitor.tcp.rx_pkt_keepalive++;
														IIP_OPS_DEBUG_PRINTF("%p Received Keep-alive %u\n", (void *) conn, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
														/* we will send a keep-alive ack */
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
														IIP_OPS_DEBUG_PRINTF("%p Weird, ack to already acked packet (acked %u pkt-ack %u)\n",
																(void *) conn, conn->acked_seq, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
														out_of_order = 1;
													}
												}
											} else {
												s->monitor.tcp.rx_pkt_winupdate++;
												IIP_OPS_DEBUG_PRINTF("%p Received Window Update\n", (void *) conn);
											}
										} else { /* packet has the payload */
											if (__iip_ntohl(PB_TCP(p->buf)->ack_seq_be) == conn->acked_seq) { /* pattern B */
												/* this is valid */
											} else {
												IIP_OPS_DEBUG_PRINTF("%p Weird, ack to already acked packet (acked %u pkt-ack %u)\n",
														(void *) conn, conn->acked_seq, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
												out_of_order = 1;
											}
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
									}
								}
								if (!out_of_order) {
									if (conn->flags & __IIP_TCP_CONN_FLAGS_PEER_RX_FAILED) {
										if (__iip_ntohl(PB_TCP(p->buf)->ack_seq_be) - conn->sent_seq_when_loss_detected < 2147483648U) {
											conn->flags &= ~__IIP_TCP_CONN_FLAGS_PEER_RX_FAILED;
											IIP_OPS_DEBUG_PRINTF("%p Peer succeed to recover: ACKed by peer %u\n", (void *) conn, conn->acked_seq);
										}
									}
									conn->dup_ack_received = 0;
									if (conn->dup_ack_sent) {
										IIP_OPS_DEBUG_PRINTF("%p Missed packet is recovered by Dup ACK request: %u\n", (void *) conn, __iip_ntohl(conn->ack_seq_be));
										conn->dup_ack_sent = 0;
									}
									conn->peer_win = __iip_ntohs(PB_TCP(p->buf)->win_be);
									if (p->flags & __IIP_PB_FLAGS_OPT_HAS_TS) {
										conn->ts = p->tcp.opt.ts[0];
										if (!(conn->flags & __IIP_TCP_CONN_FLAGS_PEER_RX_FAILED) && PB_TCP_HDR_HAS_ACK(p->buf)) {
											uint32_t nticks = s->tcp.pkt_ts - p->tcp.opt.ts[1];
											if (conn->state == __IIP_TCP_STATE_SYN_SENT || conn->state == __IIP_TCP_STATE_SYN_RECVD) {
												conn->rtt.srtt = nticks;
												conn->rtt.rttvar = nticks / 2;
											} else {
												uint32_t delta = (nticks < conn->rtt.srtt ? conn->rtt.srtt - nticks : nticks - conn->rtt.srtt);
												if (nticks < conn->rtt.srtt)
													conn->rtt.srtt -= delta / 8;
												else
													conn->rtt.srtt += delta / 8;
												{
													uint32_t d2 = (delta < conn->rtt.rttvar ? conn->rtt.rttvar - delta : delta - conn->rtt.rttvar);
													if (delta < conn->rtt.rttvar)
														conn->rtt.rttvar -= d2 / 4;
													else
														conn->rtt.rttvar += d2 / 4;
												}
											}
										}
									}
									if (PB_TCP_HDR_HAS_ACK(p->buf))
										conn->retrans_cnt = 0;
									conn->ack_seq_be = __iip_htonl(__iip_ntohl(PB_TCP(p->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(p->buf) + PB_TCP_HDR_HAS_FIN(p->buf) + PB_TCP_PAYLOAD_LEN(p->buf));
									conn->acked_seq = __iip_ntohl(PB_TCP(p->buf)->ack_seq_be);
									/*IIP_OPS_DEBUG_PRINTF("tcp-in I src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u\n",
									  (PB_IP4(p->buf)->src_be >>  0) & 0x0ff,
									  (PB_IP4(p->buf)->src_be >>  8) & 0x0ff,
									  (PB_IP4(p->buf)->src_be >> 16) & 0x0ff,
									  (PB_IP4(p->buf)->src_be >> 24) & 0x0ff,
									  (PB_IP4(p->buf)->dst_be >>  0) & 0x0ff,
									  (PB_IP4(p->buf)->dst_be >>  8) & 0x0ff,
									  (PB_IP4(p->buf)->dst_be >> 16) & 0x0ff,
									  (PB_IP4(p->buf)->dst_be >> 24) & 0x0ff,
									  __iip_ntohs(PB_TCP(p->buf)->src_be),
									  __iip_ntohs(PB_TCP(p->buf)->dst_be),
									  PB_TCP_HDR_HAS_SYN(p->buf), PB_TCP_HDR_HAS_ACK(p->buf), PB_TCP_HDR_HAS_FIN(p->buf), PB_TCP_HDR_HAS_RST(p->buf),
									  __iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->ack_seq_be),
									  PB_TCP_PAYLOAD_LEN(p->buf));*/
									if (PB_TCP_HDR_HAS_RST(p->buf)) {
										if (conn->state != __IIP_TCP_STATE_CLOSED) {
											conn->state = __IIP_TCP_STATE_CLOSED;
											__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
											__iip_dequeue_obj(s->tcp.conns, conn, 0);
											__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
											IIP_OPS_DEBUG_PRINTF("%p: RST - TCP_STATE_CLOSED\n", (void *) conn);
										}
									} else {
										uint8_t is_connected = 0, is_accepted = 0;
										uint8_t syn = 0, ack = 0, fin = 0, rst = 0;
										switch (conn->state) {
											/* client */
											case __IIP_TCP_STATE_FIN_WAIT1:
												if (PB_TCP_HDR_HAS_ACK(p->buf)) {
													if (PB_TCP(p->buf)->ack_seq_be == conn->fin_ack_seq_be) {
														if (PB_TCP_HDR_HAS_FIN(p->buf)) {
															ack = 1;
															conn->state = __IIP_TCP_STATE_TIME_WAIT;
															conn->time_wait_ts_ms = now_ms;
															IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_FIN_WAIT1 - TCP_STATE_TIME_WAIT\n", (void *) conn);
														} else {
															conn->state = __IIP_TCP_STATE_FIN_WAIT2;
															IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_FIN_WAIT1 - TCP_STATE_FIN_WAIT2\n", (void *) conn);
														}
													} else if (PB_TCP_HDR_HAS_FIN(p->buf)) {
														/*
														 * this is the case where the peer also sent fin mostly at the same time,
														 * and especially here is for close initiators sending fin-ack
														 * rather than than only fin
														 */
														ack = 1;
														rst = 1;
														conn->state = __IIP_TCP_STATE_TIME_WAIT;
														conn->time_wait_ts_ms = now_ms;
														IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_FIN_WAIT1 - TCP_STATE_TIME_WAIT\n", (void *) conn);
													}
												} else {
													if (PB_TCP_HDR_HAS_FIN(p->buf)) {
														ack = 1;
														conn->state = __IIP_TCP_STATE_CLOSING;
														IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_FIN_WAIT1 - TCP_STATE_CLOSING\n", (void *) conn);
													}
												}
												break;
											case __IIP_TCP_STATE_FIN_WAIT2:
												if (PB_TCP_HDR_HAS_FIN(p->buf)) {
													ack = 1;
													conn->state = __IIP_TCP_STATE_TIME_WAIT;
													conn->time_wait_ts_ms = now_ms;
													IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_FIN_WAIT2 - TCP_STATE_TIME_WAIT\n", (void *) conn);
												}
												break;
											case __IIP_TCP_STATE_CLOSING:
												if (PB_TCP_HDR_HAS_ACK(p->buf)) {
													conn->state = __IIP_TCP_STATE_TIME_WAIT;
													conn->time_wait_ts_ms = now_ms;
													IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_CLOSING - TCP_STATE_TIME_WAIT\n", (void *) conn);
												}
												break;
											case __IIP_TCP_STATE_TIME_WAIT:
												/* wait 2 MSL timeout */
												break;
											case __IIP_TCP_STATE_SYN_SENT:
												if (PB_TCP_HDR_HAS_SYN(p->buf) && PB_TCP_HDR_HAS_ACK(p->buf)) {
													ack = 1;
													conn->state = __IIP_TCP_STATE_ESTABLISHED;
													is_connected = 1;
													IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_SYN_SENT - TCP_STATE_ESTABLISHED\n", (void *) conn);
												}
												break;
												/* server */
											case __IIP_TCP_STATE_SYN_RECVD:
												syn = (PB_TCP_HDR_HAS_ACK(p->buf) ? 0 : 1);
												ack = 1;
												conn->state = __IIP_TCP_STATE_ESTABLISHED;
												is_accepted = 1;
												IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_SYN_RECVD - TCP_STATE_ESTABLISHED\n", (void *) conn);
												/* fall through */
											case __IIP_TCP_STATE_ESTABLISHED:
												if (PB_TCP_HDR_HAS_FIN(p->buf)) {
													ack = 1;
													conn->state = __IIP_TCP_STATE_CLOSE_WAIT;
													IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_ESTABLISHED - TCP_STATE_CLOSE_WAIT\n", (void *) conn);
												} else if (PB_TCP_HDR_HAS_ACK(p->buf) && PB_TCP_PAYLOAD_LEN(p->buf)) {
													conn->rx_buf_cnt.used++;
													iip_ops_tcp_payload(s, conn, p->pkt, conn->opaque, p->tcp.inc_head, p->tcp.dec_tail, opaque);
												}
												/* fall through */
											case __IIP_TCP_STATE_CLOSE_WAIT:
												if (PB_TCP_HDR_HAS_FIN(p->buf)) {
													fin = 1;
													conn->state = __IIP_TCP_STATE_LAST_ACK;
													IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_CLOSE_WAIT - TCP_STATE_LAST_ACK\n", (void *) conn);
												}
												break;
											case __IIP_TCP_STATE_LAST_ACK:
												if (PB_TCP_HDR_HAS_ACK(p->buf) && PB_TCP(p->buf)->ack_seq_be == conn->fin_ack_seq_be) {
													conn->state = __IIP_TCP_STATE_CLOSED;
													__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
													__iip_dequeue_obj(s->tcp.conns, conn, 0);
													__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
													IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_LAST_ACK - TCP_STATE_CLOSED\n", (void *) conn);
												}
												break;
											case __IIP_TCP_STATE_CLOSED:
												IIP_OPS_DEBUG_PRINTF("%p: got packet although the connection is closed\n", (void *) conn);
												/* do nothing */
												break;
											default:
												__iip_assert(0);
												break;
										}
										if (syn || ack || fin || rst) {
											__iip_tcp_push(s, conn, NULL, syn, ack, fin, rst, NULL, opaque);
											if (fin)
												conn->fin_ack_seq_be = conn->seq_be;
										}
										/* execute callback after establishing the connection */
										if (is_connected) {
											IIP_OPS_DEBUG_PRINTF("connected peer port %u\n", __iip_ntohs(PB_TCP(p->buf)->src_be));
											conn->opaque = iip_ops_tcp_connected(s, conn, p->pkt, opaque);
										}
										if (is_accepted) {
											IIP_OPS_DEBUG_PRINTF("accept peer port %u\n", __iip_ntohs(PB_TCP(p->buf)->src_be));
											conn->opaque = iip_ops_tcp_accepted(s, conn, p->pkt, opaque);
										}
									}
								}
							}
							if (p->tcp.opt.sack_opt_off)
								__iip_enqueue_obj(conn->tcp_sack_rx, p, 0);
							else
								__iip_free_pb(s, p, opaque);
							if ((4294967295U / 2) < (__iip_ntohl(conn->seq_be) - conn->acked_seq))
								break; /* release acked packets before overflowing, we will come back if head[0] still has a packet */
						}
						{ /* release acked packets */
							struct pb *p, *_n;
							__iip_q_for_each_safe(conn->head[2], p, _n, 0) {
								/*
								 *        conn->acked_seq             conn->seq_be
								 *                  |                        |
								 *  ----- acked ----|------- unacked --------|
								 *              |   |   |
								 *              |   |   |
								 *              A   B   C
								 */
								if ((__iip_ntohl(conn->seq_be) - conn->acked_seq) <= (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(p->buf)->seq_be) + ((PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf)) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf))))) { /* A or B */
									if (PB_TCP_PAYLOAD_LEN(p->buf)) {
										if (!(p->flags & __IIP_PB_FLAGS_SACKED)) { /* increase window size for congestion control */
											if (conn->cc.ssthresh < conn->cc.win) {
												conn->cc.win = (conn->cc.win < 65535U ? conn->cc.win + 1 : conn->cc.win);
												/*IIP_OPS_DEBUG_PRINTF("slow increase win %u ssthresh %u\n", conn->cc.win, conn->cc.ssthresh);*/
											} else {
												conn->cc.win = (conn->cc.win < 65535U / 2 ? conn->cc.win * 2 : 65535U);
												/*IIP_OPS_DEBUG_PRINTF("fast increase win %u ssthresh %u"\n, conn->cc.win, conn->cc.ssthresh);*/
											}
										}
										if (p->ack_cb_pkt)
											iip_ops_tcp_acked(s, conn, p->ack_cb_pkt, conn->opaque, opaque);
									}
									__iip_dequeue_obj(conn->head[2], p, 0);
									__iip_free_pb(s, p, opaque);
								} else
									break;
							}
						}
					} while (conn->head[0][0]);
					if (conn->sack_ok) {
						if (conn->head[2][0]) {
							if (conn->tcp_sack_rx[0]) { /* send packets requested through sack */
								__iip_assert(conn->tcp_sack_rx[1]);
								IIP_OPS_DEBUG_PRINTF("coping with sack: entire unacked range %u %u\n",
										conn->acked_seq,
										__iip_ntohl(PB_TCP(conn->head[2][1]->buf)->seq_be) + ((PB_TCP_HDR_HAS_SYN(conn->head[2][1]->buf) || PB_TCP_HDR_HAS_FIN(conn->head[2][1]->buf)) ? 1 : PB_TCP_PAYLOAD_LEN(conn->head[2][1]->buf)));
								{ /* we reconstruct retransmission queue from scratch, so release existing ones first */
									struct pb *p, *_n;
									__iip_q_for_each_safe(conn->head[3], p, _n, 0) {
										__iip_dequeue_obj(conn->head[3], p, 0);
										__iip_free_pb(s, p, opaque);
									}
								}
								{
									/*
									 * associate sack entries with each packet
									 * NOTE: here, tcp_sack_rx is not ordered
									 */
									struct pb *p, *_n;
									__iip_q_for_each_safe(conn->tcp_sack_rx, p, _n, 0) {
										__iip_dequeue_obj(conn->tcp_sack_rx, p, 0);
										{
											struct pb *_p, *__n;
											__iip_q_for_each_safe(conn->head[2], _p, __n, 0) {
												uint8_t rx_sackbuf[(15 * 4 /* max tcp header size */) - sizeof(struct iip_tcp_hdr) /* common header size */];
												uint16_t c = 2;
												uint32_t __ex = __iip_ntohl(PB_TCP(conn->head[2][1]->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(conn->head[2][1]->buf) + PB_TCP_HDR_HAS_FIN(conn->head[2][1]->buf) + PB_TCP_PAYLOAD_LEN(conn->head[2][1]->buf);
												__iip_assert(PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off] <= sizeof(rx_sackbuf));
												memcpy(rx_sackbuf, &(PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1]), PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off]);
												while (c <= rx_sackbuf[1]) {
													uint8_t do_skip = 0;
													if ((__iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 4]))) - __iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 0]))) >= 2147483648U)
															|| (__iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 4]))) == __iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 0]))))) {
														/* invalid entry  */
														do_skip = 1;
													} else if (c == 2) {
														if (__iip_ntohl(PB_TCP(p->buf)->ack_seq_be) - __iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + 2 + 4]))) < 2147483648U) {
															/*
															 * compare with the ack field
															 * d-sack pattern 1
															 */
															do_skip = 1;
														} else if ((10 <= rx_sackbuf[1])
																/*
																 *  2: ...--|
																 * 10:  ...---|
																 */
																&& ((__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + 10 + 4]))) - __iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + 2 + 4])))) < 2147483648U)
																/*
																 *  2:  |--...
																 * 10: |---...
																 */
																&& ((__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + 2 + 0]))) - __iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + 10 + 0])))) < 2147483648U)) {
															/*
															 * compare with the second field
															 * d-sack pattern 2
															 */
															do_skip = 1;
														}
													} else if (conn->acked_seq - __iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 4]))) < 2147483648U) {
														/*
														 * sack entry for acked packets,
														 * data is properly received by peer,
														 * so, just ignore
														 */
														do_skip = 1;
													}
													if (do_skip) {
														if (c != rx_sackbuf[1]) {
															c += 8;
															continue;
														}
													} else {
														if (c <= 10) { /* sort from big to small */
															uint16_t cnt;
															do { /* bubble sort : TODO: faster sort */
																cnt = 0;
																{
																	uint16_t i;
																	for (i = c; i < rx_sackbuf[1] - 8; i += 8) {
																		if (__iip_ntohl(*((uint32_t *)(&rx_sackbuf[i + 4 + 8]))) - __iip_ntohl(*((uint32_t *)(&rx_sackbuf[i + 0]))) < 2147483648U) {
																			uint32_t h, t;
																			h = *((uint32_t *)(&rx_sackbuf[i + 0]));
																			t = *((uint32_t *)(&rx_sackbuf[i + 4]));
																			*((uint32_t *)(&rx_sackbuf[i + 0])) = *((uint32_t *)(&rx_sackbuf[i + 0 + 8]));
																			*((uint32_t *)(&rx_sackbuf[i + 4])) = *((uint32_t *)(&rx_sackbuf[i + 4 + 8]));
																			*((uint32_t *)(&rx_sackbuf[i + 0 + 8])) = h;
																			*((uint32_t *)(&rx_sackbuf[i + 4 + 8])) = t;
																			cnt++;
																		}
																	}
																}
															} while (cnt);
															{ /* debug */
																uint16_t i;
																for (i = 2; i < rx_sackbuf[1]; i += 8) {
																	/*IIP_OPS_DEBUG_PRINTF("%2u/%2u: sle %u sre %u\n",
																			i, rx_sackbuf[1],
																			__iip_ntohl(*((uint32_t *)(&rx_sackbuf[i + 0]))),
																			__iip_ntohl(*((uint32_t *)(&rx_sackbuf[i + 4]))));*/
																}
															}
														}
														/* set flag and increase congestion window if _p is sacked */
														if (!(_p->flags & __IIP_PB_FLAGS_SACKED)) {
															uint32_t sle = __iip_ntohl(*((uint32_t *)(&rx_sackbuf[1 + c + 0])));
															uint32_t sre = __iip_ntohl(*((uint32_t *)(&rx_sackbuf[1 + c + 4])));
#define SEQ_LE_RAW(__pb) (__iip_ntohl(PB_TCP((__pb)->buf)->seq_be) + (__pb)->tcp.inc_head)
#define SEQ_RE_RAW(__pb) (__iip_ntohl(PB_TCP((__pb)->buf)->seq_be) + PB_TCP_HDR_HAS_SYN((__pb)->buf) + PB_TCP_HDR_HAS_FIN((__pb)->buf) + PB_TCP_PAYLOAD_LEN((__pb)->buf) - (__pb)->tcp.dec_tail)
															/*IIP_OPS_DEBUG_PRINTF("cmp %u %u with sle %u sre %u\n",
															  SEQ_LE_RAW(_p), SEQ_RE_RAW(_p), sle, sre);*/
															if (SEQ_LE_RAW(_p) - sre < 2147483648U) {
																/*
																 * _p        |-----------|
																 * sack |---|
																 */
															} else if (sle - SEQ_RE_RAW(_p) < 2147483648U) {
																/*
																 * _p        |-----------|
																 * sack                    |---|
																 */
															} else if (sle - SEQ_LE_RAW(_p) < 2147483648U) {
																if (sre - SEQ_RE_RAW(_p) < 2147483648U) {
																	/*
																	 * _p        |----=======|
																	 * sack          |---------|
																	 */
																	_p->tcp.dec_tail += SEQ_RE_RAW(_p) - sle;
																} else {
																	/*
																	 * _p        |---===-----|
																	 * sack         |---|
																	 *
																	 * TODO: this case needs to split a packet,
																	 * a bit complicated, so, do not implement for the moment
																	 */
																}
															} else {
																if (SEQ_RE_RAW(_p) - sre < 2147483648U) {
																	/*
																	 * _p        |=====------|
																	 * sack  |---------|
																	 */
																	_p->tcp.inc_head += sre - SEQ_LE_RAW(_p);
																} else {
																	/*
																	 * _p        |===========|
																	 * sack  |-----------------|
																	 */
																	_p->tcp.inc_head += SEQ_RE_RAW(_p) - SEQ_LE_RAW(_p);
																}
															}
															__iip_assert(SEQ_RE_RAW(_p) - SEQ_LE_RAW(_p) < 2147483648U);
															if (SEQ_LE_RAW(_p) == SEQ_RE_RAW(_p)) {
																IIP_OPS_DEBUG_PRINTF("%u %u is sacked\n",
																		__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																		__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(_p->buf) + PB_TCP_HDR_HAS_FIN(_p->buf) + PB_TCP_PAYLOAD_LEN(_p->buf));
																if (conn->cc.ssthresh < conn->cc.win) {
																	conn->cc.win = (conn->cc.win < 65535U ? conn->cc.win + 1 : conn->cc.win);
																} else {
																	conn->cc.win = (conn->cc.win < 65535U / 2 ? conn->cc.win * 2 : 65535U);
																}
																_p->flags |= __IIP_PB_FLAGS_SACKED;
															}
#undef _ROFF
#undef _LOFF
														}
													}
													if (((c == rx_sackbuf[1]
															|| __ex != __iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 4])))))
															&& (__ex - conn->acked_seq < 2147483648U)) {
														uint32_t mle = (c == rx_sackbuf[1] ? conn->acked_seq :__iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 4])))); /* missing left edge */
														uint32_t mre = __ex; /* missing right edge */
														uint16_t to_be_updated = _p->clone.to_be_updated;
														__iip_assert(mre - mle < 2147483648U);
														if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be)) <= (__iip_ntohl(conn->seq_be) - mre)) {
															/*
															 * pattern 1: do nothing
															 *                         unacked
															 *           |-- pkt --|      |
															 *   |   |
															 *  mle mre
															 */
															/*IIP_OPS_DEBUG_PRINTF("SACK: pattern 1: mle %u mre %u seq %u seq-to %u head %u tail %u\n",
															  mle, mre,
															  __iip_ntohl(PB_TCP(_p->buf)->seq_be),
															  __iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
															  _p->clone.range[_p->clone.to_be_updated].increment_head,
															  _p->clone.range[_p->clone.to_be_updated].decrement_tail);*/
														} else if ((__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf))) >= (__iip_ntohl(conn->seq_be) - mle)) {
															/*
															 * pattern 2: do nothing
															 *                         unacked
															 *           |-- pkt --|      |
															 *                      |   |
															 *                     mle mre
															 */
															/*IIP_OPS_DEBUG_PRINTF("SACK: pattern 2: mle %u mre %u seq %u seq-to %u head %u tail %u\n",
															  mle, mre,
															  __iip_ntohl(PB_TCP(_p->buf)->seq_be),
															  __iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
															  _p->clone.range[_p->clone.to_be_updated].increment_head,
															  _p->clone.range[_p->clone.to_be_updated].decrement_tail);*/
														} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) <= __iip_ntohl(conn->seq_be) - mle)
																&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) >= __iip_ntohl(conn->seq_be) - mre)) {
															/*
															 * pattern 3: all has to be retransmitted
															 *                         unacked
															 *           |-- pkt --|      |
															 *        |              |
															 *       mle            mre
															 * or
															 *           |-- pkt --|      |
															 *           |         |
															 *          mle       mre
															 *
															 */
															_p->flags |= __IIP_PB_FLAGS_SACK_REPLY_SEND_ALL;
															/*IIP_OPS_DEBUG_PRINTF("SACK: pattern 3: mle %u mre %u seq %u seq-to %u head %u tail %u\n",
															  mle, mre,
															  __iip_ntohl(PB_TCP(_p->buf)->seq_be),
															  __iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
															  _p->clone.range[_p->clone.to_be_updated].increment_head,
															  _p->clone.range[_p->clone.to_be_updated].decrement_tail);*/
														} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) > __iip_ntohl(conn->seq_be) - mle)
																&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) < __iip_ntohl(conn->seq_be) - mre)) {
															/*
															 * pattern 4: forward head and back tail
															 *                         unacked
															 *           |-- pkt --|      |
															 *              |   |
															 *             mle mre
															 */
															_p->clone.range[_p->clone.to_be_updated].increment_head = mle - __iip_ntohl(PB_TCP(_p->buf)->seq_be);
															_p->clone.range[_p->clone.to_be_updated].decrement_tail = (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) - mre;
															IIP_OPS_DEBUG_PRINTF("SACK: resize 4: mle %u mre %u seq %u seq-to %u head %u tail %u\n",
																	mle, mre,
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
																	_p->clone.range[_p->clone.to_be_updated].increment_head,
																	_p->clone.range[_p->clone.to_be_updated].decrement_tail);
															__iip_assert(_p->clone.range[_p->clone.to_be_updated].increment_head + _p->clone.range[_p->clone.to_be_updated].decrement_tail);
															_p->clone.to_be_updated++;
														} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) <= __iip_ntohl(conn->seq_be) - mle)
																&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) < __iip_ntohl(conn->seq_be) - mre)
																&& (__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) > __iip_ntohl(conn->seq_be) - mre) /* to be sure for debug */) {
															/*
															 * pattern 5: back tail
															 *                         unacked
															 *           |-- pkt --|      |
															 *         |   |
															 *        mle mre
															 * or
															 *           |-- pkt --|      |
															 *           |   |
															 *          mle mre
															 *
															 */
															_p->clone.range[_p->clone.to_be_updated].increment_head = 0;
															_p->clone.range[_p->clone.to_be_updated].decrement_tail = (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) - mre;
															IIP_OPS_DEBUG_PRINTF("SACK: resize 5: mle %u mre %u seq %u seq-to %u head %u tail %u\n",
																	mle, mre,
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
																	_p->clone.range[_p->clone.to_be_updated].increment_head,
																	_p->clone.range[_p->clone.to_be_updated].decrement_tail);
															__iip_assert(_p->clone.range[_p->clone.to_be_updated].increment_head + _p->clone.range[_p->clone.to_be_updated].decrement_tail);
															_p->clone.to_be_updated++;
														} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) > __iip_ntohl(conn->seq_be) - mle)
																&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) >= __iip_ntohl(conn->seq_be) - mre)
																&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) < __iip_ntohl(conn->seq_be) - mle) /* to be sure for debug */) {
															/*
															 * pattern 6: forward head
															 *                         unacked
															 *           |-- pkt --|      |
															 *                   |   |
															 *                  mle mre
															 * or
															 *           |-- pkt --|      |
															 *                 |   |
															 *                mle mre
															 */
															_p->clone.range[_p->clone.to_be_updated].increment_head = mle - __iip_ntohl(PB_TCP(_p->buf)->seq_be);
															_p->clone.range[_p->clone.to_be_updated].decrement_tail = 0;
															IIP_OPS_DEBUG_PRINTF("SACK: resize 6: mle %u mre %u seq %u seq-to %u head %u tail %u\n",
																	mle, mre,
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
																	_p->clone.range[_p->clone.to_be_updated].increment_head,
																	_p->clone.range[_p->clone.to_be_updated].decrement_tail);
															__iip_assert(_p->clone.range[_p->clone.to_be_updated].increment_head + _p->clone.range[_p->clone.to_be_updated].decrement_tail);
															_p->clone.to_be_updated++;
														} else {
															/* we should not come here */
															IIP_OPS_DEBUG_PRINTF("mle %u mre %u seq %u seq-to %u\n",
																	mle, mre,
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																	__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf));
															__iip_assert(0);
														}

														if (to_be_updated != _p->clone.to_be_updated) { /* added new entry */
															/*
															 * check overlap entries:
															 * we do this for each new entry so that we can ensure that
															 * there is no overlap in the entries
															 */
															uint16_t i;
															for (i = 0; i < _p->clone.to_be_updated - 1; i++) {
																void *_p_pkt;
																if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque))
																	_p_pkt = iip_ops_pkt_scatter_gather_chain_get_next(_p->pkt, opaque);
																else
																	_p_pkt = _p->orig_pkt;
																__iip_assert(_p_pkt);
																if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head > iip_ops_pkt_get_len(_p_pkt, opaque) /* TODO: no multi segment */ - _p->clone.range[i].decrement_tail) {
																	/*
																	 * pattern 1
																	 * new:      |  |
																	 * i  : |  |
																	 */
																	IIP_OPS_DEBUG_PRINTF("1: sack[%u/%u]: head %u tail %u : %u %u\n", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
																} else if (iip_ops_pkt_get_len(_p_pkt, opaque) /* TODO: no multi segment */ - _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail < _p->clone.range[i].increment_head) {
																	IIP_OPS_DEBUG_PRINTF("2: sack[%u/%u]: (%u) head %u tail %u : %u %u\n", i, _p->clone.to_be_updated, iip_ops_pkt_get_len(_p_pkt, opaque), _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
																	/*
																	 * pattern 2
																	 * new:      |  |
																	 * i  :           |  |
																	 */
																} else if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head >= _p->clone.range[i].increment_head
																		&& _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail >= _p->clone.range[i].decrement_tail) {
																	IIP_OPS_DEBUG_PRINTF("3: sack[%u/%u]: head %u tail %u : %u %u\n", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
																	/*
																	 * pattern 3
																	 * new:      |  |
																	 * i  :    |      |
																	 *  or
																	 * new:      |  |
																	 * i  :      |  |
																	 */
																	__iip_assert(_p->clone.range[i].increment_head + _p->clone.range[i].decrement_tail);
																	_p->clone.to_be_updated--;
																} else if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head <= _p->clone.range[i].increment_head
																		&& _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail <= _p->clone.range[i].decrement_tail) {
																	IIP_OPS_DEBUG_PRINTF("4: sack[%u/%u]: head %u tail %u : %u %u\n", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
																	/*
																	 * pattern 4: full overlap, remove
																	 * new:    |      |
																	 * i  :      |  |
																	 * or
																	 * new:    |      |
																	 * i  :    |  |
																	 * or
																	 * new:    |      |
																	 * i  :        |  |
																	 *
																	 */
																	__iip_memmove(&_p->clone.range[i], &_p->clone.range[i + 1], sizeof(_p->clone.range[i]) * (_p->clone.to_be_updated - i));
																	_p->clone.to_be_updated--;
																	i = (uint16_t) -1; /* check the coverage of other parts */
																} else if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head > _p->clone.range[i].increment_head
																		&& _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail < _p->clone.range[i].decrement_tail
																		&& _p->clone.range[_p->clone.to_be_updated - 1].increment_head <= iip_ops_pkt_get_len(_p_pkt, opaque) /* TODO: no multi segment */ - _p->clone.range[i].decrement_tail /* to be sure for debug */) {
																	IIP_OPS_DEBUG_PRINTF("5: sack[%u/%u]: head %u tail %u : %u %u\n", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
																	/*
																	 * pattern 5: merge
																	 * new:      |  |
																	 * i  :    |  |
																	 *  or
																	 * new:      |  |
																	 * i  :   |  |
																	 */
																	_p->clone.range[_p->clone.to_be_updated - 1].increment_head = _p->clone.range[i].increment_head;
																	if (!_p->clone.range[_p->clone.to_be_updated - 1].increment_head && !_p->clone.range[_p->clone.to_be_updated - 1].decrement_tail) {
																		/* all data, remove clone info */
																		__iip_memset(&_p->clone, 0, sizeof(_p->clone));
																	} else {
																		__iip_memmove(&_p->clone.range[i], &_p->clone.range[i + 1], sizeof(_p->clone.range[i]) * (_p->clone.to_be_updated - i));
																		_p->clone.to_be_updated--;
																		i = (uint16_t) -1; /* check if we have bridged two separate parts */
																	}
																} else if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head < _p->clone.range[i].increment_head
																		&& _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail > _p->clone.range[i].decrement_tail
																		&& iip_ops_pkt_get_len(_p_pkt, opaque) /* TODO: no multi segment */ -  _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail >= _p->clone.range[i].increment_head /* to be sure for debug */) {
																	IIP_OPS_DEBUG_PRINTF("6: sack[%u/%u]: head %u tail %u : %u %u\n", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
																	/*
																	 * pattern 6
																	 * new:      |  |
																	 * i  :        |  |
																	 *  or
																	 * new:      |  |
																	 * i  :         |  |
																	 */
																	_p->clone.range[_p->clone.to_be_updated - 1].decrement_tail = _p->clone.range[i].decrement_tail;
																	if (!_p->clone.range[_p->clone.to_be_updated - 1].increment_head && !_p->clone.range[_p->clone.to_be_updated - 1].decrement_tail) {
																		/* all data, remove clone info */
																		__iip_memset(&_p->clone, 0, sizeof(_p->clone));
																	} else {
																		__iip_memmove(&_p->clone.range[i], &_p->clone.range[i + 1], sizeof(_p->clone.range[i]) * (_p->clone.to_be_updated - i));
																		_p->clone.to_be_updated--;
																		i = (uint16_t) -1; /* check if we have bridged two separate parts */
																	}
																} else {
																	/* we should not come here */
																	__iip_assert(0);
																}
															}
														}
													}
													__ex = __iip_ntohl(*((uint32_t *)(&rx_sackbuf[c + 0])));
													c += 8;
												}
											}
										}
										__iip_free_pb(s, p, opaque);
									}
									{
										struct pb *p, *_n;
										__iip_q_for_each_safe(conn->head[2], p, _n, 0) {
											/* sort sack entries, here, we are sure that there is no overlapping */
											uint16_t cnt;
											do { /* bubble sort : TODO: faster sort */
												cnt = 0;
												{
													uint16_t i;
													for (i = 0; i < p->clone.to_be_updated - 1; i++) {
														if (p->clone.range[i].increment_head > p->clone.range[i + 1].increment_head) {
															uint32_t h, t;
															h = p->clone.range[i].increment_head;
															t = p->clone.range[i].decrement_tail;
															p->clone.range[i].increment_head = p->clone.range[i + 1].increment_head;
															p->clone.range[i].decrement_tail = p->clone.range[i + 1].decrement_tail;
															p->clone.range[i + 1].increment_head = h;
															p->clone.range[i + 1].decrement_tail = t;
															cnt++;
														}
													}
												}
											} while (cnt);
											{ /* debug */
												uint16_t i; uint8_t got_error = 0;
												for (i = 0; i < p->clone.to_be_updated - 1; i++) {
													if (p->clone.range[i].increment_head >= p->clone.range[i + 1].increment_head) {
														got_error = 1;
														IIP_OPS_DEBUG_PRINTF("sack[%u/%u]: head %u tail %u : %u %u\n", i, p->clone.to_be_updated, p->clone.range[i].increment_head, p->clone.range[i].decrement_tail, p->clone.range[i + 1].increment_head, p->clone.range[i + 1].decrement_tail);
													} else {
														IIP_OPS_DEBUG_PRINTF("sack[%u/%u]: head %u tail %u : %u %u\n", i, p->clone.to_be_updated, p->clone.range[i].increment_head, p->clone.range[i].decrement_tail, p->clone.range[i + 1].increment_head, p->clone.range[i + 1].decrement_tail);
													}
												}
												__iip_assert(!got_error);
											}
										}
									}
								}
								{
									struct pb *p, *_n;
									__iip_q_for_each_safe(conn->head[2], p, _n, 0) {
										uint16_t i;
										for (i = 0; (i < p->clone.to_be_updated) || (p->flags & __IIP_PB_FLAGS_SACK_REPLY_SEND_ALL); i++) {
											void *cp;
											if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
												if (iip_ops_pkt_scatter_gather_chain_get_next(p->pkt, opaque)) {
													cp = iip_ops_pkt_clone(iip_ops_pkt_scatter_gather_chain_get_next(p->pkt, opaque), opaque);
													__iip_assert(cp);
													if (p->clone.to_be_updated) {
														if (p->clone.range[i].increment_head) iip_ops_pkt_increment_head(cp, p->clone.range[i].increment_head, opaque);
														if (p->clone.range[i].decrement_tail) iip_ops_pkt_decrement_tail(cp, p->clone.range[i].decrement_tail, opaque);
													}
												} else {
													cp = NULL;
													__iip_assert(PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf));
												}
											} else {
												if (p->orig_pkt) {
													cp = iip_ops_pkt_clone(p->orig_pkt, opaque);
													__iip_assert(cp);
													if (p->clone.to_be_updated) {
														if (p->clone.range[i].increment_head) iip_ops_pkt_increment_head(cp, p->clone.range[i].increment_head, opaque);
														if (p->clone.range[i].decrement_tail) iip_ops_pkt_decrement_tail(cp, p->clone.range[i].decrement_tail, opaque);
													}
												} else {
													cp = NULL;
													__iip_assert(PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf));
												}
											}
											{ /* CLONE */
												struct iip_tcp_conn _conn;
												__iip_memcpy(&_conn, conn, sizeof(_conn));
												_conn.seq_be = __iip_htonl(__iip_ntohl(PB_TCP(p->buf)->seq_be) + (p->clone.to_be_updated ? p->clone.range[i].increment_head : 0));
												__iip_tcp_push(s, &_conn, cp,
														PB_TCP_HDR_HAS_SYN(p->buf), PB_TCP_HDR_HAS_ACK(p->buf), PB_TCP_HDR_HAS_FIN(p->buf), PB_TCP_HDR_HAS_RST(p->buf),
														NULL,
														opaque);
												{
													struct pb *out_p = _conn.head[1][1];
													__iip_dequeue_obj(_conn.head[1], out_p, 0);
													__iip_enqueue_obj(conn->head[3], out_p, 0); /* workaround to bypass the ordered queue */
												}
											}
											if (p->flags & __IIP_PB_FLAGS_SACK_REPLY_SEND_ALL)
												break;
										}
										p->flags &= ~(__IIP_PB_FLAGS_SACK_REPLY_SEND_ALL);
										__iip_memset(&p->clone, 0, sizeof(p->clone));
									}
								}
								if (conn->head[3][0]) { /* debug */
									uint32_t __ex = __iip_ntohl(PB_TCP(conn->head[3][0]->buf)->seq_be);
									{
										struct pb *p, *_n;
										__iip_q_for_each_safe(conn->head[3], p, _n, 0) {
											if (__ex != __iip_ntohl(PB_TCP(p->buf)->seq_be))
												IIP_OPS_DEBUG_PRINTF("sack skip : %u %u (len %u)\n", __ex, __iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->seq_be) - __ex);
											/*IIP_OPS_DEBUG_PRINTF("sack reply: %u %u (len %u)\n", __iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->seq_be) + ((PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf)) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf)), __iip_ntohl(PB_TCP(p->buf)->seq_be) + ((PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf)) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf)) - __iip_ntohl(PB_TCP(p->buf)->seq_be));*/
											__ex = __iip_ntohl(PB_TCP(p->buf)->seq_be) + ((PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf)) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf));
										}
									}
								}
							}
						}
					} else if (conn->dup_ack_received == 3) { /* 3 dup acks are received, we do retransmission for fast recovery, or sack */
						__iip_assert(!(!conn->head[2][0] && conn->head[2][1]));
						__iip_assert(!(conn->head[2][0] && !conn->head[2][1]));
						if (conn->head[2][0]) {
							{ /* send one packet requested by peer */
								void *cp;
								if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
									if (iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque)) {
										cp = iip_ops_pkt_clone(iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque), opaque);
										__iip_assert(cp);
									} else {
										cp = NULL;
										__iip_assert(PB_TCP_HDR_HAS_SYN(conn->head[2][0]->buf) || PB_TCP_HDR_HAS_FIN(conn->head[2][0]->buf));
									}
								} else {
									if (conn->head[2][0]->orig_pkt) {
										cp = iip_ops_pkt_clone(conn->head[2][0]->orig_pkt, opaque);
										__iip_assert(cp);
									} else {
										cp = NULL;
										__iip_assert(PB_TCP_HDR_HAS_SYN(conn->head[2][0]->buf) || PB_TCP_HDR_HAS_FIN(conn->head[2][0]->buf));
									}
								}
								if (conn->acked_seq != __iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be)) {
									__iip_assert(cp);
									/*
									 * we have packet 1, 2, 3, 4
									 * - packet 1 is partially acked
									 * - packet 2, 3, 4 are not acked
									 *
									 *         acked_seq        seq_be
									 * ------------|   unacked    |
									 *         | 1   | 2   | 3 |4 |
									 *         * -----------------* : A
									 *             *--------------* : B
									 *               *------------* : C
									 *             |
									 *            dup
									 *
									 * this could happen for example because of the NIC-based segmentation
									 */
									__iip_assert(__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be) /* A */ > __iip_ntohl(conn->seq_be) - conn->acked_seq /* B */);
									__iip_assert((__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(conn->head[2][0]->buf))) /* C */ < __iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be) /* B */);
									iip_ops_pkt_increment_head(cp, conn->acked_seq /* dup ack */ - __iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be), opaque);
								}
								{ /* CLONE */
									struct iip_tcp_conn _conn;
									__iip_memcpy(&_conn, conn, sizeof(_conn));
									_conn.seq_be = __iip_htonl(__iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be) + conn->acked_seq /* dup ack */ - __iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be));
									__iip_tcp_push(s, &_conn, cp,
											PB_TCP_HDR_HAS_SYN(conn->head[2][0]->buf), PB_TCP_HDR_HAS_ACK(conn->head[2][0]->buf), PB_TCP_HDR_HAS_FIN(conn->head[2][0]->buf), PB_TCP_HDR_HAS_RST(conn->head[2][0]->buf),
											NULL, opaque);
									{
										struct pb *out_p = _conn.head[1][1];
										__iip_dequeue_obj(_conn.head[1], out_p, 0);
										__iip_enqueue_obj(conn->head[3], out_p, 0); /* workaround to bypass the ordered queue */
									}
								}
								IIP_OPS_DEBUG_PRINTF("dup ack reply: %u\n", __iip_ntohl(PB_TCP(conn->head[3][1]->buf)->seq_be));
							}
							{ /* loss detected */
								IIP_OPS_DEBUG_PRINTF("loss detected (3 dup ack) : %p seq %u ack %u\n", (void *) conn, __iip_ntohl(conn->seq_be), __iip_ntohl(conn->ack_seq_be));
								conn->cc.ssthresh = (conn->cc.win / 2 < 1 ? 2 : conn->cc.win / 2);
								conn->cc.win = conn->cc.ssthresh; /* fast retransmission */
								__iip_assert(conn->head[2][0] && conn->head[2][1]);
								conn->sent_seq_when_loss_detected = __iip_ntohl(PB_TCP(conn->head[2][1]->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(conn->head[2][1]->buf) + PB_TCP_HDR_HAS_FIN(conn->head[2][1]->buf) + PB_TCP_PAYLOAD_LEN(conn->head[2][1]->buf);
								conn->flags |= __IIP_TCP_CONN_FLAGS_PEER_RX_FAILED;
							}
						} else {
							/* we have received an ack telling the receiver successfully got the data  */
						}
					}
					{ /* release unchecked received sack packets */
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->tcp_sack_rx, p, _n, 0) {
							__iip_dequeue_obj(conn->tcp_sack_rx, p, 0);
							__iip_free_pb(s, p, opaque);
						}
					}
					{ /* cancel retransmission if ack is received  */
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->head[3], p, _n, 0) {
							if ((__iip_ntohl(conn->seq_be) - conn->acked_seq) <= (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(p->buf)->seq_be) + ((PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf)) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf))))) {
								__iip_dequeue_obj(conn->head[3], p, 0);
								__iip_free_pb(s, p, opaque);
							}
						}
					}
					{ /* cancel retransmission exceeding flow and congestion windows */
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->head[3], p, _n, 0) {
							if ((uint32_t) conn->cc.win * PB_TCP_PAYLOAD_LEN(p->buf) < (uint32_t)((__iip_ntohl(PB_TCP(p->buf)->seq_be) - conn->acked_seq) + PB_TCP_PAYLOAD_LEN(p->buf)) ||
									((uint32_t) conn->peer_win << conn->ws) < (__iip_ntohl(PB_TCP(p->buf)->seq_be) + (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf)) + PB_TCP_HDR_HAS_FIN(p->buf) - conn->acked_seq /* len to be filled on the rx side */) {
								__iip_dequeue_obj(conn->head[3], p, 0);
								__iip_free_pb(s, p, opaque);
							}
						}
					}
					/* timeout check */
					if (!conn->head[3][0] && !conn->head[5][0]) { /* not in recovery mode */
						if (conn->head[2][0]) {
							if (conn->head[2][0]->tcp.rto_ms < now_ms - conn->head[2][0]->ts) { /* timeout and do retransmission */
								if (conn->retrans_cnt < IIP_CONF_TCP_RETRANS_CNT) {
									void *cp;
									if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
										if (iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque)) {
											cp = iip_ops_pkt_clone(iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque), opaque);
											__iip_assert(cp);
										} else {
											cp = NULL;
											__iip_assert(PB_TCP_HDR_HAS_SYN(conn->head[2][0]->buf) || PB_TCP_HDR_HAS_FIN(conn->head[2][0]->buf));
										}
									} else {
										if (conn->head[2][0]->orig_pkt) {
											cp = iip_ops_pkt_clone(conn->head[2][0]->orig_pkt, opaque);
											__iip_assert(cp);
										} else {
											cp = NULL;
											__iip_assert(PB_TCP_HDR_HAS_SYN(conn->head[2][0]->buf) || PB_TCP_HDR_HAS_FIN(conn->head[2][0]->buf));
										}
									}
									{ /* CLONE */
										struct iip_tcp_conn _conn;
										__iip_memcpy(&_conn, conn, sizeof(_conn));
										_conn.seq_be = PB_TCP(conn->head[2][0]->buf)->seq_be;
										__iip_tcp_push(s, &_conn, cp,
												PB_TCP_HDR_HAS_SYN(conn->head[2][0]->buf),
												PB_TCP_HDR_HAS_ACK(conn->head[2][0]->buf),
												PB_TCP_HDR_HAS_FIN(conn->head[2][0]->buf),
												PB_TCP_HDR_HAS_RST(conn->head[2][0]->buf),
												NULL,
												opaque);
										{
											struct pb *out_p = _conn.head[1][1];
											__iip_dequeue_obj(_conn.head[1], out_p, 0);
											__iip_enqueue_obj(conn->head[3], out_p, 0); /* workaround to bypass the ordered queue */
										}
									}
									conn->head[2][0]->ts = now_ms;
									conn->head[2][0]->tcp.rto_ms *= 2;
									if (60000U /* 60 sec */ < conn->head[2][0]->tcp.rto_ms)
										conn->head[2][0]->tcp.rto_ms = 60000U;
									conn->retrans_cnt++;
									s->monitor.tcp.tx_pkt_re++;
									if (!(conn->flags & __IIP_TCP_CONN_FLAGS_PEER_RX_FAILED)) {
										IIP_OPS_DEBUG_PRINTF("loss detected (timeout retransmit cnt %u rto %u) : %p seq %u ack %u\n",
												conn->retrans_cnt, conn->head[2][0]->tcp.rto_ms, (void *) conn, __iip_ntohl(conn->seq_be), __iip_ntohl(conn->ack_seq_be));
										conn->cc.ssthresh = (conn->cc.win / 2 < 1 ? 2 : conn->cc.win / 2);
										conn->cc.win = 1;
										__iip_assert(conn->head[2][0] && conn->head[2][1]);
										conn->sent_seq_when_loss_detected = __iip_ntohl(PB_TCP(conn->head[2][1]->buf)->seq_be) + PB_TCP_HDR_HAS_SYN(conn->head[2][1]->buf) + PB_TCP_HDR_HAS_FIN(conn->head[2][1]->buf) + PB_TCP_PAYLOAD_LEN(conn->head[2][1]->buf);
										conn->flags |= __IIP_TCP_CONN_FLAGS_PEER_RX_FAILED;
									}
								} else {
									conn->state = __IIP_TCP_STATE_CLOSED;
									__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
									__iip_dequeue_obj(s->tcp.conns, conn, 0);
									__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
									IIP_OPS_DEBUG_PRINTF("%p: TCP_STATE_CLOSED because of timeout after %u retransmission\n", (void *) conn, IIP_CONF_TCP_RETRANS_CNT);
									continue;
								}
							}
						}
					}
					if (conn->head[2][0]) {
						if (conn->head[2][0]->tcp.rto_ms < now_ms - conn->head[2][0]->ts)
							_next_us = 0;
						else {
							uint32_t _next_us_tmp = (conn->head[2][0]->tcp.rto_ms - (now_ms - conn->head[2][0]->ts)) * 1000U;
							if (_next_us_tmp < _next_us)
								_next_us = _next_us_tmp;
						}
					}
					if (!conn->head[3][0] && !conn->head[5][0]) {
						if ((__iip_ntohl(conn->ack_seq_be) != conn->ack_seq_sent)) /* we got payload, but ack is not pushed by the app */
							__iip_tcp_push(s, conn, NULL, 0, 1, 0, 0, NULL, opaque);
					}
					{ /* transmit urgent packets */
						struct pb **queue = conn->head[5];
						struct pb *p, *_n;
						__iip_q_for_each_safe(queue, p, _n, 0) {
							__iip_dequeue_obj(queue, p, 0);
							{
								__iip_assert(p->pkt);
								{
									void *clone_pkt = iip_ops_pkt_clone(p->pkt, opaque);
									__iip_assert(clone_pkt);
									iip_ops_l2_push(clone_pkt, opaque);
									s->monitor.tcp.tx_pkt++;
								}
							}
							__iip_free_pb(s, p, opaque);
						}
					}
					{ /* if retransmission queue is empty, packets from normal queue are sent */
						struct pb **queue = (conn->head[3][0] ? conn->head[3] : conn->head[1]);
						{ /* either retransmission or normal queue */
							struct pb *p, *_n;
							__iip_q_for_each_safe(queue, p, _n, 0) {
								/* check if flow/congestion control stops tx */
								if (PB_TCP_PAYLOAD_LEN(p->buf)) {
									/* congestion control */
									if ((uint32_t) conn->cc.win * PB_TCP_PAYLOAD_LEN(p->buf) < (uint32_t)((__iip_ntohl(PB_TCP(p->buf)->seq_be) - conn->acked_seq) + PB_TCP_PAYLOAD_LEN(p->buf))) {
										s->monitor.tcp.cc_stop++;
										break;
									}
									/* flow control */
									/*IIP_OPS_DEBUG_PRINTF("flow control %u %u (%u %u %u)\n",
											((uint32_t) conn->peer_win << conn->ws),
											(__iip_ntohl(PB_TCP(p->buf)->seq_be) + (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf)) - conn->acked_seq,
											__iip_ntohl(PB_TCP(p->buf)->seq_be), (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf), conn->acked_seq);*/
									if (((uint32_t) conn->peer_win << conn->ws) < (__iip_ntohl(PB_TCP(p->buf)->seq_be) + (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf)) + PB_TCP_HDR_HAS_FIN(p->buf) - conn->acked_seq /* len to be filled on the rx side */) {
										/* no space to be sent on the rx side, postpone tx */
										s->monitor.tcp.fc_stop++;
										break;
									}
								}
								__iip_dequeue_obj(queue, p, 0);
								{
									__iip_assert(p->pkt);
									{
										void *clone_pkt = iip_ops_pkt_clone(p->pkt, opaque);
										__iip_assert(clone_pkt);
										/*IIP_OPS_DEBUG_PRINTF("seq %u len %u\n", __iip_ntohl(PB_TCP(p->buf)->seq_be), PB_TCP_PAYLOAD_LEN(p->buf));*/
										iip_ops_l2_push(clone_pkt, opaque);
										s->monitor.tcp.tx_pkt++;
									}
								}
								p->tcp.rto_ms = (conn->rtt.srtt + 4 * conn->rtt.rttvar) * 200 /* tick is incremented every 200 ms by fast timer */;
								if (!p->tcp.rto_ms)
									p->tcp.rto_ms = 200U;
								if (60000U /* 60 sec */ < p->tcp.rto_ms)
									p->tcp.rto_ms = 60000U;
								p->ts = now_ms;
								/*IIP_OPS_DEBUG_PRINTF("tcp-out: src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u\n",
								   (PB_IP4(p->buf)->src_be >>  0) & 0x0ff,
								   (PB_IP4(p->buf)->src_be >>  8) & 0x0ff,
								   (PB_IP4(p->buf)->src_be >> 16) & 0x0ff,
								   (PB_IP4(p->buf)->src_be >> 24) & 0x0ff,
								   (PB_IP4(p->buf)->dst_be >>  0) & 0x0ff,
								   (PB_IP4(p->buf)->dst_be >>  8) & 0x0ff,
								   (PB_IP4(p->buf)->dst_be >> 16) & 0x0ff,
								   (PB_IP4(p->buf)->dst_be >> 24) & 0x0ff,
								   __iip_ntohs(PB_TCP(p->buf)->src_be),
								   __iip_ntohs(PB_TCP(p->buf)->dst_be),
								   PB_TCP_HDR_HAS_SYN(p->buf), PB_TCP_HDR_HAS_ACK(p->buf), PB_TCP_HDR_HAS_FIN(p->buf), PB_TCP_HDR_HAS_RST(p->buf),
								   __iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->ack_seq_be),
								   PB_TCP_PAYLOAD_LEN(p->buf)); */
								if (queue != conn->head[3] && (PB_TCP_HDR_HAS_SYN(p->buf) || PB_TCP_HDR_HAS_FIN(p->buf) || PB_TCP_PAYLOAD_LEN(p->buf)))
									__iip_enqueue_obj(conn->head[2], p, 0);
								else
									__iip_free_pb(s, p, opaque);
							}
						}
					}

				}
			}
		}
		{ /* close tcp connections */
			struct iip_tcp_conn *conn, *_conn_n;
			__iip_q_for_each_safe(s->tcp.closed_conns, conn, _conn_n, 0) {
				iip_ops_tcp_closed(conn, conn->opaque, opaque);
				{
					uint8_t i;
					for (i = 0; i < 5; i++) {
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->head[i], p, _n, 0) {
							__iip_assert(p->pkt);
							__iip_dequeue_obj(conn->head[i], p, 0);
							__iip_free_pb(s, p, opaque);
						}
					}
				}
				__iip_dequeue_obj(s->tcp.closed_conns, conn, 0);
				__iip_memset(conn, 0, sizeof(struct iip_tcp_conn));
				__iip_enqueue_obj(s->pool.conn, conn, 0);
			}
		}
	}
	iip_ops_l2_flush(opaque);
	*next_us = _next_us;
#if 0
	{
		uint32_t now = __iip_now_in_ms(opaque);
		if (1000U < now - s->monitor.prev_print_ts) {
			IIP_OPS_DEBUG_PRINTF("tcp rx %u keep-alive %u, dup-ack %u, win-update %u, tx %u re-tx %u (stop fc %u cc %u th %u)\n",
				s->monitor.tcp.rx_pkt,
				s->monitor.tcp.rx_pkt_keepalive,
				s->monitor.tcp.rx_pkt_dupack,
				s->monitor.tcp.rx_pkt_winupdate,
				s->monitor.tcp.tx_pkt,
				s->monitor.tcp.tx_pkt_re,
				s->monitor.tcp.fc_stop,
				s->monitor.tcp.cc_stop,
				s->monitor.tcp.th_stop);
			__iip_memset(&s->monitor, 0, sizeof(s->monitor));
			{
				struct iip_tcp_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					IIP_OPS_DEBUG_PRINTF("tcp %p fc-win %u (win %u ws %u) cc-win %u (win %u) acked %u (unacked %u)\n",
							conn,
							(uint32_t) conn->peer_win << conn->ws,
							(uint32_t) conn->peer_win,
							conn->ws,
							(uint32_t) conn->cc.win * 0x0000ffffU,
							conn->cc.win,
							conn->acked_seq,
							__iip_ntohl(conn->seq_be) - conn->acked_seq);
				}
			}
			s->monitor.prev_print_ts = now;
		}
	}
#endif
	return ret;
}
