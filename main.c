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

#define IIP_CONF_ENDIAN (1) /* little 1, big 2 */

/* TODO: properly configure them */
#define IIP_CONF_IP4_TTL		(64)
#define IIP_CONF_TCP_OPT_WS		(7U) /* RFC 7323 : between 0 ~ 14 */ /* TODO: how to determine this ? */
#define IIP_CONF_TCP_OPT_MSS		(1460U)
#define IIP_CONF_TCP_OPT_SACK_OK	(1U)
#define IIP_CONF_TCP_RX_BUF_CNT		(512U) /* should be smaller than 735439 (1GB with 1460 mss) : limit by RFC 7323 */
#define IIP_CONF_TCP_WIN_INIT		(1)
#define IIP_CONF_TCP_MSL_SEC		(1) /* maximum segment lifetime, in second : RFC 793 recommends 2 min, but we can choose as we wish */
#define IIP_CONF_TCP_SSTHRESH_INIT	(256)
#define IIP_CONF_TCP_RTO_MS_INIT	(200U) /* 200 ms */
#define IIP_CONF_TCP_CONN_HT_SIZE	(829) /* generally bigger is faster at the cost of memory consumption */
#define IIP_CONF_TCP_TIMESTAMP_ENABLE	(1)

#if !defined(IIP_CONF_ENDIAN)
#error "byte order is not defined"
#endif

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
		for (__i = 0; __i < __n; __i++) \
			((uint8_t *) __dest)[__i] = ((uint8_t *) __src)[__i]; \
	} while (0)
#endif

#ifndef __iip_memset
#define __iip_memset(__s, __c, __n) \
	do { \
		uint32_t __i; \
		for (__i = 0; __i < __n; __i++) \
			((uint8_t *) __s)[__i] = __c; \
	} while (0)
#endif

#ifndef __iip_memcmp
#define __iip_memcmp(__s1, __s2, __n) \
({ \
	uint32_t __i = 0, ret = 0; \
	for (__i = 0; __i < __n; __i++) { \
		if (((uint8_t *) __s1)[__i] != ((uint8_t *) __s2)[__i]) { \
			ret = __i + 1; \
			break; \
		} \
	} \
	ret; \
})
#endif

#ifndef __iip_memmove
#define __iip_memmove(__dst, __src, __n) \
	do { \
		if ((uintptr_t) __dst > (uintptr_t) __src) { \
			uint32_t __i = 0; \
			for (__i = __n - 1; __i != (uint32_t) -1; __i--) { \
				((uint8_t *) __dst)[__i] = ((uint8_t *) __src)[__i]; \
			} \
		} else if ((uintptr_t) __dst < (uintptr_t) __src) { \
			uint32_t __i = 0; \
			for (__i = 0; __i < __n; __i++) { \
				((uint8_t *) __dst)[__i] = ((uint8_t *) __src)[__i]; \
			} \
		} \
	} while (0)
#endif

#ifndef __iip_assert
#define __iip_assert(_cond) \
	do { \
		if (!(_cond))  { \
			printf("\x1b[31m(%u)[%s:%u]: assertion fail \x1b[39m\n", iip_ops_util_core(), __func__, __LINE__); \
			while (1) ; \
		} \
	} while (0)
#endif

#define __iip_netcsum16(__b, __l, __c, __m) \
	({ \
		uint32_t __r = 0; uint16_t __n; uint8_t __k; \
		for (__n = 0, __k = 0; __n < (__c); __n++) { \
			uint32_t __i = 0; \
			for (__i = 0; __i < (__l)[__n]; __i++, __k = (__k ? 0 : 1)) { \
				uint16_t __v = ((uint8_t *)((__b)[__n]))[__i] & 0x00ff; \
				if (__k == 0) { \
					__v <<= 8; \
				} \
				__r += __v; \
			} \
		} \
		__r -= (__m); \
		__r = (__r >> 16) + (__r & 0x0000ffff); \
		__r = (__r >> 16) + __r; \
		(uint16_t)~((uint16_t) __r); \
	})

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
		(__obj)->prev[__x] = (__obj)->next[__x] = (void *) 0; \
	} while (0)

#define __iip_enqueue_obj(__queue, __obj, __x) \
	do { \
		(__obj)->prev[__x] = (__obj)->next[__x] = (void *) 0; \
		if (!((__queue)[0])) { \
			(__queue)[0] = (__queue)[1] = (__obj); \
		} else { \
			(__obj)->next[__x] = (void *) 0; \
			(__obj)->prev[__x] = (__queue)[1]; \
			(__queue)[1]->next[__x] = (__obj); \
			(__queue)[1] = (__obj); \
		} \
	} while (0)

#define __iip_q_for_each_safe(__queue, _i, _n, __x) \
	for ((_i) = (__queue)[0], _n = ((_i) ? _i->next[__x] : ((void *) 0)); (_i); (_i) = _n, _n = ((_i) ? (_i)->next[__x] : ((void *) 0)))

#define D(fmt, ...) do { if (iip_verbose_level) printf("\x1b[32m(%u)[%s:%u]: " fmt "\x1b[39m\n", iip_ops_util_core(), __func__, __LINE__, ##__VA_ARGS__); } while (0)

#define __iip_now_in_ms() \
	({ \
		uint32_t t[3]; \
		iip_ops_util_now_ns(t); \
		uint64_t _t = (((uint64_t) t[0] << 32) + (uint64_t) t[1]) * 1000000000UL + t[2]; \
		((uint32_t) ((_t / 1000000UL) & 0xffffffff)); \
	})

#define __iip_now_in_us() \
	({ \
		uint32_t t[3]; \
		iip_ops_util_now_ns(t); \
		uint64_t _t = (((uint64_t) t[0] << 32) + (uint64_t) t[1]) * 1000000000UL + t[2]; \
		((uint32_t) ((_t / 1000UL) & 0xffffffff)); \
	})

/* protocol headers */

struct iip_eth_hdr {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type_be; /* type in big endian */
} __attribute__((packed));

struct iip_ip4_hdr {
#if IIP_CONF_ENDIAN == 1
	uint8_t l:4, v:4; /* the unit of l is 4 octet */
#elif IIP_CONF_ENDIAN == 2
	uint8_t v:4, l:4; /* the unit of l is 4 octet */
#else
#error "invalid IIP_CONF_ENDIAN: it should be either 1 (little) or 2 (big)"
#endif
	uint8_t tos;
	uint16_t len_be;
	uint16_t id_be;
	uint16_t off_be;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum_be;
	uint32_t src_be;
	uint32_t dst_be;
} __attribute__((packed));

struct iip_arp_hdr {
	uint16_t hw_be;
	uint16_t proto_be;
	uint8_t lhw;
	uint8_t lproto;
	uint16_t op_be;
	uint8_t mac_sender[6];
	uint8_t ip_sender[4];
	uint8_t mac_target[6];
	uint8_t ip_target[4];
} __attribute__((packed));

struct iip_icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t csum_be;
	union {
		struct {
			uint16_t id_be;
			uint16_t seq_be;
		} echo;
	};
} __attribute__((packed));

struct iip_l4_ip4_pseudo_hdr {
	uint32_t ip4_src_be;
	uint32_t ip4_dst_be;
	uint8_t pad;
	uint8_t proto;
	uint16_t len_be;
} __attribute__((packed));

struct iip_tcp_hdr {
	uint16_t src_be;
	uint16_t dst_be;
	uint32_t seq_be;
	uint32_t ack_seq_be;
#if IIP_CONF_ENDIAN == 1
	uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif IIP_CONF_ENDIAN == 2
	uint16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
#error "invalid IIP_CONF_ENDIAN: it should be either 1 (little) or 2 (big)"
#endif
	uint16_t win_be;
	uint16_t csum_be;
	uint16_t urg_p_be;
} __attribute__((packed));

struct iip_udp_hdr {
	uint16_t src_be;
	uint16_t dst_be;
	uint16_t len_be;
	uint16_t csum_be;
} __attribute__((packed));

#define PB_ETH(__b) ((struct iip_eth_hdr *)(__b))
#define PB_IP4(__b) ((struct iip_ip4_hdr *)((uintptr_t) PB_ETH(__b) + sizeof(struct iip_eth_hdr)))
#define PB_ARP(__b) ((struct iip_arp_hdr *)(PB_IP4(__b)))
#define PB_ICMP(__b) ((struct iip_icmp_hdr *)((uintptr_t) PB_IP4(__b) + PB_IP4(__b)->l * 4))
#define PB_ICMP_PAYLOAD(__b) ((struct uint8_t *)((uintptr_t) PB_ICMP(__b) + sizeof(struct iip_icmp_hdr)))
#define PB_ICMP_PAYLOAD_LEN(__b) (__iip_htons(PB_IP4(__b)->len_be) - PB_IP4(__b)->l * 4 - sizeof(struct iip_icmp_hdr))
#define PB_TCP(__b) ((struct iip_tcp_hdr *)((uintptr_t) PB_IP4(__b) + PB_IP4(__b)->l * 4))
#define PB_TCP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_TCP(__b) + PB_TCP(__b)->doff * 4))
#define PB_TCP_PAYLOAD_LEN(__b) (__iip_htons(PB_IP4(__b)->len_be) - PB_IP4(__b)->l * 4 - PB_TCP(__b)->doff * 4)
#define PB_TCP_OPT(__b) ((uint8_t *)((uintptr_t) PB_TCP(__b) + sizeof(struct iip_tcp_hdr)))
#define PB_TCP_OPTLEN(__b) (PB_TCP(__b)->doff * 4 - sizeof(struct iip_tcp_hdr))
#define PB_UDP(__b) ((struct iip_udp_hdr *)((uintptr_t) PB_IP4(__b) + PB_IP4(__b)->l * 4))
#define PB_UDP_PAYLOAD(__b) ((uint8_t *)((uintptr_t) PB_UDP(__b) + sizeof(struct iip_udp_hdr)))
#define PB_UDP_PAYLOAD_LEN(__b) ((uint16_t)(__iip_ntohs(PB_UDP(__b)->len_be)))

int printf(const char *, ...); /* assuming someone implements this */

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
static void iip_ops_eth_flush(void *);
static void iip_ops_eth_push(void *, void *); /* assuming packet object is released by app */
static void iip_ops_arp_reply(void *, void *, void *);
static void iip_ops_icmp_reply(void *, void *, void *);
static uint8_t iip_ops_tcp_accept(void *, void *, void *);
static void *iip_ops_tcp_accepted(void *, void *, void *, void *);
static void *iip_ops_tcp_connected(void *, void *, void *, void *);
static void iip_ops_tcp_closed(void *, void *, void *);
static void iip_ops_tcp_payload(void *, void *, void *, void *, void *);
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
static uint16_t iip_ops_util_core(void);
static void iip_ops_util_now_ns(uint32_t [3]);

static uint8_t iip_verbose_level = 0;

/* data structures */

#define __IIP_PB_FLAGS_NEED_ACK_CB_PKT_FREE (1UL << 2)

struct pb {
	void *pkt;
	void *buf;
	void *ack_cb_pkt;
	uint64_t flags;
	void *orig_pkt; /* for no scatter gather mode */

	uint32_t ts;

	struct {
		uint32_t rto_ms;
		uint8_t dup_ack;
		struct {
			uint8_t ws;
			uint16_t mss;
			uint8_t sack_ok;
			uint16_t sack_opt_off;
			uint8_t has_ts;
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

struct iip_tcp_hdr_conn {
	uint8_t state;

	uint16_t local_port_be;
	uint16_t peer_port_be;
	uint32_t local_ip4_be;
	uint32_t peer_ip4_be;
	uint8_t local_mac[6];
	uint8_t peer_mac[6];

	uint32_t seq_be;
	uint32_t ack_seq_be;
	uint16_t win_be;

	/* management */
	uint32_t acked_seq;
	uint32_t ts;
	uint16_t peer_win;
	uint32_t ack_seq_sent;
	uint32_t seq_next_expected;
	uint8_t dup_ack_received;
	uint8_t dup_ack_sent;
	uint32_t time_wait_ts_ms;

	uint8_t dup_ack_throttle; /* non-standard optimization */
	uint32_t dup_ack_throttle_ts_us;

	uint32_t fin_ack_seq_be;

	struct {
		uint8_t ws; /* 0 ~ 14 : max window size 1GB : 1 << 30 (16 + 14) RFC 7323 */
		uint16_t mss;
		uint8_t sack_ok;
	} opt[2]; /* option of 0: peer[0], 1: local */

	struct { /* number of packet buffer (not in byte) for rx */
		uint32_t limit; /* we should have 1GB (735439) as the max : 1GB / 1460 (mss) = 735439.6.. */
		uint32_t used;
	} rx_buf_cnt;

	struct {
		uint16_t ssthresh;
		uint16_t win;
	} cc; /* congestion control */

	void *opaque;

	struct pb *head[5][2]; /* 0: rx, 1: tx, 2: tx sent, 3: tx urgent, 4: rx out-of-order */

	struct iip_tcp_hdr_conn *prev[2];
	struct iip_tcp_hdr_conn *next[2];
};

struct workspace {
	struct {
		struct pb *ip4_rx_fragment[2];
	} queue;
	struct {
		uint32_t p_cnt;
		struct pb *p[2];
		struct iip_tcp_hdr_conn *conn[2];
	} pool;
	struct {
		uint32_t prev_very_fast;
		uint32_t prev_fast;
		uint32_t prev_slow;
		uint32_t prev_very_slow;
	} timer;
	struct {
		uint32_t iss; /* initial send sequence number */
		uint32_t pkt_ts;
		struct iip_tcp_hdr_conn *conns[2];
		struct iip_tcp_hdr_conn *conns_ht[IIP_CONF_TCP_CONN_HT_SIZE][2];
		struct iip_tcp_hdr_conn *closed_conns[2];
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
		(__obj)->prev[__x] = (__obj)->next[__x] = (void *) 0; \
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
	return sizeof(struct iip_tcp_hdr_conn);
}

static void iip_add_pb(void *_mem, void *_p)
{
	__iip_enqueue_obj(((struct workspace *) _mem)->pool.p, (struct pb *) _p, 0);
	((struct workspace *) _mem)->pool.p_cnt++;
}

static void iip_add_tcp_conn(void *_mem, void *_conn)
{
	__iip_enqueue_obj(((struct workspace *) _mem)->pool.conn, (struct iip_tcp_hdr_conn *) _conn, 0);
}

/* protocol stack implementation */

static void iip_arp_request(void *_mem __attribute__((unused)),
			    uint8_t local_mac[6],
			    uint32_t local_ip4_be,
			    uint32_t target_ip4_be,
			    void *opaque)
{
	void *out_pkt = iip_ops_pkt_alloc(opaque);
	__iip_assert(out_pkt);
	{
		struct iip_eth_hdr ethh = {
			.src[0] = local_mac[0],
			.src[1] = local_mac[1],
			.src[2] = local_mac[2],
			.src[3] = local_mac[3],
			.src[4] = local_mac[4],
			.src[5] = local_mac[5],
			.dst[0] = 0xff,
			.dst[1] = 0xff,
			.dst[2] = 0xff,
			.dst[3] = 0xff,
			.dst[4] = 0xff,
			.dst[5] = 0xff,
			.type_be = __iip_htons(0x0806),
		};
		__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[0], &ethh, sizeof(struct iip_eth_hdr));
	}
	{
		struct iip_arp_hdr arph = {
			.hw_be = __iip_htons(0x0001),
			.proto_be = __iip_htons(0x0800),
			.lhw = 6,
			.lproto = 4,
			.op_be = __iip_htons(0x0001),
			.mac_sender[0] = local_mac[0],
			.mac_sender[1] = local_mac[1],
			.mac_sender[2] = local_mac[2],
			.mac_sender[3] = local_mac[3],
			.mac_sender[4] = local_mac[4],
			.mac_sender[5] = local_mac[5],
			.ip_sender[0] = (uint8_t)((local_ip4_be >>  0) & 0xff),
			.ip_sender[1] = (uint8_t)((local_ip4_be >>  8) & 0xff),
			.ip_sender[2] = (uint8_t)((local_ip4_be >> 16) & 0xff),
			.ip_sender[3] = (uint8_t)((local_ip4_be >> 24) & 0xff),
			.ip_target[0] = (uint8_t)((target_ip4_be >>  0) & 0xff),
			.ip_target[1] = (uint8_t)((target_ip4_be >>  8) & 0xff),
			.ip_target[2] = (uint8_t)((target_ip4_be >> 16) & 0xff),
			.ip_target[3] = (uint8_t)((target_ip4_be >> 24) & 0xff),
		};
		__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[sizeof(struct iip_eth_hdr)], &arph, sizeof(struct iip_arp_hdr));
	}
	iip_ops_pkt_set_len(out_pkt, sizeof(struct iip_eth_hdr) + sizeof(struct iip_arp_hdr), opaque);
	iip_ops_eth_push(out_pkt, opaque);
}

static uint16_t __iip_tcp_push(struct workspace *s,
			       struct iip_tcp_hdr_conn *conn, void *_pkt,
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
		uint16_t l = 1500 - (sizeof(struct iip_ip4_hdr) + __iip_round_up(sizeof(struct iip_tcp_hdr) + (syn ? 4 + 3 + (conn->opt[1].sack_ok ? 2 : 0) : 0) + (sackbuf ? sackbuf[1] : 0) + (IIP_CONF_TCP_TIMESTAMP_ENABLE ? 10 : 0), 4));
		payload_len = (l < (uint16_t) (total_payload_len - pushed_payload_len) ? l : total_payload_len - pushed_payload_len);
		if (payload_len != total_payload_len) {
			assert((pkt = iip_ops_pkt_clone(_pkt, opaque)) != (void *) 0);
			iip_ops_pkt_increment_head(pkt, pushed_payload_len, opaque);
			iip_ops_pkt_set_len(pkt, payload_len, opaque);
		}
	}
	{
		struct iip_eth_hdr *ethh = PB_ETH(out_p->buf);
		__iip_memcpy(ethh->src, conn->local_mac, 6);
		__iip_memcpy(ethh->dst, conn->peer_mac, 6);
		ethh->type_be = __iip_htons(0x0800);
	}
	{
		struct iip_ip4_hdr *ip4h = PB_IP4(out_p->buf);
		ip4h->l = sizeof(struct iip_ip4_hdr) / 4;
		ip4h->len_be = __iip_htons(sizeof(struct iip_ip4_hdr) + __iip_round_up(sizeof(struct iip_tcp_hdr) + (syn ? 4 + 3 + (conn->opt[1].sack_ok ? 2 : 0) : 0) + (sackbuf ? sackbuf[1] : 0) + (IIP_CONF_TCP_TIMESTAMP_ENABLE ? 10 : 0), 4) + payload_len);
		ip4h->v = 4; /* ip4 */
		ip4h->tos = 0;
		ip4h->id_be = 0; /* no ip4 fragment */
		ip4h->off_be = 0; /* no ip4 fragment */
		ip4h->ttl = IIP_CONF_IP4_TTL;
		ip4h->proto = 6; /* tcp */
		ip4h->src_be = conn->local_ip4_be;
		ip4h->dst_be = conn->peer_ip4_be;
		ip4h->csum_be = 0;
		if (!iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)) { /* ip4 csum */
			uint8_t *_b[1] = { (uint8_t *) ip4h, };
			uint16_t _l[1] = { ip4h->l * 4, };
			ip4h->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 1, 0));
		} else
			iip_ops_nic_offload_ip4_tx_checksum_mark(out_p->pkt, opaque);
	}
	__iip_assert(conn->rx_buf_cnt.limit < (1U << 30) /* 1GB limit : RFC 7323 */ / conn->opt[1].mss);
	{
		struct iip_tcp_hdr *tcph = PB_TCP(out_p->buf);
		tcph->doff = __iip_round_up(sizeof(struct iip_tcp_hdr) + (syn ? 4 + 3 + (conn->opt[1].sack_ok ? 2 : 0) : 0) + (sackbuf ? sackbuf[1] : 0) + (IIP_CONF_TCP_TIMESTAMP_ENABLE ? 10 : 0), 4) / 4;
		tcph->src_be = conn->local_port_be;
		tcph->dst_be = conn->peer_port_be;
		tcph->seq_be = conn->seq_be;
		tcph->ack_seq_be = conn->ack_seq_be;
		tcph->syn = syn;
		tcph->ack = ack;
		tcph->rst = rst;
		tcph->fin = fin;
		tcph->win_be = __iip_htons((uint16_t) (((conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * conn->opt[1].mss) >> conn->opt[1].ws));
		tcph->csum_be = 0;
		{
			uint8_t *optbuf = PB_TCP_OPT(out_p->buf), optlen = 0;
			{
				if (syn) { /* mss */
					optbuf[optlen + 0] = 2;
					optbuf[optlen + 1] = 4;
					*((uint16_t *) &(optbuf[optlen + 2])) = __iip_htons(conn->opt[1].mss);
					optlen += optbuf[optlen + 1];
				}
				if (syn) { /* window scale */
					optbuf[optlen + 0] = 3;
					optbuf[optlen + 1] = 3;
					__iip_assert(conn->opt[1].ws < 15); /* RFC 7323 */
					optbuf[optlen + 2] = conn->opt[1].ws;
					optlen += optbuf[optlen + 1];
				}
				if (syn && conn->opt[1].sack_ok) { /* sack ok */
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
				__iip_assert(tcph->doff == __iip_round_up(sizeof(struct iip_tcp_hdr) + optlen, 4) / 4); /* we already have configured */
			}
			__iip_memset(&optbuf[optlen], 0, tcph->doff * 4 - optlen);
		}
		if (!iip_ops_nic_feature_offload_tcp_tx_checksum(opaque)) {
			struct iip_l4_ip4_pseudo_hdr _pseudo = {
				.ip4_src_be = conn->local_ip4_be,
				.ip4_dst_be = conn->peer_ip4_be,
				.pad = 0,
				.proto = 6,
				.len_be = __iip_htons(tcph->doff * 4 + payload_len),
			};
			uint8_t *_b[3] = { (uint8_t *) &_pseudo, (uint8_t *) tcph, (pkt ? (uint8_t *) iip_ops_pkt_get_data(pkt, opaque) : (void *) 0), };
			uint16_t _l[3] = { sizeof(_pseudo), tcph->doff * 4, payload_len, };
			tcph->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 3, 0));
		} else
			iip_ops_nic_offload_tcp_tx_checksum_mark(out_p->pkt, opaque); /* relies on the value of doff on packet buf */
	}

	if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
		if (pkt) iip_ops_pkt_scatter_gather_chain_append(out_p->pkt, pkt, opaque);
		iip_ops_pkt_set_len(out_p->pkt, sizeof(struct iip_eth_hdr) + PB_IP4(out_p->buf)->l * 4 + PB_TCP(out_p->buf)->doff * 4, opaque);
	} else {
		if (pkt) __iip_memcpy(PB_TCP_PAYLOAD(out_p->buf), iip_ops_pkt_get_data(pkt, opaque), payload_len);
		iip_ops_pkt_set_len(out_p->pkt, sizeof(struct iip_eth_hdr) + PB_IP4(out_p->buf)->l * 4 + PB_TCP(out_p->buf)->doff * 4 + payload_len, opaque);
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
	struct iip_tcp_hdr_conn *conn = (struct iip_tcp_hdr_conn *) _handle;
	if (conn->state != __IIP_TCP_STATE_ESTABLISHED)
		return 0;
	return __iip_tcp_push((struct workspace *) _mem, conn, pkt, 0, 1, 0, 0, (void *) 0, opaque);
}

static uint16_t iip_tcp_close(void *_mem, void *_handle, void *opaque)
{
	struct iip_tcp_hdr_conn *conn = (struct iip_tcp_hdr_conn *) _handle;
	if (conn->state == __IIP_TCP_STATE_ESTABLISHED) {
		conn->state = __IIP_TCP_STATE_FIN_WAIT1;
		D("TCP_STATE_FIN_WAIT1");
		{
			uint16_t ret = __iip_tcp_push((struct workspace *) _mem, conn, (void *) 0, 0, 1, 1, 0, (void *) 0, opaque);
			conn->fin_ack_seq_be = conn->seq_be;
			return ret;
		}
	} else
		return 0;
}

static void iip_tcp_rxbuf_consumed(void *_mem __attribute__((unused)), void *_handle, uint16_t cnt, void *opaque __attribute__((unused)))
{
	struct iip_tcp_hdr_conn *conn = (struct iip_tcp_hdr_conn *) _handle;
	__iip_assert(cnt <= conn->rx_buf_cnt.used);
	conn->rx_buf_cnt.used -= cnt;
}

static void __iip_tcp_conn_init(struct workspace *s, struct iip_tcp_hdr_conn *conn,
				uint8_t local_mac[6], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[6], uint32_t peer_ip4_be, uint16_t peer_port_be,
				uint8_t state, void *opaque __attribute__((unused)))
{
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
	conn->opt[1].ws = IIP_CONF_TCP_OPT_WS;
	conn->opt[1].mss = IIP_CONF_TCP_OPT_MSS;
	conn->cc.win = IIP_CONF_TCP_WIN_INIT;
	conn->cc.ssthresh = IIP_CONF_TCP_SSTHRESH_INIT;
	__iip_assert(conn->rx_buf_cnt.limit * conn->opt[1].mss < (1U << 30));
	conn->win_be = __iip_htons((conn->rx_buf_cnt.limit * conn->opt[1].mss) >> conn->opt[1].ws);
	conn->opt[1].sack_ok = IIP_CONF_TCP_OPT_SACK_OK;
	__iip_enqueue_obj(s->tcp.conns, conn, 0);
	__iip_enqueue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
	__iip_assert(conn->rx_buf_cnt.used < conn->rx_buf_cnt.limit);
}

static uint16_t iip_tcp_connect(void *_mem,
				uint8_t local_mac[6], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[6], uint32_t peer_ip4_be, uint16_t peer_port_be,
				void *opaque)
{
	struct workspace *s = (struct workspace *) _mem;
	struct iip_tcp_hdr_conn *conn = s->pool.conn[0];
	__iip_assert(conn);
	__iip_dequeue_obj(s->pool.conn, conn, 0);
	__iip_tcp_conn_init(s, conn, local_mac, local_ip4_be, local_port_be, peer_mac, peer_ip4_be, peer_port_be, __IIP_TCP_STATE_SYN_SENT, opaque);
	return __iip_tcp_push(s, conn, (void *) 0, 1, 0, 0, 0, (void *) 0, opaque);
}

static uint16_t iip_udp_send(void *_mem __attribute__((unused)),
			     uint8_t local_mac[6], uint32_t local_ip4_be, uint16_t local_port_be,
			     uint8_t peer_mac[6], uint32_t peer_ip4_be, uint16_t peer_port_be,
			     void *pkt, void *opaque)
{
	void *out_pkt = iip_ops_pkt_alloc(opaque);
	uint16_t payload_len = (pkt ? iip_ops_pkt_get_len(pkt, opaque) : 0);
	__iip_assert(out_pkt);
	{
		struct iip_eth_hdr *ethh = PB_ETH(iip_ops_pkt_get_data(out_pkt, opaque));
		__iip_memcpy(ethh->src, local_mac, 6);
		__iip_memcpy(ethh->dst, peer_mac, 6);
		ethh->type_be = __iip_htons(0x0800);
	}
	{
		struct iip_ip4_hdr *ip4h = PB_IP4(iip_ops_pkt_get_data(out_pkt, opaque));
		ip4h->l = sizeof(struct iip_ip4_hdr) / 4;
		ip4h->len_be = __iip_htons(ip4h->l * 4 + sizeof(struct iip_udp_hdr) + payload_len);
		ip4h->v = 4; /* ip4 */
		ip4h->tos = 0;
		ip4h->id_be = 0; /* no ip4 fragment */
		ip4h->off_be = 0; /* no ip4 fragment */
		ip4h->ttl = IIP_CONF_IP4_TTL;
		ip4h->proto = 17; /* udp */
		ip4h->src_be = local_ip4_be;
		ip4h->dst_be = peer_ip4_be;
		ip4h->csum_be = 0;
		if (!iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)) { /* ip4 csum */
			uint8_t *_b[1] = { (uint8_t *) ip4h, };
			uint16_t _l[1] = { ip4h->l * 4, };
			ip4h->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 1, 0));
		} else
			iip_ops_nic_offload_ip4_tx_checksum_mark(out_pkt, opaque);
		{
			struct iip_udp_hdr *udph = PB_UDP(iip_ops_pkt_get_data(out_pkt, opaque));
			udph->src_be = local_port_be;
			udph->dst_be = peer_port_be;
			udph->len_be = __iip_htons(sizeof(struct iip_udp_hdr) + payload_len);
			udph->csum_be = 0;
			if (!iip_ops_nic_feature_offload_udp_tx_checksum(opaque)) { /* udp csum */
				struct iip_l4_ip4_pseudo_hdr _pseudo = {
					.ip4_src_be = local_ip4_be,
					.ip4_dst_be = peer_ip4_be,
					.pad = 0,
					.proto = 17,
					.len_be = __iip_htons(sizeof(struct iip_udp_hdr) + payload_len),
				};
				uint8_t *_b[3] = { (uint8_t *) &_pseudo, (uint8_t *) udph, (pkt ? (uint8_t *) iip_ops_pkt_get_data(pkt, opaque) : (void *) 0), };
				uint16_t _l[3] = { sizeof(_pseudo), sizeof(struct iip_udp_hdr), payload_len, };
				udph->csum_be = __iip_htons(__iip_netcsum16(_b, _l, 3, 0));
			} else
				iip_ops_nic_offload_udp_tx_checksum_mark(out_pkt, opaque);

			if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
				if (pkt) iip_ops_pkt_scatter_gather_chain_append(out_pkt, pkt, opaque);
				iip_ops_pkt_set_len(out_pkt, sizeof(struct iip_eth_hdr) + ip4h->l * 4 + sizeof(struct iip_udp_hdr), opaque);
			} else {
				if (pkt) __iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[sizeof(struct iip_eth_hdr) + ip4h->l * 4 + sizeof(struct iip_udp_hdr)], iip_ops_pkt_get_data(pkt, opaque), payload_len);
				iip_ops_pkt_set_len(out_pkt, sizeof(struct iip_eth_hdr) + ip4h->l * 4 + __iip_ntohs(udph->len_be), opaque);
				if (pkt) iip_ops_pkt_free(pkt, opaque);
			}
		}
	}

	if (iip_ops_nic_feature_offload_udp_tx_tso(opaque))
		iip_ops_nic_offload_udp_tx_tso_mark(out_pkt, opaque);

	iip_ops_eth_push(out_pkt, opaque);

	return 0;
}

static uint16_t iip_run(void *_mem, uint8_t mac[6], uint32_t ip4_be, void *pkt[], uint16_t cnt, uint32_t *next_us, void *opaque)
{
	struct workspace *s = (struct workspace *) _mem;
	uint16_t ret = 0;
	uint32_t _next_us = 1000000UL; /* 1 sec */
	{ /* periodic timer */
		uint32_t now_ms = __iip_now_in_ms();
		if (1 <= now_ms - s->timer.prev_very_fast){ /* 1 ms */
			s->timer.prev_very_fast = now_ms;
		}
		if (200 <= now_ms - s->timer.prev_fast){ /* fast timer every 200 ms */
			/* send delayed ack */
			{
				struct iip_tcp_hdr_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					if (conn->state == __IIP_TCP_STATE_ESTABLISHED && !conn->head[3][0]) {
						if ((__iip_ntohl(conn->ack_seq_be) != conn->ack_seq_sent)) /* we got payload, but ack is not pushed by the app */
							__iip_tcp_push(s, conn, (void *) 0, 0, 1, 0, 0, (void *) 0, opaque);
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
				struct iip_tcp_hdr_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					switch (conn->state) {
					case __IIP_TCP_STATE_TIME_WAIT:
						if (IIP_CONF_TCP_MSL_SEC * 1000U * 2 < now_ms - conn->time_wait_ts_ms) {
							conn->state = __IIP_TCP_STATE_CLOSED;
							__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
							__iip_dequeue_obj(s->tcp.conns, conn, 0);
							__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
							D("TCP_STATE_TIME_WAIT - TCP_STATE_CLOSED (%u %u (%u %u))", IIP_CONF_TCP_MSL_SEC * 1000U * 2, (now_ms - conn->time_wait_ts_ms) * 1000U, now_ms, conn->time_wait_ts_ms);
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
			_next_us = (s->timer.prev_very_fast + 1000U - now_ms < _next_us * 1000U ? (s->timer.prev_very_fast + 1000U - now_ms) * 1000U : _next_us);
			_next_us = (s->timer.prev_fast + 1000U - now_ms < _next_us * 1000U ? (s->timer.prev_fast + 1000U - now_ms) * 1000U : _next_us);
			_next_us = (s->timer.prev_slow + 1000U - now_ms < _next_us * 1000U ? (s->timer.prev_slow + 1000U - now_ms) * 1000U : _next_us);
			_next_us = (s->timer.prev_very_slow + 1000U - now_ms < _next_us * 1000U ? (s->timer.prev_very_slow + 1000U - now_ms) * 1000U : _next_us);
		}
	}
	{ /* phase 1: steer packet to an ip4_rx queue or discard after executing callback  */
		struct pb *ip4_rx[2] = { 0 };
		{
			uint16_t i;
			for (i = 0; i < cnt; i++) {
				uint8_t pkt_used = 0;
				struct pb *p = __iip_alloc_pb(s, pkt[i], opaque);
				switch (__iip_ntohs(PB_ETH(p->buf)->type_be)) {
				case 0x0800: /* ip */
					if (!__iip_memcmp(mac, PB_ETH(p->buf)->dst, 6)) {
						/*D("ip4-in : src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u v %u, l %u, proto %u",
								(PB_IP4(p->buf)->src_be >>  0) & 0x0ff,
								(PB_IP4(p->buf)->src_be >>  8) & 0x0ff,
								(PB_IP4(p->buf)->src_be >> 16) & 0x0ff,
								(PB_IP4(p->buf)->src_be >> 24) & 0x0ff,
								(PB_IP4(p->buf)->dst_be >>  0) & 0x0ff,
								(PB_IP4(p->buf)->dst_be >>  8) & 0x0ff,
								(PB_IP4(p->buf)->dst_be >> 16) & 0x0ff,
								(PB_IP4(p->buf)->dst_be >> 24) & 0x0ff,
								PB_IP4(p->buf)->v, PB_IP4(p->buf)->l,
								PB_IP4(p->buf)->proto);*/
						if (PB_IP4(p->buf)->v != 4) { /* ip version*/
							D("this is not ipv4 (%u)", PB_IP4(p->buf)->v);
							break;
						}
						if (PB_IP4(p->buf)->l * 4 > iip_ops_pkt_get_len(pkt[i], opaque)) {
							D("ip4 hdr invalid length");
							break;
						}
						if (iip_ops_nic_feature_offload_ip4_rx_checksum(opaque)) {
							if (!iip_ops_nic_offload_ip4_rx_checksum(p->pkt, opaque)) {
								D("invalid ip4 csum");
								break;
							}
						} else {
							uint8_t *_b[1] = { (uint8_t *) PB_IP4(p->buf), };
							uint16_t _l[1] = { PB_IP4(p->buf)->l * 4, };
							if (__iip_ntohs(PB_IP4(p->buf)->csum_be) != __iip_netcsum16(_b, _l, 1, __iip_ntohs(PB_IP4(p->buf)->csum_be))) {
								D("invalid ip4 csum");
								break;
							}
						}
						if (PB_IP4(p->buf)->dst_be != ip4_be) {
							D("ip4 but not for me");
							break;
						}
						/* TODO: handling ip options */
						if (__iip_ntohs(PB_IP4(p->buf)->off_be) & (0x2000 /* more packet flag */ | 0x1fff /* offset */)) {
							D("fragmented ip4");
							__iip_enqueue_obj(s->queue.ip4_rx_fragment, p, 0);
						} else
							__iip_enqueue_obj(ip4_rx, p, 0);
						pkt_used = 1;
					}
					break;
				case 0x0806: /* arp */
					{
						uint8_t bc_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, };
						if (!__iip_memcmp(mac, PB_ETH(p->buf)->dst, 6) || !__iip_memcmp(bc_mac, PB_ETH(p->buf)->dst, 6)) {
							switch (__iip_ntohs(PB_ARP(p->buf)->hw_be)) {
							case 0x0001: /* ethernet */
								switch (__iip_ntohs(PB_ARP(p->buf)->proto_be)) {
								case 0x0800: /* ipv4 */
									if (PB_ARP(p->buf)->lhw != 6) {
										D("unknown hardawre addr size %u", PB_ARP(p->buf)->lhw);
										break;
									}
									if (PB_ARP(p->buf)->lproto != 4) {
										D("unknown ip addr size %u", PB_ARP(p->buf)->lproto);
										break;
									}
									switch (__iip_ntohs(PB_ARP(p->buf)->op_be)) {
									case 0x0001: /* request */
										if (ip4_be == *((uint32_t *) PB_ARP(p->buf)->ip_target)) { /* arp response */
											void *out_pkt = iip_ops_pkt_alloc(opaque);
											__iip_assert(out_pkt);
											{
												struct iip_eth_hdr ethh = {
													.src[0] = mac[0],
													.src[1] = mac[1],
													.src[2] = mac[2],
													.src[3] = mac[3],
													.src[4] = mac[4],
													.src[5] = mac[5],
													.dst[0] = PB_ARP(p->buf)->mac_sender[0],
													.dst[1] = PB_ARP(p->buf)->mac_sender[1],
													.dst[2] = PB_ARP(p->buf)->mac_sender[2],
													.dst[3] = PB_ARP(p->buf)->mac_sender[3],
													.dst[4] = PB_ARP(p->buf)->mac_sender[4],
													.dst[5] = PB_ARP(p->buf)->mac_sender[5],
													.type_be = __iip_htons(0x0806),
												};
												__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[0], &ethh, sizeof(struct iip_eth_hdr));
											}
											{
												struct iip_arp_hdr arph = {
													.hw_be = __iip_htons(0x0001),
													.proto_be = __iip_htons(0x0800),
													.lhw = 6,
													.lproto = 4,
													.op_be = __iip_htons(0x0002),
													.mac_sender[0] = mac[0],
													.mac_sender[1] = mac[1],
													.mac_sender[2] = mac[2],
													.mac_sender[3] = mac[3],
													.mac_sender[4] = mac[4],
													.mac_sender[5] = mac[5],
													.mac_target[0] = PB_ARP(p->buf)->mac_sender[0],
													.mac_target[1] = PB_ARP(p->buf)->mac_sender[1],
													.mac_target[2] = PB_ARP(p->buf)->mac_sender[2],
													.mac_target[3] = PB_ARP(p->buf)->mac_sender[3],
													.mac_target[5] = PB_ARP(p->buf)->mac_sender[5],
													.ip_sender[0] = PB_ARP(p->buf)->ip_target[0],
													.ip_sender[1] = PB_ARP(p->buf)->ip_target[1],
													.ip_sender[2] = PB_ARP(p->buf)->ip_target[2],
													.ip_sender[3] = PB_ARP(p->buf)->ip_target[3],
													.ip_target[0] = PB_ARP(p->buf)->ip_sender[0],
													.ip_target[1] = PB_ARP(p->buf)->ip_sender[1],
													.ip_target[2] = PB_ARP(p->buf)->ip_sender[2],
													.ip_target[3] = PB_ARP(p->buf)->ip_sender[3],
												};
												__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[sizeof(struct iip_eth_hdr)], &arph, sizeof(struct iip_arp_hdr));
											}
											iip_ops_pkt_set_len(out_pkt, sizeof(struct iip_eth_hdr) + sizeof(struct iip_arp_hdr), opaque);
											iip_ops_eth_push(out_pkt, opaque);
										}
										break;
									case 0x0002: /* reply */
										if (ip4_be == *((uint32_t *) PB_ARP(p->buf)->ip_target))
											iip_ops_arp_reply(s, pkt[i], opaque);
										break;
									default:
										D("unknown arp op 0x%x", __iip_ntohs(PB_ARP(p->buf)->op_be));
										break;
									}
									break;
								default:
									D("unknown protocol type 0x%x", __iip_ntohs(PB_ARP(p->buf)->proto_be));
									break;
								}
								break;
							default:
								D("unknown hardware type 0x%x", __iip_ntohs(PB_ARP(p->buf)->hw_be));
								break;
							}
						} else
							D("arp but not for me");
					}
					break;
				default:
					D("unknown ether type 0x%x", __iip_ntohs(PB_ETH(p->buf)->type_be));
					break;
				}
				if (!pkt_used)
					__iip_free_pb(s, p, opaque);
			}
			ret = i;
		}
		{ /* phase 2: steer ip4 packets to a queue of tcp connection or discard after executing callback for icmp and udp */
			struct pb *tcp_sack_rx[2] = { 0 };
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
									D("icmp reply");
									iip_ops_icmp_reply(s, p->pkt, opaque);
									break;
								case 8: /* echo */
									D("icmp echo");
									{
										struct iip_icmp_hdr icmph = {
											.type = 0, /* icmp reply */
											.code = 0,
											.echo.id_be = PB_ICMP(p->buf)->echo.id_be,
											.echo.seq_be = PB_ICMP(p->buf)->echo.seq_be,
										};
										struct iip_ip4_hdr ip4h = {
											.l = sizeof(struct iip_ip4_hdr) / 4,
											.v = 4, /* ip4 */
											.len_be = __iip_htons(ip4h.l * 4 + sizeof(struct iip_icmp_hdr) + (PB_ICMP_PAYLOAD_LEN(p->buf))),
											.tos = 0,
											.id_be = 0, /* no ip4 fragment */
											.off_be = 0, /* no ip4 fragment */
											.ttl = IIP_CONF_IP4_TTL,
											.proto = 1, /* icmp */
											.src_be = PB_IP4(p->buf)->dst_be,
											.dst_be = PB_IP4(p->buf)->src_be,
										};
										struct iip_eth_hdr ethh = {
											.src[0] = PB_ETH(p->buf)->dst[0],
											.src[1] = PB_ETH(p->buf)->dst[1],
											.src[2] = PB_ETH(p->buf)->dst[2],
											.src[3] = PB_ETH(p->buf)->dst[3],
											.src[4] = PB_ETH(p->buf)->dst[4],
											.src[5] = PB_ETH(p->buf)->dst[5],
											.dst[0] = PB_ETH(p->buf)->src[0],
											.dst[1] = PB_ETH(p->buf)->src[1],
											.dst[2] = PB_ETH(p->buf)->src[2],
											.dst[3] = PB_ETH(p->buf)->src[3],
											.dst[4] = PB_ETH(p->buf)->src[4],
											.dst[5] = PB_ETH(p->buf)->src[5],
											.type_be = __iip_htons(0x0800),
										};
										/* TODO: large icmp packet */
										{ /* icmp csum */
											uint8_t *_b[2] = { (uint8_t *) &icmph, (uint8_t *) PB_ICMP_PAYLOAD(p->buf), };
											uint16_t _l[2] = { sizeof(struct iip_icmp_hdr), PB_ICMP_PAYLOAD_LEN(p->buf), };
											icmph.csum_be = __iip_htons(__iip_netcsum16(_b, _l, 2, 0));
										}
										{
											void *out_pkt = iip_ops_pkt_alloc(opaque);
											__iip_assert(out_pkt);

											if (!iip_ops_nic_feature_offload_ip4_tx_checksum(opaque)) { /* ip4 csum */
												uint8_t *_b[1] = { (uint8_t *) &ip4h, };
												uint16_t _l[1] = { ip4h.l * 4, };
												ip4h.csum_be = __iip_htons(__iip_netcsum16(_b, _l, 1, 0));
											}
											__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[0], &ethh, sizeof(struct iip_eth_hdr));
											__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[sizeof(struct iip_eth_hdr)], &ip4h, sizeof(struct iip_ip4_hdr));
											__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[sizeof(struct iip_eth_hdr) + sizeof(struct iip_ip4_hdr)], &icmph, sizeof(struct iip_icmp_hdr));
											__iip_memcpy(&((uint8_t *) iip_ops_pkt_get_data(out_pkt, opaque))[sizeof(struct iip_eth_hdr) + sizeof(struct iip_ip4_hdr) + sizeof(struct iip_icmp_hdr)], PB_ICMP_PAYLOAD(p->buf), PB_ICMP_PAYLOAD_LEN(p->buf));
											if (iip_ops_nic_feature_offload_ip4_tx_checksum(opaque))
												iip_ops_nic_offload_ip4_tx_checksum_mark(out_pkt, opaque);
											iip_ops_pkt_set_len(out_pkt, sizeof(struct iip_eth_hdr) + __iip_htons(PB_IP4(p->buf)->len_be), opaque);
											iip_ops_eth_push(out_pkt, opaque);
										}
									}
									break;
								default: /* TODO */
									D("unsupported icmp type %u", PB_ICMP(p->buf)->type);
									break;
								}
							}
							break;
						case 6: /* tcp */
							if (iip_ops_nic_feature_offload_tcp_rx_checksum(opaque)) {
								if (!iip_ops_nic_offload_tcp_rx_checksum(p->pkt, opaque)) {
									D("invalid tcp checksum hdr");
									break;
								}
							} else {
								struct iip_l4_ip4_pseudo_hdr _pseudo = {
									.ip4_src_be = PB_IP4(p->buf)->src_be,
									.ip4_dst_be = PB_IP4(p->buf)->dst_be,
									.proto = PB_IP4(p->buf)->proto,
									.len_be = __iip_htons(__iip_ntohs(PB_IP4(p->buf)->len_be) - PB_IP4(p->buf)->l * 4),
								};
								uint8_t *_b[3] = { (uint8_t *) &_pseudo, (uint8_t *) PB_TCP(p->buf), PB_TCP_PAYLOAD(p->buf), };
								uint16_t _l[3] = { sizeof(_pseudo), PB_TCP(p->buf)->doff * 4, PB_TCP_PAYLOAD_LEN(p->buf), };
								{
									uint16_t p_csum = __iip_ntohs(PB_TCP(p->buf)->csum_be), c_csum = __iip_netcsum16(_b, _l, 3, __iip_ntohs(PB_TCP(p->buf)->csum_be));
									if ((p_csum == 0xffff ? 0 : p_csum) != (c_csum == 0xffff ? 0 : c_csum)) { /* 0xffff is 0 */
										D("invalid tcp checksum hdr: %u %u : payload len %u", p_csum, c_csum, PB_TCP_PAYLOAD_LEN(p->buf));
										break;
									}
								}
							}
							__iip_assert(PB_TCP(p->buf)->doff);
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
												if (PB_TCP(p->buf)->syn) /* accept only with syn */
													p->tcp.opt.mss = (uint16_t) __iip_ntohs(*((uint16_t *) &PB_TCP_OPT(p->buf)[l + 2]));
											}
											break;
										case 3: /* window scale */
											if (PB_TCP_OPT(p->buf)[l + 1] == 3) {
												if (PB_TCP(p->buf)->syn) /* accept only with syn */
													p->tcp.opt.ws = PB_TCP_OPT(p->buf)[l + 2];
											}
											break;
										case 4: /* sack permitted */
											if (PB_TCP_OPT(p->buf)[l + 1] == 2) {
												if (PB_TCP(p->buf)->syn) /* accept only with syn */
													p->tcp.opt.sack_ok = 1;
											}
											break;
										case 5: /* sack */
											if (PB_TCP_OPT(p->buf)[l + 1] >= (2 + 8))
												p->tcp.opt.sack_opt_off = l + 1; /* pointing to the length, to diffrenciate sack starting at opt[0] */
											if (p->tcp.opt.sack_opt_off) { /* debug */
												uint16_t c = 2;
												while (c < PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off]) {
													D("rx sack: %u/%u: sle %u sre %u",
															c, PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off],
															__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 0]))),
															__iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 4]))));
													c += 8;
												}
											}
											break;
										case 8: /* timestamp */
											if (PB_TCP_OPT(p->buf)[l + 1] == 10) {
												p->tcp.opt.has_ts = 1;
												p->tcp.opt.ts[0] = __iip_ntohl(*(uint32_t *) &PB_TCP_OPT(p->buf)[l + 2]);
												p->tcp.opt.ts[1] = __iip_ntohl(*(uint32_t *) &PB_TCP_OPT(p->buf)[l + 6]);
											}
											break;
										default:
											D("unknown tcp option %u", PB_TCP_OPT(p->buf)[l]);
											break;
										}
										l += PB_TCP_OPT(p->buf)[l + 1];
										break;
									}
								}
							}
							{ /* find tcp conneciton and push the packet to its queue */
								struct iip_tcp_hdr_conn *conn = ((void *) 0);
								{ /* connection lookup */
									struct iip_tcp_hdr_conn *c, *_n;
									__iip_q_for_each_safe(s->tcp.conns_ht[(PB_IP4(p->buf)->src_be + PB_TCP(p->buf)->src_be + PB_TCP(p->buf)->dst_be) % IIP_CONF_TCP_CONN_HT_SIZE], c, _n, 0) {
										if (c->local_port_be == PB_TCP(p->buf)->dst_be
												&& c->peer_port_be == PB_TCP(p->buf)->src_be
												&& c->peer_ip4_be == PB_IP4(p->buf)->src_be) {
											conn = c;
											break;
										}
									}
								}
								if (PB_TCP(p->buf)->syn) {
									if (conn) { /* connect */
										if (!PB_TCP(p->buf)->ack) /* invalid, just ignore */
											conn = (void *) 0;
									} else { /* accept */
										if (iip_ops_tcp_accept(s, p->pkt, opaque)) {
											if (PB_TCP(p->buf)->ack) {
												D("WARNING: got syn-ack for non-existing connection, maybe RSS sterring would be wrong");
											} else { /* got a new connection request, so allocate conn obj */
												conn = s->pool.conn[0];
												__iip_assert(conn);
												__iip_dequeue_obj(s->pool.conn, conn, 0);
												__iip_tcp_conn_init(s, conn,
														PB_ETH(p->buf)->dst, PB_IP4(p->buf)->dst_be, PB_TCP(p->buf)->dst_be,
														PB_ETH(p->buf)->src, PB_IP4(p->buf)->src_be, PB_TCP(p->buf)->src_be,
														__IIP_TCP_STATE_SYN_RECVD, opaque);
											}
										}
									}
									if (conn) {
										conn->opt[0].mss = (p->tcp.opt.mss ? p->tcp.opt.mss : IIP_CONF_TCP_OPT_MSS);
										conn->opt[0].ws = (p->tcp.opt.ws ? p->tcp.opt.ws : 0);
										conn->opt[0].sack_ok = p->tcp.opt.sack_ok;
										conn->seq_next_expected = __iip_ntohl(PB_TCP(p->buf)->seq_be);
									}
								}
								if (conn) {
									/* Sequence number check */
									{ /* TODO: protection against wrapped sequence (PAWS) numbers : RFC 1323 */
									}
									{
										struct pb *_p = p;
										while (1) {
											if (conn->seq_next_expected != __iip_ntohl(PB_TCP(_p->buf)->seq_be)) {
												if ((conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * conn->opt[1].mss < __iip_ntohl(PB_TCP(_p->buf)->seq_be) - conn->seq_next_expected) {
													/*D("tcp-in D src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u (window %u diff %u)",
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
															PB_TCP(_p->buf)->syn, PB_TCP(_p->buf)->ack, PB_TCP(_p->buf)->fin, PB_TCP(_p->buf)->rst,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->ack_seq_be),
															PB_TCP_PAYLOAD_LEN(_p->buf),
															(conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * conn->opt[1].mss,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be) - conn->seq_next_expected);*/
													if (p != _p) /* p will be released by the notmal path */
														__iip_free_pb(s, _p, opaque);
													if (conn->head[4][0]) {
														_p = conn->head[4][0];
														__iip_dequeue_obj(conn->head[4], _p, 0);
													} else
														break;
												} else {
													/*D("tcp-in O src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u",
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
															PB_TCP(_p->buf)->syn, PB_TCP(_p->buf)->ack, PB_TCP(_p->buf)->fin, PB_TCP(_p->buf)->rst,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->ack_seq_be),
															PB_TCP_PAYLOAD_LEN(_p->buf))*/
													/* push packet to out-of-order queue, sorted by sequence number */
													if (!conn->head[4][0]) {
														__iip_assert(!conn->head[4][1]);
														__iip_enqueue_obj(conn->head[4], _p, 0);
													} else {
														struct pb *__p = conn->head[4][1];
														__iip_assert(__p->buf);
														__iip_assert(conn);
														while (__p && (__iip_ntohl(PB_TCP(_p->buf)->seq_be) - conn->seq_next_expected) < __iip_ntohl(PB_TCP(__p->buf)->seq_be) - conn->seq_next_expected) {
															__p = __p->prev[0];
														}
														{
															uint8_t overlap = 0;
															if (__p && __p->buf) { /* add next to __p */
																if (__iip_ntohl(PB_TCP(_p->buf)->seq_be) - conn->seq_next_expected < (__iip_ntohl(PB_TCP(__p->buf)->seq_be) + PB_TCP(__p->buf)->syn + PB_TCP(__p->buf)->fin + PB_TCP_PAYLOAD_LEN(__p->buf)) - conn->seq_next_expected) { /* overlap check */
																	D("overlap _p %u-%u __p %u-%u",
																			__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																			__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP(_p->buf)->syn + PB_TCP(_p->buf)->fin + PB_TCP_PAYLOAD_LEN(_p->buf),
																			__iip_ntohl(PB_TCP(__p->buf)->seq_be), __iip_ntohl(PB_TCP(__p->buf)->seq_be) + PB_TCP(__p->buf)->syn + PB_TCP(__p->buf)->fin + PB_TCP_PAYLOAD_LEN(__p->buf));
																	overlap = 1;

																} else if (__p->next[0] && (__iip_ntohl(PB_TCP(__p->next[0]->buf)->seq_be) - conn->seq_next_expected < (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP(_p->buf)->syn + PB_TCP(_p->buf)->fin + PB_TCP_PAYLOAD_LEN(_p->buf)) - conn->seq_next_expected)) { /* overlap check */
																	D("overlap _pnext %u-%u _p %u-%u",
																			__iip_ntohl(PB_TCP(__p->next[0]->buf)->seq_be),
																			__iip_ntohl(PB_TCP(__p->next[0]->buf)->seq_be) + PB_TCP(__p->buf)->syn + PB_TCP(__p->buf)->fin + PB_TCP_PAYLOAD_LEN(__p->next[0]->buf),
																			__iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP(_p->buf)->syn + PB_TCP(_p->buf)->fin + PB_TCP_PAYLOAD_LEN(_p->buf));
																	overlap = 1;
																} else {
																	_p->prev[0] = __p;
																	_p->next[0] = __p->next[0];
																	__p->next[0] = _p;
																	if (_p->next[0])
																		_p->next[0]->prev[0] = _p;
																	else
																		conn->head[4][1] = _p;
																}
															} else { /* this is the head */
																if ((__iip_ntohl(PB_TCP(conn->head[4][0]->buf)->seq_be) - conn->seq_next_expected < (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP(_p->buf)->syn + PB_TCP(_p->buf)->fin + PB_TCP_PAYLOAD_LEN(_p->buf)) - conn->seq_next_expected)) { /* overlap check */
																	D("overlap head4t %u-%u _p %u-%u (%u %u)",
																			__iip_ntohl(PB_TCP(conn->head[4][0]->buf)->seq_be),
																			__iip_ntohl(PB_TCP(conn->head[4][0]->buf)->seq_be) + PB_TCP(conn->head[4][0]->buf)->syn + PB_TCP(conn->head[4][0]->buf)->fin +  PB_TCP_PAYLOAD_LEN(conn->head[4][0]->buf),
																			__iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
																			__iip_ntohl(PB_TCP(conn->head[4][0]->buf)->seq_be) - conn->seq_next_expected, (PB_TCP(_p->buf)->seq_be + PB_TCP(_p->buf)->syn + PB_TCP(_p->buf)->fin + PB_TCP_PAYLOAD_LEN(_p->buf)) - conn->seq_next_expected);
																	overlap = 1;
																} else {
																	_p->next[0] = conn->head[4][0];
																	__iip_assert(!conn->head[4][0]->prev[0]);
																	conn->head[4][0]->prev[0] = _p;
																	conn->head[4][0] = _p;
																}
															}
															if (overlap) {
																if (p != _p) /* p will be released by the notmal path */
																	__iip_free_pb(s, _p, opaque);
																if (conn->head[4][0]) {
																	_p = conn->head[4][0];
																	__iip_dequeue_obj(conn->head[4], _p, 0);
																	continue;
																} else
																	break;
															}
														}
													}
													if (p == _p)
														pkt_used = 1;
													/* D("out-of-order: %u %u", __iip_ntohl(PB_TCP(_p->buf)->seq_be), conn->seq_next_expected); */
													if (conn->dup_ack_throttle) {
														if (100000U < __iip_now_in_us() - conn->dup_ack_throttle_ts_us) {
															conn->dup_ack_throttle = 0;
															D("throttle off by timer");
														}
													}
													if (!conn->dup_ack_throttle && !_p->tcp.dup_ack) {
														uint8_t sackbuf[(15 * 4) - sizeof(struct iip_tcp_hdr) - 19] = { 5, 2, };
														if (conn->opt[0].sack_ok) {
															uint32_t _ex = conn->seq_next_expected;
															{
																struct pb *__p = conn->head[4][0];
																while (sackbuf[1] < (sizeof(sackbuf) - 2 - 8) && __p) {
																	if (_ex != __iip_ntohl(PB_TCP(__p->buf)->seq_be)) {
																		*((uint32_t *) &sackbuf[sackbuf[1] +                0]) = __iip_htonl(_ex);
																		*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)]) = PB_TCP(__p->buf)->seq_be;
																		D("SACK %u: sle %u sre %u", sackbuf[1],
																				__iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] +                0])),
																				__iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)])));
																		__iip_assert(__iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] + 0])) - conn->seq_next_expected < __iip_ntohl(*((uint32_t *) &sackbuf[sackbuf[1] + sizeof(uint32_t)])) - conn->seq_next_expected);
																		sackbuf[1] += 8;
																	}
																	_ex = __iip_ntohl(PB_TCP(__p->buf)->seq_be) + PB_TCP(__p->buf)->syn + PB_TCP(__p->buf)->fin + PB_TCP_PAYLOAD_LEN(__p->buf);
																	__p = __p->next[0];
																}
															}
															__iip_assert(sackbuf[1] != 2);
														}
														D("%p (port %u) Send Dup ACK %u %u (skipped %u) (window %u) (%u %u) ack_seq_sent %u",
																conn,
																__iip_ntohs(PB_TCP(_p->buf)->src_be),
																conn->seq_next_expected,
																__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																__iip_ntohl(PB_TCP(_p->buf)->seq_be) - conn->seq_next_expected,
																(conn->rx_buf_cnt.limit - conn->rx_buf_cnt.used) * conn->opt[1].mss,
																conn->seq_next_expected,
																__iip_ntohl(PB_TCP(_p->buf)->seq_be),
																conn->ack_seq_sent);
														{ /* send dup ack */
															__iip_tcp_push(s, conn, (void *) 0, 0, 1, 0, 0, (sackbuf[1] == 2 ? (void *) 0 : sackbuf), opaque);
															{ /* workaround to bypass the ordered queue */
																struct pb *dup_ack_p = conn->head[1][1];
																__iip_dequeue_obj(conn->head[1], dup_ack_p, 0);
																__iip_enqueue_obj(conn->head[3], dup_ack_p, 0);
															}
														}
														_p->tcp.dup_ack = 1;
														conn->dup_ack_sent++;
														if (conn->dup_ack_sent == 3) {
															conn->dup_ack_sent = 0;
															conn->dup_ack_throttle = 1;
															conn->dup_ack_throttle_ts_us = __iip_now_in_us();
															D("throttle on");
														}
													}
													break;
												}
											} else {
												__iip_enqueue_obj(conn->head[0], _p, 0);
												pkt_used = 1;
												s->monitor.tcp.rx_pkt++;
												conn->seq_next_expected += PB_TCP(_p->buf)->syn + PB_TCP(_p->buf)->fin + PB_TCP_PAYLOAD_LEN(_p->buf);
												if (conn->dup_ack_throttle) {
													D("throttle off by in-order packet");
													conn->dup_ack_throttle = 0;
												}
												if (_p->tcp.dup_ack) {
													D("%u to %u is now in-order", __iip_ntohl(PB_TCP(_p->buf)->seq_be), __iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf));
												}
												if (conn->head[4][0]) {
													_p = conn->head[4][0];
													/*D("recheck expected %u", conn->seq_next_expected);*/
													__iip_dequeue_obj(conn->head[4], _p, 0);
												} else
													break;
											}
										}
									}
								} else {
									D("NO CONNECTION FOUND: src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u",
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
											PB_TCP(p->buf)->syn, PB_TCP(p->buf)->ack, PB_TCP(p->buf)->fin, PB_TCP(p->buf)->rst,
											__iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->ack_seq_be),
											PB_TCP_PAYLOAD_LEN(p->buf));
									/* we send rst as a reply */
									struct iip_tcp_hdr_conn _conn = { 0 };
									__iip_tcp_conn_init(s, &_conn,
											PB_ETH(p->buf)->dst, PB_IP4(p->buf)->dst_be, PB_TCP(p->buf)->dst_be,
											PB_ETH(p->buf)->src, PB_IP4(p->buf)->src_be, PB_TCP(p->buf)->src_be,
											__IIP_TCP_STATE_SYN_RECVD, opaque);
									_conn.ack_seq_be = __iip_ntohl(PB_TCP(p->buf)->seq_be) + PB_TCP(p->buf)->syn + PB_TCP(p->buf)->fin + PB_TCP_PAYLOAD_LEN(p->buf);
									__iip_tcp_push(s, &_conn, (void *) 0, 0, 0, 0, 1, (void *) 0, opaque);
									{
										struct pb *out_p = _conn.head[1][1];
										__iip_dequeue_obj(_conn.head[1], out_p, 0);
										{
											void *clone_pkt = iip_ops_pkt_clone(out_p->pkt, opaque);
											__iip_assert(clone_pkt);
											iip_ops_eth_push(clone_pkt, opaque);
										}
										__iip_free_pb(s, out_p, opaque);
									}
									__iip_dequeue_obj(s->tcp.conns_ht[(_conn.peer_ip4_be + _conn.local_port_be + _conn.peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], &_conn, 1);
									__iip_dequeue_obj(s->tcp.conns, &_conn, 0);
								}
							}
							break;
						case 17: /* udp */
							if (iip_ops_nic_feature_offload_udp_rx_checksum(opaque)) {
								if (!iip_ops_nic_offload_udp_rx_checksum(p->pkt, opaque)) {
									D("invalid udp checksum hdr");
									break;
								}
							} else {
								struct iip_l4_ip4_pseudo_hdr _pseudo = {
									.ip4_src_be = PB_IP4(p->buf)->src_be,
									.ip4_dst_be = PB_IP4(p->buf)->dst_be,
									.pad = 0,
									.proto = 17,
									.len_be = PB_UDP(p->buf)->len_be,
								};
								uint8_t *_b[2] = { (uint8_t *) &_pseudo, (uint8_t *) PB_UDP(p->buf), };
								uint16_t _l[2] = { sizeof(_pseudo), __iip_ntohs(PB_UDP(p->buf)->len_be), };
								{
									uint16_t p_csum = __iip_ntohs(PB_UDP(p->buf)->csum_be), c_csum = __iip_netcsum16(_b, _l, 2, __iip_ntohs(PB_UDP(p->buf)->csum_be));
									if ((p_csum == 0xffff ? 0 : p_csum) != (c_csum == 0xffff ? 0 : c_csum)) { /* 0xffff is 0 */
										D("invalid udp checksum hdr: %u %u : payload len %u", p_csum, c_csum, ntohs(PB_UDP(p->buf)->len_be));
										break;
									}
								}
							}
							iip_ops_udp_payload(s, p->pkt, opaque);
							break;
						default:
							D("unsupported l4 protocol %u", PB_IP4(p->buf)->proto);
							break;
						}
						if (!pkt_used)
							__iip_free_pb(s, p, opaque);
					}
				}
			}

			{ /* phase 3: iterate all tcp connections */
				struct iip_tcp_hdr_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					uint32_t stop_rx_traverse = 0;
					do {
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->head[0], p, _n, 0) {
							/* phase 3.1: process received in-order packets */
							__iip_dequeue_obj(conn->head[0], p, 0);
							{
								uint8_t out_of_order = 0;
								if (!PB_TCP(p->buf)->syn && !PB_TCP(p->buf)->fin && !PB_TCP(p->buf)->rst) {
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
														conn->dup_ack_received++;
														D("%p Received Dup ACK (cnt %u) %u (has sack %u) (win %u sent %u)",
																conn, conn->dup_ack_received, conn->acked_seq, p->tcp.opt.sack_opt_off,
																((uint32_t) conn->peer_win << conn->opt[0].ws),
																__iip_ntohl(conn->seq_be) + PB_TCP_PAYLOAD_LEN(p->buf) - conn->acked_seq /* len to be filled on the rx side */);
													} else { /* pattern A */
														/*
														 *        conn->acked_seq              conn->seq_be
														 *                  |                        |
														 *  ----- acked ----|------- unacked --------|
														 *              |
														 *              |
														 *              A
														 */
														D("%p Weird, ack to already acked packet (acked %u pkt-ack %u)",
																conn, conn->acked_seq, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
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
														D("%p Received Keep-alive %u", conn, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
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
														D("%p Weird, ack to already acked packet (acked %u pkt-ack %u)",
																conn, conn->acked_seq, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
														out_of_order = 1;
													}
												}
											} else {
												s->monitor.tcp.rx_pkt_winupdate++;
												D("%p Received Window Update", conn);
											}
										} else { /* packet has the payload */
											if (__iip_ntohl(PB_TCP(p->buf)->ack_seq_be) == conn->acked_seq) { /* pattern B */
												/* this is valid */
											} else {
												D("%p Weird, ack to already acked packet (acked %u pkt-ack %u)",
														conn, conn->acked_seq, __iip_ntohl(PB_TCP(p->buf)->ack_seq_be));
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
									conn->dup_ack_received = 0;
									if (conn->dup_ack_sent) {
										D("%p Missed packet is recovered by Dup ACK request: %u", conn, __iip_ntohl(conn->ack_seq_be));
										conn->dup_ack_sent = 0;
									}
									conn->peer_win = __iip_ntohs(PB_TCP(p->buf)->win_be);
									conn->ts = p->tcp.opt.ts[0];
									conn->ack_seq_be = __iip_htonl(__iip_ntohl(PB_TCP(p->buf)->seq_be) + (((PB_TCP_PAYLOAD_LEN(p->buf) == 0) && (PB_TCP(p->buf)->syn || PB_TCP(p->buf)->fin)) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf)));
									conn->acked_seq = __iip_ntohl(PB_TCP(p->buf)->ack_seq_be);
									/*D("tcp-in I src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u",
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
									  PB_TCP(p->buf)->syn, PB_TCP(p->buf)->ack, PB_TCP(p->buf)->fin, PB_TCP(p->buf)->rst,
									  __iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->ack_seq_be),
									  PB_TCP_PAYLOAD_LEN(p->buf));*/
									if (PB_TCP(p->buf)->rst) {
										if (conn->state != __IIP_TCP_STATE_CLOSED) {
											conn->state = __IIP_TCP_STATE_CLOSED;
											__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
											__iip_dequeue_obj(s->tcp.conns, conn, 0);
											__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
											D("RST - TCP_STATE_CLOSED");
										}
									} else {
										uint8_t is_connected = 0, is_accepted = 0;
										uint8_t syn = 0, ack = 0, fin = 0;
										switch (conn->state) {
											/* client */
											case __IIP_TCP_STATE_FIN_WAIT1:
												if (PB_TCP(p->buf)->ack) {
													if (PB_TCP(p->buf)->ack_seq_be == conn->fin_ack_seq_be) {
														if (PB_TCP(p->buf)->fin) {
															ack = 1;
															conn->state = __IIP_TCP_STATE_TIME_WAIT;
															conn->time_wait_ts_ms = __iip_now_in_ms();
															D("TCP_STATE_FIN_WAIT1 - TCP_STATE_TIME_WAIT");
														} else {
															conn->state = __IIP_TCP_STATE_FIN_WAIT2;
															D("TCP_STATE_FIN_WAIT1 - TCP_STATE_FIN_WAIT2");
														}
													}
												} else {
													if (PB_TCP(p->buf)->fin) {
														ack = 1;
														conn->state = __IIP_TCP_STATE_CLOSING;
														D("TCP_STATE_FIN_WAIT1 - TCP_STATE_CLOSING");
													}
												}
												break;
											case __IIP_TCP_STATE_FIN_WAIT2:
												if (PB_TCP(p->buf)->fin) {
													ack = 1;
													conn->state = __IIP_TCP_STATE_TIME_WAIT;
													conn->time_wait_ts_ms = __iip_now_in_ms();
													D("TCP_STATE_FIN_WAIT2 - TCP_STATE_TIME_WAIT");
												}
												break;
											case __IIP_TCP_STATE_CLOSING:
												if (PB_TCP(p->buf)->ack) {
													conn->state = __IIP_TCP_STATE_TIME_WAIT;
													conn->time_wait_ts_ms = __iip_now_in_ms();
													D("TCP_STATE_CLOSING - TCP_STATE_TIME_WAIT");
												}
												break;
											case __IIP_TCP_STATE_TIME_WAIT:
												/* wait 2 MSL timeout */
												break;
											case __IIP_TCP_STATE_SYN_SENT:
												if (PB_TCP(p->buf)->syn && PB_TCP(p->buf)->ack) {
													ack = 1;
													conn->state = __IIP_TCP_STATE_ESTABLISHED;
													is_connected = 1;
													D("TCP_STATE_SYN_SENT - TCP_STATE_ESTABLISHED");
												}
												break;
												/* server */
											case __IIP_TCP_STATE_SYN_RECVD:
												syn = (PB_TCP(p->buf)->ack ? 0 : 1);
												ack = 1;
												conn->state = __IIP_TCP_STATE_ESTABLISHED;
												is_accepted = 1;
												D("TCP_STATE_SYN_RECVD - TCP_STATE_ESTABLISHED");
												/* fall through */
											case __IIP_TCP_STATE_ESTABLISHED:
												if (PB_TCP(p->buf)->fin) {
													ack = 1;
													conn->state = __IIP_TCP_STATE_CLOSE_WAIT;
													D("TCP_STATE_ESTABLISHED - TCP_STATE_CLOSE_WAIT");
												} else if (PB_TCP(p->buf)->ack && PB_TCP_PAYLOAD_LEN(p->buf)) {
													conn->rx_buf_cnt.used++;
													iip_ops_tcp_payload(s, conn, p->pkt, conn->opaque, opaque);
												}
												/* fall through */
											case __IIP_TCP_STATE_CLOSE_WAIT:
												if (PB_TCP(p->buf)->fin) {
													fin = 1;
													conn->state = __IIP_TCP_STATE_LAST_ACK;
													D("TCP_STATE_CLOSE_WAIT - TCP_STATE_LAST_ACK");
												}
												break;
											case __IIP_TCP_STATE_LAST_ACK:
												if (PB_TCP(p->buf)->ack && PB_TCP(p->buf)->ack_seq_be == conn->fin_ack_seq_be) {
													conn->state = __IIP_TCP_STATE_CLOSED;
													__iip_dequeue_obj(s->tcp.conns_ht[(conn->peer_ip4_be + conn->local_port_be + conn->peer_port_be) % IIP_CONF_TCP_CONN_HT_SIZE], conn, 1);
													__iip_dequeue_obj(s->tcp.conns, conn, 0);
													__iip_enqueue_obj(s->tcp.closed_conns, conn, 0);
													D("TCP_STATE_LAST_ACK - TCP_STATE_CLOSED");
												}
												break;
											case __IIP_TCP_STATE_CLOSED:
												D("got packet although the connection is closed");
												/* do nothing */
												break;
											default:
												__iip_assert(0);
												break;
										}
										if (syn || ack || fin) {
											__iip_tcp_push(s, conn, (void *) 0, syn, ack, fin, 0, (void *) 0, opaque);
											if (fin)
												conn->fin_ack_seq_be = conn->seq_be;
										}
										/* execute callback after establishing the connection */
										if (is_connected) {
											D("connected peer port %u", __iip_ntohs(PB_TCP(p->buf)->src_be));
											conn->opaque = iip_ops_tcp_connected(s, conn, p->pkt, opaque);
										}
										if (is_accepted) {
											D("accept peer port %u", __iip_ntohs(PB_TCP(p->buf)->src_be));
											conn->opaque = iip_ops_tcp_accepted(s, conn, p->pkt, opaque);
										}
									}
								}
							}
							if (p->tcp.opt.sack_opt_off)
								__iip_enqueue_obj(tcp_sack_rx, p, 0);
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
								if ((__iip_ntohl(conn->seq_be) - conn->acked_seq) <= (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(p->buf)->seq_be) + ((PB_TCP(p->buf)->syn || PB_TCP(p->buf)->fin) ? 1 : PB_TCP_PAYLOAD_LEN(p->buf))))) { /* A or B */
									if (PB_TCP_PAYLOAD_LEN(p->buf)) {
										{ /* increase window size for congestion control */
											if (conn->cc.ssthresh < conn->cc.win) {
												conn->cc.win = (conn->cc.win < 65535U ? conn->cc.win + 1 : conn->cc.win);
												/*D("slow increase win %u ssthresh %u", conn->cc.win, conn->cc.ssthresh);*/
											} else {
												conn->cc.win = (conn->cc.win < 65535U / 2 ? conn->cc.win * 2 : 65535U);
												/*D("fast increase win %u ssthresh %u", conn->cc.win, conn->cc.ssthresh);*/
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
					} while (conn->head[0][0] && !stop_rx_traverse); /* phase 3.1: process received in-order packets */

					/* phase 3.2:
					 * now, in-order packets are processed and all acked packets are released
					 * here, we start handling dup-ack and sack requests if we have
					 */
					/* dup ack check */
					if (conn->dup_ack_received > 2) { /* 3 dup acks are received, we do retransmission for fast recovery, or sack */
						__iip_assert(!(!conn->head[2][0] && conn->head[2][1]));
						__iip_assert(!(conn->head[2][0] && !conn->head[2][1]));
						if (conn->head[2][0]) {
							void *cp;
							if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
								if (iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque)) {
									cp = iip_ops_pkt_clone(iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque), opaque);
									__iip_assert(cp);
								} else {
									cp = (void *) 0;
									__iip_assert(PB_TCP(conn->head[2][0]->buf)->syn || PB_TCP(conn->head[2][0]->buf)->fin);
								}
							} else {
								if (conn->head[2][0]->orig_pkt) {
									cp = iip_ops_pkt_clone(conn->head[2][0]->orig_pkt, opaque);
									__iip_assert(cp);
								} else {
									cp = (void *) 0;
									__iip_assert(PB_TCP(conn->head[2][0]->buf)->syn || PB_TCP(conn->head[2][0]->buf)->fin);
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
								struct iip_tcp_hdr_conn _conn;
								__iip_memcpy(&_conn, conn, sizeof(_conn));
								_conn.seq_be = __iip_htonl(__iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be) + conn->acked_seq /* dup ack */ - __iip_ntohl(PB_TCP(conn->head[2][0]->buf)->seq_be));
								__iip_tcp_push(s, &_conn, cp,
										PB_TCP(conn->head[2][0]->buf)->syn, PB_TCP(conn->head[2][0]->buf)->ack, PB_TCP(conn->head[2][0]->buf)->fin, PB_TCP(conn->head[2][0]->buf)->rst,
										(void *) 0, opaque);
								{
									struct pb *out_p = _conn.head[1][1];
									__iip_dequeue_obj(_conn.head[1], out_p, 0);
									__iip_enqueue_obj(conn->head[3], out_p, 0); /* workaround to bypass the ordered queue */
								}
							}
							D("dup ack reply: %u", __iip_ntohl(PB_TCP(conn->head[3][1]->buf)->seq_be));
							conn->dup_ack_received = 0;
						} else {
							/* we have received an ack telling the receiver successfully got the data  */
						}
						{ /* loss detected */
							D("loss detected (3 dup ack) : %p seq %u ack %u", conn, __iip_ntohl(conn->seq_be), __iip_ntohl(conn->ack_seq_be));
							conn->cc.ssthresh = (conn->cc.win / 2 < 1 ? 2 : conn->cc.win / 2);
							conn->cc.win = conn->cc.ssthresh; /* fast retransmission */
						}
					}
					/* sack check */
					if (tcp_sack_rx[0]) { /* sack requested */
						__iip_assert(tcp_sack_rx[1]);
						if (conn->head[2][0]) {
							{
								/*
								 * associate sack entries with each packet
								 * NOTE: here, tcp_sack_rx is not ordered
								 */
								struct pb *p, *_n;
								__iip_q_for_each_safe(tcp_sack_rx, p, _n, 0) {
									__iip_dequeue_obj(tcp_sack_rx, p, 0);
									{
										struct pb *_p, *__n;
										__iip_q_for_each_safe(conn->head[2], _p, __n, 0) {
											uint16_t c = 2;
											while (c < PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off]) {
												uint32_t sle = __iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 0])));
												uint32_t sre = __iip_ntohl(*((uint32_t *)(&PB_TCP_OPT(p->buf)[p->tcp.opt.sack_opt_off - 1 + c + 4])));
												uint16_t to_be_updated = _p->clone.to_be_updated;
												if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be)) <= (__iip_ntohl(conn->seq_be) - sre)) {
													/*
													 * pattern 1: do nothing
													 *                         unacked
													 *           |-- pkt --|      |
													 *   |   |
													 *  sle sre
													 */
												} else if ((__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf))) >= (__iip_ntohl(conn->seq_be) - sle)) {
													/*
													 * pattern 2: do nothing
													 *                         unacked
													 *           |-- pkt --|      |
													 *                      |   |
													 *                     sle sre
													 */
												} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) <= __iip_ntohl(conn->seq_be) - sle)
														&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) >= __iip_ntohl(conn->seq_be) - sre)) {
													/*
													 * pattern 3: all has to be retransmitted
													 *                         unacked
													 *           |-- pkt --|      |
													 *        |              |
													 *       sle            sre
													 * or
													 *           |-- pkt --|      |
													 *           |         |
													 *          sle       sre
													 *
													 */
												} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) > __iip_ntohl(conn->seq_be) - sle)
														&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) < __iip_ntohl(conn->seq_be) - sre)) {
													/*
													 * pattern 4: forward head and back tail
													 *                         unacked
													 *           |-- pkt --|      |
													 *              |   |
													 *             sle sre
													 */
													_p->clone.range[_p->clone.to_be_updated].increment_head = sle - __iip_ntohl(PB_TCP(_p->buf)->seq_be);
													_p->clone.range[_p->clone.to_be_updated].decrement_tail = (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) - sre;
													D("SACK: resize 4: sle %u sre %u seq %u seq-to %u head %u tail %u",
															sle, sre,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be),
															__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
															_p->clone.range[_p->clone.to_be_updated].increment_head,
															_p->clone.range[_p->clone.to_be_updated].decrement_tail);
													__iip_assert(_p->clone.range[_p->clone.to_be_updated].increment_head + _p->clone.range[_p->clone.to_be_updated].decrement_tail);
													_p->clone.to_be_updated++;
												} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) <= __iip_ntohl(conn->seq_be) - sle)
														&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) < __iip_ntohl(conn->seq_be) - sre)
														&& (__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) > __iip_ntohl(conn->seq_be) - sre) /* to be sure for debug */) {
													/*
													 * pattern 5: back tail
													 *                         unacked
													 *           |-- pkt --|      |
													 *         |   |
													 *        sle sre
													 * or
													 *           |-- pkt --|      |
													 *           |   |
													 *          sle sre
													 *
													 */
													_p->clone.range[_p->clone.to_be_updated].increment_head = 0;
													_p->clone.range[_p->clone.to_be_updated].decrement_tail = (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) - sre;
													D("SACK: resize 5: sle %u sre %u seq %u seq-to %u head %u tail %u",
															sle, sre,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be),
															__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
															_p->clone.range[_p->clone.to_be_updated].increment_head,
															_p->clone.range[_p->clone.to_be_updated].decrement_tail);
													__iip_assert(_p->clone.range[_p->clone.to_be_updated].increment_head + _p->clone.range[_p->clone.to_be_updated].decrement_tail);
													_p->clone.to_be_updated++;
												} else if ((__iip_ntohl(conn->seq_be) - __iip_ntohl(PB_TCP(_p->buf)->seq_be) > __iip_ntohl(conn->seq_be) - sle)
														&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) >= __iip_ntohl(conn->seq_be) - sre)
														&& (__iip_ntohl(conn->seq_be) - (__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf)) < __iip_ntohl(conn->seq_be) - sle) /* to be sure for debug */) {
													/*
													 * pattern 6: forward head
													 *                         unacked
													 *           |-- pkt --|      |
													 *                   |   |
													 *                  sle sre
													 * or
													 *           |-- pkt --|      |
													 *                 |   |
													 *                sle sre
													 */
													_p->clone.range[_p->clone.to_be_updated].increment_head = sle - __iip_ntohl(PB_TCP(_p->buf)->seq_be);
													_p->clone.range[_p->clone.to_be_updated].decrement_tail = 0;
													D("SACK: resize 6: sle %u sre %u seq %u seq-to %u head %u tail %u",
															sle, sre,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be),
															__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf),
															_p->clone.range[_p->clone.to_be_updated].increment_head,
															_p->clone.range[_p->clone.to_be_updated].decrement_tail);
													__iip_assert(_p->clone.range[_p->clone.to_be_updated].increment_head + _p->clone.range[_p->clone.to_be_updated].decrement_tail);
													_p->clone.to_be_updated++;
												} else {
													/* we should not come here */
													D("sle %u sre %u seq %u seq-to %u",
															sle, sre,
															__iip_ntohl(PB_TCP(_p->buf)->seq_be),
															__iip_ntohl(PB_TCP(_p->buf)->seq_be) + PB_TCP_PAYLOAD_LEN(_p->buf));
													__iip_assert(0);
												}

												if (to_be_updated != _p->clone.to_be_updated) { /* added new entry */
													D("%u %u", to_be_updated, _p->clone.to_be_updated);
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
														assert(_p_pkt);
														if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head > iip_ops_pkt_get_len(_p_pkt, opaque) /* TODO: no multi segment */ - _p->clone.range[i].decrement_tail) {
															/*
															 * pattern 1
															 * new:      |  |
															 * i  : |  |
															 */
															D("1: sack[%u/%u]: head %u tail %u : %u %u", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
														} else if (iip_ops_pkt_get_len(_p_pkt, opaque) /* TODO: no multi segment */ - _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail < _p->clone.range[i].increment_head) {
															D("2: sack[%u/%u]: (%u) head %u tail %u : %u %u", i, _p->clone.to_be_updated, iip_ops_pkt_get_len(_p_pkt, opaque), _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
															/*
															 * pattern 2
															 * new:      |  |
															 * i  :           |  |
															 */
														} else if (_p->clone.range[_p->clone.to_be_updated - 1].increment_head >= _p->clone.range[i].increment_head
																&& _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail >= _p->clone.range[i].decrement_tail) {
															D("3: sack[%u/%u]: head %u tail %u : %u %u", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
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
															D("4: sack[%u/%u]: head %u tail %u : %u %u", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
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
															D("5: sack[%u/%u]: head %u tail %u : %u %u", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
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
															D("6: sack[%u/%u]: head %u tail %u : %u %u", i, _p->clone.to_be_updated, _p->clone.range[_p->clone.to_be_updated - 1].increment_head, _p->clone.range[_p->clone.to_be_updated - 1].decrement_tail, _p->clone.range[i].increment_head, _p->clone.range[i].decrement_tail);
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
													D("sack[%u/%u]: head %u tail %u : %u %u", i, p->clone.to_be_updated, p->clone.range[i].increment_head, p->clone.range[i].decrement_tail, p->clone.range[i + 1].increment_head, p->clone.range[i + 1].decrement_tail);
												} else {
													D("sack[%u/%u]: head %u tail %u : %u %u", i, p->clone.to_be_updated, p->clone.range[i].increment_head, p->clone.range[i].decrement_tail, p->clone.range[i + 1].increment_head, p->clone.range[i + 1].decrement_tail);
												}
											}
											__iip_assert(!got_error);
										}
									}
								}
							}
						}
						{
							struct pb *p, *_n;
							__iip_q_for_each_safe(conn->head[2], p, _n, 0) {
								uint16_t i;
								for (i = 0; i < p->clone.to_be_updated; i++) {
									void *cp;
									if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
										if (iip_ops_pkt_scatter_gather_chain_get_next(p->pkt, opaque)) {
											cp = iip_ops_pkt_clone(iip_ops_pkt_scatter_gather_chain_get_next(p->pkt, opaque), opaque);
											__iip_assert(cp);
											if (p->clone.range[i].increment_head) iip_ops_pkt_increment_head(cp, p->clone.range[i].increment_head, opaque);
											if (p->clone.range[i].decrement_tail) iip_ops_pkt_decrement_tail(cp, p->clone.range[i].decrement_tail, opaque);
										} else {
											cp = (void *) 0;
											__iip_assert(PB_TCP(p->buf)->syn || PB_TCP(p->buf)->fin);
										}
									} else {
										if (p->orig_pkt) {
											cp = iip_ops_pkt_clone(p->orig_pkt, opaque);
											__iip_assert(cp);
										} else {
											cp = (void *) 0;
											__iip_assert(PB_TCP(p->buf)->syn || PB_TCP(p->buf)->fin);
										}
									}
									{ /* CLONE */
										struct iip_tcp_hdr_conn _conn;
										__iip_memcpy(&_conn, conn, sizeof(_conn));
										_conn.seq_be = __iip_htonl(__iip_ntohl(PB_TCP(p->buf)->seq_be) + p->clone.range[i].increment_head);
										__iip_tcp_push(s, &_conn, cp,
												PB_TCP(p->buf)->syn, PB_TCP(p->buf)->ack, PB_TCP(p->buf)->fin, PB_TCP(p->buf)->rst,
												(void *) 0,
												opaque);
										{
											struct pb *out_p = _conn.head[1][1];
											__iip_dequeue_obj(_conn.head[1], out_p, 0);
											__iip_enqueue_obj(conn->head[3], out_p, 0); /* workaround to bypass the ordered queue */
											D("sack reply: %u", __iip_ntohl(PB_TCP(out_p->buf)->seq_be));
										}
									}
								}
								__iip_memset(&p->clone, 0, sizeof(p->clone));
							}
						}
						{ /* loss detected */
							D("loss detected (sack) : %p seq %u ack %u", conn, __iip_ntohl(conn->seq_be), __iip_ntohl(conn->ack_seq_be));
							conn->cc.ssthresh = (conn->cc.win / 2 < 1 ? 2 : conn->cc.win / 2);
							conn->cc.win = 1;
						}
					}
					/* timeout check */
					if (!conn->head[3][0]) { /* not in recovery mode */
						if (conn->head[2][0]) {
							uint32_t now = __iip_now_in_ms();
							if (conn->head[2][0]->tcp.rto_ms < now - conn->head[2][0]->ts) { /* timeout and do retransmission */
								void *cp;
								if (iip_ops_nic_feature_offload_tx_scatter_gather(opaque)) {
									if (iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque)) {
										cp = iip_ops_pkt_clone(iip_ops_pkt_scatter_gather_chain_get_next(conn->head[2][0]->pkt, opaque), opaque);
										__iip_assert(cp);
									} else {
										cp = (void *) 0;
										__iip_assert(PB_TCP(conn->head[2][0]->buf)->syn || PB_TCP(conn->head[2][0]->buf)->fin);
									}
								} else {
									if (conn->head[2][0]->orig_pkt) {
										cp = iip_ops_pkt_clone(conn->head[2][0]->orig_pkt, opaque);
										__iip_assert(cp);
									} else {
										cp = (void *) 0;
										__iip_assert(PB_TCP(conn->head[2][0]->buf)->syn || PB_TCP(conn->head[2][0]->buf)->fin);
									}
								}
								{ /* CLONE */
									struct iip_tcp_hdr_conn _conn;
									__iip_memcpy(&_conn, conn, sizeof(_conn));
									_conn.seq_be = PB_TCP(conn->head[2][0]->buf)->seq_be;
									__iip_tcp_push(s, &_conn, cp,
											PB_TCP(conn->head[2][0]->buf)->syn,
											PB_TCP(conn->head[2][0]->buf)->ack,
											PB_TCP(conn->head[2][0]->buf)->fin,
											PB_TCP(conn->head[2][0]->buf)->rst,
											(void *) 0,
											opaque);
									{
										struct pb *out_p = _conn.head[1][1];
										__iip_dequeue_obj(_conn.head[1], out_p, 0);
										__iip_enqueue_obj(conn->head[3], out_p, 0); /* workaround to bypass the ordered queue */
									}
								}
								conn->head[2][0]->ts = now;
								conn->head[2][0]->tcp.rto_ms = (conn->head[2][0]->tcp.rto_ms < 5000000 ? conn->head[2][0]->tcp.rto_ms * 4 : 5000000); /* TODO: proper setting */
								s->monitor.tcp.tx_pkt_re++;
								{ /* loss detected */
									D("loss detected (timeout) : %p seq %u ack %u", conn, __iip_ntohl(conn->seq_be), __iip_ntohl(conn->ack_seq_be));
									conn->cc.ssthresh = (conn->cc.win / 2 < 1 ? 2 : conn->cc.win / 2);
									conn->cc.win = 1;
								}
							}
						}
					}
					if (!conn->head[3][0]) {
						if ((__iip_ntohl(conn->ack_seq_be) != conn->ack_seq_sent)) /* we got payload, but ack is not pushed by the app */
							__iip_tcp_push(s, conn, (void *) 0, 0, 1, 0, 0, (void *) 0, opaque);
					}

					/* phase 3.3: transmit queued packets */
					{
						struct pb **queue = (conn->head[3][0] ? conn->head[3] : conn->head[1]);
						{ /* normal tx queue */
							struct pb *p, *_n;
							__iip_q_for_each_safe(queue, p, _n, 0) {
								/* check if flow/congestion control stops tx */
								if (queue != conn->head[3]) {
									if (PB_TCP_PAYLOAD_LEN(p->buf)) {
										/* congestion control */
										if (conn->cc.win * 0xffff <= (__iip_ntohl(PB_TCP(p->buf)->seq_be) - conn->acked_seq) + PB_TCP_PAYLOAD_LEN(p->buf)) {
											s->monitor.tcp.cc_stop++;
											break;
										}
										/* flow control */
										/*D("flow control %u %u (%u %u %u)",
												((uint32_t) conn->peer_win << conn->opt[0].ws),
												(__iip_ntohl(PB_TCP(p->buf)->seq_be) + (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf)) - conn->acked_seq,
												__iip_ntohl(PB_TCP(p->buf)->seq_be), (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf), conn->acked_seq);*/
										if (((uint32_t) conn->peer_win << conn->opt[0].ws) < (__iip_ntohl(PB_TCP(p->buf)->seq_be) + (uint32_t) PB_TCP_PAYLOAD_LEN(p->buf)) + PB_TCP(p->buf)->fin - conn->acked_seq /* len to be filled on the rx side */) {
											/* no space to be sent on the rx side, postpone tx */
											s->monitor.tcp.fc_stop++;
											break;
										}
									}
								}
								__iip_dequeue_obj(queue, p, 0);
								{
									__iip_assert(p->pkt);
									void *clone_pkt = iip_ops_pkt_clone(p->pkt, opaque);
									__iip_assert(clone_pkt);
									/*D("seq %u len %u", __iip_ntohl(PB_TCP(p->buf)->seq_be), PB_TCP_PAYLOAD_LEN(p->buf));*/
									iip_ops_eth_push(clone_pkt, opaque);
									s->monitor.tcp.tx_pkt++;
								}
								p->tcp.rto_ms = IIP_CONF_TCP_RTO_MS_INIT;
								p->ts = __iip_now_in_ms();
								/*D("tcp-out: src-ip %u.%u.%u.%u dst-ip %u.%u.%u.%u src-port %u dst-port %u syn %u ack %u fin %u rst %u seq %u ack %u len %u",
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
								   PB_TCP(p->buf)->syn, PB_TCP(p->buf)->ack, PB_TCP(p->buf)->fin, PB_TCP(p->buf)->rst,
								   __iip_ntohl(PB_TCP(p->buf)->seq_be), __iip_ntohl(PB_TCP(p->buf)->ack_seq_be),
								   PB_TCP_PAYLOAD_LEN(p->buf)); */
								if (queue != conn->head[3] && (PB_TCP(p->buf)->syn || PB_TCP(p->buf)->fin || PB_TCP_PAYLOAD_LEN(p->buf)))
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
			struct iip_tcp_hdr_conn *conn, *_conn_n;
			__iip_q_for_each_safe(s->tcp.closed_conns, conn, _conn_n, 0) {
				iip_ops_tcp_closed(conn, conn->opaque, opaque);
				{
					uint8_t i;
					for (i = 0; i < 4; i++) {
						struct pb *p, *_n;
						__iip_q_for_each_safe(conn->head[i], p, _n, 0) {
							__iip_assert(p->pkt);
							__iip_dequeue_obj(conn->head[i], p, 0);
							__iip_free_pb(s, p, opaque);
						}
					}
				}
				__iip_dequeue_obj(s->tcp.closed_conns, conn, 0);
				__iip_memset(conn, 0, sizeof(struct iip_tcp_hdr_conn));
				__iip_enqueue_obj(s->pool.conn, conn, 0);
			}
		}
	}
	iip_ops_eth_flush(opaque);
	*next_us = _next_us;
#if 0
	{
		uint32_t now = __iip_now_in_ms();
		if (1000U < now - s->monitor.prev_print_ts) {
			D("tcp rx %u keep-alive %u, dup-ack %u, win-update %u, tx %u re-tx %u (stop fc %u cc %u th %u)",
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
				struct iip_tcp_hdr_conn *conn, *_conn_n;
				__iip_q_for_each_safe(s->tcp.conns, conn, _conn_n, 0) {
					D("tcp %p fc-win %u (win %u ws %u) cc-win %u (win %u) acked %u (unacked %u)",
							conn,
							(uint32_t) conn->peer_win << conn->opt[0].ws,
							(uint32_t) conn->peer_win,
							conn->opt[0].ws,
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
