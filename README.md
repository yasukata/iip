# iip: an integratable TCP/IP stack

iip is an integratable TCP/IP stack implementation, aiming to offer the following properties:
- **easy integration**: iip aims to minimize dependencies on CPU architectures, NICs, libraries, and compiler features. Please see https://github.com/yasukata/iip#compilation-test for its dependency.
- **good performance**: iip is aware of multi-core scalability, NIC hardware offloading features, and zero-copy I/O; on a 32 CPU core machine, iip can handle more than 60 millions of short TCP messages in one second, and for bulk TCP data transfer, a single CPU core is enough for iip to saturate a 100 Gbps link thanks to NIC offloading features and zero-copy I/O. Please see https://github.com/yasukata/bench-iip#rough-numbers for rough performance numbers.

## other building blocks

### I/O subsystem
- [iip-dpdk](https://github.com/yasukata/iip-dpdk): a DPDK-based backend (Linux).
- [iip-af_xdp](https://github.com/yasukata/iip-af_xdp): an AF_XDP-based backend (Linux).
- [iip-netmap](https://github.com/yasukata/iip-netmap): a netmap-based backend (FreeBSD or Linux).

### example application
- [bench-iip](https://github.com/yasukata/bench-iip): a benchmark tool.

## getting started

Please visit an example application page at [https://github.com/yasukata/bench-iip](https://github.com/yasukata/bench-iip) for testing iip. 

## compilation test

The following program is to see the dependency of compilation.

```c
typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;
typedef unsigned long	uintptr_t;

#ifdef __cplusplus
#define NULL (0)
#else
#define NULL ((void *) 0)
#endif

int printf_nothing(const char *format, ...) { (void) format; return 0; }
#define IIP_OPS_DEBUG_PRINTF printf_nothing

#include "main.c"

static void *   iip_ops_pkt_alloc(void *opaque) { (void) opaque; return (void *) 0; }
static void     iip_ops_pkt_free(void *pkt, void *opaque) { (void) pkt; (void) opaque; }
static void *   iip_ops_pkt_get_data(void *pkt, void *opaque) { (void) pkt; (void) opaque; return (void *) 0; }
static uint16_t iip_ops_pkt_get_len(void *pkt, void *opaque) { (void) pkt; (void) opaque; return 0; }
static void     iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque) { (void) pkt; (void) len; (void) opaque; }
static void     iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque) { (void) pkt; (void) len; (void) opaque; }
static void     iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque) { (void) pkt; (void) len; (void) opaque; }
static void *   iip_ops_pkt_clone(void *pkt, void *opaque) { (void) pkt; (void) opaque; return (void *) 0; }
static void     iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque) { (void) pkt_head; (void) pkt_tail; (void) opaque; }
static void *   iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque) { (void) pkt_head; (void) opaque; return (void *) 0; }

static void     iip_ops_util_now_ns(uint32_t t[3], void *opaque) { (void) t; (void) opaque; }

static uint16_t iip_ops_l2_hdr_len(void *pkt, void *opaque) { (void) pkt; (void) opaque; return 0; }
static uint8_t*	iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque) { (void) pkt; (void) opaque; return (uint8_t *) 0; }
static uint8_t*	iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque) { (void) pkt; (void) opaque; return (uint8_t *) 0; }
static uint16_t	iip_ops_l2_ethertype_be(void *pkt, void *opaque) { (void) pkt; (void) opaque; return 0; }
static uint16_t	iip_ops_l2_addr_len(void *opaque) { (void) opaque; return 0; }
static void	iip_ops_l2_broadcast_addr(uint8_t bcaddr[], void *opaque) { (void) bcaddr; (void) opaque; }
static void	iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque) { (void) pkt; (void) src; (void) src; (void) dst; (void) ethertype_be; (void) opaque; }
static uint8_t	iip_ops_l2_skip(void *pkt, void *opaque) { (void) pkt; (void) opaque; return 0; }
static void     iip_ops_l2_flush(void *opaque) { (void) opaque; }
static void     iip_ops_l2_push(void *_m, void *opaque) { (void) _m; (void) opaque; }

static uint8_t  iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque) { (void) m; (void) opaque; return 0; }
static uint8_t  iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque) { (void) m; (void) opaque; return 0; }
static uint8_t  iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque) { (void) m; (void) opaque; return 0; }
static void     iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque) { (void) m; (void) opaque; }
static uint8_t  iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque) { (void) opaque; return 0; }
static void     iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque) { (void) m; (void) opaque; }
static void     iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque) { (void) m; (void) opaque; }
static uint8_t  iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque) { (void) opaque; return 0; }
static uint8_t  iip_ops_nic_feature_offload_udp_tx_tso(void *opaque) { (void) opaque; return 0; }
static void     iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque) { (void) m; (void) opaque; }
static void     iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque) { (void) m; (void) opaque; }

static uint8_t	iip_ops_arp_lhw(void *opaque) { (void) opaque; return 0; }
static uint8_t	iip_ops_arp_lproto(void *opaque) { (void) opaque; return 0; }
static void     iip_ops_arp_reply(void *_mem, void *m, void *opaque) { (void) _mem; (void) m; (void) opaque; }
static void     iip_ops_icmp_reply(void *_mem, void *m, void *opaque) { (void) _mem; (void) m; (void) opaque; }
static uint8_t  iip_ops_tcp_accept(void *mem, void *m, void *opaque) { (void) mem; (void) m; (void) opaque; return 0; }
static void *   iip_ops_tcp_accepted(void *mem, void *handle, void *m, void *opaque) { (void) mem; (void) handle; (void) m; (void) opaque; return (void *) 0; }
static void *   iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque) { (void) mem; (void) handle; (void) m; (void) opaque; return (void *) 0; }
static void     iip_ops_tcp_payload(void *mem, void *handle, void *m, void *tcp_opaque, void *opaque) { (void) mem; (void) handle; (void) m; (void) tcp_opaque; (void) opaque; }
static void     iip_ops_tcp_acked(void *mem, void *handle, void *m, void *tcp_opaque, void *opaque) { (void) mem; (void) handle; (void) m; (void) tcp_opaque; (void) opaque; }
static void     iip_ops_tcp_closed(void *handle, void *tcp_opaque, void *opaque) { (void) handle; (void) tcp_opaque; (void) opaque; }
static void     iip_ops_udp_payload(void *mem, void *m, void *opaque) { (void) mem; (void) m; (void) opaque; }

void _start(void) {
  (void) iip_run;
  (void) iip_udp_send;
  (void) iip_tcp_connect;
  (void) iip_tcp_rxbuf_consumed;
  (void) iip_tcp_close;
  (void) iip_tcp_send;
  (void) iip_arp_request;
  (void) iip_add_tcp_conn;
  (void) iip_add_pb;
  (void) iip_tcp_conn_size;
  (void) iip_pb_size;
  (void) iip_workspace_size;
}
```

When the code above is saved in a file named ```stub.c```, the following command supposedly generates a binary ```a.out```.

```
gcc -Werror -Wextra -Wall -pedantic -m32 -std=c89 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

```
g++ -Werror -Wextra -Wall -pedantic -m32 -std=c++98 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

Note that the program above is just for checking whether ```main.c``` can be compiled or not, and the generated binary ```a.out``` is not runnable.
