# iip: an integratable TCP/IP stack

iip is an integratable TCP/IP stack implementation, having the following properties:
- portable: iip aims to minimize dependencies on CPU architectures, NICs, libraries, and compiler features.
- aware of multi-core scalability: iip does not maintain in-memory objects shared across different CPU cores.
- aiming at high-performance: iip handles millions packets in one second for a short TCP messaging workload; please see https://github.com/yasukata/bench-iip#rough-numbers for rough performance numbers.

## other building blocks

### I/O subsystem
- [iip-dpdk](https://github.com/yasukata/iip-dpdk): a DPDK-based backend.
- [iip-af_xdp](https://github.com/yasukata/iip-af_xdp): an AF_XDP-based backend.

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

#define D
#define __iip_memcpy
#define __iip_memset
#define __iip_memmove
#define __iip_assert

static void *   iip_ops_pkt_alloc(void *opaque __attribute__((unused))) { return (void *) 0; }
static void     iip_ops_pkt_free(void *pkt __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void *   iip_ops_pkt_get_data(void *pkt __attribute__((unused)), void *opaque __attribute__((unused))) { return (void *) 0; }
static uint16_t iip_ops_pkt_get_len(void *pkt __attribute__((unused)), void *opaque __attribute__((unused))) { return 0; }
static void     iip_ops_pkt_set_len(void *pkt __attribute__((unused)), uint16_t len __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_pkt_increment_head(void *pkt __attribute__((unused)), uint16_t len __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_pkt_decrement_tail(void *pkt __attribute__((unused)), uint16_t len __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void *   iip_ops_pkt_clone(void *pkt __attribute__((unused)), void *opaque __attribute__((unused))) { return (void *) 0; }
static void     iip_ops_pkt_scatter_gather_chain_append(void *pkt_head __attribute__((unused)), void *pkt_tail __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void *   iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head __attribute__((unused)), void *opaque __attribute__((unused))) { return (void *) 0; }

static uint16_t iip_ops_util_core(void) { return 0; }
static void     iip_ops_util_now_ns(uint32_t t[3] __attribute__((unused))) { }

static void     iip_ops_eth_flush(void *opaque __attribute__((unused))) { }
static void     iip_ops_eth_push(void *_m __attribute__((unused)), void *opaque __attribute__((unused))) { }

static uint8_t  iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_rx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_offload_ip4_rx_checksum(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_offload_tcp_rx_checksum(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_offload_udp_rx_checksum(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { return 0; }
static void     iip_ops_nic_offload_ip4_tx_checksum_mark(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }
static uint8_t  iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque __attribute__((unused))) { return 0; }
static void     iip_ops_nic_offload_tcp_tx_checksum_mark(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_nic_offload_tcp_tx_tso_mark(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }
static uint8_t  iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque __attribute__((unused))) { return 0; }
static uint8_t  iip_ops_nic_feature_offload_udp_tx_tso(void *opaque __attribute__((unused))) { return 0; }
static void     iip_ops_nic_offload_udp_tx_checksum_mark(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_nic_offload_udp_tx_tso_mark(void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }

static void     iip_ops_arp_reply(void *_mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_icmp_reply(void *_mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }
static uint8_t  iip_ops_tcp_accept(void *mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused))) { return 0; }
static void *   iip_ops_tcp_accepted(void *mem __attribute__((unused)), void *handle __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused))) { return (void *) 0; }
static void *   iip_ops_tcp_connected(void *mem __attribute__((unused)), void *handle __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused))) { return (void *) 0; }
static void     iip_ops_tcp_payload(void *mem __attribute__((unused)), void *handle __attribute__((unused)), void *m __attribute__((unused)), void *tcp_opaque __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_tcp_acked(void *mem __attribute__((unused)), void *handle __attribute__((unused)), void *m __attribute__((unused)), void *tcp_opaque __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_tcp_closed(void *handle __attribute__((unused)), void *tcp_opaque __attribute__((unused)), void *opaque __attribute__((unused))) { }
static void     iip_ops_udp_payload(void *mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused))) { }

#include "main.c"

void _start(void) { }
```

When the code above is saved in a file named ```stub.c```, the following command supposedly generates a binary ```a.out```.

```
gcc -m32 -std=c89 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

Note that the program above is just for checking whether ```main.c``` can be compiled or not, and the generated binary ```a.out``` is not runnable.
