# iip: an integratable TCP/IP stack

iip is an integratable TCP/IP stack implementation, aiming to offer the following properties:
- **easy integration**: iip aims to minimize dependencies on CPU architectures, NICs, libraries, and compiler features. Please see https://github.com/yasukata/iip#compilation-test for its dependency.
- **good performance**: iip is aware of multi-core scalability, NIC hardware offloading features, and zero-copy I/O; on a 32 CPU core machine, iip can handle more than 60 millions of short TCP messages in one second, and for bulk TCP data transfer, a single CPU core is enough for iip to saturate a 100 Gbps link thanks to NIC offloading features and zero-copy I/O. Please see https://github.com/yasukata/bench-iip#rough-numbers for rough performance numbers.

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

#ifdef _IS_CPP
#define NULL (0)
#else
#define NULL ((void *) 0)
#endif
#define D(_a, ...)

int printf(const char *, ...) { return 0; }

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
  (void) iip_verbose_level;
}
```

When the code above is saved in a file named ```stub.c```, the following command supposedly generates a binary ```a.out```.

```
gcc -Werror -Wextra -Wall -m32 -std=c89 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

```
g++ -D_IS_CPP=1 -Werror -Wextra -Wall -m32 -std=c++98 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

Note that the program above is just for checking whether ```main.c``` can be compiled or not, and the generated binary ```a.out``` is not runnable.
