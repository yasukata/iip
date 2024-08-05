# iip: an integratable TCP/IP stack

iip is an integratable TCP/IP stack implementation aiming to allow for easy integration and good performance simultaneously.

**WARNING: The authors will not bear any responsibility if the implementations, provided by the authors, cause any problems.**

## other building blocks

### I/O subsystem
- [iip-dpdk](https://github.com/yasukata/iip-dpdk): a DPDK-based backend (Linux); [how to use](https://github.com/yasukata/bench-iip#build).
- [iip-af_xdp](https://github.com/yasukata/iip-af_xdp): an AF_XDP-based backend (Linux); [how to use](https://github.com/yasukata/bench-iip#af_xdp-based-backend).
- [iip-netmap](https://github.com/yasukata/iip-netmap): a netmap-based backend (FreeBSD or Linux); [how to use](https://github.com/yasukata/bench-iip#netmap-based-backend).

### example application
- [bench-iip](https://github.com/yasukata/bench-iip): a benchmark tool.

### simulation
- [iip-ns](https://github.com/yasukata/iip-ns): a helper for running iip on the ns-3 simulator (Linux).

## getting started

Please visit an example application page at [https://github.com/yasukata/bench-iip](https://github.com/yasukata/bench-iip) for testing iip. 

## api

### callback: packet manipulation

<details>

<summary>please click here to show the list of functions</summary>

- static void * iip_ops_pkt_alloc(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return a user-specific packet (e.g., ```rte_mbuf``` in DPDK) having a pointer to a packet buffer associated with a NIC while incrementing a reference count for the packet buffer.
  - hint: conceptually equivalent to ```rte_pktmbuf_alloc``` of DPDK.
- static void iip_ops_pkt_free(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: release a packet object allocated by ```iip_ops_pkt_alloc```, and descrements the reference count for the packet buffer pointed by the passed ```pkt```; if the reference conunt becomes 0, this also has to release the packet buffer not only the packet representation data structure.
  - hint: conceptually equivalent to ```rte_pktmbuf_free``` of DPDK.
- static void * iip_ops_pkt_get_data(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return a pointer to the top address of the packet data pointed by ```pkt```.
  - hint: conceptually equivalent to ```rte_pktmbuf_mtod``` of DPDK.
- static uint16_t iip_ops_pkt_get_len(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return a length of the packet data pointed by ```pkt```.
  - hint: conceptually equivalent to returning a value of ```rte_pktmbuf_data_len``` of DPDK.
- static void iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. the length of the packet
    3. a pointer to an opaque object
  - behavior: manipulate the metadata of ```pkt``` to set ```len``` as the length of the packet.
  - hint: conceptually equivalent to setting the value of ```len``` to ```rte_pktmbuf_data_len``` of DPDK.
- static void iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. the length to increment the offset
    3. a pointer to an opaque object
  - behavior: manipulate the metadata of ```pkt``` to increment the offset from the top address of the packet buffer by the length specified by ```len```.
  - hint: conceptually equivallent to ```rte_pktmbuf_adj``` of DPDK.
- static void iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. the length to shorten the packet data length
    3. a pointer to an opaque object
  - behavior: manipulate the metadata of ```pkt``` to shorten the length of the packet by the length specified by ```len```.
  - hint: conceptually equivallent to ```rte_pktmbuf_trim``` of DPDK.
- static void * iip_ops_pkt_clone(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return a cloned packet representation structure ```pkt``` and increment the reference count to the packet buffer pointed by ```pkt```.
  - hint: conceptually equivallent to ```rte_pktmbuf_clone``` of DPDK.
- static void iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque)
  - arguments
    1. a pointer to a packet object that is the head of a packet chain
    2. a pointer to a packet object to be appended to the packet chain starting by ```pkt_head```
    3. a pointer to an opaque object
  - behavior: append ```pkt_tail``` to the packet chain whose head is ```pkt_head```.
  - hint: conceptually equivallent to ```rte_pktmbuf_chain``` of DPDK.
- static void * iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return a ponter to a packet object subsequent to ```pkt_head``` in the packet chain.
  - hint: conceptually equivallent to returning a value of ```((struct rte_mbuf *) pkt_head)->next``` of DPDK.

</details>

### callback: general utility

<details>

<summary>please click here to show the list of functions</summary>

- static void iip_ops_util_now_ns(uint32_t t[3], void *opaque)
  - arguments
    1. an array to store the obtained current time
    2. a pointer to an opaque object
  - behavior: store the current time in nanosecond to ```t[3]```, and use the array to store overflowing values.
  - note: while this interface allows to pass a nanosecond scale timestamp, the current iip implementation internally uses it in the granurarity of millisecond.

</details>

### callback: l2 information

<details>

<summary>please click here to show the list of functions</summary>

- static uint16_t iip_ops_l2_hdr_len(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return the l2 header length of the packet pointed by ```pkt```.
- static uint8_t * iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return a pointer to the source address array of the l2 header of the packet pointed by ```pkt```.
  - note
    1. the return value does not need to be on the packet buffer, and other addresses (e.g., part of a packet representation data structure) are also fine.
    2. the iip code will access the range between the returned address and the returned address + ```sizeof(uint8_t) * iip_ops_l2_hdr_len```.
    3. the iip code anticipates the lifetime of the source address array object is the same as the packet buffer pointed by ```pkt```.
- static uint8_t * iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
  - this is the same as ```iip_ops_l2_hdr_src_ptr``` except the return value having the destination address of the l2 header.
- static uint16_t iip_ops_l2_ethertype_be(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return EtherType of the packet pointed by ```pkt```.
- static uint16_t iip_ops_l2_addr_len(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return the length of a l2 header.
- static void iip_ops_l2_broadcast_addr(uint8_t bcaddr[], void *opaque)
  - arguments
    1. a pointer to an array to store the broadcast address
    2. a pointer to an opaque object
  - behavior: store the l2 broadcast address to ```bcaddr```.
  - hint: the maximum size of the ```bcaddr``` array is configured by the ```IIP_CONF_L2ADDR_LEN_MAX``` parameter.
- static void iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. l2 source address
    3. l2 destination address
    4. EtherType in big endian
    5. a pointer to an opaque object
  - behavior: apply values specified by ```src```, ```dst```, ```ethertype_be``` to the packet data pointed by ```pkt```.
- static uint8_t iip_ops_l2_skip(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return 0 if ```pkt``` should be processed by iip, and if other values are returned, iip discards ```pkt``` without checking its header.

</details>

### callback: arp information

<details>

<summary>please click here to show the list of functions</summary>

- static uint8_t iip_ops_arp_lhw(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return a value to be set to the hardware addr length field for an ARP packet sent over a network interface identified by ```opaque```.
- static uint8_t iip_ops_arp_lproto(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return a value to be set to the protocol addr length field for an ARP packet sent over a network interface identified by ```opaque```.

</details>

### callback: nic control

<details>

<summary>please click here to show the list of functions</summary>

- static void iip_ops_l2_push(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: push ```pkt``` to the TX queue of a NIC identified by ```opaque```.
  - note: while it is not mandatory, this can trigger packet transmission.
- static void iip_ops_l2_flush(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: trigger transmission of packets, queued by ```iip_ops_l2_push``` to, the TX queue of a NIC identified by ```opaque```.
- static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: trigger transmission of packets, queued by ```iip_ops_l2_push``` to, the TX queue of a NIC identified by ```opaque```.
- static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support IPv4 RX checksum, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support IPv4 TX checksum, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support TCP RX checksum, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support TCP TX checksum, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support TSO, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support UDP RX checksum, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support UDP TX checksum, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
  - arguments
    1. a pointer to an opaque object
  - behavior: return 0 if a network interface identified by ```opaque``` does not support UDP TSO, and return other value if the network interface  has the support.
- static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return 0 if the IPv4 checksum of the packet pointed by ```pkt``` is invalied, otherwise, return other value.
- static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return 0 if the TCP checksum of the packet pointed by ```pkt``` is invalied, otherwise, return other value.
- static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: return 0 if the UDP checksum of the packet pointed by ```pkt``` is invalied, otherwise, return other value.
- static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: mark the metadata of ```pkt``` to apply IPv4 TX checksum offloading at the transmison of the packet pointed by ```pkt```.
- static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: mark the metadata of ```pkt``` to apply TCP TX checksum offloading at the transmison of the packet pointed by ```pkt```.
- static void iip_ops_nic_offload_tcp_tx_tso_mark(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: mark the metadata of ```pkt``` to apply TSO at the transmison of the packet pointed by ```pkt```.
- static void iip_ops_nic_offload_udp_tx_checksum_mark(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: mark the metadata of ```pkt``` to apply UDP checksum offloading at the transmison of the packet pointed by ```pkt```.
- static void iip_ops_nic_offload_udp_tx_tso_mark(void *pkt, void *opaque)
  - arguments
    1. a pointer to a packet object
    2. a pointer to an opaque object
  - behavior: mark the metadata of ```pkt``` to apply UDP TSO at the transmison of the packet pointed by ```pkt```.

</details>

### callback: handlers for input events

<details>

<summary>please click here to show the list of functions</summary>

- static void iip_ops_arp_reply(void *context, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to a packet object: a received arp packet
    3. a pointer to an opaque object
  - note
    - invoked when an ARP reply is received.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static void iip_ops_icmp_reply(void *context, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to a packet object: a received icmp packet
    3. a pointer to an opaque object
  - note
    - invoked when an ICMP reply is received.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static uint8_t iip_ops_tcp_accept(void *context, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to a packet object: a tcp packet having the syn flag
    3. a pointer to an opaque object
  - behavior: return 0 if the system should not establish the connection (i.e., the syn is for a valid listening port), otherwise, return other value.
  - note
    - invoked when a TCP packet having the syn flag is received.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static void * iip_ops_tcp_accepted(void *context, void *handle, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. a pointer to a packet object: a tcp packet having the syn flag
    4. a pointer to an opaque object
  - behavior: return a new opaque value that will be internally associated with a new TCP connection.
  - note
    - invoked when the system accepts a new TCP connection.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static void * iip_ops_tcp_connected(void *context, void *handle, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. a pointer to a packet object: a tcp packet having the syn and ack flags
    4. a pointer to an opaque object
  - behavior: return a new opaque value that will be internally associated with a new TCP connection.
  - note
    - invoked when a TCP connection is accepted by the peer host.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static void iip_ops_tcp_payload(void *context, void *handle, void *pkt, void *tcp_opaque, uint16_t head_off, uint16_t tail_off, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. a pointer to a packet object: a tcp packet having the payload
    4. a pointer to a connection-specific opaque object allocated in either ```iip_ops_tcp_accepted``` or ```iip_ops_tcp_connected```
    5. the offset in the payload buffer to start reading
    6. the length of the tail data in the payload buffer that should not be read
    7. a pointer to an opaque object
  - note
    - invoked when a TCP payload is received.
    - ```head_off`` and ```tail_off``` are for handling TCP segments whose payloads have overlapping parts.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static void iip_ops_tcp_acked(void *context, void *handle, void *pkt, void *tcp_opaque, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. a pointer to a packet object: a tcp packet which is transmitted and acked
    4. a pointer to a connection-specific opaque object allocated in either ```iip_ops_tcp_accepted``` or ```iip_ops_tcp_connected```
    5. a pointer to an opaque object
  - note
    - invoked when a TCP ack for tramsitted data is received.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.
- static void iip_ops_tcp_closed(void *handle, uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be, void *tcp_opaque, void *opaque)
  - arguments
    1. a pointer to iip's internal TCP connection representation structure
    2. local mac address associated with the closed TCP connection
    3. local ipv4 address associated with the closed TCP connection
    4. local tcp port associated with the closed TCP connection
    5. peer mac address associated with the closed TCP connection
    6. peer ipv4 address associated with the closed TCP connection
    7. peer tcp port associated with the closed TCP connection
    8. a pointer to iip's internal TCP connection representation structure
    9. a pointer to an opaque object
  - note
    - invoked when a TCP connection is closed.
    - this is a good point to release```tcp_opaque```.
- static void iip_ops_udp_payload(void *context, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to a packet object: a udp packet having the payload
    3. a pointer to an opaque object
  - note
    - invoked when a UDP payload is received.
    - ```iip_ops_pkt_free``` will be called for ```pkt``` after this callback returns.

</details>

### for memory allocation

<details>

<summary>please click here to show the list of functions</summary>

- static uint32_t iip_workspace_size(void)
  - return the size of a context object.
- static uint32_t iip_tcp_conn_size(void)
  - return the size of a tcp connection object.
- static uint32_t iip_pb_size(void)
  - return the size of an iip-specific packet representation data structure.
- static void iip_add_tcp_conn(void *context, void *conn)
  - add ```conn``` a tcp connection object whose size is checked by ```iip_tcp_conn_size``` to a memory pool maintained in ```context```.
- static void iip_add_pb(void *context, void *p)
  - add ```p``` an iip-specific packet representation data structure whose size is checked by ```iip_pb_size``` to a memory pool maintained in ```context```.

</details>

### for active operations

<details>

<summary>please click here to show the list of functions</summary>

- static void iip_arp_request(void *context, uint8_t local_mac[], uint32_t local_ip4_be, uint32_t target_ip4_be, void *opaque)
  - arguments
    1. a pointer to a context object
    2. source mac address
    3. source ipv4 address
    4. target ipv4 address
    5. a pointer to an opaque object
  - send an ARP request packet having ```local_mac```, ```local_ip4_be```, and ```target_ip4_be``` for its fields.
- static uint16_t iip_tcp_connect(void *context, uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be, void *opaque)
  - arguments
    1. a pointer to a context object
    2. local mac address
    3. local ipv4 address
    4. local tcp port to be used
    5. destination mac address
    6. destination ipv4 address
    7. destination tcp port
    8. a pointer to an opaque object
  - try to establish a TCP connection to the specified host.
  - note: an ARP table is assumed to be maintained by users.
- static uint16_t iip_tcp_close(void *context, void *handle, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. a pointer to an opaque object
  - close a TCP connection associated with ```handle```.
- static uint16_t iip_tcp_send(void *context, void *handle, void *pkt, uint16_t tcp_flags, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. a pointer to a packet objct
    4. tcp flags
    5. a pointer to an opaque object
  - send a TCP payload, pointed by ```pkt```, over a TCP connection associated with ```handle```.
  - note: ```tcp_flags``` can be used for setting application-specific flags such as urgent.
- static void iip_tcp_rxbuf_consumed(void *context, void *handle, uint16_t cnt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. a pointer to iip's internal TCP connection representation structure
    3. the number of consumed received tcp packets
    4. a pointer to an opaque object
  - tells iip that ```cnt``` of packets are consumed by the application.
  - note: this information is used for flow control.
- static uint16_t iip_udp_send(void *context, uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be, void *pkt, void *opaque)
  - arguments
    1. a pointer to a context object
    2. local mac address
    3. local ipv4 address
    4. local udp port
    5. destination mac address
    6. destination ipv4 address
    7. destination udp port
    8. a pointer to a packet object
    9. a pointer to an opaque object
  - transmit a UDP packet having the information specified by the arguments in its fields.
- static uint16_t iip_run(void *context, uint8_t mac[], uint32_t ip4_be, void *pkt[], uint16_t cnt, uint32_t *next_us, void *opaque)
  - arguments
    1. a pointer to a context object
    2. local mac address
    3. local ipv4 address
    4. a pointer to an array of the pointers to packet objects for received packets
    5. the number of entries in the ```pkt``` array
    6. a pointer to a variable that the TCP/IP stack code will set to request the time for the next invocation
    7. a pointer to an opaque object
  - push received packets pointed through ```pkt``` to iip and run its TCP/IP processing code.
  - note
    - this fucntion assumes to be called periodically to trigger timer-based events; the next invocation time is requested through ```next_us```.
    - the ```pkt``` array does not always need to have a pointer to a packet, and empty is also fine.

</details>

### figure

<details>

<summary>please click here to show the diagram illustrating how the API works.</summary>

note: this figure focuses on the common paths of TCP processing, and does not cover exhaustive code paths.

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/fig/api.svg" width="800px">

</details>

## compilation test

The following program is to see the dependency of compilation.

<details>

<summary>please click here to show the program</summary>

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
static void     iip_ops_tcp_payload(void *mem, void *handle, void *m, void *tcp_opaque, uint16_t head_off, uint16_t tail_off, void *opaque) { (void) mem; (void) handle; (void) m; (void) tcp_opaque; (void) head_off; (void) tail_off; (void) opaque; }
static void     iip_ops_tcp_acked(void *mem, void *handle, void *m, void *tcp_opaque, void *opaque) { (void) mem; (void) handle; (void) m; (void) tcp_opaque; (void) opaque; }
static void     iip_ops_tcp_closed(void *handle, uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be, void *tcp_opaque, void *opaque) { (void) handle; (void) local_mac; (void) local_ip4_be; (void) local_port_be; (void) peer_mac; (void) peer_ip4_be; (void) peer_port_be; (void) tcp_opaque; (void) opaque; }
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

</details>

When the code above is saved in a file named ```stub.c```, the following command supposedly generates a binary ```a.out```.

```
gcc -Werror -Wextra -Wall -pedantic -m32 -std=c89 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

```
g++ -Werror -Wextra -Wall -pedantic -m32 -std=c++98 -nostartfiles -nodefaultlibs -nostdlib -nostdinc stub.c
```

Note that the program above is just for checking whether ```main.c``` can be compiled or not, and the generated binary ```a.out``` is not runnable.

## more information

### paper

A paper about iip appears at ACM SIGCOMM Computer Communication Review (CCR).

I would appreciate it if you cite this paper when you refer to iip in your work.

### presentation

The paper above is selected to be presented in [the Best of CCR session at SIGCOMM 2024](https://conferences.sigcomm.org/sigcomm/2024/ccr/).

- prerecorded video: https://youtu.be/g7iq13SymUI?si=zBj2mUqesMmKYhXv
- slides for the on-site presentation: https://yasukata.github.io/presentation/2024/08/sigcomm2024/sigcomm2024ccr_slides_yasukata.pdf

### authors' other project/paper using iip

- In a paper "Developing Process Scheduling Policies in User Space with Common OS Features" that appears at 15th ACM SIGOPS Asia-Pacific Workshop on Systems (APSys 2024), the authors leverage iip for networked server experiments : https://github.com/yasukata/priority-elevation-trick
