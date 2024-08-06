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

You can see the texts by clicking the button below; **please note that this is just for quick reference and the official publication for this work is the one issued from SIGCOMM CCR**.

<details>

<summary>click here to show the texts</summary>

## Abstract

This paper presents iip, an integratable TCP/IP stack, which aims to become a handy option for developers and researchers who wish to have a high-performance TCP/IP stack implementation for their projects. The problem that motivated us to newly develop iip is that existing performance-optimized TCP/IP stacks often incur tremendous integration complexity and existing portability-aware TCP/IP stacks have significant performance limitations. In this paper, we overhaul the responsibility boundary between a TCP/IP stack implementation and the code provided by developers, and introduce an API that enables iip to allow for easy integration and good performance simultaneously, then report performance numbers of iip along with insights on performance-critical factors.

## 1 Introduction

TCP/IP is a standardized network protocol suite, and TCP/IP stacks are software that implements the procedures to comply with the TCP/IP standard. TCP/IP stacks have been typically implemented as part of Operating System (OS) kernels. On the other hand, the hardware innovation, enabling NICs to achieve tens of Gigabit per second throughput, made it challenging for the legacy TCP/IP stack implementations to sufficiently take the performance benefit of the NICs. To address this challenge, research and industry communities have invented many performance-optimized TCP/IP stacks [1, 8, 10, 12, 17, 19, 25, 27, 29, 32, 33] and demonstrated their significant performance advantages over the legacy TCP/IP stack implementations. However, the existing performance-optimized TCP/IP stacks often incur tremendous integration complexity (§ 2.1). While there have been various portability-aware TCP/IP stack implementations [4, 5, 6, 28] that are free from the issues of the existing performance-optimized TCP/IP stacks, their performance is substantially limited because they are not sufficiently aware of performance-critical factors (§ 2.2).

**Problem.** The problem, this work addresses, is that there has been no TCP/IP stack implementation that allows for easy integration and good performance simultaneously. Consequently, developers, who wish to integrate a high-performance TCP/IP stack implementation to speed up their systems, have had limited and laborious options: for example, intensively modifying one of the existing TCP/IP stack implementations [3, 11, 13, 14, 16, 18, 21, 22, 27], building a new TCP/IP stack from scratch, accepting performance limitations of one of the existing portability-aware TCP/IP stack implementations, or giving up the integration.

**Contributions.** To address this problem, this paper presents iip, an integratable TCP/IP stack, which is designed to allow for easy integration and good performance simultaneously (§ 3). The key challenge of this work is the API design (§ 3.2); specifically, we have overhauled the responsibility boundary between a TCP/IP stack implementation and the code of developers and reexamined what should and should not be provided by a TCP/IP stack implementation to achieve high performance without introducing intolerable integration complexity. Besides these, this paper reports experiment results which show how each of the factors, the iip design takes into account, contributes to its performance (§ 4).

## 2 Previous Work

### 2.1 Performance-optimized TCP/IP Stacks

***2.1.1 Dependencies on other components***

Existing performance-optimized TCP/IP stacks typically introduce many dependencies on CPU architectures, NICs, OSes, libraries, and compilers, and these dependencies often substantially diminish the integratability of the TCP/IP stacks. For example, the paper about the Luna [33] TCP/IP stack says that the authors gave up the use of existing performance-optimized TCP/IP stacks and decided to build Luna from scratch because the existing implementations have compatibility issues: VPP [1] is not well-compatible with Mellanox NICs, and IX [3] depends on the Dune [2] kernel module which works only on specific versions of the Linux kernel and relies on outdated Intel NIC drivers. Another example, indicating the significance of this issue, is that many tailor-made performance-optimized networked systems [3, 11, 13, 14, 16, 18, 21, 22] do not employ existing performance-optimized TCP/IP stacks, instead, they take one of the existing portability-aware TCP/IP stacks, such as lwIP [5], as the basement of their TCP/IP processing components and intensively modify the code base of it to mitigate its performance issues (§ 2.2).

***2.1.2 Functionality conflicts***

In many cases, existing performance-optimized TCP/IP stacks are proposed as part of an application development framework [19, 25, 27] or a new OS [3, 21, 32] having various functionalities such as a specific thread runtime. The issue is that their TCP/IP stack components often depend on such extra facilities, and they cause functionality conflicts that make it difficult for developers to integrate the TCP/IP stack components into other systems. For example, when developers wish to use a TCP/IP stack implementation of a specific application development framework and integrate it into a particular new OS, if the TCP/IP stack relies on a framework-specific thread runtime and the new OS also has its specific thread runtime, the developers face a functionality conflict caused by the two independent thread runtimes; as a result, the developers cannot use the TCP/IP stack of the application development framework on the new OS, as long as they do not modify either the TCP/IP stack or the new OS, because two thread runtimes normally cannot coexist on a single system.

***2.1.3 Limited choices for CPU core assignment models***

There are three CPU core assignment models for threads executing networking and application logic; we borrow the terms from a previous study [30] and call them split, merge, and unified, respectively:

-   **Split.** The split model runs the networking logic and the application logic on two different threads, and dedicates a CPU core to each of the threads. The setup of this model requires at least two CPU cores, and in multi-core environments, the numbers of CPU cores preserved for the networking and application logic are typically configured by users.

-   **Merge.** The merge model runs the networking logic and the application logic on two different threads similarly to the split model, but executes the two threads on the same CPU core; this model can be applied for a single CPU core at minimum, and in multi-core environments, the single CPU core setup, having a pair of the threads executing networking and application logic on the same CPU core, is duplicated to available CPU cores.

-   **Unified.** The unified model executes the networking and application logic on the same thread. Similarly to the merge model, one CPU core is the minimum number of CPU cores necessary for the setup of this model, and multi-core environments duplicate the single CPU core setup for available CPU cores.

These models have different properties in the following aspects:

-   **CPU utilization.** The split model, where the threads executing networking and application logic run on two different CPU cores, leads to low CPU utilization because it introduces a CPU resource boundary that prohibits the two threads from yielding unused CPU cycles to each other; this means that even if one of the two threads is fully busy and the other thread is occasionally idle and has unused CPU cycles, the busy thread cannot take over the unused CPU cycles from the other thread. Contrarily, the merge and unified models, which execute the networking and application logic on the same CPU core, make no CPU resource boundary between the networking and application logic, and these two can yield unused CPU cycles to each other; consequently, these two models can achieve higher CPU utilization than the split model.

-   **Inter-thread communication overhead.** The split and merge models use two threads for executing networking and application logic, therefore, they impose the inter-thread communication overhead, and that of the merge model tends to be higher compared to the split model because the merge model executes two threads on the same CPU core, and every transition between the execution of networking and application logic requires a context switch that incurs comparatively high CPU overhead, on the other hand, in the split model, the context switch is not necessary for the transition between the two threads because these two run on different CPU cores. However, the split model imposes a different type of overhead; the speed of data movement between the two threads is limited by the hardware-level synchronization necessary to ensure the cache coherency between the two CPU cores. Besides these, the unified model is free from these overheads because it does not split the execution of networking and application logic into different threads.

The issue is that many existing performance-optimized TCP/IP stacks do not allow developers to freely choose a desired CPU core assignment model; for example, mTCP [10] does not allow developers to choose the unified model, and TAS [12] only accepts the split model. Because of this issue, it is often difficult for developers to integrate existing performance-optimized TCP/IP stacks into other systems in a performance-optimal manner (§ 4.2).

### 2.2 Portability-aware TCP/IP Stacks

***2.2.1 Unaware of NIC hardware offloading features***

In workloads involving bulk data transfer, we found that the commonly available NIC offloading features, particularly checksum offloading and TCP Segmentation Offload (TSO), are essential to effectively utilize high-speed links (§ 4.3). However, the existing portability-aware TCP/IP stacks are not aware of the NIC offloading features even if they are available, consequently, their bulk data transfer performance is substantially limited. Moreover, other commonly available offloading features, such as scatter-gather and Receive Side Scaling (RSS), are necessary for zero-copy transmission (§ 2.2.2) and multi-core scalability (§ 2.2.3), but, mainly due to the lack of awareness of NIC offloading features, the existing portability-aware TCP/IP stacks do not offer them. We note that modifying an existing portability-aware TCP/IP stack to employ the NIC offloading features is often complicated because, to effectively utilize them, the foundational components, such as the packet management mechanism and the API, should take the availability of NIC offloading features into account as of the design phase of the TCP/IP stack.

***2.2.2 Lack of zero-copy I/O capability***

In bulk data transfer workloads, zero-copy I/O is important for CPU cache efficiency (§ 4.3). Nevertheless, many existing portability-aware TCP/IP stacks do not support zero-copy I/O. One of the reasons for this is that they often maintain packet data on internal buffers which are managed independently of a NIC I/O subsystem; consequently, they require memory copies between their internal buffers and the packet buffers associated with a NIC. Another reason is, as described in § 2.2.1, the lack of awareness of NIC offloading features; particularly, the scatter-gather feature of NIC hardware, which enables TCP/IP stacks to instantiate a packet header and a payload on non-contiguous memory addresses, is necessary for an ideal zero-copy transmission mechanism, which can concurrently send the same payload to different hosts, to avoid the conflicts at the header space adjacent to the payload data on the memory.

***2.2.3 Lack of multi-core scalability***

For workloads that exchange small messages, we find that multiple CPU cores are necessary to sufficiently take the performance benefit of high-speed NICs (§ 4.1). However, the existing portability-aware TCP/IP stacks are not designed to scale their performance on multi-core machines; for example, lwIP [5]’s internal data manipulation does not pay attention to thread safety, and FNET [4] and picoTCP [28] employ heavy locks for concurrency coordination. Moreover, as mentioned in § 2.2.1, they are not aware of the RSS feature of NIC hardware which allows for affinity-aware packet steering where packets for a certain TCP connection are always received at a specific NIC receive queue although the previous work [7, 10, 15, 20, 25] demonstrated that the NIC-based affinity-aware packet steering enables TCP/IP stacks to reduce data exchanges between different CPU cores and contributes to multi-core scalability.

## 3 Design

### 3.1 Overview

***3.1.1 Dependencies***

To address the dependency issue discussed in § 2.1.1, iip pays attention to the following:

-   **Programming language selection.** An inevitable dependency point is the programming language. We decided to implement iip in the C programming language because C is one of the most widely used programming languages and there are many full-blown C compilers for varied computation environments. The implementation of iip complies with the C89 standard so that old and future versions of C compilers can compile the source code of iip. We also pay attention to the compatibility with the C++98 standard so that iip can be integrated into C++-based systems.

-   **Indirection for using external facilities.** To minimize dependencies on other components, iip does not directly employ features specific to CPU architectures, NICs, OSes, libraries, and compilers; consequently, the compilation of the iip code base does not require external libraries, including libc, and relevant header files. The approach, to enabling the TCP/IP processing code of iip to access platform-dependent features without introducing dependencies, is to define, as iip’s API specification (§ 3.2), a set of functions that are the wrappers to access platform-dependent functionalities and assume to be provided by developers.

We note that iip does not depend even on a standardized API such as POSIX, therefore, it can be integrated into systems that are governed by a specialized runtime or a new OS and do not comply with a standardized interface.

***3.1.2 Functionality***

To minimize the chance of causing the functionality conflict issue described in § 2.1.2, iip only implements the functionality of TCP/IP processing, and as mentioned in § 3.1.1, it does not depend on specific external components except the C programming language. On the other hand, developers, considering the use of iip, should be aware that iip can become a conflict point when the developers’ code, which depends on iip, has to be integrated with a system that relies on another TCP/IP stack implementation. Therefore, our recommendation for developers is to implement an abstraction layer to access networking features by themselves and let their code access the features of iip through it so that they can easily replace iip with another TCP/IP stack implementation at the level of the abstraction layer.

***3.1.3 CPU core assignment models***

As discussed in § 2.1.3, many existing performance-optimized TCP/IP stacks do not allow developers to freely choose the CPU core assignment model although the model selection has a significant impact on application performance (§ 4.2). The root cause of this issue is that they implement the loops that execute their TCP/IP processing code, and developers cannot customize the behavior of the hard-coded loops although, to apply the unified model, developers need to colocate both the networking and application logic in the same loop (§ 2.1.3). To avoid this issue, iip does not implement a loop to execute its TCP/IP processing code, instead, iip only offers functions to be called in a thread so that developers can embed them into an arbitrary thread which is provided by the developers (§ 3.2).

***3.1.4 Use of NIC hardware offloading features***

As described in § 2.2.1, NIC hardware offloading features are essential for TCP/IP stacks to achieve high performance (§ 4). One of the main reasons why the existing portability-aware TCP/IP stacks do not leverage NIC hardware offloading features is that they are specific to NICs and less generic compared to the simple network I/O functionality. While iip also does not cover all offloading features of existing NICs, it leverages commonly available NIC offloading features, such as checksum, scatter-gather, TSO, and Large Receive Offload (LRO) if they are available; iip defines, as part of its API, callbacks to be implemented by developers (§ 3.2.2) to leverage the NIC offloading features without introducing dependencies on NICs (§ 3.1.1).

***3.1.5 Zero-copy I/O capability***

As discussed in § 2.2.2, zero-copy I/O capability is important for TCP/IP stacks to achieve high performance for bulk data transfer workloads (§ 4.3). To offer zero-copy I/O capability, iip pays attention to the following:

-   **Packet buffer allocation.** In the API of iip, developers are responsible for implementing the allocator for packet buffers associated with a NIC (§ 3.2.2). This means that developers can instantiate packet buffers, associated with a NIC, in arbitrary memory address space, and can perform zero-copy I/O by putting packet buffers in the memory address space that their application logic can directly access.

-   **Scatter-gather feature of NIC hardware.** As discussed in § 2.2.2, a zero-copy transmission mechanism, which can concurrently send the same payload, has to avoid the contention for the header space adjacent to the payload data. To realize this, iip does not use the adjacent space of payload data for putting its header, and instantiates a header on an independent memory address and assembles these two at the packet transmission using the scatter-gather feature of NIC hardware (§ 3.2.3).

***3.1.6 Multi-core scalability***

As described in § 2.2.3, multi-core scalability is crucial for taking the performance benefit of high-speed NICs (§ 4.1). For multi-core scalability, similar to the previous work [7, 10, 15, 20, 25], iip minimizes the contention for the access to in-memory objects shared across multiple CPU cores by dedicating in-memory objects, such as the queue of accepted TCP connections, to each CPU core. To realize this without introducing dependencies (§ 3.1.1), particularly on a memory allocator and a thread runtime, iip assumes the assistance of developers through a data structure representing the context of TCP/IP processing which is defined as part of the API (§ 3.2.1). We implement the TCP/IP processing code of iip to be stateless and the states of protocol processing are maintained through the context object, and iip assumes that developers feed a dedicated context object to a thread executing the TCP/IP processing code of iip; since it only manipulates a fed context object, the threads do not experience contentions for the access to shared in-memory objects while executing iip’s TCP/IP processing code. On the other hand, this approach requires packets for a certain TCP connection to be steered to the same thread because, on the entire system, there is only one thread that has the in-memory object representing the TCP connection and it is not shared with the other threads, therefore, iip assumes that developers steer received packets to a certain thread in an affinity-aware manner, for example, by using the RSS feature of a NIC (§ 2.2.3).

### 3.2 API

The API of iip defines a set of callback functions to be implemented by developers (§ 3.2.2) and functions to be provided by iip(§ 3.2.3); from the point of view of developers, the entry point for the execution of the iip code is the functions provided by iip, and they internally call the callback functions implemented by developers.

***3.2.1 Common arguments***

The following objects are the common arguments passed between developers’ code and the API of iip:

-   **Context object.** As described in § 3.1.6, the TCP/IP processing code of iip itself is stateless, and the states of protocol processing, such as the states of TCP connections, are associated with a context object. iip assumes that developers allocate a dedicated context object and feed it to each thread executing the TCP/IP processing code of iip; we note that the developers’ code just needs to pass the pointer to the context object to the API of iip and does not need to recognize the content of the context object. As a side note, while this context object is mainly designed for multi-core scalability (§ 3.1.6), iip’s context-based TCP/IP processing is beneficial to the integration with simulators such as ns-3 [24] and specifically allows a simulator process to instantiate multiple nodes installing iip in the same memory address space without using extra tricks such as dlmopen applied in the Direct Code Execution (DCE) [26] framework.

-   **Packet object.** To avoid introducing dependencies (§ 3.1.1) on a packet representation data structure, the API of iip offers an abstraction to intermediate packet representation between developers’ code and the TCP/IP processing code of iip; the developers’ code, through the arguments of functions, passes the pointers to packet objects, whose representation data structure is defined by developers, to the TCP/IP processing code of iip, and iip wraps each of the passed pointers by an iip-specific packet representation data structure. We note that the developers’ code does not need to know the content of this iip-specific packet representation data structure, and iip is also agnostic on the packet representation used in the code of the developers. Internally, iip processes packets based on the iip-specific representation. To manipulate packet representation data structures specific to developers’ code, iip defines callback functions, to be implemented by developers, that allow iip’s TCP/IP processing code to indirectly apply settings, such as the packet data length, to developer-specific packet representation data structures (§ 3.2.2).

-   **Opaque object.** For the flexibility of callback function development (§ 3.2.2), each of the functions defined by the API of iip takes a pointer to an opaque object which can be an arbitrary object instantiated by the developers’ code, and when the code of iip invokes a callback function implemented by the developers, the pointer to the opaque object is passed to the callback; the developers can employ the pointer to an opaque object to implement their specific logic in a callback function.

***3.2.2 Callback functions to be implemented by developers***

iip assumes that developers implement the following callback functions:

-   **Generic memory allocator.** The generic memory allocator, whose functionalities are represented by malloc and free of the standard C library, depends on platforms because its low-level operations leverage OS-specific system calls, such as mmap, and its high-level free space management typically involves CPU-specific atomic operations for accepting concurrent memory allocation requests on multi-core machines; therefore, iip assumes the generic memory allocator is provided by developers. Internally, the TCP/IP processing code of iip employs the provided callback functions to, for example, allocate and release iip-specific packet representation data structures (§ 3.2.1).

-   **NIC control.** The NIC control, including the capabilities to transmit a packet and access the NIC offloading features, is platform-dependent and, thus, is assumed to be provided by developers.

-   **Packet management.** As discussed in § 3.2.1, packet representation can be specific to developers’ code; therefore, iip assumes that developers provide callbacks to allocate, release, and manipulate packet representation data structures specific to the code of the developers. Internally, iip’s TCP/IP processing code uses these provided callback functions to allocate and manipulate the developer-specific packet representation data structures to be passed to other callback functions implemented by the developers, and release the developer-specific packet representation data structures which are pushed from the developers’ code through the functions provided by iip(§ 3.2.3). Along with this, as described in § 3.1.5, developers are expected to provide a packet buffer allocator and implement callbacks to access the features of it; the TCP/IP processing code of iip uses them mainly to allocate packet buffers to put the data to be transmitted and to release consumed packet buffers. These packet management features, to be provided by developers, are assumed to maintain a reference count for each object that they manage so that, for example, multiple packet representation data structures can point to the same packet buffer and it will be released only when no pointer references it anymore; this behavior is particularly needed to allow iip to make shallow copies of a packet by duplicating packet representation data structures pointing to the same packet buffer.

-   **Generic utilities.** iip assumes that generic platform-dependent utilities, such as a function to get the current time, are offered by developers through callback functions.

-   **Input event handling.** The API of iip defines a series of callback functions that are invoked for different types of incoming events such as accepting a new TCP connection and receiving a TCP payload. Developers can implement application-specific logic, such as parsing a received TCP payload to figure out an embedded request and sending back a TCP payload as the response to the request, in these callback functions.

***3.2.3 Functions provided by iip***

iip implements the following:

-   **Periodic invocation of the code of iip.** As described in § 3.1.3, iip does not implement a loop to execute its TCP/IP processing code, in other words, it does not maintain a thread to invoke timer-based events such as TCP retransmission timeout. To cope with this issue, iip implements a function assumed to be called by a thread provided by developers at certain intervals; this function requests the time for the next invocation through a variable whose pointer is passed as the argument for this function.

-   **Push received packets to iip.** iip offers a function that allows developers’ code to push received packets to the TCP/IP processing facility of iip; many of the callbacks for input event handling (§ 3.2.2) are called in this function.

-   **Operations involving packet transmission.** iip offers functions to transmit packets over specific network protocols; for example, sending ARP, ICMP, TCP, and UDP data, trying to establish a TCP connection, and closing a TCP connection. Developers can use these functions to implement application-specific logic. The payload transmission will be conducted in a zero-copy fashion if iip finds, using the callback function described in § 3.2.2, that the NIC supports the scatter-gather feature. For a zero-copy payload transmission, internally, iip’s TCP/IP processing code first calls the callback function (§ 3.2.2) to allocate a new packet buffer, and crafts a packet header on it, then, sends the crafted header with the payload, passed from the developers’ code, over the NIC; in this procedure, the header and the payload are put on non-contiguous memory addresses and these two are concatenated by the scatter-gather feature of the NIC at the packet transmission. As seen here, iip does not use the adjacent space of the payload for putting its header, therefore, it can avoid the header space contention issue which is described in § 2.2.2.

### 3.3 Limitations

We discuss the limitations of iip.

**Integration overhead.** The typical integration steps for iip are to implement the callback functions wrapping the access to platform-specific facilities (§ 3.2.2), develop a function to be executed by a thread that pulls packets from a NIC and pushes them to iip using the API while calling the function assuming to be invoked periodically to trigger timer-based events (§ 3.2.3), and implement application-specific logic in the callbacks for input events (§ 3.2.2). We think that engineering for these steps is not too costly because many callback functions just need to proxy the operation requests to underlying platform-specific functions.

**Compatibility with existing programs.** iip does not comply with the networking APIs of major OSes such as the POSIX socket, therefore, it is not compatible with existing programs made for the widely used OSes. A potential approach to obtain compatibility with existing programs is to apply iip through a software layer that emulates networking-relevant system calls using a system call hook mechanism such as the LD_PRELOAD trick and zpoline [31].

**Maturity of the implementation.** iip is made from scratch, therefore, its implementation is less mature compared to the existing legacy TCP/IP stacks. However, we believe that the primary matter is the time spent on development and we can enhance the quality of the iip implementation by continuous improvement.

## 4 Evaluation

This section reports the performance numbers of iip.

***Figure 1: Performance for a TCP ping-pong workload which exchanges 1-byte payloads.***

***(a) Throughput according to the number of CPU cores (§ 4.1)***

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/paper/ccr/fig1a.svg" width="500px">

***(b) 99th percentile latency and throughput of the 32 CPU core case (§ 4.1)***

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/paper/ccr/fig1b.svg" width="500px">

***(c) 99th percentile latency and throughput of the three CPU core assignment models (§ 2.1.3) for the 2 CPU core case (§ 4.2)***

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/paper/ccr/fig1c.svg" width="500px">

***Figure 2: TCP bulk data transfer throughput (§ 4.3).***

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/paper/ccr/fig2.svg" width="500px">

**Experiment setup.** For the experiments, we use two machines; each machine has two 16-core Intel Xeon Gold 6326 CPUs clocked at 2.90 GHz and 128 GB of DRAM. The two machines are directly connected via Mellanox ConnectX-5 100 Gbps NICs. Both machines install Linux 6.2. The benchmark programs use iip for TCP/IP processing and leverage Data Plane Development Kit (DPDK) [9] to perform packet I/O over the NICs. We refer to a setup, that adopts the unified model (§ 2.1.3) and activates all of the commonly available NIC offloading features along with zero-copy I/O, as the default setup, and we apply it on both machines unless otherwise stated. In all cases, the number of NIC queues is the same as the number of threads executing the networking logic, and we activate the RSS feature of NIC hardware to distribute incoming packets to the multiple NIC queues in an affinity-aware manner (§ 3.1.6).

### 4.1 Small Message Exchange

We evaluate the multi-core scalability of iip(§ 3.1.6) using a workload that exchanges small messages (§ 2.2.3).

**Benchmark.** We run a TCP ping-pong workload; we use one of the two machines to run a pinger process and the other machine executes a ponger process, and they exchange 1-byte TCP payloads as quickly as possible. In this experiment, the pinger process uses 32 CPU cores and adopts the unified model described in § 2.1.3 for its CPU core assignment model, and the ponger process also adopts the unified model. We run the benchmark while changing the number of CPU cores assigned to the ponger process.

[**Throughput results.**](https://github.com/yasukata/bench-iip/tree/9cf2488ec93ae51f4bd7b18923a5d1a233852f66?tab=readme-ov-file#multi-core-server-performance) For the throughput measurement, we configure the number of TCP connections established between the pinger and ponger processes so that each thread of the ponger process will handle 32 concurrent TCP connections. Figure 1a reports the results. In the default setup, iip achieves 2.9 and 72.3 million requests per second using 1 CPU core and 32 CPU cores, respectively. When the ponger deactivates zero-copy transmission by disabling the scatter-gather feature of the NIC and configures iip to perform memory copies between the memory regions maintained by the application logic and the packet buffers allocated in the TCP/IP processing code of iip, we observe slightly better throughput compared to the default setup; while this result is not intuitive, a previous study [23] reports the similar trend and explains that the software overhead necessary for the use of the scatter-gather feature of a NIC is more costly than the memory copy particularly when the size of the packet to be sent is small. When we disable the checksum offloading feature of the NIC on the ponger side, we observe 11~26% throughput degradation compared to the default setup case.

[**Latency results.**](https://github.com/yasukata/bench-iip/tree/9cf2488ec93ae51f4bd7b18923a5d1a233852f66?tab=readme-ov-file#32-core-server-latency) We have measured the latency to exchange the 1-byte TCP payload for the case where the ponger process has 32 CPU cores while changing the number of TCP connections. Figure 1b reports the 99th percentile latency along with the observed throughput. Similarly to the throughput test above, we observe, compared to the default setup, slightly better performance when zero-copy transmission is disabled, and lower performance when the checksum offloading feature of the NIC is deactivated.

### 4.2 CPU Core Assignment Models

We quantify the effect of the CPU core assignment models (§ 3.1.3).

**Benchmark.** We use the same TCP ping-pong workload used in § 4.1; we run it with different configurations where the ponger process uses 2 CPU cores and adopts the split and merge models, and compare the default setup adopting the unified model with them. In the cases of the split and merge models, the two threads communicate with each other over message queues. In the split model case, each thread continuously monitors the message queue in its primary loop to detect a new message pushed by the other thread. In the merge model case, the thread executing the application logic enters the sleep state to yield CPU cycles to the thread for networking when it has no data to be processed, and the thread executing the networking logic wakes it up using the event notification mechanism provided by the kernel after pushing a message to the message queue; to ensure that the thread for the application logic can continue to run while it has the data to be processed, we configure the thread for the application logic to have a higher scheduling priority than the thread executing the networking logic.

[**Results.**](https://github.com/yasukata/bench-iip/tree/9cf2488ec93ae51f4bd7b18923a5d1a233852f66?tab=readme-ov-file#separate-threads-for-networking-and-app-logic) Figure 1c shows the 99th percentile latency versus throughput results. When the offered load is small, the split model exhibits lower latency compared to the merge model because the split model does not incur the context switch for the transition of the execution of networking and application logic. On the other hand, the merge model achieves higher throughput compared to the split model when the offered load is increased; this is because the merge model does not have the CPU resource boundary which prohibits, in the split model, the networking and application logic from yielding unused CPU cycles to each other. Besides these, the unified model is free from both of the issues, consequently, it achieves the best performance among these three cases.

### 4.3 Bulk Data Transfer

We examine the effect of each NIC offloading feature (§ 3.1.4) through a bulk data transfer workload.

**Benchmark.** We use one of the two machines as a receiver and the other as a sender, and we use a single CPU core on each machine. These two establish a single TCP connection; for each case, the sender repeatedly sends a certain size of data, which is located in memory, to the receiver as fast as possible. Along with the default setup, we run this benchmark with five configurations: turning off 1) the scatter-gather feature of the NIC to disable zero-copy transmission on the sender side, 2) TSO on the sender, 3) both TSO and checksum offloading on the sender, 4) LRO on the receiver, and 5) checksum offloading on the receiver side.

[**Results.**](https://github.com/yasukata/bench-iip/tree/9cf2488ec93ae51f4bd7b18923a5d1a233852f66?tab=readme-ov-file#bulk-transfer) The throughput results are reported in Figure 2. The default setup almost reaches the NIC bandwidth limit. We found that the effect of zero-copy transmission, enabled by the scatter-gather feature of the NIC, gets bigger when the data size becomes larger; according to this result, we consider that zero-copy transmission mitigates the use of the CPU cache space, consequently, it leads to higher throughput particularly when the size of the data to be transferred is large. We observed that the throughput is almost halved once TSO is disabled, and when the sender additionally disables the checksum offloading feature of the NIC, the throughput goes down to just 10% of the default setup case. We did not see throughput degradation when LRO was turned off on the receiver side; note that this result does not mean that LRO does not contribute to the performance, and this only indicates that the receiver was fast enough without LRO, particularly for this workload. Similarly to the sender case, when the receiver turns off the checksum offloading feature of the NIC, we observe that the throughput goes down to approximately 10% of the default setup case.

## 5 Conclusion

This paper has presented iip, an integratable TCP/IP stack, which aims to become a handy option for developers and researchers who wish to have a high-performance TCP/IP stack implementation for their projects. We plan to make continuous maintenance and improvement efforts so that iip can be widely accepted by users.

## References

- [1] David Richard Barach and Eliot Dresselhaus. 2011. Vectorized software packet forwarding. Patent No. US7961636B1, Filed May 27th., 2004, Issued Jun 14th., 2011.
- [2] Adam Belay, Andrea Bittau, Ali Mashtizadeh, David Terei, David Mazières, and Christos Kozyrakis. 2012. Dune: Safe User-level Access to Privileged CPU Features. In 10th USENIX Symposium on Operating Systems Design and Implementation (OSDI 12). USENIX Association, Hollywood, CA, 335–348. https://www.usenix.org/conference/osdi12/technical-sessions/presentation/belay
- [3] Adam Belay, George Prekas, Ana Klimovic, Samuel Grossman, Christos Kozyrakis, and Edouard Bugnion. 2014. IX: A Protected Dataplane Operating System for High Throughput and Low Latency. In 11th USENIX Symposium on Operating Systems Design and Implementation (OSDI 14). USENIX Association, Broomfield, CO, 49–65. https://www.usenix.org/conference/osdi14/technical-sessions/presentation/belay
- [4] Andrej Butok. 2005. FNET. https://fnet.sourceforge.io/.
- [5] Adam Dunkels. 2003. Full TCP/IP for 8-bit architectures. In Proceedings of the 1st International Conference on Mobile Systems, Applications and Services (San Francisco, California) (MobiSys ’03). Association for Computing Machinery, New York, NY, USA, 85–98. https://doi.org/10.1145/1066116.1066118
- [6] egnite Software GmbH. 2001. Ethernut. http://www.ethernut.de/.
- [7] Sangjin Han, Scott Marshall, Byung-Gon Chun, and Sylvia Ratnasamy. 2012. MegaPipe: A New Programming Interface for Scalable Network I/O. In 10th USENIX Symposium on Operating Systems Design and Implementation (OSDI 12). USENIX Association, Hollywood, CA, 135–148. https://www.usenix.org/conference/osdi12/technical-sessions/presentation/han
- [8] Michio Honda, Felipe Huici, Costin Raiciu, Joao Araujo, and Luigi Rizzo. 2014. Rekindling network protocol innovation with user-level stacks. SIGCOMM Comput. Commun. Rev. 44, 2 (apr 2014), 52–58. https://doi.org/10.1145/2602204.2602212
- [9] Intel. 2010. Data Plane Development Kit. https://www.dpdk.org/.
- [10] EunYoung Jeong, Shinae Wood, Muhammad Jamshed, Haewon Jeong, Sunghwan Ihm, Dongsu Han, and KyoungSoo Park. 2014. mTCP: a Highly Scalable User-level TCP Stack for Multicore Systems. In 11th USENIX Symposium on Networked Systems Design and Implementation (NSDI 14). USENIX Association, Seattle, WA, 489–502. https://www.usenix.org/conference/nsdi14/technical-sessions/presentation/jeong
- [11] Kostis Kaffes, Timothy Chong, Jack Tigar Humphries, Adam Belay, David Mazières, and Christos Kozyrakis. 2019. Shinjuku: Preemptive Scheduling for μsecond-scale Tail Latency. In 16th USENIX Symposium on Networked Systems Design and Implementation (NSDI 19). USENIX Association, Boston, MA, 345–360. https://www.usenix.org/conference/nsdi19/presentation/kaffes
- [12] Antoine Kaufmann, Tim Stamler, Simon Peter, Naveen Kr. Sharma, Arvind Krishnamurthy, and Thomas Anderson. 2019. TAS: TCP Acceleration as an OS Service. In Proceedings of the Fourteenth EuroSys Conference 2019 (Dresden, Germany) (EuroSys ’19). Association for Computing Machinery, New York, NY, USA, Article 24, 16 pages. https://doi.org/10.1145/3302424.3303985
- [13] Simon Kuenzer, Vlad-Andrei Bădoiu, Hugo Lefeuvre, Sharan Santhanam, Alexander Jung, Gaulthier Gain, Cyril Soldani, Costin Lupu, Ştefan Teodorescu, Costi Răducanu, Cristian Banu, Laurent Mathy, Răzvan Deaconescu, Costin Raiciu, and Felipe Huici. 2021. Unikraft: fast, specialized unikernels the easy way. In Proceedings of the Sixteenth European Conference on Computer Systems (Online Event, United Kingdom) (EuroSys ’21). Association for Computing Machinery, New York, NY, USA, 376–394. https://doi.org/10.1145/3447786.3456248
- [14] Simon Kuenzer, Anton Ivanov, Filipe Manco, Jose Mendes, Yuri Volchkov, Florian Schmidt, Kenichi Yasukata, Michio Honda, and Felipe Huici. 2017. Unikernels Everywhere: The Case for Elastic CDNs. In Proceedings of the 13th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (Xi’an, China) (VEE ’17). Association for Computing Machinery, New York, NY, USA, 15–29. https://doi.org/10.1145/3050748.3050757
- [15] Xiaofeng Lin, Yu Chen, Xiaodong Li, Junjie Mao, Jiaquan He, Wei Xu, and Yuanchun Shi. 2016. Scalable Kernel TCP Design and Implementation for Short-Lived Connections. In Proceedings of the Twenty-First International Conference on Architectural Support for Programming Languages and Operating Systems (Atlanta, Georgia, USA) (ASPLOS ’16). Association for Computing Machinery, New York, NY, USA, 339–352. https://doi.org/10.1145/2872362.2872391
- [16] Filipe Manco, Costin Lupu, Florian Schmidt, Jose Mendes, Simon Kuenzer, Sumit Sati, Kenichi Yasukata, Costin Raiciu, and Felipe Huici. 2017. My VM is Lighter (and Safer) than your Container. In Proceedings of the 26th Symposium on Operating Systems Principles (Shanghai, China) (SOSP ’17). Association for Computing Machinery, New York, NY, USA, 218–233. https://doi.org/10.1145/3132747.3132763
- [17] Ilias Marinos, Robert N.M. Watson, and Mark Handley. 2014. Network stack specialization for performance. In Proceedings of the 2014 ACM Conference on SIGCOMM (Chicago, Illinois, USA) (SIGCOMM ’14). Association for Computing Machinery, New York, NY, USA, 175–186. https://doi.org/10.1145/2619239.2626311
- [18] Joao Martins, Mohamed Ahmed, Costin Raiciu, Vladimir Olteanu, Michio Honda, Roberto Bifulco, and Felipe Huici. 2014. ClickOS and the Art of Network Function Virtualization. In 11th USENIX Symposium on Networked Systems Design and Implementation (NSDI 14). USENIX Association, Seattle, WA, 459–473. https://www.usenix.org/conference/nsdi14/technical-sessions/presentation/martins
- [19] Amy Ousterhout, Joshua Fried, Jonathan Behrens, Adam Belay, and Hari Balakrishnan. 2019. Shenango: Achieving High CPU Efficiency for Latency-sensitive Datacenter Workloads. In 16th USENIX Symposium on Networked Systems Design and Implementation (NSDI 19). USENIX Association, Boston, MA, 361–378. https://www.usenix.org/conference/nsdi19/presentation/ousterhout
- [20] Aleksey Pesterev, Jacob Strauss, Nickolai Zeldovich, and Robert T. Morris. 2012. Improving network connection locality on multicore systems. In Proceedings of the 7th ACM European Conference on Computer Systems (Bern, Switzerland) (EuroSys ’12). Association for Computing Machinery, New York, NY, USA, 337–350. https://doi.org/10.1145/2168836.2168870
- [21] Simon Peter, Jialin Li, Irene Zhang, Dan R. K. Ports, Doug Woos, Arvind Krishnamurthy, Thomas Anderson, and Timothy Roscoe. 2014. Arrakis: The Operating System is the Control Plane. In 11th USENIX Symposium on Operating Systems Design and Implementation (OSDI 14). USENIX Association, Broomfield, CO, 1–16. https://www.usenix.org/conference/osdi14/technical-sessions/presentation/peter
- [22] George Prekas, Marios Kogias, and Edouard Bugnion. 2017. ZygOS: Achieving Low Tail Latency for Microsecond-scale Networked Tasks. In Proceedings of the 26th Symposium on Operating Systems Principles (Shanghai, China) (SOSP ’17). Association for Computing Machinery, New York, NY, USA, 325–341. https://doi.org/10.1145/3132747.3132780
- [23] Deepti Raghavan, Shreya Ravi, Gina Yuan, Pratiksha Thaker, Sanjari Srivastava, Micah Murray, Pedro Henrique Penna, Amy Ousterhout, Philip Levis, Matei Zaharia, and Irene Zhang. 2023. Cornflakes: Zero-Copy Serialization for Microsecond-Scale Networking. In Proceedings of the 29th Symposium on Operating Systems Principles (Koblenz, Germany) (SOSP ’23). Association for Computing Machinery, New York, NY, USA, 200–215. https://doi.org/10.1145/3600006.3613137
- [24] George F. Riley and Thomas R. Henderson. 2010. The ns-3 Network Simulator. Springer Berlin Heidelberg, Berlin, Heidelberg, 15–34. https://doi.org/10.1007/978-3-642-12331-3_2
- [25] Cloudius Systems. 2014. Seastar. http://www.seastar-project.org/.
- [26] Hajime Tazaki, Frédéric Uarbani, Emilio Mancini, Mathieu Lacage, Daniel Camara, Thierry Turletti, and Walid Dabbous. 2013. Direct code execution: revisiting library OS architecture for reproducible network experiments. In Proceedings of the Ninth ACM Conference on Emerging Networking Experiments and Technologies (Santa Barbara, California, USA) (CoNEXT ’13). Association for Computing Machinery, New York, NY, USA, 217–228. https://doi.org/10.1145/2535372.2535374
- [27] Tencent. 2017. F-Stack. https://www.f-stack.org/.
- [28] Maxime Vincent. 2014. PicoTCP: the reference TCP/IP stack for IoT. In FOSDEM 2014 (Brussels, Belgium). https://archive.fosdem.org/2014/schedule/event/deviot03/
- [29] Kenichi Yasukata, Michio Honda, Douglas Santry, and Lars Eggert. 2016. StackMap: Low-Latency Networking with the OS Stack and Dedicated NICs. In 2016 USENIX Annual Technical Conference (USENIX ATC 16). USENIX Association, Denver, CO, 43–56. https://www.usenix.org/conference/atc16/technical-sessions/presentation/yasukata
- [30] Kenichi Yasukata, Felipe Huici, Vincenzo Maffione, Giuseppe Lettieri, and Michio Honda. 2017. HyperNF: building a high performance, high utilization and fair NFV platform. In Proceedings of the 2017 Symposium on Cloud Computing (Santa Clara, California) (SoCC ’17). Association for Computing Machinery, New York, NY, USA, 157–169. https://doi.org/10.1145/3127479.3127489
- [31] Kenichi Yasukata, Hajime Tazaki, Pierre-Louis Aublin, and Kenta Ishiguro. 2023. zpoline: a system call hook mechanism based on binary rewriting. In 2023 USENIX Annual Technical Conference (USENIX ATC 23). USENIX Association, Boston, MA, 293–300. https://www.usenix.org/conference/atc23/presentation/yasukata
- [32] Irene Zhang, Amanda Raybuck, Pratyush Patel, Kirk Olynyk, Jacob Nelson, Omar S. Navarro Leija, Ashlie Martinez, Jing Liu, Anna Kornfeld Simpson, Sujay Jayakar, Pedro Henrique Penna, Max Demoulin, Piali Choudhury, and Anirudh Badam. 2021. The Demikernel Datapath OS Architecture for Microsecond-scale Datacenter Systems. In Proceedings of the ACM SIGOPS 28th Symposium on Operating Systems Principles (Virtual Event, Germany) (SOSP ’21). Association for Computing Machinery, New York, NY, USA, 195–211. https://doi.org/10.1145/3477132.3483569
- [33] Lingjun Zhu, Yifan Shen, Erci Xu, Bo Shi, Ting Fu, Shu Ma, Shuguang Chen, Zhongyu Wang, Haonan Wu, Xingyu Liao, Zhendan Yang, Zhongqing Chen, Wei Lin, Yijun Hou, Rong Liu, Chao Shi, Jiaji Zhu, and Jiesheng Wu. 2023. Deploying User-space TCP at Cloud Scale with LUNA. In 2023 USENIX Annual Technical Conference (USENIX ATC 23). USENIX Association, Boston, MA, 673–687. https://www.usenix.org/conference/atc23/presentation/zhu-lingjun

</details>

### presentation

The paper above is selected to be presented in [the Best of CCR session at SIGCOMM 2024](https://conferences.sigcomm.org/sigcomm/2024/ccr/).

- prerecorded video: https://youtu.be/g7iq13SymUI?si=zBj2mUqesMmKYhXv
- slides for the on-site presentation: https://yasukata.github.io/presentation/2024/08/sigcomm2024/sigcomm2024ccr_slides_yasukata.pdf

### authors' other project/paper using iip

- In a paper "Developing Process Scheduling Policies in User Space with Common OS Features" that appears at 15th ACM SIGOPS Asia-Pacific Workshop on Systems (APSys 2024), the authors leverage iip for networked server experiments : https://github.com/yasukata/priority-elevation-trick
