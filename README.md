# iip: an integratable TCP/IP stack

iip is an integratable TCP/IP stack implementation, having the following properties:
- portable: iip does not rely on specific CPUs, NICs, libraries, and compiler features.
- aware of multi-core scalability: iip does not maintain in-memory objects shared across different CPU cores.
- aiming at high-performance: iip handles millions packets in one second for a short TCP messaging workload; please see https://github.com/yasukata/bench-iip#rough-numbers for rough performance numbers.

## other building blocks

### I/O subsystem
- [iip-dpdk](https://github.com/yasukata/iip-dpdk): a DPDK-based backend.

### example application
- [bench-iip](https://github.com/yasukata/bench-iip): a benchmark tool.

## getting started

Please vist an example application page at [https://github.com/yasukata/bench-iip](https://github.com/yasukata/bench-iip) for testing iip. 

