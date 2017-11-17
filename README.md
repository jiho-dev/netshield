**NetShield**
=====================

NetShield is Firewall on Linux. It uses Netfilter HOOK script to receive packets, but is not Netfilter Module. It also replaces Netfilter and has its own framework to meet Firewall functionalities. Such as maintaining sessions, looking up the Firewall rules, and tiny pluggable modules.

The performance of NetShield is to meet the needs in recent network infrastructure, which has multi-10G and 40G NICs possibily receiving the smallest packets(aka 64 Bytes). The hardware running NetShield is not specified. All of the general x86 platform accommodating Linux well can be used without any peripheral devices.

Now NetShield runs as a Linux kernel module, but soon will support DPDK for better performance. As you know, DPDK is a novel plaform to develop the Firewall and IDS/IPS. It has fundamentally different mechanism to receive huge amount of packets and pass them to the application which has mainly its own purpose.

NetShield adopts brand-new technologies:
* Packet Classification: HyperSplit
* Sesstion Table: Cuckoo Hash
* Hash Algorithm: MurmurHash3
* Session Timeout: Wheel Timer

## Features:

* Sesstion Table supported more than 100M tuples: Done
* Packet Classification: Done
* TCP Stateful Tracking: Done
* NAT: Under developing
* ARP proxy: Soon
* BlackList matching Source IP: Soon
* TCP MSS Hack: Soon
* Support DPDK: TBD
* IPV6: TBD
* IP v4/v6 Fragmention: TBD
* Syn Proxy: TBD
* L2 Firewall: TBD
* Application Firewall: TBD
* IPSEC : TBD
* Exact Pattern Matching for DPI: TBD
* PCRE Pattern Matching for DPI: TBD
* Rate Limits: TBD

## References: 

Cuckoo Hashing, by Rasmus Pagh and Flemming Friche Rodler. 
- http://www.it-c.dk/people/pagh/papers/cuckoo-jour.pdf

Hashtable Implementation Using Cuckoo Hashing. 
- http://warpzonestudios.com/hashtable-cuckoo/

Algorithmic Improvements for Fast Concurrent Cuckoo Hashing.
- https://www.cs.princeton.edu/~mfreed/docs/cuckoo-eurosys14-slides.pdf

MurmurHash3, by Austin Appleby. 
- http://en.wikipedia.org/wiki/MurmurHash
- https://github.com/aappleby/smhasher

MemC3
- https://github.com/efficient/memc3

HyperSplit
- http://security.riit.tsinghua.edu.cn/teacher/THU-USC-5th-Forum.pdf

