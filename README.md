**NetShield**
=====================

NetShield is Firewall on Linux. It uses Netfilter HOOK script, but not Netfilter Module. NetShield replaces Netfilter and has its own framework to meet Firewall functionalities. It will gurantees wire speed on multi-10G NICs with the smallest packets(aka 64 Bytes). Now NetShield runs as a Linux kernel module, but soon will support DPDK for better performance.

NetShield adopts brand-new technologies:
* Packet Classification: HyperSplit
* Sesstion Table: Cuckoo Hash
* Hash Algorithm: MurmurHash3
* Session Timeout: Wheel Timer

## Features:

* Sesstion Table supported more than 100M tuples: Done
* Packet Classification: Done
* TCP Stateful Tracking: Done
* NAT: Soon
* BlackList matching Source IP: Soon
* TCP MSS Hack: Soon
* ARP proxy: Soon
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

