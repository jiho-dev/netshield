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
* TCP Stateful Tracking: Done(2017/10/30)
* NAT: Done(2017/12/2)
* ARP proxy: Done(2017/12/2)
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

## Compile: 

* OS: Ubuntu 1604 or higher version
* Required package: libjons-c
* Compile: it is very simple, just type make at each subdirectories.
<pre><code>
git clone https://github.com/jhjgithub/netshield.git
cd netshield
cd linux-4.10.17
make menuconfig
make bzImage
...
cd ../libhypersplit
make
...
cd ../kmod
make
...
cd ../nsctl
make
...
</code></pre>

## NetShield Policy Format:

NetShield uses JSON for its policy format. It is very easy for you to learn how to write the policy.
Policy File:
<pre><code>
{
	"version": "1.0",
	"id" 	: "NetShield",
	"desc" 	: "This is NetShield Policies",
	"policy" : {
		"firewall" 	: [
			{
			"desc" 	: "SSH Server",
			"src_ip"  : [ "0.0.0.0", "0.0.0.0"],
			"dst_ip"  : [  "204.152.188.196",  "204.152.188.196"],
			"src_port": [  0, 65535],
			"dst_port": [  22, 22],
			"protocol": [  6, 6],
			"nic"     : [  "eth0", "eth0"],
			"action"  : "allow",
			"state"   : "enable",
			},
		],

		"nat"  		: [
			{
			"desc" : "SNAT Rule",
			"src_ip"  : [  "0.0.0.0", "0.0.0.0"],
			"dst_ip"  : [  "0.0.0.0", "0.0.0.0"],
			"src_port": [  0, 65535],
			"dst_port": [  0, 65535],
			"protocol": [  0, 255],
			"nic"     : [  "any", "any"],
			// snat, dnat, bnat, pnat
			"action"  : "snat",		
			"state"   : "enable",
			"nat_info": 
			{
				"snat": 
				{
					// snat_masking, snat_hash, snat_napt, dnat_redir, dnat_local_redir
					"type": "snat_napt", 
					//"option": ["arp_proxy", "dynamic_ip"],
					"option": ["arp_proxy"],
					"nic": "eth2",	// any, eth0 ~
					"nat_ip":   [  "1.1.1.3", "1.1.1.3"],
					"nat_port": [  3000, 65535],
				},
				"dnat": {
				},
			},
			},
		],
	}
}
</code></pre>

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

## Contact me:

* You can reach me at irongate@naver.com

