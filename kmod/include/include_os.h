#ifndef __INCLUDE_OS_H
#define __INCLUDE_OS_H


#if defined(linux)
#if defined(__KERNEL__)
#include <linux/module.h>
#include <linux/ctype.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/arp.h>
#include <linux/zlib.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/netfilter_bridge.h>
#include <linux/cdev.h>
#include <include_os.h>
#include <linux/ctype.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <asm/unaligned.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/kthread.h>
#include <linux/etherdevice.h>
#include <linux/workqueue.h>
#include <linux/sort.h>
#include <net/ipv6.h>
#include <net/sch_generic.h>
#include <linux/rcupdate.h>

#else

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h> 
#include <linux/ip.h>
#include <netinet/in.h>

#endif


#endif
#endif

