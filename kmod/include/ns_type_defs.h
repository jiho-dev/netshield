#ifndef _NS_TYPE_DEFS_H_
#define _NS_TYPE_DEFS_H_

#include <linux/version.h>

///////////////////////////////////////////////////////////////////////////
// kernel과 user mode의 endian mode 정의 호환성을 위해서 사용
///////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__
#include <asm/byteorder.h>
#else
#include <endian.h>
#endif

#if defined(__KERNEL__)
#  if defined(__BIG_ENDIAN)
#define NS_BIG_ENDIAN
#  elif defined(__LITTLE_ENDIAN)
#define NS_LITTLE_ENDIAN
#  else
#    error "Could not determine byte order"
#  endif
#elif defined(__BYTE_ORDER)
#  if __BYTE_ORDER == __BIG_ENDIAN
#define NS_BIG_ENDIAN
#  elif __BYTE_ORDER == __LITTLE_ENDIAN
#define NS_LITTLE_ENDIAN
#  else
#    error "Could not determine byte order"
#  endif
#endif

///////////////////////////////////////////////////////////////////////////
// Define Hooking ID
///////////////////////////////////////////////////////////////////////////

enum {
	NS_HOOK_PRE_ROUTING 	= 0,
	NS_HOOK_LOCAL_IN 		= 1,
	NS_HOOK_FORWARD 		= 2,
	NS_HOOK_LOCAL_OUT 		= 3,
	NS_HOOK_POST_ROUTING 	= 4,

	NS_HOOK_MAX
};

enum {
	NS_DEL_SESSION 	= 	-1,
	NS_DROP 		= 0,
	NS_ACCEPT 		= 1,
	NS_STOLEN 		= 2,
	NS_QUEUE 		= 3,
	NS_REPEAT 		= 4,
	NS_STOP 		= 5,

	NS_MAX
};

enum {
	NS_FALSE 	= 0,
	NS_TRUE 	= 1,
};

enum {
	NS_FAIL 		= -1,
	NS_SUCCESS 	= 0,
	NS_ERROR 		= 1,
};

/// 함수 옵션들의 집합
enum {
	FUNC_FLAG_IPV6 = 0x01,
};
	

///////////////////////////////////////////////////////////////////////////
// kernel의 spinlock_t를 user에서 컴파일 하기 위해 정의, 코드 호환성 유지.
///////////////////////////////////////////////////////////////////////////

#ifndef __KERNEL__

struct lockdep_map {
	char		*key;
	char		*class_cache;
	const char	*name;
};

typedef struct {
	volatile unsigned int slock;
} raw_spinlock_t;


typedef struct {
	raw_spinlock_t raw_lock;
} spinlock_t;

#endif // !__KERNEL__

///////////////////////////////////////////////////////////////////////////
// kernel과 user의 코드 호환성을 위해서 정의함.
// 또한 32/64 bit의 호환성을 고려함.
///////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__
typedef struct hlist_node 	hlist_node_t;
typedef struct hlist_head 	hlist_head_t;
typedef struct list_head 	list_head_t;
typedef struct rcu_head 	rcu_head_t;
typedef struct dst_entry	dstent_t;
typedef struct hh_cache		hh_cache_t;
typedef struct neighbour    neigh_t;
typedef struct xfrm_state 	ipsec_sad_t; // Security Association Database (SAD)
typedef struct xfrm_policy 	ipsec_spd_t; // Security Policy Database (SPD)
typedef struct ctl_table 	ctltab_t;
typedef struct seq_operations seqops_t;
typedef wait_queue_head_t 	wq_head_t;


#define ns_iph(__skb)	ip_hdr(__skb)
#define ns_iph6(__skb) 	ipv6_hdr(__skb)
#define ns_tcph(__skb)	tcp_hdr(__skb)
#define ns_udph(__skb)	udp_hdr(__skb)
#define ns_icmph(__skb)	icmp_hdr(__skb)
#define ns_raw(__skb)	skb_transport_header(__skb)
#define ns_eth(__skb)  	(eth_t*)skb_mac_header(__skb)
#define ns_iplen(__skb)	(__skb->len)
#define ns_task(__skb) 	(ns_task_t*)(&__skb->nstask[0])
#define ns_for_each_netdev(dev) for_each_netdev(&init_net, dev)
#define htonll(x) 		__cpu_to_be64(x)
#define ntohll(x) 		__be64_to_cpu(x)
#define is_same_ether_addr(d,s) !compare_ether_addr(d,s)


typedef struct sk_buff 		skb_t;
typedef	struct net_device 	netdev_t;
typedef spinlock_t 			nslock_t;
typedef struct Qdisc 		qdisc_t;
typedef struct Qdisc_ops 	qdisc_op_t;
typedef struct netdev_queue netdev_queue_t;
typedef struct ctl_table 	ctl_table_t;

#else 	// ! __KERNEL__

typedef struct { char *_p[2];} 	pointer_2_t;
typedef struct { char *_p;} 	pointer_1_t;
typedef struct { int  counter;} atomic_t;
typedef struct { unsigned long long int counter;} atomic64_t;
typedef struct { int _d;}		dstent_t;
typedef pointer_2_t 		 	rcu_head_t;
typedef struct { int _h;}		hh_cache_t;
typedef struct { int _h;}		neigh_t;
typedef struct { int _h;}		netdev_t;
typedef struct { char *_p;} 	ipsec_sad_t;
typedef struct { char *_p;} 	ipsec_spd_t;

#ifndef HAVE_LIST_HEAD
#define HAVE_LIST_HEAD 		1
typedef struct list_head {
	struct list_head *next, *prev;
} list_head_t;
#endif

#ifndef HAVE_HLIST_HEAD
#define HAVE_HLIST_HEAD 	1
typedef struct hlist_head {
	struct hlist_node *first;
} hlist_head_t;

typedef struct hlist_node {
	struct hlist_node *next, **pprev;
} hlist_node_t;
#endif

typedef struct ctl_table_s {
	const char *procname;
	void *data;
	int maxlen;
	mode_t mode;
	struct ctl_table *child;
	struct ctl_table *parent;
	void *proc_handler;
	void *strategy;
	void *de;
	void *extra1;
	void *extra2;
} ctltab_t;

#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif

typedef struct _user_skb_t {
	unsigned int	len;
	char 			*mach;
	char 			*iph;
	char 			*tph;
	// see SKB_WT_T_SIZE in os/include/linux/skbuff.h
#define SKB_WT_T_SIZE 	120
	char 			nstask[SKB_WT_T_SIZE];
	sk_buff_data_t	transport_header;
	sk_buff_data_t	network_header;
	sk_buff_data_t	mac_header;
	sk_buff_data_t	tail;
	sk_buff_data_t	end;
	unsigned char	*head, *data;
	unsigned int	truesize;
	atomic_t		users;

} skb_t;

typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;


#define	ENOENT		 	2


#define ns_iph(__skb)	ip_hdr(__skb)
#define ns_iph6(__skb) 	ipv6_hdr(__skb)
#define ns_tcph(__skb)	tcp_hdr(__skb)
#define ns_udph(__skb)	udp_hdr(__skb)
#define ns_icmph(__skb)	icmp_hdr(__skb)
#define ns_raw(__skb)	skb_transport_header(__skb)
#define ns_eth(__skb)  	(eth_t*)skb_mac_header(__skb)
#define ns_iplen(__skb)	(__skb->len)
#define ns_for_each_netdev(dev) for_each_netdev(&init_net, dev)
#define htonll(x) 		__cpu_to_be64(x)
#define ntohll(x) 		__be64_to_cpu(x)
#define is_same_ether_addr(d,s) !compare_ether_addr(d,s)

#define INIT_RCU_HEAD(r) init_rcu_head(r)

#endif

///////////////////////////////////////////////////////////////////////////
// kernel과 user mode의 공통 사항
///////////////////////////////////////////////////////////////////////////

typedef struct iphdr		iph_t;
typedef struct ipv6hdr 		iph6_t;
typedef struct tcphdr		tph_t;
typedef struct udphdr		uph_t;
typedef struct icmphdr		ich_t;
typedef struct icmp6hdr 	ich6_t;
typedef struct arphdr 		arh_t;
typedef struct ethhdr 		eth_t;
typedef	struct ipv6_opt_hdr ip6opt_t;
typedef struct timer_list 	timer_list_t;
typedef unsigned long 		ulong_t;
typedef uint8_t 			nid_t; 		///< for WSP Node ID
typedef uint32_t 			ip4_t; 		///< for IPv4 address
typedef uint32_t 			ips_rid_t;	///< for IPS Rule ID
typedef uint16_t 			ips_app_gid_t;	///< for IPS Appliction Group ID
typedef uint16_t 			ips_att_gid_t;	///< for IPS Attack Group ID
typedef uint32_t 			ipolicy_id_t;	///< for IPS Policy ID
typedef __int128_t 			int128_t;
typedef __uint128_t 		uint128_t;

typedef union _ip6_t {
	uint8_t		a8[16];
	uint16_t	a16[8];
	uint32_t	a32[4];
	uint64_t	a64[2]; 	// 0: high part, 1: low part

} ip6_t;

typedef union {
	ip4_t v4;
	ip6_t v6;
} ip_t;


#ifndef ETH_ALEN
#define ETH_ALEN 			6
#endif

#endif
