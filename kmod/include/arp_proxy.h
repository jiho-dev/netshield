#ifndef __ARP_PROXY_H__
#define __ARP_PROXY_H__

typedef struct arp_proxy_ip_s {
	rcu_head_t 	rcu;
	list_head_t list;

	int32_t 	ifidx;
	ip4_t 		sip;
	ip4_t 		eip;

	ns_node_id_t nid; 		// 현재의 소유주
	ns_node_id_t owner_nid; 	// 원래의 소유주
	uint16_t 	flag;

} arp_proxy_ip_t;

// arp_proxy_ip_t.flag
#define ARP_PRXY_SNAT 		0x0001
#define ARP_PRXY_DNAT 		0x0002

// from NAT options
#define ARP_PRXY_DYNAMIC 	0x0010 
#define ARP_PRXY_PROXYING 	0x0020 

/////////////////////////////////
//
typedef struct arp_proxy_s {
	struct list_head ip_list;
	spinlock_t 		lock;
	atomic_t 		cnt;
} arp_proxy_t;

///////////////////////////////////////////
#ifdef __KERNEL__

int32_t arpp_rcv(skb_t *skb, netdev_t *dev, struct packet_type *pt, netdev_t *orig_dev);
int32_t arpp_add_ip(int32_t ifidx, ip4_t sip, ip4_t eip, uint16_t flag);
void 	arpp_clean_ip(void);
int32_t arpp_init(void);
void 	arpp_clean(void);
#endif

#endif
