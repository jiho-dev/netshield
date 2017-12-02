#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <log.h>
#include <ns_malloc.h>
#include <options.h>
#include <arp_proxy.h>
#include <misc.h>

// 방화벽에서 NAT를 사용시 NAT IP에 대한 ARP 응답 모듈
// 동작 방식: 
// 커널에 ARP protocol handler를 등록해서 ARP 패킷을 수신 한다.
// handler에서는 ARP 패킷이 NAT IP에 대한 요청인 경우
// arp_send()를 이용해서 응답 메세지를 보낸다.

arp_proxy_t g_arpp_root;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////

int32_t arpp_send_reply_for_nat(netdev_t* dev, uint32_t tip, char* tha, uint32_t sip, char* sha);
void* 	seq_natip_start(struct seq_file *s, loff_t *pos);
void* 	seq_natip_next(struct seq_file *s, void *v, loff_t *pos);
void 	seq_natip_stop(struct seq_file *s, void *v);
int32_t seq_natip_show(struct seq_file *s, void *v);
int32_t mllb_update_nh_state_by_arp_reply(netdev_t *indev, char *snder_mac, ip4_t snder_ip);

seqops_t seq_natip_ops = {
	.start = seq_natip_start,
	.next = seq_natip_next,
	.stop = seq_natip_stop,
	.show = seq_natip_show,
};


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

/*
 *	Process an arp request.
 */

int32_t arpp_process(skb_t *skb)
{
	netdev_t *dev = skb->dev;
	struct in_device *in_dev = in_dev_get(dev);
	arh_t *arp;
	unsigned char *arp_ptr;
	unsigned char *sha, *tha;
	ip4_t sip, tip;
	uint16_t dev_type = dev->type;
	int32_t hop;
	eth_t* eth;

	/* arpp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (in_dev == NULL)
		goto out;

	arp = (arh_t*)ns_iph(skb);

	switch (dev_type) {
	default:	
		if (arp->ar_pro != htons(ETH_P_IP) ||
			htons(dev_type) != arp->ar_hrd)
			goto out;
		break;
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
		if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
			 arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
			arp->ar_pro != htons(ETH_P_IP))
			goto out;
		break;
	}

	hop = ntohs(arp->ar_op);

	/* Understand only these message types */

	if (hop != ARPOP_REPLY && hop != ARPOP_REQUEST)
		goto out;

	/*
	 *	Extract fields
	 */
	arp_ptr= (unsigned char *)(arp+1);
	sha	= arp_ptr;
	arp_ptr += dev->addr_len;
	memcpy(&sip, arp_ptr, 4);
	arp_ptr += 4;
	tha	= arp_ptr;
	arp_ptr += dev->addr_len;
	memcpy(&tip, arp_ptr, 4);

	/* 
	 *	Check for bad requests for 127.x.x.x and requests for multicast
	 *	addresses.  If this is one such, delete it.
	 */

	if (ipv4_is_loopback(tip) || ipv4_is_multicast(tip))
		goto out;

	/*
	 *     Special case: We must set Frame Relay source Q.922 address
	 */
	if (dev_type == ARPHRD_DLCI)
		sha = dev->broadcast;

	/* Special case: ARP REQUEST host is invalid */
	if (sip == 0) {
		goto out;
	}

	eth = ns_eth(skb);

#if 0
	// IP/MAC monitoring
	if (OPT_VAL(l2fw)) {
		if (l2f_arp_main(eth->h_source, dev, tip, tha, sip, sha) == NS_DROP) {
			return NS_DROP;
		}
	}
#endif

	// arp proxying
	if (hop == ARPOP_REQUEST) {
		if (GET_OPT_VALUE(nat_arp_proxy) && 
			// 만일 장비의 NIC에 설정된 IP라면 응답 하지 않는다.
			// OS에서 응답 할 것이다.
			!ns_is_local_address(tip)) {

			arpp_send_reply_for_nat(dev, tip, tha, sip, sha);
		}

	}
	else if (hop == ARPOP_REPLY) {

	}

out:
	if (in_dev)
		in_dev_put(in_dev);

	return NS_ACCEPT;
}

/*
 *	Receive an arp request from the device layer.
 */

int32_t arpp_rcv(skb_t *skb, netdev_t *dev, struct packet_type *pt, netdev_t *orig_dev)
{
	arh_t *arp;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	if (!pskb_may_pull(skb, (sizeof(arh_t) +
				 (2 * dev->addr_len) +
				 (2 * sizeof(u32)))))
		goto freeskb;

	arp = (arh_t*)ns_raw(skb);

	if (arp->ar_hln != dev->addr_len ||
	    dev->flags & IFF_NOARP ||
	    skb->pkt_type == PACKET_OTHERHOST ||
	    skb->pkt_type == PACKET_LOOPBACK ||
	    arp->ar_pln != 4) {

		dbg(0, "Abnormal ARP packet: pkt_type=%d, ar_pln=%d, flag=0x%x, ar_hln=%d, addr_len=%d ", 
			skb->pkt_type, arp->ar_pln, dev->flags, arp->ar_hln, dev->addr_len);

		goto freeskb;
	}

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		goto out_of_mem;
	}

	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));

	return arpp_process(skb);

freeskb:

out_of_mem:
	return NS_DROP;
}

//////////////////////////////////////////////////////////////////////

int32_t arpp_send_reply_for_nat(netdev_t* dev, 
		uint32_t tip, char* tha, uint32_t sip, char* sha)
{
	int32_t unicast = 1;
	ip4_t htip, hsip;
	arp_proxy_ip_t* prxyip;

	ENT_FUNC(3);

	htip = ntohl(tip);
	hsip = ntohl(sip);

	dbg(5, "RCV ARP Request: %s: target=" IP_FMT ":" MAC_FMT " , to=" IP_FMT ":" MAC_FMT, 
		dev->name, IPN(tip), MAC(tha), IPN(sip), MAC(sha)); 

	ns_rd_lock() {

		// XXX: 흠, NAT 룰이 많은 경우 검색 성능에 문제가 생긴다.
		list_for_each_entry_rcu(prxyip, &g_arpp_root.ip_list, list) {
			// entry가 추가 될때 dev를 못찾은 경우이다.
			// dev를 새로 찾아서 업데이트 한다.
			if (prxyip->ifidx == 0) {
				prxyip->ifidx = ns_get_nic_idx_by_ip(prxyip->sip);
			}

			// arp를 수신한 dev가 NAT로 설정된 NIC 인지 검사 해야 한다.
			if (dev->ifindex != prxyip->ifidx || 
				!(prxyip->sip <= htip && htip <= prxyip->eip)) {

				continue;
			}

			if (unicast) {
				dbg(5, "SND ARP Reply Unicast: %s: target=" IP_FMT ", to=" IP_FMT, 
					dev->name, IPN(tip), IPN(sip));
				arp_send(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha, dev->dev_addr, sha);
			}
			else {
				//arp_send(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, NULL, dev->dev_addr, sha);
				//dbg(0, "ARP RES Broadcast: %s: target=" IP_FMT ", to=" IP_FMT, 
				//		dev->name, IPN(tip), IPN(sip));
			}

			break;
		}

	} ns_rd_unlock();

	return 0;
}

int32_t arpp_add_ip(int32_t ifidx, ip4_t sip, ip4_t eip, uint16_t flag)
{
	arp_proxy_ip_t* prxyip;
	ns_node_id_t nid = 0;

	ENT_FUNC(3);

	prxyip = ns_malloc_kz(sizeof(arp_proxy_ip_t));
	ns_mem_assert(prxyip, "arp_proxy_ip_t", return -1);

	INIT_LIST_HEAD(&prxyip->list);
	prxyip->sip = sip;
	prxyip->eip = eip;
	prxyip->ifidx = ifidx;
	prxyip->flag = flag;

	prxyip->nid = nid;
	prxyip->owner_nid = nid;

	dbg(5, "arp proxy ip: sip="IP_FMT ",eip="IP_FMT, IPH(sip), IPH(eip));

	ns_rw_lock(&g_arpp_root.lock) {
		list_add_tail(&prxyip->list, &g_arpp_root.ip_list);
	} ns_rw_unlock(&g_arpp_root.lock);

	atomic_inc(&g_arpp_root.cnt);

	return 0;
}

///////////////////////////////////////////////////////

void arpp_clean_ip(void)
{
	arp_proxy_ip_t* prxyip;
	int32_t cnt=0;

	ENT_FUNC(3);

	ns_rw_lock(&g_arpp_root.lock) {

		while (!list_empty(&g_arpp_root.ip_list)) {
			prxyip = list_entry(g_arpp_root.ip_list.next, arp_proxy_ip_t, list);

			// dsync를 안하므로, 모든 노드는 자신의 소유이다.
			// 그래서 모두 지워도 무방하다.
			list_del_init(&prxyip->list);
			ns_free(prxyip);
			cnt ++;
		}

	} ns_rw_unlock(&g_arpp_root.lock);
}


/////////////////////////////////////////////////////////

void* seq_natip_start(struct seq_file *s, loff_t *pos)
{
	ENT_FUNC(3);

	if (*pos == 0) {
		return SEQ_START_TOKEN;
	}

	return NULL;
}

void* seq_natip_next(struct seq_file *s, void *v, loff_t *pos)
{
	ENT_FUNC(3);

	return NULL;
}

void seq_natip_stop(struct seq_file *s, void *v)
{
	ENT_FUNC(3);
}

int32_t seq_natip_show(struct seq_file *s, void* v)
{
	arp_proxy_ip_t* prxyip;
	netdev_t* dev;
	char sip[20], eip[20];
	int32_t i;

	ENT_FUNC(3);

	seq_printf(s, "%-3s %-5s %-4s %-3s %-5s %-10s %-15s %-15s \n",
			   "No", "Dev", "NAT", "NID", "Owner", "Flag", "Start IP", "End IP");

	i = 1;
	ns_rd_lock() {

		list_for_each_entry_rcu(prxyip, &g_arpp_root.ip_list, list) {
			// entry가 추가 될때 dev를 못찾은 경우이다.
			// dev를 새로 찾아서 업데이트 한다.
			if (prxyip->ifidx == 0) {
				prxyip->ifidx = ns_get_nic_idx_by_ip(prxyip->sip);
			}

			sprintf(sip, IP_FMT, IPH(prxyip->sip));
			sprintf(eip, IP_FMT, IPH(prxyip->eip));

			dev = ns_get_nic_by_idx(prxyip->ifidx);
			seq_printf(s, "%-3d %-5s %-4s %-3d %-5d 0x%8x %-15s %-15s\n",
					   i,
					   dev?dev->name:"None",
					   (prxyip->flag&ARP_PRXY_SNAT)?"SNAT":"DNAT", 
					   prxyip->nid, 
					   prxyip->owner_nid,
					   prxyip->flag,
					   sip,
					   eip);

			if (dev)
				dev_put(dev);
		}

	} ns_rd_unlock();

	return 0;
}

//////////////////////////////////////////////////////

/*
 *	Called once on startup.
 */

int32_t arpp_init(void)
{
	ns_init_lock(&g_arpp_root.lock);
	INIT_LIST_HEAD(&g_arpp_root.ip_list);
	atomic_set(&g_arpp_root.cnt, 0);

	return 0;
}

void arpp_clean(void) 
{
	arpp_clean_ip();
}

