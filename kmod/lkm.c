#include <include_os.h>

#include <ns_type_defs.h>
#include <skey.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <commands.h>
#include <log.h>
#include <extern.h>
#include <version.h>
#include <misc.h>

DECLARE_DBG_LEVEL(2);
extern uint32_t 	netshield_running;

//////////////////////////////////////////////////////

int32_t arpp_rcv(skb_t *skb, netdev_t *dev, struct packet_type *pt, netdev_t *orig_dev);

/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

int32_t lkm_post_main(int32_t ret, netshield_hook_state_t *state)
{
	OKFN okfn = (OKFN)state->okfn;

	switch (ret) {
	case NS_ACCEPT:
		if (state->call_okfn && okfn)
			ret = okfn(state->net, state->sk, state->skb);
		break;
	case NS_STOLEN:
	case NS_QUEUE:
		ret = 0;
		break;
	case NS_REPEAT:
		ret = -ERANGE;
		break;
	case NS_DROP:
	case NS_STOP:
	default:
		kfree_skb(state->skb);
		ret = -EPERM;
		break;
	}

	return ret;
}

int32_t lkm_main(netshield_hook_state_t *state)
{
	skb_t  *skb = state->skb;
	ns_task_t* 	nstask = NULL;

	if (unlikely(!skb)) {
		return NS_ACCEPT;
	}

	prefetch(skb->data);

	nstask = (ns_task_t*)&skb->nstask[0];
	memset(nstask, 0, sizeof(ns_task_t));

	// callback thread를 위해서 저장
	nstask->okfn = state->okfn;

#if 0
	if (state->pf == PF_INET6) {
		if (!OPT_VAL(ipv6)) {
			return NS_DROP;
		}

		return ns_main6(state);
	}
#endif

	return netshield_main(state);
}

int32_t setup_in_dev(netshield_hook_state_t *state)
{
	if (state->pf == PF_INET6) {
#if 0
		iph6_t* iph;

		iph = wiph6(state->skb);
		in_dev = ns_get_nic_by_ip6((ip_t*)&iph->saddr);
#endif
	}
	else {
		iph_t* iph;
		iph = ns_iph(state->skb);
		state->in = ns_get_nic_by_ip(iph->saddr);
	}

	// 그래도 NULL이므로 out NIC를 in NIC로 가정 한다.
	if (state->in == NULL) {
		if (state->out == NULL) {
			return -1;
		}
		else {
			state->in = state->out;
			dev_hold(state->in);
		}
	}

	return 0;
}

int32_t lkm_hook_ip_pkt(netshield_hook_state_t *state)
{
	int32_t ret = NS_DROP;
	netdev_t *in_dev = (netdev_t*)state->in;
	netdev_t *out_dev = (netdev_t*)state->out;

	if (netshield_running == 0)
		goto END;

#if 0
	if (skb->ip_summed == CHECKSUM_HW)
		skb->ip_summed = CHECKSUM_NONE;
#endif

	// 1. call hooking function
	switch (state->hook) {
	case NS_HOOK_PRE_ROUTING:
		DBG(5, "hook=%d, skb=0x%p, in=%s, out=%s", 
			state->hook, state->skb, in_dev?in_dev->name:"NULL", 
			out_dev?out_dev->name:"NULL");

		ret = lkm_main(state);
		break;
		// output hooking 지점을 선택하는 옵션으로 
		// LOCAL_OUT과 POST_ROUTING 중에 선택 된다.
		// 성능상 LOCAL_OUT으로 선택 되어야 하나,
		// 기능상 POST_ROUTING이 안정적이다.
		// 2008.09.25 by patrick
		// 우선 LOCAL_OUT으로 설계한다.
	case NS_HOOK_LOCAL_OUT:
		// in NIC가 NULL이면 src ip를 이용해서 NIC를 구한다.
		if (in_dev == NULL) {
			if (setup_in_dev(state)) {
				ret = NS_DROP;
				goto END;
			}
		}
		else {
			// 이런 경우는 없는듯.
			dev_hold(in_dev);
			//DBG(0, "Unexpected condition !");
		}

#if 0
		DBG(5, "hook=%d, skb=0x%p, in=%s, out=%s", 
			state->hook, state->skb, in_dev?in_dev->name:"NULL", 
			out_dev?out_dev->name:"NULL");
#endif

		ret = lkm_main(state);
		if (in_dev)
			dev_put(in_dev);

		break;

	case NS_HOOK_POST_ROUTING:
#if 0
		// 패킷이 마지막으로 거치는 hook
		DBG(5, "hook=%d, skb=0x%p, in=%s, out=%s", 
			state->hook, state->skb, in_dev?in_dev->name:"NULL", 
			out_dev?out_dev->name:"NULL");
#endif

		ret = NS_ACCEPT;
		break;

	case NS_HOOK_LOCAL_IN:
#if 0
		// 장비로 향하는 패킷이 마지막으로 거치는 hook
		DBG(5, "hook=%d, skb=0x%p, in=%s, out=%s", 
			state->hook, state->skb, in_dev?in_dev->name:"NULL", 
			out_dev?out_dev->name:"NULL");
#endif

		ret = NS_ACCEPT;
		break;

	case NS_HOOK_FORWARD:
	default:
#if 0
		DBG(5, "hook=%d, skb=0x%p, in=%s, out=%s", 
			state->hook, state->skb, in_dev?in_dev->name:"NULL", 
			out_dev?out_dev->name:"NULL");
#endif

		ret = NS_ACCEPT;
		break;
	}

END:

	// 2. check result and call okfn
	return lkm_post_main(ret, state);
}

#if 0
int32_t lkm_hook_arp_pkt(netshield_hook_state_t *state)
{
	// ARP는 받아 들인다.
	int32_t ret = NS_ACCEPT;

	if (netshield_running == 0)
		goto END;

	// 1. call hooking function
	switch (state->hook) {
	case NF_ARP_IN:
		ret = arpp_rcv(state->skb, state->in, NULL, NULL);
		break;
	default:
		ret = NS_ACCEPT;
		break;
	}

END:
	// 2. check result and call okfn
	return lkm_post_main(ret, state);
}
#endif

/////////////////////////////////////////////////////////////
/////

// for IPv4
netshield_hook_t lkm_ip_hook = 
{
	.pf = PF_INET,
	.ns_main = lkm_hook_ip_pkt,
};

#if 0
// for IPv6
netshield_hook_t lkm_ip6_hook = 
{
	.pf = PF_INET6,
	.ns_main = lkm_hook_ip_pkt,
};

netshield_hook_t lkm_arp_hook = 
{
	.pf = NFPROTO_ARP,
	.ns_main = lkm_hook_arp_pkt,
};
#endif


/////////////////////////////////////////////////////////////

///@cond DOXYGEN_EXCLUDE_THIS

int32_t  lkm_init(void)
{
#if 0
	// INFO: if you face an error here at compile time
	//      you should check correctness of these value
	ASSERT_COMPILE(sizeof(ns_task_t) != WT_T_SIZE);
	// see SKB_WT_T_SIZE in os/include/linux/skbuff.h
	ASSERT_COMPILE(SKB_WT_T_SIZE != WT_T_SIZE);
#endif

	if (netshield_init()) {
		ns_err("Can't init NetShield Module");
		return -1;
	}

	// 패닉 핸들러 초기화
	//init_panic_dump();

	// HOOKing
	if (register_netshield_hook(&lkm_ip_hook)) {
		ns_err("Can't register IPv4 NetShield Hook");
		return -1;
	}

#if 0
	if (register_netshield_hook(&lkm_ip6_hook)) {
		ns_err("Can't register IPv6 NetShield Hook");
		return -1;
	}

	if (register_netshield_hook(&lkm_arp_hook)) {
		ns_err("Can't register ARP NetShield Hook");
		return -1;
	}
#endif

	ns_log("Start NetShield Module V%d.%d%s", 
			 NETSHIELD_VERSION_MAJ, NETSHIELD_VERSION_MIN, 
#ifdef CONFIG_NS_DEBUG
			 "-Debug"
#else
			 ""
#endif
			 );

	netshield_enable();

	return 0;
}

void lkm_clean(void)
{
	wait_queue_head_t 	wq;

	init_waitqueue_head(&wq);

	netshield_disable();

	synchronize_net();

	unregister_netshield_hook(lkm_ip_hook.pf);
	//unregister_netshield_hook(lkm_ip6_hook.pf);
	//unregister_netshield_hook(lkm_arp_hook.pf);

	netshield_clean();
	//clean_panic_dump();

	ns_log("Stop NetShield Module");

}

module_init(lkm_init);
module_exit(lkm_clean);
MODULE_LICENSE("GPL");

///@endcond

