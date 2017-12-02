#include <net/protocol.h>
#include <include_os.h>

#include <typedefs.h>
#include <ns_task.h>
#include <ns_macro.h>

//#include <commands.h>
//#include <log.h>
//#include <extern.h>
//#include <version.h>
//#include <misc.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */


///////////////////////////////////////////////////////////
// for IPv4

int32_t ns_keep_frag4(ns_task_t *nstask)
{
	// all codes are refered from ip_ct_gather_frags()

#if 0
	skb_t *skb = nstask->pkt;
	iph_t *iph;
	int32_t ret;
	uint32_t offset, flags;

	ENT_FUNC(3);

	iph = ns_iph(skb);
	ret = NS_ACCEPT;

	offset = ntohs(iph->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;

	if (OPT_VAL(frag) == 0) {
		if (offset == 0) {
			return NS_ACCEPT;
		}
		else {
			return NS_DROP;
		}
	}

	dbg(4, "Receive a fragment packet:frag offset=%d, flags=0x%x", offset, flags);

	// check minimal size of ip fragmentation pkt
	if (OPT_VAL(frag_pkt_min_len) &&
		((skb->len) < OPT_VAL(frag_pkt_min_len))) {
		// this pkt is abnormal fragment pkt
		// we will not care this
		OPT_VAL(frag_pkt_drop_cnt)++;

		// logging
		if (OPT_VAL(frag_pkt_drop_cnt) == 1 || (OPT_VAL(frag_pkt_drop_cnt) % 1000) == 0) {
			// first time save drop log
			WWARN("Drop the abnormally fragmented packet:count=%d", OPT_VAL(frag_pkt_drop_cnt));
		}

		return NS_DROP;
	}

	skb_orphan(skb);

	local_bh_disable();

	ret = ip_defrag(skb, (nstask->flags & WTF_HOOK_LOCAL_OUT) ?
			IP_DEFRAG_CONNTRACK_OUT :
			IP_DEFRAG_CONNTRACK_IN);

	local_bh_enable();

	if (ret) {
		if (ret == -EILSEQ || ret == -EINVAL) {
			dbg(0, "Drop Teardrop Attack packet !");
		}
		else if (ret != -EINPROGRESS) {
			//-EINVAL etc...
			dbg(0, "ip_defrage return: %d", ret);
		}

		return NS_STOLEN;
	}

	// gather fragment packets
	skb_linearize(skb);
	ip_send_check(ip_hdr(skb));
#endif

	return NS_ACCEPT;
}

int32_t frag_main(ns_task_t *nstask)
{
	skb_t *skb = nstask->pkt;
	iph_t *iph;


	// 패킷은 조합 되어서 완성된 패킷으로 반환 된다.
	// 이 부분 이후 부터는 frag 패킷이 전혀 없다.
	dbg(4, "Check fragment packet");
	iph = ns_iph(skb);

	if (!(iph->frag_off & htons(IP_MF | IP_OFFSET))) {
		return NS_ACCEPT;
	}

	return ns_keep_frag4(nstask);
}
