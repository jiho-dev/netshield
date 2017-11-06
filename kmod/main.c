#include <include_os.h>

#include <ns_type_defs.h>
#include <skey.h>
#include <timer.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <commands.h>
#include <log.h>
#include <extern.h>
#include <version.h>
#include <misc.h>
#include <smgr.h>
#include <options.h>

uint32_t netshield_running __read_mostly;
DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

int32_t nscmd_run_command(ns_task_t *nstask);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

void netshield_enable(void)
{
	struct timeval tv;

	do_gettimeofday(&tv);

	netshield_running = 1;
	SET_OPT_VALUE(start_time, (uint32_t)tv.tv_sec);
}

void netshield_disable(void)
{
	netshield_running = 0;
}

void setup_common_cmd(ns_task_t *nstask)
{
	// fragmentation, call frag_main()
	append_cmd(nstask, frag);

#if 0
	if (GET_OPT_VALUE(bl)) {
		// blacklist
		// call bl_main()
		wcq_push_cmd(&nstask->cmd, NS_CMD_IDX(bl));
	}
#endif

	// call parse_inet_protocol()
	append_cmd(nstask, inet);

	// call init_task_info()
	append_cmd(nstask, tinfo);

#if 0
	// anomaly in IPS
	if (GET_OPT_VALUE(ips) && GET_OPT_VALUE(panomaly)) {
		// call panomaly_main()
		append_cmd(nstask, panomaly);
	}
#endif

	// call smgr_fast_main()
	append_cmd(nstask, smgr_fast);
}

void setup_cmd(ns_task_t *nstask, uint8_t protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	default:
		setup_common_cmd(nstask);
		break;

	case IPPROTO_AH:
	case IPPROTO_ESP:
#if 0
		// fragmentation, call frag_main()
		append_cmd(nstask, frag);
		// call init_inet_protocol()
		wcq_push_cmd(&nstask->cmd, NS_CMD_IDX(inet));
		append_cmd(nstask, inet);
		// call ipsec_input_main()
		append_cmd(nstask, iipsec);
#endif
		break;

	case IPPROTO_IPIP:
		break;
	}
}

void print_struct_size(void)
{
#ifdef CONFIG_NS_DEBUG
	DBG(0, "=========================");

	PRINT_SZ(sk_t);
	PRINT_SZ(ns_task_t);
	PRINT_SZ(session_t);
#if 0
	PRINT_SZ(lft_t);
	PRINT_SZ(natr_t);
	PRINT_SZ(flst_t);
	PRINT_SZ(fwr_t);
	PRINT_SZ(wstat_t);
	PRINT_SZ(tcpst_t);
	PRINT_SZ(pacc_t);
	PRINT_SZ(arp_proxy_ip_t);
	//PRINT_SZ(xfrmst_t);
	//PRINT_SZ(xfrmpo_t);
	PRINT_SZ(bl_t);
	PRINT_SZ(ipsr_t);
#endif

#ifdef CONFIG_USE_KMM
	PRINT_SZ(kmm_t);
#endif

	DBG(0, "=========================");
#endif
}

int32_t netshield_init(void)
{
	print_struct_size();

	if (nscmd_init_module()) {
		ns_err("Can't init Commands");

		return -1;
	}

	//wth_init();

	return 0;
}

void netshield_clean(void)
{
	//wth_clean();
	
	nscmd_clean_module();
}

int32_t netshield_main(netshield_hook_state_t *state) 
{
	iph_t *iph = NULL;
	skb_t *skb = NULL;
	ns_task_t *nstask = NULL;
	int32_t ret = NS_DROP;

	FUNC_TEST_MSG(6, "=====> Start NetShield here <=====");

	skb = state->skb;
	iph = ns_iph(skb);
	nstask = ns_task(skb);
	nstask->pkt = skb;
	nstask->key.onic = 0;
	nstask->key.inic = state->in == NULL ? 0 : state->in->ifindex;

	prefetch(iph);

	if (state->hook == NS_HOOK_LOCAL_OUT) {
		nstask->flags |= TASK_FLAG_HOOK_LOCAL_OUT;

		if (unlikely(ns_is_loopback(iph->saddr))) {
			FUNC_TEST_MSG(5, "Localhost Packet");
			ret = NS_ACCEPT;
			goto END_MAIN;
		}
	}

	setup_cmd(nstask, iph->protocol);
	ret = nscmd_run_command(nstask);

END_MAIN:

	FUNC_TEST_MSG(6, "All processing for Security is done: %s(return:%d)",
			ret == NS_QUEUE ? "Queued" :
			ret == NS_DROP ? "Droped" : "Allowed", ret);

	FUNC_TEST_MSG(6, "=====> End NetShield <=====");

	return ret;
}
