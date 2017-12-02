#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <session.h>
#include <commands.h>
#include <log.h>
#include <misc.h>
#include <ns_malloc.h>
#include <khypersplit.h>
#include <pmgr.h>
#include <ioctl_policy.h>
#include <arp_proxy.h>
#include <smgr.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(5);

extern int32_t g_enable_nic_notify;


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */


int32_t fwp_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps)
{
	uint32_t l = 0, nl;
	uint32_t i,j;
	fw_policy_t *fwp = NULL, *f;
	nat_policy_t *natp;

	l = ioctl_ps->num_policy * sizeof(fw_policy_t);

	fwp = ns_malloc_v(l);
	ns_mem_assert(fwp, "fw_policy", return -1);

	// to make sure all the page assigned
	memset(fwp, 0, l);

	if (ns_copy_from_user(fwp, ioctl_ps->policy, l)) {
		goto ERR;
	}

	ps->num_policy = ioctl_ps->num_policy;
	ps->policy = fwp;

	for (i=0; i<ps->num_policy; i++) {
		f = &fwp[i];
		
		for (j=0; j<2; j++) {
			if (f->nat_policy[j] == NULL) {
				continue;
			}

			nl = sizeof(nat_policy_t);
			natp = ns_malloc_kz(nl);

			if (natp == NULL) {
				ns_log("Failt to alloc nat memory");
				continue;
			}

			if (ns_copy_from_user(natp, f->nat_policy[j], nl)) {
				ns_free(natp);
				f->nat_policy[j] = NULL;
			}
			else {
				// init internal data
				ns_init_lock(&natp->nat_lock);
				natp->ip_cnt = -1;
				natp->available_ip = NULL;
				INIT_LIST_HEAD(&natp->ip_list);

				f->nat_policy[j] = natp;
			}
		}
	}

	dbg(5, "Ruleset Info");
	dbg(5, "Num of Rule: %d", ps->num_policy);
	dbg(5, "Num of Mem: %d", l);

	return 0;

ERR:
	if (fwp) {
		ns_free_v(fwp);
	}

	return -1;
}

// NIC IP가 변경 되는 경우 해당 NIC를 사용하는 NAT 룰 초기화 
void fwp_update_nat_ip(int32_t if_idx)
{
	uint32_t rcnt, i, j;
	ip_t ip;
	nat_policy_t* natp;
	int32_t del_cnt;
	policyset_t *ps;
	fw_policy_t *fwp;

	ENT_FUNC(3);

	ps  = pmgr_get_nat_policyset();
	if (ps == NULL) {
		return;
	}

	ip = ns_get_nic_ip(if_idx);
	if (ip == 0)
		goto END_NAT_IP;

	dbg(4, "New NAT IP: " IP_FMT, IPH(ip));

	rcnt = ps->num_policy;
	fwp = ps->policy;

	for (i=0; i<rcnt; i++) {

		if (!(fwp[i].action & ACT_NAT))
			continue;

		for (j=0; j<2; j++) {
			natp = fwp[i].nat_policy[j];

			if (!(natp->flags & NATF_DYNAMIC_IP) || if_idx != natp->nic)
				continue;

			dbg(4, "Set NAT IP: " IP_FMT, IPH(ip));

			// 해당 IP를 사용하는 관련 세션도 모두 지운다.
			// IP가 변경 되면 기존 세션으로 통신이 불가능하기 때문에 삭제해도 무방한다.
			del_cnt = smgr_delete_by_ip(natp->nip[0], SMGR_DEL_SNAT);
			if (del_cnt > 0) {
				ns_warn("%d session(s) deleted because of changing NAT IP:" IP_FMT "->" IP_FMT,
						del_cnt, IPH(natp->nip[0]), IPH(ip));
			}
			//
			// 나중에 사용하는데서 설정 된다.
			nat_clean_ip_obj(natp);

			natp->nip[0] = 0;
			natp->nip[1] = 0;
		}

	}

END_NAT_IP:
	if (ps) {
		pmgr_policyset_release(ps);
	}
}

// NAT룰을 검사하여 nic가 미지정 인경우 IP를 이용해서 nic를 구한다.
int32_t fwp_resolve_nat_nic(nat_policy_t *natp)
{
	netdev_t *dev;

	// NAT NIC를 지정하지 않은 경우에 NAT IP를 이용해서 자동 생성 한다.
	if (natp->nic != 0) {
		return 0;
	}

	dev = ns_get_nic_by_ip(htonl(natp->nip[0]));

	dbg(5, "nat info: ip="IP_FMT " nic = %d(%s)", 
		IPH(natp->nip[0]), natp->nic, dev?dev->name:"NULL");

	if (dev) {
		natp->nic = dev->ifindex;
		dev_put(dev);
	}

	return 0;
}

// 룰이 적용 된후 NAT arp proxy IP에 대해서 처리 한다.
void fwp_update_nat_arp(policyset_t *ps)
{
	int32_t i,rcnt;
	int32_t j;
	nat_policy_t* natp;
	ip4_t sip, eip;
	fw_policy_t *new_rule;
	int32_t nic;
	uint16_t flag;

	ENT_FUNC(3);

	// clean it up
	arpp_clean_ip();

	new_rule = ps->policy;
	rcnt = ps->num_policy;

	for (i=0; i<rcnt; i++) {

		if (!(new_rule[i].action & ACT_NAT))
			continue;

		for (j=0; j<2; j++) {
			natp = new_rule[i].nat_policy[j];
			sip = eip = 0;
			flag = 0;

			if (natp == NULL) {
				continue; 
			}

			if ((natp->flags & NATF_DYNAMIC_IP) && 
				!g_enable_nic_notify) {
				g_enable_nic_notify = 1;
			}

			if (!(natp->flags & NATF_ARP_PROXY)) {
				continue;
			}

			dbg(5, "fwr=0x%p, id=%d, nat[%d]=0x%p, id=%d", 
				&new_rule[i], new_rule[i].rule_id, i, natp, natp?natp->id:-1);

			if (natp->flags & NATF_SNAT_MASK) {
				// INFO: 다이나믹 할당이면 arp proxy가 동작 안해도 된다.
				if (natp->flags & NATF_DYNAMIC_IP) {
					continue;
				}

				sip = natp->nip[0];
				eip = natp->nip[1];
				nic = natp->nic;

				// if end ip is MASK value, make end ip
				if (natp->flags & NATF_SNAT_MASKING) {
					eip = sip | ~eip;
					// masking을 하면 eip 주소가 네트웍 주소가 된다.
					// 그러므로 1을 감소해서 호스트 주소 영역으로 만든다.
					ns_dec_ip(&eip);
				}

				flag |= ARP_PRXY_SNAT;
			}
			else if (natp->flags & NATF_DNAT_MASK) {
				// DNAT인 경우 목적지 IP에 대해서 arp proxying 한다
				sip = new_rule[i].range.dst.min;
				eip = new_rule[i].range.dst.max;
				nic = new_rule[i].range.nic.min;
				flag |= ARP_PRXY_DNAT;
			}
			else {
				dbg(0, "Unexpected condition");
				continue;
			}

			dbg(6, "sip:" IP_FMT ", eip:" IP_FMT , IPH(sip), IPH(eip));

			if (sip == 0 && eip == 0)
				continue;
			else if (eip == 0) {
				eip = sip;
			}

			// NAT NIC를 지정하지 않은 경우에 NAT IP를 이용해서 자동 생성 한다.
			if (nic == 0) {
				fwp_resolve_nat_nic(natp);
			}

			// nid는 0으로 설정하고 나중에 필요할 때 설정 한다.
			arpp_add_ip(nic, sip, eip, flag);
			dbg(5, "NAT arp proxy: nic idx: %d, sip:" IP_FMT ",eip:" IP_FMT , natp->nic, IPH(sip), IPH(eip));
		}
	}
}

