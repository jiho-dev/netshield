#include <include_os.h>

#include <typedefs.h>
#include <ns_task.h>
#include <session.h>
#include <log.h>
#include <ns_macro.h>
#include <ns_malloc.h>
#include <fw_policy.h>
#include <misc.h>
#include <commands.h>

#define	IS_HW_CSUM(nstask) 	(nstask->pkt->ip_summed == CHECKSUM_PARTIAL)

DECLARE_DBG_LEVEL(2);

void MurmurHash3_x86_32(const void *skey, int len, uint32_t seed, void *out);

/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

int32_t nat_get_ip_count(nat_policy_t *n)
{
	return (int32_t)(n->nip[1] - n->nip[0]) + 1;

}

#if 0
int32_t nat_get_natkey(session_t* si, ip4_t* ip, uint16_t* port)
{
	if (si->action & (ACT_SNAT|ACT_BNAT)) {
		*ip = si->rsk.dst;
		if (si->skey.proto == IPPROTO_ICMP)
			*port = si->natinfo.sp;
		else
			*port = si->rsk.dp;
	}
	else {
		// XXX: DNAT인 경우에 여러가지 경우의 수를 검사 해야 한다.
		*ip = si->skey.dst;
		*port = si->skey.dp;
	}

	return 0;
}
#endif

uint32_t nat_make_hash(session_t *si)
{
	struct hashdata_s k;
	uint32_t hash = 0;
	skey_t *skey = &si->skey;
	natinfo_t *natinfo = &si->natinfo;

	k.proto = skey->proto;

	if (si->action & ACT_SINGLE_NAT) {
		k.ip    = skey->dst ^ natinfo->ip[0];
		k.port  = skey->dp  ^ natinfo->port[0];
	}
	else if (si->action & ACT_BNAT) {
		k.ip    = natinfo->ip[0] ^ natinfo->ip[1];
		k.port  = natinfo->port[0]  ^ natinfo->port[1];
	}
	else {
		return 0;
	}

	MurmurHash3_x86_32((const void *)&k, NS_HASH_SIZE, 0x43606326, &hash);

	return hash;
}

nat_ip_t* find_ip_obj_by_ip(nat_policy_t* natp, ip4_t ip)
{
	nat_ip_t *nip;

	list_for_each_entry(nip, &natp->ip_list, list) {
		if (nip->ip == ip) {
			return nip;
		}
	}

	return NULL;
}

// idx: zero based
nat_ip_t* find_ip_obj_by_idx(nat_policy_t* natp, uint32_t idx)
{
	nat_ip_t *nip=NULL;
	uint32_t i;

	ENT_FUNC(3);

	// out of bound
	if (idx > natp->ip_cnt)
		return NULL;

	i = 0;
	list_for_each_entry(nip, &natp->ip_list, list) {
		if (i == idx) {
			return nip;
		}

		i++;
	}

	return NULL;
}

void nat_clean_ip_obj(nat_policy_t* natp)
{
	nat_ip_t* nip;

	while (!list_empty(&natp->ip_list)) {
		nip = list_entry(natp->ip_list.next, nat_ip_t, list);
		list_del_init(&nip->list);

		if (nip->port.bitmap)
			ns_free(nip->port.bitmap);

		ns_free(nip);

	}

	natp->ip_cnt = -1;
}

int32_t nat_clean_bitmap(fw_policy_t *fwp, int32_t cnt)
{
	int32_t i;

	for (i=0; i<cnt; i++) {

		if (!(fwp[i].action & ACT_NAT)) 
			continue;

		if (fwp[i].nat_policy[0])
			nat_clean_ip_obj(fwp[i].nat_policy[0]);

		if (fwp[i].nat_policy[1])
			nat_clean_ip_obj(fwp[i].nat_policy[1]);
	}

	return 0;
}

void nat_check_and_fix_port_range(nat_policy_t* natp)
{
	if (natp->nport[0] < NAT_MIN_PORT) {
		ns_log("Start port value for NAPT is too low(%d) and wil be fixed to %d", 
			   natp->nport[0], NAT_MIN_PORT);

		natp->nport[0] = NAT_MIN_PORT;
	}

	if (natp->nport[1] < natp->nport[0]) {
		ns_log("End port value for NAPT is low(%d) than Start port value and wil be fixed to %d",
			   natp->nport[1], natp->nport[0]);

		natp->nport[1] = natp->nport[0];
	}
}

int32_t nat_init_ip_obj(nat_policy_t *natp)
{
	int32_t i;
	ip4_t cur_ip;
	nat_ip_t *nip;
	uint32_t port_cnt;
	ip4_t nic_ip = 0;
	int32_t ip_cnt = -1;

	ENT_FUNC(3);

	natp->available_ip = NULL;
	INIT_LIST_HEAD(&natp->ip_list);

	// ip obj를 사용하지 않는 경우
	if (natp->flags & NAT_IS_NOT_USE_IPOBJ) {
		return 0;
	}

	if (natp->flags & NATF_DYNAMIC_IP) {
		// NIC가 동적 IP인 경우 룰을 사용 할 때 IP를 얻어서 사용한다.
		// 만일 사용중에 NIC의 IP가 변경 되는 경우 nic notifier에서 변경된 IP를 처리 한다. 
		nic_ip = ns_get_nic_ip(natp->nic);

		// 이경우는 NIC에 아직 IP가 없다.  // 그러므로 NAT를 할 수 없다.
		if (nic_ip == 0)
			return -1;

		// set ip
		natp->nip[0] = natp->nip[1] = nic_ip;
		ip_cnt = 1;
	}
	else {
		ip_cnt = nat_get_ip_count(natp);
	}

	// 포트가 뒤집어진 경우 수정
	if (natp->flags & NAT_IS_USE_PORTOBJ) {
		nat_check_and_fix_port_range(natp);
	}

	port_cnt = natp->nport[1] - natp->nport[0] + 1;
	cur_ip = natp->nip[0];

	for (i=0; i<ip_cnt; i++) {
		if (natp->flags & NATF_DYNAMIC_IP) {
			cur_ip = nic_ip;
		}

		nip = (nat_ip_t*)ns_malloc_az(sizeof(nat_ip_t));
		ns_mem_assert(nip, "nat_ip_t", break);

		// 정보 저장
		nip->ip = cur_ip;
		nip->port_cnt = port_cnt;
		nip->free_cnt = port_cnt;
		INIT_LIST_HEAD(&nip->list);

		list_add_tail(&nip->list, &natp->ip_list);

		if (!(natp->flags & NATF_DYNAMIC_IP)) {
			ns_inc_ip(&cur_ip);
		}
	}

	if (i < 1) {
		natp->ip_cnt = -1;
	}
	else {
		natp->ip_cnt = i;
		// 최초 obj 저장
		natp->available_ip = list_entry(natp->ip_list.next, nat_ip_t, list);
	}

	return 0;
}

int32_t nat_reserve_port(nat_policy_t *natp, nat_ip_t *nip, uint16_t *new_port)
{
	int32_t ret=0;
	uint16_t offset;

	ENT_FUNC(3);

	/*
	TCP TIME_WAIT 문제를 극복하기 위해서 nat prot를 계속 증가하게 수정
	TIME_WAIT 문제: TCP 서버 사이드에서 FIN handshaking을 정상적으로 완료해도 
	마지막 FIN ACK 유실에 대해서 처리하기 위해서 일정기간 동안 TIME_WAIT상태로
	남아 있다. 이때 REUSE_ADDR 플래그 없이 해당 포트를 bind를 하는 경우 바인딩 에러 발생

	INFO: 새로운 nat port를 이전에 사용하고 해제한 포트를 바로 재사용하면,
	TCP TIME_WAIT 주기 내에서 재사용 되어서 연결에 실패할 가능성이 높다.
	이문제를 해결하기 위해서는 nat port를 계속 증가시키고
	끝점에 오면 다시 시작점으로 돌려서 검색한다.
	*/

	if (nip == NULL)
		return -1;

	if (nip->port_cnt == 0 || nip->free_cnt == 0) {
		dbg(0, "Invalid NAT IP Obj: NAT IP="IP_FMT ", port: %u-%u, port_cnt=%u, free_cnt=%u", 
			IPH(nip->ip), 
			natp->nport[0], 
			natp->nport[1], 
			nip->port_cnt, 
			nip->free_cnt);

		return -1;
	}

	if (nip->port.bitmap == NULL) {
		nip->port.bitmap = ns_malloc_az(NAT_PORT_BITMAP_SIZE);
		ns_mem_assert(nip->port.bitmap, "port_bitmap", return -1);

		nip->port.start_offset = natp->nport[0];

		// set all usable
		// '1' 인경우 사용 가능하다는 의미 이다.
		memset(nip->port.bitmap, 0xff, NAT_PORT_BITMAP_SIZE);
	}

	// 새로운 포트 값이 0이면, (새로운 포트 할당 요구)
	if (*new_port == 0) {

START_SEARCH:

		// 	- 마지막 포트 번호에 도달하면, 처음부터 찾는다.
		if (natp->nport[1] < nip->port.start_offset) {
			nip->port.start_offset = natp->nport[0];
		}

		// find_next_bit()을 호출하여 bit(할당 가능한 포트번호)를 찾는다.
		//	- 못찾는 경우 (size 값을 리턴했으면)
		// zero based index
		offset = (uint16_t) find_next_bit((const unsigned long*)nip->port.bitmap, 
										  (int)natp->nport[1]+1, (int)nip->port.start_offset);

		if (natp->nport[0] <= offset && offset <= natp->nport[1]) {

			// lock로 보호 되기 때문에 atomic 연산이 필요 없다.
			clear_bit((int32_t)offset, (volatile unsigned long *)nip->port.bitmap);
			*new_port = offset;

			if (nip->free_cnt)
				nip->free_cnt --;

			if (offset < natp->nport[1]) {
				nip->port.start_offset = offset + 1;
			}
			else {
				nip->port.start_offset = natp->nport[0];
				dbg(0, "out of range: %u, %u", offset, natp->nport[1]);
			}

			dbg(5, "NAT info: new_port=%u, start_offset=%u, port=%u-%u, free_ports=%u, port_cnt=%u", 
				offset, 
				nip->port.start_offset,
				natp->nport[0], natp->nport[1], 
				nip->free_cnt, nip->port_cnt);
		}
		else if (nip->port.start_offset != natp->nport[0]) {
			dbg(0, "go back to begin: %u", nip->port.start_offset);

			// 검색에 실패하면, 무조건 처음 위치로 설정하고 재검색
			nip->port.start_offset = natp->nport[0];

			// 재 검색 한다.
			goto START_SEARCH;
		}
		else {
			// 이경우는 offset을 처음으로 설정하고도 포트를 찾지 못했다.
			ret = -1;

			dbg(0, "No more available port: NAT IP="IP_FMT ", port: %u-%u, offset=%u, port_cnt=%u, free_cnt=%u", 
				IPH(nip->ip), 
				natp->nport[0], 
				natp->nport[1], 
				offset, 
				nip->port_cnt, nip->free_cnt);
		}

	}
	else {
		//	clear_bit()를 호출하여 그 포터 번호를 사용중으로 설정한다.
		clear_bit(*new_port, (volatile unsigned long *)nip->port.bitmap);

		if (nip->free_cnt)
			nip->free_cnt --;
	}

	return ret;
}

int32_t nat_reserve_ip_port(nat_policy_t *natp, session_t *si, ip_t *new_ip, uint16_t *new_port)
{
	nat_ip_t *nip = NULL;
	int32_t ret = -1, found=0;
	ip4_t sip =  si->skey.src;

	ENT_FUNC(3);

	if (natp->flags & NATF_SNAT_HASH) {
		int32_t hidx;

		// hashed인경우 ip를 공유 하므로 port로 함께 변경 한다.
		hidx = sip % natp->ip_cnt;
		nip = find_ip_obj_by_idx(natp, hidx);
	}

	if (nip == NULL) {
		nip = natp->available_ip;
	}

	// 빈 ip_obj를 찾는다
	if (nip == NULL || nip->free_cnt == 0) {

		natp->available_ip = nip = NULL;
		found = 0;

		list_for_each_entry(nip, &natp->ip_list, list) {
			if (nip->free_cnt != 0) {
				found = 1;
				break;
			}
		}

		// no more free ip obj
		if (found == 0 || nip == NULL) {
			dbg(5, "No more available NAT IP");
			return -1;	
		}
		else if (nip && nip->free_cnt == 0) {
			dbg(5, "All NAT objects have already used: ip_cnt=%d, port_cnt=%d, free_cnt=%d", 
				natp->ip_cnt, nip->port_cnt, nip->free_cnt);

			return -1;
		}

		natp->available_ip = nip;
	}

	ret = nat_reserve_port(natp, nip, new_port);
	if (ret == 0) {
		*new_ip = nip->ip;
	}

	return ret;
}

ip4_t nat_get_masked_ip(ip4_t src, ip4_t nat_ip, uint32_t mask)
{
	// 1) src ip의 NAT IP mask 제외한 만큼 구하고,
	// 2) NAT IP의 mask 값을 구한다.
	// 3) 두 값을 합한다.
	// ex) NAT IP: 210.1.1.0 ~ 255(C class), mask: 255.255.255.0
	// ex) src ip: 192.168.1.30 --> 210.1.1.30으로 변경 됨 

	ip4_t new_ip;

	new_ip = (src & ~mask) | (nat_ip & mask);

	return new_ip;
}

int32_t nat_bind_snat_info(session_t *si, nat_policy_t *natp, ip_t *new_ip, uint16_t *new_port)
{
	int32_t ret = 0;

	ENT_FUNC(3);

	switch (natp->flags & NATF_SNAT_MASK) {
	case NATF_SNAT_MASKING: 
		*new_ip = nat_get_masked_ip(si->skey.src, natp->nip[0], natp->nip[1]);
		*new_port = si->skey.sp;
		break;

	case NATF_SNAT_HASH: 
	case NATF_SNAT_NAPT:
		ns_rw_lock_irq(&natp->nat_lock) {
			if (nat_reserve_ip_port(natp, si, new_ip, new_port) == 0) {
				// 사용 완료후 세션이 삭제 될때 관련 데이터를 릴리즈 해라..
				si->action |= ACT_NAT_RELEASE;
			}
			else {
				ret = -1;
				ns_err("All NAT objects are already used");
			}

		} ns_rw_unlock_irq(&natp->nat_lock);

		break;

	default:
		ret = -1;
		ns_err("Unknown SNAT flags: 0x%x", natp->flags);
		break;
	}

	return ret;
}

int32_t nat_bind_dnat_info(session_t *si, nat_policy_t *natp, int32_t inic, ip_t *new_ip, uint16_t *new_port)
{
	int32_t ret = 0;

	ENT_FUNC(3);

	switch( natp->flags & NATF_DNAT_MASK) {
	case NATF_DNAT_RDIR: 
		// ip 변경
		// mask를 사용하는 경우 1:1 mapping이다.
		if (natp->nip[1] != 0) {
			*new_ip = nat_get_masked_ip(si->skey.dst, natp->nip[0], natp->nip[1]);
		}
		else {
			*new_ip = natp->nip[0];
		}

		// port가 지정 되어 있는 경우 변경
		if (natp->nport[0] != 0)
			*new_port = natp->nport[0];
		else if (si->skey.proto == IPPROTO_ICMP) {
			// virtual ip를 사용해서 DNAT를 거는 경우 icmp id가 잘못 되어 
			// 항상 동일한 id로 nat 되는 버그가 있음.
			// 원본 패킷의 id를 그래도 사용하게 복사함
			*new_port = si->skey.sp;
		}
		else {
			*new_port = si->skey.dp;
		}

		break;

	case NATF_DNAT_LRDIR:
		// 패킷이 들어온 인터페이스의 IP로 DNAT을 한다.
		*new_ip = ns_get_nic_ip(inic);

		// port가 지정 되어 있는 경우 변경
		if (natp->nport[0] != 0)
			*new_port = natp->nport[0];
		else
			*new_port = si->skey.dp;

		break;

	default:
		ret = -1;
		ns_err("Unknown DNAT flags: 0x%x", natp->flags);
		break;
	}

	return ret;
}

int32_t nat_do_binding(session_t* si, nat_policy_t *natp, int32_t inic, ip_t *new_ip, uint16_t *new_port)
{
	int32_t ret = -1;

	ENT_FUNC(3);

	dbg(6, "RuleID=%u, flags=0x%x, nat_ip[0]=" IP_FMT ",nat_ip[1]=" IP_FMT ",port=%d ~ %d, ip_cnt=%d",
		natp->id,
		natp->flags,
		IPH(natp->nip[0]), 
		IPH(natp->nip[1]), 
		natp->nport[0],
		natp->nport[1],
		natp->ip_cnt);

	// it is first time
	if (natp->ip_cnt < 0) {
		ns_rw_lock_irq(&natp->nat_lock) {
			ret = nat_init_ip_obj(natp);
		} ns_rw_unlock_irq(&natp->nat_lock);

		if (ret)
			return ret;
	}

	*new_ip = 0;
	*new_port = 0;

	if (natp->flags & NATF_SNAT_MASK) {
		ret = nat_bind_snat_info(si, natp, new_ip, new_port);
	}
	else if (natp->flags & NATF_DNAT_MASK) {
		ret = nat_bind_dnat_info(si, natp, inic, new_ip, new_port);
	}

	return ret;
}

int32_t nat_bind_info(session_t* si, fw_policy_t* fwp, nic_id_t inic)
{
	nat_policy_t *n[2];
	int32_t ret=0, idx=0;
	natinfo_t *natinfo = &si->natinfo;

	ENT_FUNC(3);

	bzero(natinfo, sizeof(natinfo_t));

	// Single NAT
	n[0] = fwp->nat_policy[0];
	if (n[0] == NULL)
		return -1;

	// check valid for Both NAT
	n[1] = fwp->nat_policy[1];

	if (fwp->action & ACT_BNAT) {
		if (n[1] == NULL)
			return -1;

		// Both NAT에서 SNAT(1st) + DNAT(2nd) 만 가능하다.
		if ((n[0]->flags & NATF_DNAT_MASK) ||
			(n[1]->flags & NATF_SNAT_MASK)) {

			dbg(0, "A second NAT is only available with DNAT: id=%d", fwp->rule_id);
			return -1;
		}
	}

	idx = 0;
	if (n[0]->flags & NATF_DNAT_MASK) {
		idx = 1;
	}

	// for Single NAT
	if ((ret=nat_do_binding(si, n[0], inic, &natinfo->ip[idx], &natinfo->port[idx]))) {
		return -1;
	}

	// for Both NAT
	if (fwp->action & ACT_BNAT) {
		if ((ret=nat_do_binding(si, n[1], inic, &natinfo->ip[1], &natinfo->port[1]))) {
			return -1;
		}
	}

	// assign NAT info into Session
	dbg(0, "NAT info: RuleID=%u, 1st new_ip=" IP_FMT ":%d" ", 2nd new_ip=" IP_FMT ":%d", 
		fwp->rule_id,
		IPH(natinfo->ip[0]), natinfo->port[0], 
		IPH(natinfo->ip[1]), natinfo->port[1]);

	return ret;
}

int32_t nat_update_used_nat_info(session_t* si)
{
#warning "FIXME"
#if 0
	nat_policy_t* natp = NULL;
	nat_ip_t* nip;
	ip4_t ip;
	uint16_t port;

	ENT_FUNC(3);

	if (!si || !si->mrule.nat)
		return -1;

	natp = si->mrule.nat->nat_policy[0];

	// port bitmap을 사용하는 경우는 아래의 경우에 한정한다.
	if (!(si->action & ACT_NAT_RELEASE) || !natp) {
		return -1;
	}

	// 각종 정보를 업데이트 한다.
	// 1. ip_obj를 생성 한다.
	// 2. 현재 사용중인 port를 표시 한다.
	// 	  이때, bitmap의 위치가 유동적이므로 이를 조정 해야 한다.

	ns_rw_lock_irq(&natp->nat_lock) {

		if (natp->ip_cnt < 0) {
			nat_init_ip_obj(natp);
		}

		nat_get_natkey(si, &ip, &port);
		nip = find_ip_obj_by_ip(natp, ip);
		if (nip) {
			nat_reserve_port(natp, nip, &port);
		}
		else {
			dbg(0, "Not available ip obj: "IP_FMT, IPH(ip));
		}

	} ns_rw_unlock_irq(&natp->nat_lock);

	si->mrule.nat->sc ++;
	si->mrule.nat->hits ++;

	// 룰이 마지막으로 사용된 시간
	si->mrule.nat->timestamp = wise_get_time();
#endif

	return 0;
}

int32_t nat_release_info(session_t* si, fw_policy_t* fwp)
{
	nat_ip_t *nip;
	uint16_t port=0;
	ip_t  ip;
	int32_t i;
	nat_policy_t *p;

	ENT_FUNC(3);

	if (!(si->action & ACT_NAT_RELEASE) || fwp == NULL) {
		dbg(0, "Can't release NAT info: 0x%llx, natp=0x%p", si->action, fwp);
		return -1;
	}

	DBGKEY(9, SKEY, &si->skey);

	for (i=0; i<2; i++) {

		ip = si->natinfo.ip[i];
		port = si->natinfo.port[i];
		p = fwp->nat_policy[i];

		if (ip == 0 || p == NULL) {
			continue;
		}

		ns_rw_lock_irq(&p->nat_lock);
		nip = find_ip_obj_by_ip(p, ip);

		if (nip == NULL) {
			dbg(0, "Could not find ip obj: "IP_FMT ", port=%u", IPH(ip), port);
		}
		else if (nip->port.bitmap) {
			set_bit(port, (volatile unsigned long *)nip->port.bitmap);
			nip->free_cnt ++;

			dbg(5, "si=0x%p, Release ip=" IP_FMT ", port=%u, free_cnt=%d", 
				si, IPH(ip), port, nip->free_cnt);
		}
		else {
			dbg(0, "port bitmap is NULL, si=0x%p, release ip=" IP_FMT ", port=%u", si, IPH(ip), port);
		}

		ns_rw_unlock_irq(&p->nat_lock);
	}

	return 0;
}

///////////////////////////////////////////////////
// apply NAT to packet

int32_t nat_port_csum(iph_t* iph, int32_t is_hw_csum, ip4_t new_ip, ip4_t old_ip, 
					  uint16_t new_port, uint16_t old_port, uint16_t *csum)
{
	if (csum == NULL) 
		return -1;

	if (iph->protocol == IPPROTO_ICMP) {
		*csum = ns_csum(old_port ^ 0xffff, new_port, *csum);
	}
	else if (*csum == 0 && iph->protocol == IPPROTO_UDP) {
		// FIXME: option 기능으로 추가 예정
		// UDP 인경우 checksum 값이 0이면 checksum을 계산하지 않는다는 의미이다.
		// nothing
		//ns_err("A UDP packet comes in with NO CHECKSUM and then don't be applied checksum");
	}
	else if (is_hw_csum) {
		// CHECKSUM_HW 인경우 HW에서 checksum을 계산 한다.
		// 만일 CHECKSUM_HW 인 상태에서 NIC가 지원하지 않는 경우 dev_queue_xmit()에서
		// skb_checksum_help()이 호출 된다
		// tcp_ipv4.c의 tcp_v4_send_check()에서 보면 checksum 값을 inverse한다.
		// 그러므로, 다시 원복해서 계산하고 결과를 inverse한다.
		// 또한, port 변경에 대한 내용은 제외 한다.(이유는 잘 모르겠다.)
		*csum = ~ns_csum(~old_ip, new_ip, ~(*csum));
	}
	else {
		*csum = ns_csum(~old_ip, new_ip, ns_csum(old_port ^ 0xffff, new_port, *csum));
	}

	return 0;
}

int32_t nat_sw_checksum(skb_t* skb, ip4_t newip, int32_t is_chg_dst)
{
	/*****************************************
	  1)TCP checksum 구성 요소: 
	  -. 12 byte pseudo header + TCP header + TCP payload

	  2) pseudo header의 구조
	  -. 4 byte: source address
	  -. 4 byte: destination address
	  -. 1 byte: zero
	  -. 1 byte: protocol (IPPROTO_TCP = 6)
	  -. 2 byte: TCP length (TCP header + TCP payload)

	  3) 리눅스에서는 skb->sum에 tcp payload checksum을 미리 계산하고
	  tcp/ip 스택에서 tcp/ip 헤더의 내용이 결정되면 checksum을 완성 한다.
	 ****************************************************/

	iph_t *iph = ns_iph(skb);
	tph_t *tph = ns_tcph(skb);
	unsigned int tcphoff = iph->ihl * 4;
	uint16_t tt;

	// tcp checksum 전체를 재계산 한다.
	tph->check = 0;
	tt = skb->csum;

	// tcp payload 부분에 대한 checksum 계산.
	skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);

	dbg(5, "old csum=0x%x, new csum=0x%x", tt, skb->csum);

	// pseudo header 포함한 tcp header에 대한 checksum 계산.
	if (is_chg_dst) {
		tph->check = csum_tcpudp_magic(iph->saddr, newip,
									   skb->len - tcphoff,
									   iph->protocol,
									   skb->csum);
	}
	else {
		tph->check = csum_tcpudp_magic(newip, iph->daddr,
									   skb->len - tcphoff,
									   iph->protocol,
									   skb->csum);
	}

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	//skb_checksum_help(skb, 0);

	return 0;
}

int32_t nat_apply_icmperr(ns_task_t* nstask, int32_t is_dnat) 
{
	int32_t ret = 0;

	iph_t *iph = (iph_t *)(ns_raw(nstask->pkt) + sizeof(ich_t));
	ip4_t *p_oldip=NULL, newip=0;
	uint16_t *p_oldport=NULL, newport=0, oldport=0, *p_check=NULL;
	skey_t *skey;
	uint8_t* h;
	natinfo_t *n;

	DUMP_PKT(4, iph, nstask->skey.inic);

	skey = &nstask->si->skey;
	h = (uint8_t* )iph + (iph->ihl << 2);
	n = &nstask->si->natinfo;

	if (is_dnat) {
		newip = skey->dst;
		newport = skey->dp;
	}
	else {
		newip = skey->src;
		newport = skey->sp;
	}

	p_oldip   = is_dnat ? &iph->daddr : &iph->saddr;

	// change ip/port and its checksum
	switch (iph->protocol) {
	case IPPROTO_TCP:
		p_oldport = is_dnat ? &((tph_t*)h)->dest : &((tph_t*)h)->source;
		p_check   = &((tph_t*)h)->check;
		break;
	case IPPROTO_UDP:
		p_oldport = is_dnat ? &((uph_t*)h)->dest : &((uph_t*)h)->source;
		p_check   = &((uph_t*)h)->check;
		break;
	case IPPROTO_ICMP:
		p_oldport = &((ich_t*)h)->un.echo.id;
		p_check   = &((ich_t*)h)->checksum;
		break;
	default:
		dbg(5, "ICMP ERR: Unknown");
		return 0;
	}

	// 원래 값은 host order이다.
	newip = htonl(newip);
	newport = htons(newport);

	if (p_oldport) {
		oldport = *p_oldport;
		*p_oldport = newport;
	}

	// port checksum
	if (p_check) {
		nat_port_csum(iph, 0, newip, *p_oldip, newport, oldport, p_check);
	}

	// ip checksum
	if (ISREQ(nstask)) {
		skey_t* k = &nstask->skey;
		iph_t* org_iph;
		ich_t* ic;

		org_iph = ns_iph(nstask->pkt);
		ic = ns_icmph(nstask->pkt);

		ns_warn("ICMP ERR pkt in NAT:" IP_FMT "->" IP_FMT ":type=%d, code=%d:: payload: " IP_FMT"->" IP_FMT "(%s)",
				IPN(org_iph->saddr), IPN(org_iph->daddr),
				ic->type, ic->code,
				IPN(iph->saddr),
				IPN(iph->daddr),
				ns_get_protocol_name(k->proto));
	} 
	else {
		iph->check = ns_csum(~(*p_oldip), newip, iph->check);

		// ip 변경
		*p_oldip = newip;
	}

	DUMP_PKT(0, iph, nstask->skey.inic);

	return ret;
}

int32_t nat_apply(ns_task_t* nstask, int32_t is_chg_dst, int32_t is_dnat)
{
	int32_t ret = 0;
	iph_t *iph = ns_iph(nstask->pkt);
	tph_t *tph = ns_tcph(nstask->pkt);
	uph_t *uph = ns_udph(nstask->pkt);
	ich_t *ich = ns_icmph(nstask->pkt);
	ip4_t *p_oldip=NULL, newip=0;
	uint16_t *p_oldport=NULL, newport=0, oldport=0, *p_check=NULL;
	skey_t *skey;
	natinfo_t *n;
		
	if (nstask->pkt->pkt_type == PACKET_OTHERHOST) {
		dbg(5, "This packet is OTHERHOST");
		nstask->pkt->pkt_type = PACKET_HOST;
	}

	skey = &nstask->si->skey;
	n = &nstask->si->natinfo;

	if (is_dnat) {
		if (is_chg_dst) {
			newip = n->ip[1];
			newport = n->port[1];
		}
		else {
			newip = skey->dst;
			newport = skey->dp;
		}
	}
	else {
		if (is_chg_dst) {
			newip = skey->src;
			newport = skey->sp;
		}
		else {
			newip = n->ip[0];
			newport = n->port[0];
		}
	}

	p_oldip   = is_chg_dst ? &iph->daddr : &iph->saddr;

	// change ip/port and its checksum
	switch (iph->protocol) {
	case IPPROTO_TCP:
		p_oldport = is_chg_dst ? &tph->dest  : &tph->source;
		p_check   = &tph->check;
		break;

	case IPPROTO_UDP:
		p_oldport = is_chg_dst ? &uph->dest  : &uph->source;
		p_check   = &uph->check;
		break;

	case IPPROTO_ICMP:
		p_oldport = &ich->un.echo.id;
		p_check   = &ich->checksum;

		// icmp error 인경우 원래의 id를 그대로 사용 한다.
		if (nstask->flags & TASK_FLAG_ICMPERR) {
			nat_apply_icmperr(nstask, is_dnat);
			newport =  *p_oldport;
		}
		break;

	default:
		return 0;
	}

	// 원래 값은 host order이다.
	newip 	= htonl(newip);
	newport = htons(newport);

	if (p_oldport) {
		oldport  = *p_oldport;
		*p_oldport = newport;
	}

	// port checksum
	if (p_check) {
#if 1
		nat_port_csum(iph, IS_HW_CSUM(nstask), newip, *p_oldip, newport, oldport, p_check);

#else
		nat_sw_checksum(nstask->pkt, newip, is_chg_dst);
#endif
	}

	// ip change and checksum
	iph->check = ns_csum(~(*p_oldip), newip, iph->check);
	*p_oldip = newip;

	return ret;
}

// ********* NAT 패킷 처리에서 패킷의 SRC/DST 변경 여부 판단 알고리즘 ****************
// 1. NAT는 종류와 상관 없이 SRC나 DST를 변경 해야 한다.
//    예를 들면 SNAT의 REQUEST(outbound) 패킷은 SRC를 변경해야 하고
//    RESPONSE(inbound) 패킷은 DST를 변경 해야 한다.
//    반대로 DNAT의 경우 REQUEST에 대해서 DST를 변경해야 하고
//    RESPONSE에 대해서 SRC를 변경 해야 한다.
// 2. SNAT/DNAT/REQ/RES에 대해 SRC/DST 변경 여부에 대한 진리표는 Exclusive-OR 진리표와 같다
//  * LEGEND: 
//		-. Dir: REQ =0, RES =1
//		-. Nat: SNAT=0, DNAT=1
//		-. Ret: SRC =0, DST =1
//
//  ** NAT TRUTH TABLE - Exclusive-OR **
//   D | N | R
//  ---+---+---
//   0 | 0 | 0
//  ---+---+---
//   0 | 1 | 1
//  ---+---+---
//   1 | 0 | 1
//  ---+---+---
//   1 | 1 | 0
//  ---+---+---
inline int32_t nat_truth_table(int32_t dnat, int32_t res)
{
	// change to boolean value
	dnat &= 0x01;
	res  &= 0x01;

	return (dnat ^ res);
}

int32_t nat_main(ns_task_t* nstask)
{
	int32_t ret = NS_ACCEPT;
	int32_t is_chg_dst, is_dnat;

	ENT_FUNC(3);

	if (!nstask->si) {
		return NS_DROP;
	}

	DUMP_PKT(0, ns_iph(nstask->pkt), nstask->skey.inic);

	// Both NAT
	if (nstask->si->action & ACT_BNAT) {

#if 0
		// do SNAT
		is_dnat = 0;
		is_chg_dst = nat_truth_table(is_dnat, ISRES(nstask));

		if (is_chg_dst && 
			!(nstask->flags & TASK_FLAG_HOOK_POST_ROUTING)) {
			if (nat_apply(nstask, is_chg_dst, is_dnat)) {
				ret = NS_DROP;
				goto END;
			}
		}
		else {
			putoff = 1;
		}

		// do DNAT
		is_dnat = 1;
		is_chg_dst = nat_truth_table(is_dnat, ISRES(nstask));

		if (is_chg_dst && 
			!(nstask->flags & TASK_FLAG_HOOK_POST_ROUTING)) {
			if (nat_apply(nstask, is_chg_dst, is_dnat)) {
				ret = NS_DROP;
				goto END;
			}
		}
		else {
			putoff = 1;
		}

		if (putoff) {
			// call nat_main()
			append_cmd(nstask, nat);

			// put it off to PRE_ROUTING
			ret = NS_QUEUE;
		}
#else
		// do SNAT, DNAT
		for (is_dnat = 0; is_dnat < 2; is_dnat ++) {
			is_chg_dst = nat_truth_table(is_dnat, ISRES(nstask));

			if ((is_chg_dst && !(nstask->flags & TASK_FLAG_HOOK_POST_ROUTING)) ||
				(!is_chg_dst && (nstask->flags & TASK_FLAG_HOOK_POST_ROUTING))) {
				if (nat_apply(nstask, is_chg_dst, is_dnat)) {
					ret = NS_DROP;
					goto END;
				}
			}
		}

		// PRE_ROUTING
		if (!(nstask->flags & TASK_FLAG_HOOK_POST_ROUTING)) {
			// call nat_main()
			append_cmd(nstask, nat);
			ret = NS_QUEUE;
		}

#endif
	}
	// Single NAT
	else if (nstask->si->action & ACT_SINGLE_NAT) {
		is_dnat = (nstask->si->action & ACT_DNAT) != 0;
		is_chg_dst = nat_truth_table(is_dnat, ISRES(nstask));

		// PRE_ROUTING: DNAT
		// POST_ROUTPING: SNAT
		if ((is_chg_dst && !(nstask->flags & TASK_FLAG_HOOK_POST_ROUTING)) ||
			(!is_chg_dst && (nstask->flags & TASK_FLAG_HOOK_POST_ROUTING))) {
			ret = NS_ACCEPT;

			if (nat_apply(nstask, is_chg_dst, is_dnat)) {
				ret = NS_DROP;
			}
		}
		else {
			// call nat_main()
			append_cmd(nstask, nat);
			ret = NS_QUEUE;
		}
	}
	else {
		dbg(5, "No actoin ");
	}

END:
	DUMP_PKT(0, ns_iph(nstask->pkt), nstask->skey.inic);

	return ret;
}
