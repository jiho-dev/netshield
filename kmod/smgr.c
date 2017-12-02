#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <session.h>
#include <commands.h>
#include <log.h>
#include <ns_malloc.h>
#include <khypersplit.h>
#include <pmgr.h>
#include <ioctl_session.h>
#include <options.h>
#include <tcp_state.h>
#include <smgr.h>


//////////////////////////////////////////////////////

smgr_t		*g_smgr; 
extern struct kmem_cache	*netshield_scache;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

void netshield_create_sem_cache(int32_t size);
int32_t smgr_post_main(ns_task_t *nstask);
int32_t nstimer_get_lifetime(uint32_t cur_time, uint32_t timeout, uint32_t timestamp);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

uint32_t smgr_get_next_sid(void)
{
	return (uint32_t)atomic_inc_return(&g_smgr->last_id);
}

void smgr_remove_alist(smgr_t *smgr, session_t *si)
{
	if (smgr == NULL) {
		return;
	}

	atomic_dec(&smgr->all);
	atomic_dec(&smgr->mine);

	ns_rw_lock_irq(&smgr->smgr_lock) {
		list_del_rcu(&si->alist);
		session_release(si);

#if 0
		if (!list_empty(&si->rlist)) {
			list_del_rcu(&si->rlist);
			session_release(si);
		}
#endif

	} ns_rw_unlock_irq(&smgr->smgr_lock);
}

void smgr_add_alist(smgr_t *smgr, session_t* si)
{
	if (smgr == NULL) {
		return;
	}

	atomic_inc(&smgr->all);
	atomic_inc(&smgr->mine);

	ns_rw_lock_irq(&smgr->smgr_lock) {
		list_add_tail_rcu(&si->alist, &g_smgr->all_slist);
		session_hold(si);

	} ns_rw_unlock_irq(&smgr->smgr_lock);
}

int32_t smgr_add_session(smgr_t *smgr, session_t *si)
{
	ENT_FUNC(3);

	smgr_add_alist(smgr, si);

	session_insert(smgr->stab, si);
	nstimer_insert(&si->timer, 10);

	dbg(5, "Add a new session: si=0x%p, refcnt=%d", si, atomic_read(&si->refcnt));

	return 0;
}

int32_t smgr_delete_session(session_t *si, uint32_t flags)
{
	ENT_FUNC(3);

	dbg(5, "Delete old session: si=0x%p, refcnt=%d", si, atomic_read(&si->refcnt));

	if (flags & SMGR_DEL_SAVE_LOG) {
		// 세션 종료시 INFO 로그도 같이 남김 (통계에서 사용)
#if 0
		if (si->action & ACT_LOG_INFO) {
			wlog_session(&si->nsk, LOG_STAT_INFO, 0, NULL, si->mrule.fw, si);
		}

		if (si->action & ACT_LOG_CLOSE) {
			wlog_session(&si->nsk, LOG_STAT_CLOSE, 0, NULL, si->mrule.fw, si);
		}
#endif
	}

	smgr_remove_alist(g_smgr, si);

	session_remove(g_smgr->stab, si);
	nstimer_remove(&si->timer);

	return 0;
}

int32_t smgr_delete_by_ip(ip_t ip, int32_t kind)
{
	session_t *si = NULL, *n;
	ip_t	*cmp_ip;
	int32_t del_cnt = 0;

START:
	ns_rw_lock_irq(&g_smgr->smgr_lock) {

		list_for_each_entry_safe(si, n, &g_smgr->all_slist, alist) {

			switch (kind) {
			default:
			case SMGR_DEL_SKEY_SRC:
				cmp_ip = &si->skey.src;
				break;

			case SMGR_DEL_SKEY_DST:
				cmp_ip = &si->skey.dst;
				break;

			case SMGR_DEL_SNAT:
				cmp_ip = &si->natinfo.ip[0];
				break;

			case SMGR_DEL_DNAT:
				cmp_ip = &si->natinfo.ip[1];
				break;

			}

			if (ip == *cmp_ip) {
				del_cnt++;
				// 지울 세션은 6초(DSYNC를 위한 5초 + 1)후 삭제 된다.
				// DSYNC가 동작하는 경우 싱크가 이루어져서 삭제 된다.
				//lft_change_timeout(&si->lft, 6);

				// 그러나 패킷이 계속 들어 오는 경우 세션이 계속 살아 있게 된다.
				// 그래서 바로 지워야 한다.
				// unlock없이 호출하면 deadlock이다.
				ns_rw_unlock_irq(&g_smgr->smgr_lock);
				smgr_delete_session(si, 0);
				goto START;
			}
		}

	} ns_rw_unlock_irq(&g_smgr->smgr_lock);

	return del_cnt;
}

int32_t smgr_setup_session_info(char* arg)
{
	int32_t ret=0;
	ioctl_get_sess_t *user_sinfo = (ioctl_get_sess_t*)arg;
	uint32_t scnt, max_cnt;
	session_t *si, *n;

	ENT_FUNC(3);

	max_cnt = atomic_read(&g_smgr->all);
	scnt = 0;

	dbg(5, "Current session: %u", max_cnt);

	if (max_cnt > 0) {
		list_for_each_entry_safe(si, n, &g_smgr->all_slist, alist) {
			ioctl_session_t *s = &user_sinfo->sess[scnt];
			uint32_t ctime = nstimer_get_time();

			skey_t *dsk = &s->skey;
			skey_t *ssk = &si->skey;

			dsk->src = ssk->src;
			dsk->dst = ssk->dst;
			dsk->sp = ssk->sp;
			dsk->dp = ssk->dp;
			dsk->proto = ssk->proto;

			s->sid = si->sid;
			s->born_time = si->born_time;
			s->timeout = nstimer_get_lifetime(ctime, si->timer.timeout, si->timer.timestamp);

			s->fwpolicy_id = si->mp_fw.policy ? si->mp_fw.policy->rule_id : 0;

			scnt ++;

			if (scnt >= user_sinfo->num_sess ||
				scnt >= max_cnt) {
				break;
			}
		}
	}

	user_sinfo->num_sess = scnt;

	return ret;
}

session_t *smgr_get_ftpdata_parent(session_t *si)
{
#if 0
	if (si->tcpst.pftpparent != NULL &&
		!(si->action & ACT_PRXY_FTP)) {

		return (session_t *)si->tcpst.pftpparent;
	}
#endif

	return NULL;
}

void smgr_set_ftpdata_parent(session_t *si, session_t *parent)
{
	if (si) {
		if (parent) {
			session_hold(parent);
		}

		si->tcpst.pftpparent = (void *)parent;
	}
}

int32_t smgr_slow_main(ns_task_t *nstask)
{
	smgr_t *smgr = g_smgr;
	session_t *si = NULL;
	fw_policy_t *fwp=NULL, *natp=NULL;
	policyset_t *fwps=NULL, *natps = NULL;
	int32_t ret = NS_DROP;

	ENT_FUNC(3);

	// for Firewall
	fwps = pmgr_get_firewall_policyset();
	fwp = nstask->mp_fw.policy;
	if (fwps != nstask->mp_fw.policy_set) {

		if (fwps) {
			pmgr_policyset_release(fwps);
		}

		return NS_DROP;
	}

	dbg(5, "Firewall Rule Info: desc=%s, action=0x%llx", fwp->desc, fwp->action);

	natp = nstask->mp_nat.policy;
	if (natp) {
		natps = pmgr_get_nat_policyset();
		if (natps != nstask->mp_nat.policy_set) {
			if (natps) {
				pmgr_policyset_release(natps);
			}

			natp = NULL;
			natps = NULL;
		}
		else {
			dbg(5, "NAT Rule Info: desc=%s, action=0x%llx", natp->desc, natp->action);
		}
	}

	si = session_alloc();
	if (si == NULL) {
		dbg(5, "Cannot add a new session");
		goto ERR;
	}

	memcpy(&si->skey, &nstask->skey, sizeof(skey_t));

	si->sid = smgr_get_next_sid();
	si->born_time = nstimer_get_time();
	//si->timeout = policy->timeout;
	si->timeout = -1; 	// to use system default value
	si->action = fwp->action;

	memcpy(&si->mp_fw, &nstask->mp_fw, sizeof(mpolicy_t));
	// XXX: no need to increase refcnt because nstask already had
	//pmgr_policyset_hold(fwps);

	if (natp) {
		if (nat_bind_info(si, natp, nstask->skey.inic)) {
			goto ERR;
		}

		si->action |= natp->action;
		memcpy(&si->mp_nat, &nstask->mp_nat, sizeof(mpolicy_t));
		// XXX: no need to increase refcnt because nstask already had
		//pmgr_policyset_hold(natps);
	}

	smgr_add_session(smgr, si);

	nstask->si = si;
	session_hold(si);

	// 최초에 만들어 진 세션은 정방향 처리 한다.
	nstask->flags |= TASK_FLAG_REQ;

	// 새로운 세션 이다.
	nstask->flags |= TASK_FLAG_NEW_SESS;

	if (nstask->skey.proto == IPPROTO_TCP) {
		tcp_init_seq(nstask);
	}

	smgr_post_main(nstask);

	ret = NS_ACCEPT;

	return ret;

ERR:
	if (fwps) {
		pmgr_policyset_release(fwps);
	}

	if (natps) {
		pmgr_policyset_release(natps);
	}

	if (si) {
		session_free(si);
	}

	return NS_DROP;
}

int32_t smgr_timeout(ns_task_t *nstask)
{
	iph_t		*iph = ns_iph(nstask->pkt);
	int32_t		timeout = 0, parent_timeout=0, state_changed = 0, tm_change = 0;
	session_t 	*si, *parent = NULL;
	int			oldst1=0, oldst2=0;

	ENT_FUNC(3);

	si = nstask->si;
	if (unlikely(si == NULL)) {
		return NS_ACCEPT;
	}

	switch (iph->protocol) {
	case IPPROTO_UDP:
		if (si->timeout != -1) {
			timeout = si->timeout;
		}
		else {
			// UDP에서 응답 패킷이 있는 경우 양방향 통신으로 보고
			// 응답이 완료 되었으므로 타임아웃을 줄인다.
			timeout = ISREQ(nstask) ? GET_OPT_VALUE(timeout_udp) : GET_OPT_VALUE(timeout_udp_reply);
		}

		break;

	case IPPROTO_TCP:
		timeout = GET_OPT_VALUE(timeout_close); 	// 10 sec
		parent = smgr_get_ftpdata_parent(si);

		// TCP seq를 검사한다.
		if (tcp_track_seq(nstask) && GET_OPT_VALUE(drop_tcp_oow)) {
			// drop out of window packet
			dbg(0, "tcp stateful inspection error !");

			return NS_DROP;
		}

		oldst1 = si->tcpst.tseq[0].state;
		oldst2 = si->tcpst.tseq[1].state;

		state_changed = tcp_track_states(nstask, &timeout);
		// the session came from Magic, so send DSYNC Update
		//state_changed |= MAKE_BIT(nstask->flags & WTF_MAGIC_SESS);

		if (timeout == -1) {
			timeout = GET_OPT_VALUE(timeout_tcp);
		}

		dbg(5, "Update TCP session: SID=%u, timeout=%d, state=%d:%d -> %d:%d, tcp_changed=%d",
			si->sid,
			timeout,
			oldst1, oldst2,
			si->tcpst.tseq[0].state,
			si->tcpst.tseq[1].state, state_changed);

		break;

	case IPPROTO_ICMP:
		state_changed = 1;

		if (ISREQ(nstask)) {
			timeout = si->timeout == -1 ? GET_OPT_VALUE(timeout_icmp) : si->timeout;
		}
		else {
			timeout = GET_OPT_VALUE(timeout_icmp_reply);
		}

		break;

	default:
		timeout = si->timeout == -1 ? GET_OPT_VALUE(timeout_unknown) : si->timeout;
	}

	tm_change = nstimer_change_timeout(&si->timer, timeout);

	// ftpdata has to update its control session
	if (parent && tm_change) {
		parent_timeout = si->timeout == -1 ? GET_OPT_VALUE(timeout_tcp) : si->timeout;
		nstimer_change_timeout(&parent->timer, parent_timeout);
	}

	return NS_ACCEPT;
}

int32_t smgr_init(void)
{
	smgr_t *smgr = NULL;

	ENT_FUNC(3);


	smgr = (smgr_t *)ns_malloc_kz(sizeof(smgr_t));
	ns_mem_assert(smgr, "session manager", return -1);

	smgr->stab = session_init();
	if (smgr->stab == NULL) {
		ns_free(smgr);
		smgr = NULL;
		ns_err("Can't initialize Session Table");

		return -1;
	}

	// first time after booting the system
	if (netshield_scache == NULL) {
		netshield_create_sem_cache(sizeof(session_t));
	}

	ns_mem_assert(netshield_scache, "session cache", return -1);

	ns_init_lock(&smgr->smgr_lock);
	INIT_LIST_HEAD(&smgr->all_slist);

	g_smgr = smgr;

	return 0;
}

void smgr_clean(void)
{
	void *stab;
	session_t *si, *n;

	ENT_FUNC(3);

	list_for_each_entry_safe(si, n, &g_smgr->all_slist, alist) {
		smgr_delete_session(si, 0);
	}

	stab = g_smgr->stab;

	session_clean(stab);

	ns_free(g_smgr);
}

int32_t smgr_fast_main(ns_task_t *nstask)
{
	int32_t ret;

	ENT_FUNC(3);

	ret = NS_ACCEPT;

	nstask->skey.hashkey = session_make_hash(&nstask->skey);

	dbg(0, "Hashkey: 0x%x", nstask->skey.hashkey);
	DBGKEY(0, "TASK_KEY", &nstask->skey);

	nstask->si = session_search(g_smgr->stab, &nstask->skey);

	if (nstask->si == NULL) {
		dbg(0, "-----+ Begin Slow Path +-----");
		// call pmgr_main()
		append_cmd(nstask, pmgr);
	}
	else {
		dbg(0, "++++++ Begin Fast Path ++++++");

		if (!(nstask->skey.flags & SKF_REVERSE_MATCHED)) {
			nstask->flags |= TASK_FLAG_REQ;
		}

		smgr_post_main(nstask);
	}

	return ret;
}

int32_t smgr_post_main(ns_task_t *nstask)
{
	session_t *si = nstask->si;

	// call smgr_timeout()
	append_cmd(nstask, smgr_timeout);

	if (si->action & ACT_NAT) {
		// call nat_main()
		append_cmd(nstask, nat);
	}

	return NS_ACCEPT;
}
