#include <include_os.h>

#include <ns_type_defs.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <commands.h>
#include <smgr.h>
#include <log.h>
#include <misc.h>
#include <ns_malloc.h>
#include <khypersplit.h>
#include <fw_policy.h>
#include <pmgr.h>
#include <ioctl_session.h>
#include <options.h>
#include <tcp_state.h>


//////////////////////////////////////////////////////

smgr_t		*g_smgr; 
extern struct kmem_cache	*netshield_scache;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

void netshield_create_sem_cache(int32_t size);
int32_t smgr_post_main(ns_task_t *nstask);
fw_policy_t* pmgr_get_fw_policy(policyset_t *ps, uint32_t ruleid);
policyset_t* pmgr_get_policyset(void);


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

	dbg(2, "Add a new session: si=0x%p, refcnt=%d", si, atomic_read(&si->refcnt));

	return 0;
}

int32_t smgr_delete_session(session_t *si, uint32_t flags)
{
	ENT_FUNC(3);

	dbg(2, "Delete old session: si=0x%p, refcnt=%d", si, atomic_read(&si->refcnt));

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
			sk_t *dsk = &s->sk;
			sk_t *ssk = &si->sk;

			dsk->src = ssk->src;
			dsk->dst = ssk->dst;
			dsk->sp = ssk->sp;
			dsk->dp = ssk->dp;
			dsk->proto = ssk->proto;

			s->sid = si->sid;
			s->born_time = si->born_time;
			s->timeout = si->timer.timeout;

			s->fwpolicy_id = si->fwpolicy_id;
			s->fwpolicy_idx = si->fwpolicy_idx;

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
	fw_policy_t *fwp;
	policyset_t* ps = NULL;
	int32_t ret = NS_DROP;

	ENT_FUNC(3);

	ps = pmgr_get_policyset();
	if (!ps) {
		dbg(0, "No Policy !");
		return NS_DROP;
	}

	if (ps->version != nstask->matched_fwpolicy_ver) {
		ns_log("something worng now !!");
		// XXX: todo something

		goto END;
	}

	fwp = pmgr_get_fw_policy(ps, nstask->matched_fwpolicy_idx);

	if (fwp == NULL) {
		dbg(0, "Invalid ruleid: %d", nstask->matched_fwpolicy_idx);
		goto END;
	}

	dbg(0, "Rule Info: desc=%s, action=%llu", fwp->desc, fwp->action);

	if (!fwp->action) {
		dbg(5, "Drop rule: %d", nstask->matched_fwpolicy_idx);
		goto END;
	}

	si = session_alloc();
	if (si == NULL) {
		dbg(5, "Cannot add a new session");
		goto END;
	}

	memcpy(&si->sk, &nstask->key, sizeof(sk_t));

	si->sid = smgr_get_next_sid();
	si->born_time = nstimer_get_time();
	//si->timeout = fwp->timeout;
	si->timeout = -1; 	// to use system default value
	si->fwpolicy_idx = nstask->matched_fwpolicy_idx;
	si->fwpolicy_ver = ps->version;

	smgr_add_session(smgr, si);

	nstask->si = si;
	session_hold(si);
	
	if (nstask->key.proto == IPPROTO_TCP) {
		tcp_init_seq(nstask);
	}

	smgr_post_main(nstask);

	// call smgr_timeout()
	append_cmd(nstask, smgr_timeout);

	ret = NS_ACCEPT;

END:
	if (ps) {
		pmgr_policyset_release(ps);
	}

	return ret;
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

	nstask->key.hashkey = session_make_hash(&nstask->key);

	dbg(5, "Hashkey: 0x%x", nstask->key.hashkey);
	DBGKEY(3, "TASK_KEY", &nstask->key);

	nstask->si = session_search(g_smgr->stab, &nstask->key);

	if (nstask->si == NULL) {
		dbg(5, "***** Begin Slow Path *****");
		// call pmgr_main()
		append_cmd(nstask, pmgr);
	}
	else {
		dbg(5, "***** Begin Fast Path *****");

		smgr_post_main(nstask);
		// call smgr_timeout()
		append_cmd(nstask, smgr_timeout);
	}

	return ret;
}

int32_t smgr_post_main(ns_task_t *nstask)
{

	return NS_ACCEPT;
}
