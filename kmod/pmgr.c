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


//////////////////////////////////////////////////////
// Policy Manager

pmgr_t g_pmgr;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////
int32_t  hypersplit_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps);
void 	 hypersplit_free(hypersplit_t *hs);

void 	pmgr_policyset_free(policyset_t *ps);
int32_t fwp_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps);
int32_t pmgr_commit_new_policy(policyset_t *ps, int32_t nat);
void fwp_update_nat_arp(policyset_t *ps);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */


void pmgr_policyset_hold(policyset_t *ps)
{
	if (ps) {
		atomic_inc(&ps->refcnt);
	}
}

void pmgr_policyset_release(policyset_t *ps)
{
	int32_t ref;

	if (!ps) {
		return;
	}

	ref = atomic_dec_return(&ps->refcnt);

	if (ref > 0) {
		return;
	}
	else if (ref < 0) {
		ns_log("Something wrong with policyset: %p", ps);
		return;
	}

	pmgr_policyset_free(ps);
}

void pmgr_policyset_free(policyset_t *ps)
{
	if (!ps) {
		return;
	}

	dbg(3, "Free policyset: 0x%p", ps);

#if 0
	if (ps->hypersplit.trees) {
		hypersplit_free(&ps->hypersplit);
	}
#endif

	if (ps->hs_mem) {
		ns_free_v(ps->hs_mem);
	}

	if (ps->policy) {
		ns_free_v(ps->policy);
	}

	ns_free(ps);
}

#if 0
policyset_t* pmgr_get_new_policyset(void)
{
	policyset_t *ps = NULL;

	ns_rw_lock(&g_pmgr.lock) {
		ps = g_pmgr.policyset[1];

		if (ps == NULL) {
			ps = ns_malloc_kz(sizeof(policyset_t));
			g_pmgr.policyset[1] = ps;

			dbg(3, "Alloc new policyset: 0x%p", ps);
			pmgr_policyset_hold(ps);
		}

	} ns_rw_unlock(&g_pmgr.lock);

	pmgr_policyset_hold(ps);

	return ps;
}
#endif

policyset_t* pmgr_get_policyset(int32_t idx)
{
	policyset_t *ps = NULL;

	ns_rd_lock_irq() {
		ps = (policyset_t*)rcu_dereference(g_pmgr.policyset[idx]);
		if (ps) {
			if (atomic_read(&ps->refcnt) > 0) {
				atomic_inc(&ps->refcnt);
			}
			else {
				// refcnt가 1 보다 작다면 해제중인 객체이다.
				ps = NULL;
				ns_err("Someone tried to access wrond memory");
			}
		}

	} ns_rd_unlock_irq();

	return ps;
}

policyset_t* pmgr_get_firewall_policyset(void)
{
	return pmgr_get_policyset(0);
}

policyset_t* pmgr_get_nat_policyset(void)
{
	return pmgr_get_policyset(1);
}

int32_t pmgr_apply_policy(char* arg)
{
	int32_t ret = 0;
	policyset_t *ps = NULL;
	ioctl_policyset_t ioctl_ps;

	if (ns_copy_from_user(&ioctl_ps, arg, sizeof(ioctl_policyset_t))) {
		return -EINVAL;
	}

	ps = ns_malloc_kz(sizeof(policyset_t));

	if (ps == NULL) {
		return -ENOMEM;
	}

	pmgr_policyset_hold(ps);

	ret = hypersplit_load(&ioctl_ps, ps);
	if (ret != 0) {
		ret = -EINVAL;
		goto END;
	}

	ret = fwp_load(&ioctl_ps, ps);
	if (ret != 0) {
		ret = -EINVAL;
		goto END;
	}

	ret = pmgr_commit_new_policy(ps, ioctl_ps.flags & POLICY_TYPE_NAT);

END:
	if (ret != 0) {
		dbg(3, "Cancel new policyset: 0x%p", ps);
		pmgr_policyset_release(ps);
	}

	return ret;
}

int32_t pmgr_commit_new_policy(policyset_t *ps, int32_t nat)
{
	policyset_t *old = NULL;

	nat = !!nat;

	// change new memory
	ns_rd_lock_irq() {

		old = (policyset_t*)rcu_dereference(g_pmgr.policyset[nat]);
		rcu_assign_pointer(g_pmgr.policyset[nat], ps);
		if (ps) {
			ps->version = (uint16_t)(atomic_add_return(1, &g_pmgr.version_cnt) % 65535);
			pmgr_policyset_hold(ps);
		}

	} ns_rd_unlock_irq();

	if (nat) {
		fwp_update_nat_arp(ps);
	}

	if (old) {
		pmgr_policyset_release(old);
	}

	dbg(0, "Commit New Policy: 0x%p, ver=%u, nat=%d", ps, ps->version, nat);

	return 0;
}

fw_policy_t* pmgr_get_fw_policy(policyset_t *ps, uint32_t index)
{
	if (index >= ps->num_policy) {
		dbg(0, "out of range: index=%u, num_policy=%u", index, ps->num_policy);
		return NULL;
	}

#if 0
	if (index != ps->policy[index].rule_idx) {
		return NULL;
	}
#endif

	return &ps->policy[index];

}

int32_t pmgr_init(void)
{

	return 0;
}

void pmgr_clean(void)
{
	int32_t i;

	for (i=0; i<PMGR_MAX_SET; i++) {
		if (g_pmgr.policyset[i]) {
			pmgr_policyset_release(g_pmgr.policyset[i]);
		}

		g_pmgr.policyset[i] = NULL;
	}
}

int32_t pmgr_main(ns_task_t *nstask)
{
	policyset_t* fps = NULL, *nps = NULL;
	pktinfo_t pi;
	int32_t ret = NS_DROP;
	uint32_t midx;
	mpolicy_t *mp;

	ENT_FUNC(3);

	//bzero(&pi, sizeof(pi));
	bzero(&nstask->mp_fw, sizeof(nstask->mp_fw));
	mp = &nstask->mp_fw;

	pi.dims[DIM_SIP]   = (uint32_t)nstask->skey.src;
	pi.dims[DIM_DIP]   = (uint32_t)nstask->skey.dst;
	pi.dims[DIM_SPORT] = (uint16_t)nstask->skey.sp;
	pi.dims[DIM_DPORT] = (uint16_t)nstask->skey.dp;
	pi.dims[DIM_PROTO] = (uint8_t)nstask->skey.proto;
	pi.dims[DIM_NIC]   = nstask->skey.inic;

	// for Firewall
	fps = pmgr_get_firewall_policyset();
	if (!fps) {
		dbg(0, "No Firewall Policy !");
		return NS_DROP;
	}

	midx = hypersplit_search(&fps->hypersplit, &pi);
	if (midx == HS_NO_RULE) {
		// matched default rule
		dbg(0, "No rule");
		goto ERR;
	}
	else if ((mp->policy = pmgr_get_fw_policy(fps, midx)) == NULL) {
		goto ERR;
	}
	else if (!(mp->policy->action & ACT_ALLOW)) {
		goto ERR;
	}

	dbg(0, "Matched Firewall Rule ID: %u" , midx);

	//mp->id = 0;
	//mp->idx = midx;
	//mp->ver = nps->version;
	mp->policy_set = fps;
	//mp->flags = MPOLICY_HAVE_POLICY;

	// call smgr_slow_main()
	append_cmd(nstask, smgr_slow);

	// for NAT
	mp = &nstask->mp_nat;
	bzero(&nstask->mp_nat, sizeof(nstask->mp_nat));
	nps = pmgr_get_nat_policyset();
	if (nps) {
		midx = hypersplit_search(&nps->hypersplit, &pi);
		if (midx != HS_NO_RULE &&
			((mp->policy = pmgr_get_fw_policy(nps, midx)) != NULL)) {

			dbg(0, "Matched NAT Rule ID: %u" , midx);
			//mp->id = 0;
			//mp->idx = midx;
			//mp->ver = nps->version;
			mp->policy_set = nps;
			//mp->flags = MPOLICY_HAVE_POLICY;
		}
		else {
			mp->policy = NULL;
			pmgr_policyset_release(nps);
		}
	}

	return NS_ACCEPT;

ERR:
	if (fps) {
		pmgr_policyset_release(fps);
	}

	if (nps) {
		pmgr_policyset_release(nps);
	}

	return ret;
}

