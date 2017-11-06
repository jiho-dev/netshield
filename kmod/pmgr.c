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
//#include <extern.h>
#include <misc.h>
#include <ns_malloc.h>
#include <khypersplit.h>
#include <fw_policy.h>
#include <pmgr.h>
#include <ioctl_policy.h>


//////////////////////////////////////////////////////

pmgr_t g_pmgr;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

int32_t hypersplit_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps);
void 	hypersplit_free(hypersplit_t *hs);
uint32_t hypersplit_search(hypersplit_t *hs, pktinfo_t *pkt);

void 	pmgr_policyset_free(policyset_t *ps);
int32_t fwp_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps);
int32_t pmgr_commit_new_policy(policyset_t *ps);


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

	if (ps->fw_policy) {
		ns_free_v(ps->fw_policy);
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

policyset_t* pmgr_get_policyset(void)
{
	policyset_t *ps = NULL;

	ns_rd_lock_irq() {
		ps = (policyset_t*)rcu_dereference(g_pmgr.policyset);
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

int32_t pmgr_apply_fw_policy(char* arg)
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

	ret = pmgr_commit_new_policy(ps);

END:
	if (ret != 0) {
		dbg(3, "Cancel new policyset: 0x%p", ps);
		pmgr_policyset_release(ps);
	}

	return ret;
}

int32_t pmgr_commit_new_policy(policyset_t *ps)
{
	policyset_t *old = NULL;

	// change new memory
	ns_rd_lock_irq() {
	//ns_rw_lock(&g_pmgr.lock) {

		old = (policyset_t*)rcu_dereference(g_pmgr.policyset);
		rcu_assign_pointer(g_pmgr.policyset, ps);
		if (ps) {
			ps->version = atomic_add_return(1, &g_pmgr.version_cnt);
			pmgr_policyset_hold(ps);
		}

	//} ns_rw_unlock(&g_pmgr.lock);
	} ns_rd_unlock_irq();

	if (old) {
		pmgr_policyset_release(old);
	}

	dbg(5, "Commit New Policy: 0x%p", ps);

	return 0;
}

fw_policy_t* pmgr_get_fw_policy(policyset_t *ps, uint32_t idx_id)
{
	if (idx_id >= ps->num_fw_policy) {
		return NULL;
	}

	if (idx_id != ps->fw_policy[idx_id].rule_idx) {
		return NULL;
	}


	return &ps->fw_policy[idx_id];

}

int32_t pmgr_init(void)
{

	return 0;
}

void pmgr_clean(void)
{
	pmgr_policyset_release(g_pmgr.policyset);
	g_pmgr.policyset = NULL;
}

int32_t pmgr_main(ns_task_t *nstask)
{
	policyset_t* ps ;
	uint32_t idx_id;
	pktinfo_t pi;
	int32_t ret = NS_DROP;

	ENT_FUNC(3);

	//bzero(&pi, sizeof(pi));

	pi.dims[DIM_SIP]   = (uint32_t)nstask->key.src;
	pi.dims[DIM_DIP]   = (uint32_t)nstask->key.dst;
	pi.dims[DIM_SPORT] = (uint16_t)nstask->key.sp;
	pi.dims[DIM_DPORT] = (uint16_t)nstask->key.dp;
	pi.dims[DIM_PROTO] = (uint8_t)nstask->key.proto;

	ps = pmgr_get_policyset();
	if (!ps) {
		dbg(0, "No Policy !");
		return NS_DROP;
	}

	idx_id = hypersplit_search(&ps->hypersplit, &pi);

	nstask->matched_fwpolicy_idx = idx_id;
	nstask->matched_fwpolicy_ver = ps->version;

	dbg(5, "Matched Rule ID: %d" ,idx_id);

	if (ps->hypersplit.def_rule == idx_id) {
		// matched default rule
		//dbg(0, "No rule");
		goto END;
	}
	else {
		// call smgr_slow_main()
		append_cmd(nstask, smgr_slow);
	}

	ret = NS_ACCEPT;

END:
	pmgr_policyset_release(ps);

	return ret;
}

