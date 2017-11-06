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
#include <ioctl_policy.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(5);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */


int32_t fwp_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps)
{
	uint32_t l = 0;
	fw_policy_t *fwp = NULL;

	l = ioctl_ps->num_fw_policy * sizeof(fw_policy_t);

	fwp = ns_malloc_v(l);
	ns_mem_assert(fwp, "fw_policy", return -1);

	// to make sure all the page assigned
	memset(fwp, 0, l);

	if (ns_copy_from_user(fwp, ioctl_ps->fw_policy, l)) {
		goto ERR;
	}

	ps->num_fw_policy = ioctl_ps->num_fw_policy;
	ps->fw_policy = fwp;

	DBG(5, "Ruleset Info");
	DBG(5, "Num of Rule: %d", ps->num_fw_policy);
	DBG(5, "Num of Mem: %d", l);

	return 0;

ERR:
	if (fwp) {
		ns_free_v(fwp);
	}

	return -1;
}


