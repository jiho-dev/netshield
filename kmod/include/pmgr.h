#ifndef __POLICY_MAMAGER_H__
#define __POLICY_MAMAGER_H__


struct hypersplit_s;
struct fw_policy_s;

typedef struct policyset_s {
	uint8_t 			*hs_mem;
	struct hypersplit_s hypersplit;

	struct fw_policy_s 	*fw_policy;
	uint32_t 			num_fw_policy;
	uint32_t 			version;
	atomic_t 			refcnt;
} policyset_t;

struct policy_manager_s {
	policyset_t *policyset;

	atomic_t 	version_cnt;
	nslock_t 	lock;
};

typedef struct policy_manager_s pmgr_t;


enum {
	DIM_INV		= -1,
	DIM_SIP		= 0,
	DIM_DIP		= 1,
	DIM_SPORT	= 2,
	DIM_DPORT	= 3,
	DIM_PROTO	= 4,
	DIM_MAX		= 5
};

typedef struct pktinfo_s {
	uint32_t	dims[DIM_MAX];
} pktinfo_t;


//////////////////////////////////////////////////////

int32_t pmgr_init(void);
void 	pmgr_clean(void);
int32_t pmgr_main(ns_task_t *nstask);
int32_t pmgr_apply_fw_policy(char*);
void 	pmgr_policyset_release(policyset_t *ps);

#endif
