#ifndef __SMGR_H__
#define __SMGR_H__


struct ns_task_s;

/// 세션 삭제 옵션
#define SMGR_DEL_SAVE_LOG 	0x01 	///< 세션로그 저장
#define SMGR_DEL_CALL_LFT 	0x02
#define SMGR_DEL_FORCE 		0x04 	///< 즉시 강제 삭제


/////////////////////////////////////////////

typedef struct _session_manager {
	uint32_t 	nbucket;
	void		*stab;

	list_head_t	all_slist;
	spinlock_t  smgr_lock;

	int32_t		lasttime_oomc_log;
	atomic_t 	magic_scnt;
	atomic_t 	last_id;
	atomic_t 	all;
	atomic_t 	mine;
	atomic_t 	remote;
	atomic_t 	local;
} smgr_t;



//////////////////////////////////////////////////////

int32_t smgr_init(void);
void  	smgr_clean(void);
int32_t smgr_fast_main(struct ns_task_s *nstask);
int32_t smgr_slow_main(struct ns_task_s *nstask);
int32_t smgr_timeout(struct ns_task_s *nstask);
int32_t smgr_delete_session(session_t *si, uint32_t flags);


#endif
