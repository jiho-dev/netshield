#ifndef __FW_POLICY_H__
#define __FW_POLICY_H__


//
// Firewall Policy

typedef struct range128_s {
	uint128_t min, max;
} range128_t;

typedef struct range16_s {
	uint16_t min, max;
} range16_t;

typedef struct range8_s {
	uint8_t min, max;
} range8_t;

typedef struct range_s {
	range128_t 	src;
	range128_t 	dst;
	range16_t 	sp;
	range16_t 	dp;
	range8_t 	proto;
} range_t;

typedef struct policyid_s {
	uint32_t owner_id;
	uint32_t id;
} policyid_t;

/// 방화벽 정책 구조체
typedef struct fw_policy_s {
	char 		desc[64];

	// internal data
	uint32_t	hits;				///< rule을 사용한 횟수
	uint32_t 	sc;					///< session count
	uint32_t 	timestamp;

	uint32_t 	cps;				///< for control and statistic
	uint32_t 	last_cps;
	//pacc_t 		tpacc[2];		///< total packet account, 0:RES, 1:REQ

	// external usable data
	uint32_t 	rule_id; 			///< rule id in UI
	uint32_t 	rule_idx; 			///< Unique Index in HyperSplit
	int32_t		timeout;			///< -1: setup this at creating time, 
									///< 0: forever alive, 0 < : ageing time
	uint64_t	action; 			///< see ACT_*
	uint32_t 	act_log_time;		///< logging action time, if action includes ACT_LOG_*
	range_t		range; 				///< range data
#if 0
	natr_t		*nat_info[2];		///< 0: Single NAT rule, 1: Dual NAT rule
	timerr_t	*time_info; 		///< Timer rule info
#endif

	uint64_t 	max_bps[2];			///< apply limit per session, 0 == unlimit
	uint32_t 	max_pps[2];			///< 0: RES, 1: REQ
	uint32_t 	max_cps;

} fw_policy_t;


#endif
