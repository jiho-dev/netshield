#ifndef __SESSION_H__
#define __SESSION_H__

#include <skey.h>
#include <timer.h>
#include <nat.h>

// NAT sequence number modifications for FTP Proxy
typedef struct proxy_ftp_seq_t {
	uint32_t correction_pos; 	///< position of the last TCP sequence number modification (if any)

	int16_t offset_before; 		///< sequence number offset before and after last modification
	int16_t offset_after;
} pftp_seq_t;

#if 0
// tcp assembly buff
typedef struct _tcp_assembed_buf {
	uint32_t 	isn; 		///< initial SEQ number
	uint16_t 	tlen; 		///< data buffer length
	uint16_t 	dlen;	 	///< length of data filled in buffer

	char 		data[0];
} tcp_asbuf_t;
#endif

// tcp sequence tracking
typedef	struct	_tcp_seq_t {
	uint32_t	end;		///< last seq(seq + len)
	uint32_t	maxend; 	///< max of ack
	uint16_t	maxwin; 	///< max(win)
	uint16_t	flags; 		///< Flags

	uint16_t 	mss; 		///< mss option
	uint8_t		wscale; 	///< window scale factor
	uint8_t 	state; 		///< state of the TCP connection
}__attribute__((packed, aligned(4)))  tseq_t;

/// tseq_t.flags
#define TS_WSCALE_SEEN	0x0001
#define TS_WSCALE_FIRST	0x0002
#define TS_SACK_PERMIT	0x0004
#define TS_MAX_WSCALE	14
#define TS_MAXACKWINDOW	65535

// tcp state tracking
typedef struct _tcp_state_t {
	tseq_t 		tseq[2]; 		///< 0:RES, 1:REQ, connection parameters per direction
	int32_t 	synp_diff_seq;	///< diff between cookie ISN and Server's ISN 
	union {
		pftp_seq_t 	*pftp_seq;	///< proxy FTP 처리시 seq 보정 데이터
		void 		*parent;	///< parent session pointer if child
	} u;

}__attribute__((packed, aligned(4)))  tcpst_t;

#define pftpseq 	u.pftp_seq
#define pftpparent 	u.parent

#if 0
// IPS 상태 정보
typedef struct _ips_state {
	int32_t 	smd_state[2];	///< The latest State of ACSM(0: Response, 1: Request)
	uint32_t 	last_drop_seq;	///< latest tcp seq of dropped pkt
	int8_t 		saved_log_cnt; 	///< saved log count for ips by per session
	int8_t 		saved_pkt_cnt;  ///< saved packet count for ips by per session
	uint16_t 	dummy;
} ipsst_t;
#endif

////////////////////////////////////////////////
// type of session_t.flags
#define SFLAG_ALIVE 			0x10000000 	// This can be refered to check that the session still is alive
#define SFLAG_LOCALHOST 		0x00000100 	// local host session. ex) IPCG/AS/AV ...
#define SFLAG_MINE				0x00000200 	// added by myself
#define SFLAG_REMOTE			0x00000400 	// added by WSP
#define SFLAG_LFTF_EXPIRE		0x00000800	// this node was expired
#define SFLAG_FS_HOLD			0x00000001	// Hold my Full-Sync
#define SFLAG_ALIVE_HOLD		0x00000004	// 
#define SFLAG_ALIVE_SENT		0x00000008	// 
#define SFLAG_MAGIC				0x00000010	// Magic Session
#define SFLAG_SEARCH_HOLD		0x00010000	// 세션 검색에서 검색되어 hold된 세션

// session_t.sid
#define SFLAG_SID_MASK 			0x0FFFFFFF 	// 28bits
#define SFLAG_NID_MASK 			0xF0000000 	// Node ID(VRRP ID)
#define SFLAG_NID_SHIFT  		28
#define SFLAG_GET_NID(id) 		((id & SFLAG_NID_MASK) >> SFLAG_NID_SHIFT)
#define SFLAG_GET_SID(id)		(id & SFLAG_SID_MASK)

/// session data struct
typedef struct session_s{
	skey_t 		skey;		///< session key
	list_head_t alist; 		///< 전체 리스트 연결

	uint32_t 	sid;		///< NID(4 bits) + SSEQ(28 bits)
	uint32_t	flags;		///< session 속성
	uint64_t	action; 	///< see ACT_*
	uint32_t	born_time; 	///< 생성 시각
	uint32_t 	last_logging_time;	///< 마지막 세션로그 저장 시간.

	atomic_t	refcnt;		///< 세션 참조 카운트
	int32_t 	timeout; 	///< 룰에서 복사된 값이며, 룰에 타임아웃 값이 없는 경우(-1) 시스템 기본값 사용.
	rcu_head_t 	rcu;
	uint32_t 	drop_pkts;	///< dropped packet counts
	tcpst_t		tcpst; 		///< tcp stat

	natinfo_t 	natinfo;

	mpolicy_t 	mp_fw;
	mpolicy_t 	mp_nat;

	//nstimer_t 	timer  ____cacheline_aligned_in_smp;
	nstimer_t 	timer;

} __attribute__((packed, aligned(4))) session_t;


//////////////////////////////////////////////////////

void* 	session_init(void);
void  	session_clean(void *stab);
uint32_t session_make_hash(skey_t *skey);
uint32_t session_make_nat_hash(session_t *si);
int32_t session_insert(void *stab, session_t *si);
int32_t session_remove(void *stab, session_t *si);
void 	session_hold(session_t *si);
void 	session_release(session_t *si);
session_t* session_search(void *stab, skey_t *skey);
session_t *session_alloc(void);
void session_free(session_t *si);

#endif
