#ifndef __NETSHIELD_TASK_H__
#define __NETSHIELD_TASK_H__


// type of ns_task_t.flags
#define TASK_FLAG_ICMPERR			0x00000001
#define TASK_FLAG_REQ				0x00000002
#define TASK_FLAG_NEW_SESS			0x00000004
#define TASK_FLAG_TCP_ASSEMBLE		0x00000008
#define TASK_FLAG_SYNP_OK 			0x00000010 // syn proxy에서 검증이 완료된 패킷임
#define TASK_FLAG_MAGIC_SESS		0x00000020 // matched the magic session

#define TASK_FLAG_HSF_DROP           0x00000020 // Harmsite Filter에서 Drop
#define TASK_FLAG_HSF_A_BY_DB        0x00000040 // Harmsite Filter에서 DB match 되지 않아 Accept
#define TASK_FLAG_HSF_A_BY_SUBDIR    0x00000080 // Harmsite Filter에서 DB는 match되고 subdir match 되지 않아 Accept

#define TASK_FLAG_HOOK_LOCAL_OUT    0x00000100 
#define TASK_FLAG_IN_THREAD         0x00000200 // Thread에서 실행중이다.
#define TASK_FLAG_SIMPKT          	0x00000400 // simulated packet

#define IS_IN_THREAD(nstask)       (nstask->flags & TASK_FLAG_IN_THREAD)


#ifdef __KERNEL__

#include <linux/version.h>
#include <linux/netshield_hook.h>


// ip options
#define WIPOPT_SEC		0x01
#define WIPOPT_LSRR		0x02
#define WIPOPT_TIMESTAMP		0x04
#define WIPOPT_RR		0x08
#define WIPOPT_SID		0x10
#define WIPOPT_SSRR		0x20
#define WIPOPT_RA		0x40

////////////////////////////////////////

// 실행될 명령어가 스택 구조로 저장 되어 있다.
#define MAX_CMDS		22		// byte alignment


typedef struct _cmd_queue {
	int8_t		head;			// 다음에 실행 될 command idx
	int8_t		tail;			// 다음에 추가될 idx
	uint8_t		stack[MAX_CMDS];
} __attribute__((packed, aligned(4))) nscmd_t;  // 24 bytes

//////////////////////////////////////////////////////////

// topt_t.flags
// Window scaling is advertised by the sender
#define TOPT_FLAG_WINDOW_SCALE		0x01
// SACK is permitted by the sender
#define TOPT_FLAG_SACK_PERM			0x02
// This sender sent FIN first
#define TOPT_FLAG_CLOSE_INIT		0x04
#define TOPT_FLAG_MSS				0x08
#define TOPT_FLAG_SACK				0x10
#define TOPT_FLAG_TIMESTAMP 		0x20

/// tcp option
typedef struct _tcp_opt {
	uint8_t		td_scale;	///< window scale factor 
	uint8_t		flags;		///< per direction options 
	uint16_t	mss;		///< mss option
	uint32_t	sack;		///< value of the sack
	uint32_t 	tsval; 		///< timestamp
} topt_t; 	// 12 bytes

/////////////////////////////////////////////////////

struct session_key_s;

// 패킷을 처리 하는 동안 사용 되는 구조체
typedef struct ns_task_s {
	skb_t		*pkt; 		// network packet buffer

	uint8_t		ip_hlen;	// ip header length
	uint8_t		l4_hlen; 	// l4 header length (tcp/udp/icmp)
	uint16_t	iopt; 		// IP header options, don't move because of byte alignment
	uint16_t	ip_dlen;	// ip data length
	uint16_t	l4_dlen;	// l4 data length
	char		*l4_data;	// l4 data pointer;

	nscmd_t		cmd;
	struct session_key_s key;

	uint32_t	flags; 
	uint32_t 	matched_fwpolicy_ver;
	uint32_t 	matched_fwpolicy_idx;

	struct session_s *si;
	OKFN		okfn;

	void		*smeres;
	topt_t		topt;

}__attribute__((packed, aligned(4)))  ns_task_t;

// INFO: When the members of the ns_task_t is changed 
// following value should be kept with a correct size
// Also, SKB_WT_T_SIZE in the skbuff.h should be kept

#define WT_T_SIZE 		148 
//#define WT_T_SIZE 		120 	// IPv4:92byte, IPv6:120 bytes



#endif

#endif
