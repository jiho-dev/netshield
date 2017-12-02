#ifndef __NAT_H__
#define __NAT_H__

#include <arp_proxy.h>

struct fw_policy_s;
struct session_s;
struct ns_task_s;

////////////////////////////////////////////////////////

#define NAT_MIN_PORT		3000 	// usually under 3000 port are used by OS, as known ports

//////////////////////////////////////////////////

#define NAT_PORT_BITMAP_SIZE 	8192 	// (65536 / 8) = 8192

// port 사용여부를 나타내는 bitmap 데이터 구조체
typedef struct nat_port_s {
	uint32_t 	start_offset;
	uint8_t 	*bitmap;
} nat_port_t;

// NAT IP object
typedef struct nat_ip_s {
	list_head_t list;

	ip_t 		ip; 		///< NAT IP
	uint16_t 	port_cnt; 	///< 사용가능한 총 포트 수
	uint16_t 	free_cnt;	///< 남은 포트 수

	nat_port_t 	port; 		///< port bitmap
} nat_ip_t;

typedef struct natinfo_s {
	ip_t 	 ip[2]; 	// 0: SNAT, 1: DNAT
	uint16_t port[2];	
	uint32_t hashkey;
} __attribute__((packed, aligned(1))) natinfo_t;

//////////////////////////////////////////////////////////

// NAT 룰에서 사용되는 NAT 종류
// nat_policy_t.flags
#define NATF_SNAT_MASKING		0x00000001 	// change only IP with mask and not change port
#define NATF_SNAT_HASH			0x00000002 	// select IP with hash and free port
#define NATF_SNAT_NAPT 			0x00000004 	// select available IP and free port
#define NATF_SNAT_MASK 			0x000000FF 	

#define NATF_DNAT_RDIR			0x00001000	// DNAT with Redirect
#define NATF_DNAT_LRDIR			0x00002000	// DNAT with Localhost Redirect
#define NATF_DNAT_MASK 			0x0000FF00

#define NATF_ARP_PROXY 			0x00010000 	// NAT IP에 대해서 arp 응답을 지원 한다.
#define NATF_DYNAMIC_IP 		0x00020000 	// NAT ip가 동적이며, NIC index 값을 가진다

#define NAT_IS_NOT_USE_IPOBJ 	(NATF_SNAT_MASKING | NATF_DNAT_RDIR | NATF_DNAT_LRDIR)
#define NAT_IS_USE_PORTOBJ 		(NATF_SNAT_HASH | NATF_SNAT_NAPT)


typedef struct nat_policy_s {
	uint32_t	id;			///< nat rule id, this is not unique number
	uint32_t	flags;		///< nat flags

	uint32_t 	nic; 		///< NIC Index (0: any, 1 ~)
	ip_t		nip[2];		///< nat ip range 	(0: start, 1: end), host order, MASK_IP_ONLY, RDIR 인 경우 mask값
	uint16_t	nport[2];	///< nat port range	(0: start, 1: end)

	// internal data
	int32_t 	ip_cnt; 			///< 초기값: -1
	nat_ip_t 	*available_ip; 		///< 포트 할당 공간이 남아 있는 ip
	list_head_t ip_list;
	spinlock_t 	nat_lock;

} __attribute__((packed, aligned(4))) nat_policy_t;



/////////////////////////////////////////////////////////////
#ifdef __KERNEL__

int32_t nat_bind_info(struct session_s* si, struct fw_policy_s* fwp, nic_id_t inic);
int32_t nat_release_info(struct session_s* si, struct fw_policy_s* fwp);
uint32_t nat_make_hash(struct session_s *si);
int32_t nat_main(struct ns_task_s* nstask);
void nat_clean_ip_obj(nat_policy_t* natp);

#endif


#endif
