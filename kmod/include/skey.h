#ifndef __SESSION_KEY_H__
#define __SESSION_KEY_H__


/////////////////////////////////////////////////////
// session key

/// type of skey_t.flags
#define SKF_REVERSE_MATCHED		0x1
#define SKF_IPV6				0x2 		// IPv6 address

/// session key, all data are host order
typedef struct session_key_s {
	// Session Hash Key data
	ip_t 		src;
	ip_t 		dst;
	uint16_t  	sp;		///< src port, if icmp, icmp id
	uint16_t  	dp; 	///< dst port, if icmp, icmp type
	nic_id_t	inic; 	///< in nic idx
	nic_id_t 	onic;	///< out nic idx
	uint8_t 	proto; 	///< protocol number
	uint8_t 	flags;
	uint32_t 	hashkey; ///< hash value

}__attribute__((packed, aligned(4))) skey_t; 	// 44 bytes

#define clear_key(k) 	memset(k, 0, sizeof(skey_t))

typedef struct hashdata_s {
	ip_t 		ip; 	// 16 Bytes
	uint16_t 	port; 	// 2 Bytes
	uint8_t 	proto; 	// 1 Bytes
}__attribute__((packed, aligned(1))) hashdata_t;

#define NS_HASH_SIZE 19

struct fw_policy_s;
struct policyset_s;

//#define MPOLICY_HAVE_POLICY 0x01

typedef struct matched_policy_s {
	struct fw_policy_s *policy;
	struct policyset_s *policy_set;
	//uint32_t 			ver;	 // 0: not use
}__attribute__((packed, aligned(4))) mpolicy_t; // 20 bytes



#endif
