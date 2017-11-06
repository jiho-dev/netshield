#ifndef __SESSION_KEY_H__
#define __SESSION_KEY_H__


/////////////////////////////////////////////////////
// session key

/// type of sk_t.flags
#define SKF_REVERSE_MATCHED		0x1
#define SKF_IPV6				0x2 		// IPv6 address

/// session key, all data are host order
typedef struct session_key_s {
	// Session Hash Key data
	uint128_t 	src;
	uint128_t 	dst;
	uint16_t  	sp;		///< src port, if icmp, icmp id
	uint16_t  	dp; 	///< dst port, if icmp, icmp type

	uint8_t 	proto; 	///< protocol number

	// unhashed data
	uint8_t		dummy;
	uint16_t 	flags;
	int32_t 	inic; 	///< in nic, 양방향 룰 검색을 위해서 haskkey에서 제외
	int32_t 	onic;	///< out nic, use flst for looking up SNAT rules
	uint32_t 	hashkey; ///< hash value

}__attribute__((packed, aligned(4))) sk_t;

#define clear_key(k) 	memset(k, 0, sizeof(sk_t))


#endif
