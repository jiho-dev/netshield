#ifndef __PARSE_PROTO__H__
#define __PARSE_PROTO__H__

//////////////////////////////////////////////////////////
// TCP options

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
}__attribute__((packed, aligned(4)))  topt_t; 	// 12 bytes

#endif
