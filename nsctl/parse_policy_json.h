#ifndef __PARSE_JSON_H__
#define __PARSE_JSON_H__

typedef struct policy_json_s {
	void 	*policy[2]; 	// 0: firewall, 1: nat
	int 	num_policy[2];
} policy_json_t;



#endif
