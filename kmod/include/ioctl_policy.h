#ifndef __IOCTL_POLICY_H__
#define __IOCTL_POLICY_H__

struct hypersplit_s;
struct fw_policy_s;

#define POLICY_TYPE_FIREWALL 	0x01
#define POLICY_TYPE_NAT 		0x02

typedef struct ioctl_policyset_s {
	uint32_t 	flags;
	struct hypersplit_s *hs;
	uint32_t 	num_hs_tree;
	uint32_t 	num_hs_node;
	uint32_t 	num_hs_mem;

	struct fw_policy_s 	*policy;
	uint32_t 			num_policy;

} ioctl_policyset_t;


#endif
