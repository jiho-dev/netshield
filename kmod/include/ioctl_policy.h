#ifndef __IOCTL_POLICY_H__
#define __IOCTL_POLICY_H__

struct hypersplit_s;
struct fw_policy_s;

typedef struct ioctl_policyset_s {
	struct hypersplit_s *hs;
	uint32_t 	num_hs_tree;
	uint32_t 	num_hs_node;
	uint32_t 	num_hs_mem;

	struct fw_policy_s 	*fw_policy;
	uint32_t 			num_fw_policy;

} ioctl_policyset_t;


#endif
