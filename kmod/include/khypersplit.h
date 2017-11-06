#ifndef __HYPERSPLIT_H__
#define __HYPERSPLIT_H__

#define NODE_NUM_BITS 29
#define NODE_NUM_MAX (1 << NODE_NUM_BITS)


struct hs_node {
	uint64_t	threshold;
	uint32_t	dim    : 32 - NODE_NUM_BITS;
	uint32_t	lchild : NODE_NUM_BITS;
	uint32_t	pack   : 32 - NODE_NUM_BITS;
	uint32_t	rchild : NODE_NUM_BITS;
};

struct hs_tree {
	uint32_t inode_num;
	uint32_t enode_num;
	uint32_t depth_max;

	struct hs_node	*root_node;
};

struct hypersplit_s {
	uint32_t tree_num;
	uint32_t def_rule;

	struct hs_tree	*trees;
};

typedef struct hypersplit_s hypersplit_t;


#endif

