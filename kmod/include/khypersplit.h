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

#if 0
typedef struct hs_matched_s {
	uint32_t fwid;
	uint32_t natid;
} hs_matched_t;
#endif

enum {
	DIM_INV		= -1,
	DIM_SIP		= 0,
	DIM_DIP		= 1,
	DIM_SPORT	= 2,
	DIM_DPORT	= 3,
	DIM_PROTO	= 4,
	DIM_NIC		= 5,
	DIM_MAX		= 6
};

typedef struct pktinfo_s {
	uint32_t	dims[DIM_MAX];
} pktinfo_t;

#define HS_NO_RULE UINT_MAX 	// NODE_NUM_MAX is less than UINT_MAX

///////////////////////////////////////////////

uint32_t hypersplit_search(hypersplit_t *hs, pktinfo_t *pkt);

#endif

