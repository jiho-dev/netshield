/*
 *     Filename: hypersplit.h
 *  Description: Header file for HyperSplit
 *
 *       Author: Yaxuan Qi (yaxuan@tsinghua.edu.cn)
 *               Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *         Note: The implementation is totally refactored by Xiang Wang
 */

#ifndef __HYPERSPLIT_H__
#define __HYPERSPLIT_H__

#include <stdint.h>
#include "mpool.h"
#include "rule_trace.h"

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
	//double depth_avg;

	struct hs_node	*root_node;
};

typedef struct hypersplit_s {
	uint32_t tree_num;
	uint32_t def_rule;

	struct hs_tree	*trees;
} hypersplit_t;

MPOOL(hsn_pool, struct hs_node);

///////////////////////////////////////////////

int hs_build(hypersplit_t *hypersplit, const struct partition *part);
int hs_search(const struct trace *trace, const hypersplit_t *hypersplit);
void hs_destroy(hypersplit_t *hypersplit);
size_t hs_tree_memory_size(hypersplit_t *hypersplit, uint32_t *total_node);

#endif /* __HYPERSPLIT_H__ */
