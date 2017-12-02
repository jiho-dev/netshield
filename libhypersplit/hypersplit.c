/*
 *     Filename: hypersplit.c
 *  Description: Source file for HyperSplit
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <assert.h>
#include <errno.h>
#include <limits.h>
//#include <float.h>
#include <sys/queue.h>

#include "impl.h"
#include "utils.h"
#include "hypersplit.h"

//////////////////////////////////////////////////

struct hs_queue_entry {
	uint32_t	space[DIM_MAX][2];
	STAILQ_ENTRY(hs_queue_entry) e;
	ssize_t		node_id;
	int			*rule_id;
	int			rule_num;
	int			depth;
};

STAILQ_HEAD(hs_queue_head, hs_queue_entry);

struct hs_runtime {
	struct shadow_range		shadow_rngs[DIM_MAX];
	int64_t					*shadow_pnts[DIM_MAX];
	struct hsn_pool			node_pool;
	struct hs_queue_head	wqh;
	const struct partition	*part;
	struct hs_tree			*trees;
	int						cur;
};

//////////////////////////////////////////////////

static int hs_init(struct hs_runtime *hsrt, const struct partition *part);
static void hs_terminate(struct hs_runtime *hsrt);

static int hs_trigger(struct hs_runtime *hsrt);
static int hs_process(struct hs_runtime *hsrt);
static int hs_gather(struct hs_runtime *hsrt);
static int hs_dim_decision(struct hs_runtime *hsrt, const struct hs_queue_entry *ent);
static uint32_t hs_point_decision(const struct shadow_range *shadow_rng);
static int hs_spawn(struct hs_runtime *hsrt, struct hs_queue_entry *ent, int split_dim, int is_inplace);
static int hs_space_is_fully_covered(uint32_t (*left)[2], uint32_t (*right)[2]);

//////////////////////////////////////////////////

static int hs_init(struct hs_runtime *hsrt, const struct partition *part)
{
	int i, null_flag = 0;
	struct hs_tree *trees;
	int64_t **shadow_pnts;
	struct shadow_range *shadow_rngs;

	shadow_pnts = hsrt->shadow_pnts;
	shadow_rngs = hsrt->shadow_rngs;
	for (i = 0; i < DIM_MAX; i++) {
		shadow_pnts[i] = malloc((part->rule_num << 1) *
								sizeof(*shadow_pnts[i]));
		shadow_rngs[i].pnts = malloc((part->rule_num << 2) *
									 sizeof(*shadow_rngs[i].pnts));
		shadow_rngs[i].cnts = malloc((part->rule_num << 1) *
									 sizeof(*shadow_rngs[i].cnts));
		if (!shadow_pnts[i] || !shadow_rngs[i].pnts || !shadow_rngs[i].cnts) {
			null_flag = 1;
		}
	}

	trees = calloc(part->subset_num, sizeof(*trees));
	if (null_flag || !trees) {
		free(trees);

		for (i = 0; i < DIM_MAX; i++) {
			free(shadow_rngs[i].cnts);
			free(shadow_rngs[i].pnts);
			free(shadow_pnts[i]);
		}

		return -ENOMEM;
	}

	MPOOL_INIT(&hsrt->node_pool, p2roundup(part->rule_num) << 1);
	STAILQ_INIT(&hsrt->wqh);
	hsrt->part = part;
	hsrt->trees = trees;

	return 0;
}

static void hs_terminate(struct hs_runtime *hsrt)
{
	int i;
	struct hs_queue_head *p_wqh = &hsrt->wqh;
	int64_t **shadow_pnts = hsrt->shadow_pnts;
	struct shadow_range *shadow_rngs = hsrt->shadow_rngs;

	while (!STAILQ_EMPTY(p_wqh)) {
		struct hs_queue_entry *ent = STAILQ_FIRST(p_wqh);
		STAILQ_REMOVE_HEAD(p_wqh, e);
		free(ent->rule_id);
		free(ent);
	}

	MPOOL_TERM(&hsrt->node_pool);
	free(hsrt->trees);

	for (i = 0; i < DIM_MAX; i++) {
		free(shadow_rngs[i].cnts);
		free(shadow_rngs[i].pnts);
		free(shadow_pnts[i]);
	}

	return;
}

static int hs_trigger(struct hs_runtime *hsrt)
{
	ssize_t node_id;
	struct hs_tree *p_tree;
	const struct rule_set *p_rs;
	static uint32_t space[DIM_MAX][2] = {
		{ 0, UINT32_MAX }, { 0, UINT32_MAX },
		{ 0, UINT16_MAX }, { 0, UINT16_MAX },
		{ 0, UINT8_MAX	}, { 0, UINT8_MAX  }
	};

	//assert(hsrt && hsrt->trees);
	//assert(hsrt->part->subsets[hsrt->cur].rules);
	//assert(hsrt->part->subsets[hsrt->cur].rule_num > 1);

	if (hsrt == NULL || hsrt->trees == NULL ||
		hsrt->part->subsets[hsrt->cur].rules == NULL ||
		hsrt->part->subsets[hsrt->cur].rule_num <= 1) {
		return -EINVAL;
	}

	MPOOL_RESET(&hsrt->node_pool);
	node_id = MPOOL_MALLOC(hsn_pool, &hsrt->node_pool);
	if (node_id == -1) {
		return -ENOMEM;
	}

	p_tree = &hsrt->trees[hsrt->cur];
	p_rs = &hsrt->part->subsets[hsrt->cur];

	/* There is no need to build trees: only the tree root */
	if (hs_space_is_fully_covered(space, p_rs->rules[0].dims)) {
		struct hs_node *root_node = MPOOL_ADDR(&hsrt->node_pool, node_id);
		root_node->threshold = UINT32_MAX;
		root_node->dim = DIM_SIP;
		root_node->lchild = p_rs->rules[0].pri;
		p_tree->inode_num = p_tree->enode_num = p_tree->depth_max = 1;
		//p_tree->depth_avg = 1.0;

		/* The tree root needs split */
	}
	else {
		int i, *rule_id = malloc(p_rs->rule_num * sizeof(*rule_id));
		struct hs_queue_entry *ent = malloc(sizeof(*ent));
		if (!rule_id || !ent) {
			free(ent);
			free(rule_id);
			return -ENOMEM;
		}

		for (i = 0; i < p_rs->rule_num; i++) {
			rule_id[i] = i;
		}
		memcpy(ent->space, space, sizeof(space));
		ent->node_id = node_id;
		ent->rule_id = rule_id;
		ent->rule_num = p_rs->rule_num;
		ent->depth = 1;
		p_tree->inode_num++;
		STAILQ_INSERT_HEAD(&hsrt->wqh, ent, e);
	}

	return 0;
}

static int hs_process(struct hs_runtime *hsrt)
{
	struct hs_queue_head *p_wqh;
	struct hs_queue_entry *ent;

	/* The loop processes all internal nodes */
	p_wqh = &hsrt->wqh;
	while (!STAILQ_EMPTY(p_wqh)) {
		int split_dim;
		struct hs_node *p_node;
		uint32_t split_pnt, orig_end, *split_rng;

		ent = STAILQ_FIRST(p_wqh);
		STAILQ_REMOVE_HEAD(p_wqh, e);

		/* choose split dimension */
		split_dim = hs_dim_decision(hsrt, ent);
		if (split_dim <= DIM_INV || split_dim >= DIM_MAX) {
			goto err;
		}

		/* choose split point */
		//assert(split_dim > DIM_INV && split_dim < DIM_MAX);

		split_pnt = hs_point_decision(&hsrt->shadow_rngs[split_dim]);

		p_node = MPOOL_ADDR(&hsrt->node_pool, ent->node_id);
		p_node->dim = split_dim;
		p_node->threshold = split_pnt;

		/* process left child: require a new wqe */
		split_rng = ent->space[split_dim];
		orig_end = split_rng[1], split_rng[1] = split_pnt;
		if (hs_spawn(hsrt, ent, split_dim, 0)) {
			goto err;
		}

		/* process right child: reuse current wqe */
		split_rng[1] = orig_end, split_rng[0] = split_pnt + 1;
		if (hs_spawn(hsrt, ent, split_dim, 1)) {
			goto err;
		}
	}

	return 0;

err:
	free(ent->rule_id);
	free(ent);

	return -ENOMEM;
}

static int hs_gather(struct hs_runtime *hsrt)
{
	struct hs_node *root_node;
	struct hs_tree *p_tree;
	struct hsn_pool *p_node_pool;

	p_node_pool = &hsrt->node_pool;
	root_node = realloc(MPOOL_BASE(p_node_pool),
						MPOOL_COUNT(p_node_pool) * sizeof(*root_node));
	if (!root_node) {
		return -ENOMEM;
	}

	MPOOL_BASE(p_node_pool) = NULL;
	p_tree = &hsrt->trees[hsrt->cur];
	p_tree->root_node = root_node;
	//p_tree->depth_avg /= p_tree->enode_num;

	//assert(p_tree->inode_num == MPOOL_COUNT(p_node_pool));
	//assert(p_tree->enode_num == p_tree->inode_num + 1);

	return 0;
}

static int hs_dim_decision(struct hs_runtime			*hsrt,
						   const struct hs_queue_entry	*ent)
{
	int i, dim, point_num;
	int64_t **shadow_pnts;
	struct shadow_range *shadow_rngs;
	const struct rule *rules;
	/* float measure, measure_min = FLT_MAX; */
	long measure, measure_min = LONG_MAX;

	//printf("ent=%p, ruleid=%d, rule_num=%d \n",
	//	   ent, ent->rule_id, ent->rule_num);

	//assert(ent && ent->rule_id && ent->rule_num > 1);
	if (ent == NULL || ent->rule_id == NULL || ent->rule_num <= 1) {
		return 0;
	}

	shadow_pnts = hsrt->shadow_pnts;
	shadow_rngs = hsrt->shadow_rngs;
	rules = hsrt->part->subsets[hsrt->cur].rules;

	for (dim = DIM_INV, i = 0; i < DIM_MAX; i++) {
		if (shadow_rules(&shadow_rngs[i], shadow_pnts[i], ent->space[i],
						 ent->rule_id, ent->rule_num, rules, i)) {
			return DIM_INV;
		}

		point_num = shadow_rngs[i].point_num;
		if (point_num <= 2) { /* no more range */
			continue;
		}

		/* the former is original measure, and the latter is adapted to rfg */
		/* measure = shadow_rngs[i].total / (float)(point_num >> 1); */
		measure = shadow_rngs[i].total - (point_num >> 1);
		if (measure < measure_min) { /* the less, the better */
			measure_min = measure;
			dim = i;
		}
	}

	return dim;
}

static uint32_t hs_point_decision(const struct shadow_range *shadow_rng)
{
	int i, measure, measure_max, rng_num_max;

	//assert(shadow_rng && shadow_rng->pnts && shadow_rng->cnts);
	if (shadow_rng == NULL || shadow_rng->pnts == NULL || shadow_rng->cnts == NULL) {
		return 0;
	}

	measure = shadow_rng->cnts[0];
	measure_max = shadow_rng->total >> 1; /* binary cut */
	rng_num_max = (shadow_rng->point_num >> 1) - 1;
	//assert(rng_num_max > 0);
	if (rng_num_max <= 0) {
		return 0;
	}

	for (i = 1; i < rng_num_max && measure < measure_max; i++) {
		measure += shadow_rng->cnts[i];
	}

	return shadow_rng->pnts[(i << 1) - 1];
}

static int hs_spawn(struct hs_runtime *hsrt, struct hs_queue_entry *ent,
					int split_dim, int is_inplace)
{
	struct hs_node *p_node;
	struct hs_queue_entry *p_new_wqe;
	register int i, rid, new_rule_num, *new_rule_id;

	struct hs_tree *p_tree = &hsrt->trees[hsrt->cur];
	const struct rule_set *p_rs = &hsrt->part->subsets[hsrt->cur];
	register const uint32_t *split_rng = ent->space[split_dim];

	/* Get all intersected rules */
	if (is_inplace) {
		new_rule_id = ent->rule_id;
	}
	else {
		new_rule_id = malloc(ent->rule_num * sizeof(*new_rule_id));
		if (!new_rule_id) {
			return -ENOMEM;
		}
	}

	for (new_rule_num = i = 0; i < ent->rule_num; i++) {
		rid = ent->rule_id[i];
		if (p_rs->rules[rid].dims[split_dim][0] <= split_rng[1] &&
			p_rs->rules[rid].dims[split_dim][1] >= split_rng[0]) {
			new_rule_id[new_rule_num++] = rid;
		}
	}

	/* External node */
	rid = new_rule_id[0];
	if (hs_space_is_fully_covered(ent->space, p_rs->rules[rid].dims)) {
		p_tree->enode_num++;
		//p_tree->depth_avg += ent->depth;
		if (ent->depth > p_tree->depth_max) {
			p_tree->depth_max = ent->depth;
		}

		p_node = MPOOL_ADDR(&hsrt->node_pool, ent->node_id);
		free(new_rule_id);
		if (is_inplace) {
			free(ent);
			p_node->rchild = p_rs->rules[rid].pri;
		}
		else {
			p_node->lchild = p_rs->rules[rid].pri;
		}

		/* Internal node */
	}
	else {
		uint32_t offset = p_rs->def_rule + 1;
		ssize_t node_id = MPOOL_MALLOC(hsn_pool, &hsrt->node_pool);
		if (node_id == -1) {
			goto err;
		}

		p_node = MPOOL_ADDR(&hsrt->node_pool, ent->node_id);
		if (is_inplace) {
			p_new_wqe = ent;
			p_node->rchild = node_id + offset;
		}
		else {
			p_new_wqe = malloc(sizeof(*p_new_wqe));
			if (!p_new_wqe) {
				goto err;
			}
			p_node->lchild = node_id + offset;
			memcpy(p_new_wqe->space, ent->space, sizeof(p_new_wqe->space));
			p_new_wqe->rule_id = new_rule_id;
		}
		p_new_wqe->node_id = node_id;
		p_new_wqe->rule_num = new_rule_num;
		p_new_wqe->depth = ent->depth + 1;
		p_tree->inode_num++;
		STAILQ_INSERT_HEAD(&hsrt->wqh, p_new_wqe, e);
	}

	return 0;

err:
	if (!is_inplace) {
		free(new_rule_id);
	}

	return -ENOMEM;
}

static int hs_space_is_fully_covered(uint32_t (*left)[2], uint32_t (*right)[2])
{
	int i;

	//assert(left && right);

	if (left == NULL || right == NULL) {
		return 0;
	}

	for (i = 0; i < DIM_MAX; i++) {
		/* left is fully covered by right */
		if (left[i][0] < right[i][0] || left[i][1] > right[i][1]) {
			return 0;
		}
	}

	return 1;
}

//////////////////////////////////////////////////////

int hs_build(hypersplit_t *hypersplit, const struct partition *part)
{
	int ret;
	struct hs_runtime hsrt;

	if (!hypersplit || !part || !part->subsets || part->subset_num <= 0 ||
		part->subset_num > PART_MAX || part->rule_num <= 1) {
		return -EINVAL;
	}

	/* Init */
	ret = hs_init(&hsrt, part);
	if (ret) {
		return ret;
	}

	/* Build hypersplit tree for each subset */
	for (hsrt.cur = 0; hsrt.cur < part->subset_num; hsrt.cur++) {
		/* trigger entry enqueue */
		ret = hs_trigger(&hsrt);
		if (ret) {
			goto err;
		}

		/* hypersplit building */
		ret = hs_process(&hsrt);
		if (ret) {
			goto err;
		}

		/* write subset result */
		ret = hs_gather(&hsrt);
		if (ret) {
			goto err;
		}
	}

	hypersplit->trees = hsrt.trees;
	hsrt.trees = NULL;
	hypersplit->tree_num = part->subset_num;
	hypersplit->def_rule = part->subsets[0].def_rule;

	/* Term */
	hs_terminate(&hsrt);

	return 0;

err:
	while (--hsrt.cur >= 0) {
		free(hsrt.trees[hsrt.cur].root_node);
	}

	hs_terminate(&hsrt);

	return ret;
}

int hs_search(const struct trace *trace, const hypersplit_t *hypersplit)
{
	int i, j, pri;

	register uint32_t id, offset;
	register const struct packet *p_pkt;
	register const struct hs_node *node, *root_node;

	if (!trace || !trace->pkts || !hypersplit) {
		return -EINVAL;
	}

	if (!hypersplit || !hypersplit->trees) {
		return -EINVAL;
	}

	/* For each packet */
	offset = hypersplit->def_rule + 1;

	for (i = 0; i < trace->pkt_num; i++) {
		/* For each tree */
		pri = hypersplit->def_rule;
		p_pkt = &trace->pkts[i];

		for (j = 0; j < hypersplit->tree_num; j++) {
			/* For each node */
			id = offset;
			root_node = hypersplit->trees[j].root_node;

			do {
				node = root_node + id - offset;
				id = p_pkt->dims[node->dim] <= node->threshold ?
					 node->lchild : node->rchild;
			} while (id >= offset);

			if (id < pri) {
				pri = id;
			}
		}

		trace->pkts[i].found = pri;
	}

	return 0;
}

void hs_destroy(hypersplit_t *hypersplit)
{
	int i;

	if (!hypersplit || !hypersplit->trees) {
		return;
	}

	for (i = 0; i < hypersplit->tree_num; i++) {
		free(hypersplit->trees[i].root_node);
	}

	free(hypersplit->trees);

	return;
}

size_t hs_tree_memory_size(hypersplit_t *hypersplit, uint32_t *total_node)
{
	size_t tmem = 0;
	uint32_t nodes = 0;

	if (!hypersplit || !hypersplit->trees) {
		return 0;
	}

	int j;

	tmem += (sizeof(struct hs_tree) * hypersplit->tree_num);

	for (j = 0; j < hypersplit->tree_num; j++) {
		struct hs_tree *t = &hypersplit->trees[j];

		tmem += (t->inode_num * sizeof(struct hs_node));
		nodes += t->inode_num;
	}

	if (total_node) {
		*total_node = nodes;
	}

	return tmem;
}
