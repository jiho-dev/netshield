/*
 *     Filename: rfg.c
 *  Description: Source file for Replication Free Grouping
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
//#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <sys/queue.h>

#include "impl.h"
#include "rfg.h"

////////////////////////////////////////////////

struct rfg_queue_entry {
	STAILQ_ENTRY(rfg_queue_entry) e;
	int				*rule_id;
	int				rule_num;
	unsigned int	dims; /* bitmap */
};

STAILQ_HEAD(rfg_queue_head, rfg_queue_entry);

struct rfg_runtime {
	struct rfg_queue_head	wqh;
	struct rfg_rng_rid		*raws[DIM_MAX];
	struct rfg_rng_idx		*acks[DIM_MAX];
	struct rfg_rng_idx		*rejs[DIM_MAX];
	const struct rule_set	*rulesets;
	struct rule_set			*subsets;
	int						*rule_ids[2]; /* first loop: 0 - ack, 1 - rej */
	int						rule_nums[2];
	int						cur;
};


////////////////////////////////////////////////

static int rfg_init(struct rfg_runtime *rfgrt, const struct rule_set *rulesets);
static void rfg_terminate(struct rfg_runtime *rfgrt);
static int rfg_trigger(struct rfg_runtime *rfgrt);
static int rfg_process(struct rfg_runtime *rfgrt);
static int rfg_gather(struct rfg_runtime *rfgrt);
static int rfg_spawn(int dim, int rej_rng_num, int ack_rng_num, struct rfg_runtime *rfgrt, const struct rfg_queue_entry *ent);
static uint64_t rfg_gen_min_range(int *p_rej_rng_num, int *p_ack_rng_num, struct rfg_rng_idx *rej, struct rfg_rng_idx *ack, const struct rfg_rng_rid *raw, int num);
static int rfg_check_overlap(const struct rfg_rng_idx *p_key, const struct rfg_rng_idx *ack, int ack_rng_num, int bchk_num);

////////////////////////////////////////////////

static int rfg_init(struct rfg_runtime *rfgrt, const struct rule_set *rulesets)
{
	struct rule_set *subsets;
	int i, null_flag = 0, rule_num = rulesets->rule_num - 1;
	int **rule_ids = rfgrt->rule_ids;
	struct rfg_rng_rid **raws = rfgrt->raws;
	struct rfg_rng_idx **acks = rfgrt->acks;
	struct rfg_rng_idx **rejs = rfgrt->rejs;

	for (i = 0; i < DIM_MAX; i++) {
		raws[i] = malloc(rule_num * sizeof(*raws[i]));
		acks[i] = malloc(rule_num * sizeof(*acks[i]));
		rejs[i] = malloc(rule_num * sizeof(*rejs[i]));
		if (!raws[i] || !acks[i] || !rejs[i]) {
			null_flag = 1;
		}
	}

	for (i = 0; i < 2; i++) {
		rule_ids[i] = malloc(rule_num * sizeof(*rule_ids[i]));
		if (!rule_ids[i]) {
			null_flag = 1;
		}
	}

	subsets = malloc(PART_MAX * sizeof(*subsets));
	if (null_flag && !subsets) {
		free(subsets);

		for (i = 0; i < 2; i++) {
			free(rule_ids[i]);
		}

		for (i = 0; i < DIM_MAX; i++) {
			free(rejs[i]);
			free(acks[i]);
			free(raws[i]);
		}

		return -ENOMEM;
	}

	for (i = 0; i < rule_num; i++) {
		rule_ids[0][i] = i;
	}

	STAILQ_INIT(&rfgrt->wqh);
	rfgrt->rulesets = rulesets;
	rfgrt->subsets = subsets;
	rfgrt->rule_nums[0] = rule_num;
	rfgrt->rule_nums[1] = 0;

	return 0;
}

static void rfg_terminate(struct rfg_runtime *rfgrt)
{
	int i;
	struct rfg_queue_head *qh = &rfgrt->wqh;

	while (!STAILQ_EMPTY(qh)) {
		struct rfg_queue_entry *ent = STAILQ_FIRST(qh);
		STAILQ_REMOVE_HEAD(qh, e);
		free(ent->rule_id);
		free(ent);
	}

	free(rfgrt->subsets);

	for (i = 0; i < 2; i++) {
		free(rfgrt->rule_ids[i]);
	}

	for (i = 0; i < DIM_MAX; i++) {
		free(rfgrt->rejs[i]);
		free(rfgrt->acks[i]);
		free(rfgrt->raws[i]);
	}

	return;
}

static int rfg_trigger(struct rfg_runtime *rfgrt)
{
	int cur, rule_num;

	//assert(rfgrt && rfgrt->rulesets);
	//assert(rfgrt->rulesets->rules && rfgrt->rulesets->rule_num > 1);

	if (rfgrt == NULL || rfgrt->rulesets == NULL) {
		return -EINVAL;
	}

	if (rfgrt->rulesets->rules == NULL ||
		rfgrt->rulesets->rule_num <= 1) {
		return -EINVAL;
	}

	/* After increment, the cur points to the last rejected rules */
	cur = rfgrt->cur & 0x1;
	rule_num = rfgrt->rule_nums[cur];

	/* Rejected rules of last loop enqueue */
	if (rule_num > 1) {
		int *rule_id = malloc(rule_num * sizeof(*rule_id));
		struct rfg_queue_entry *ent = malloc(sizeof(*ent));
		if (!rule_id || !ent) {
			free(ent);
			free(rule_id);
			return -ENOMEM;
		}

		memcpy(rule_id, rfgrt->rule_ids[cur], rule_num * sizeof(*rule_id));
		ent->rule_id = rule_id;
		ent->rule_num = rule_num;
		ent->dims = 0;
		rfgrt->rule_nums[cur] = 0;
		STAILQ_INSERT_TAIL(&rfgrt->wqh, ent, e);
	}

	return 0;
}

static int rfg_process(struct rfg_runtime *rfgrt)
{
	struct rfg_queue_head *qh;
	struct rfg_queue_entry *ent;
	const struct rule *rules = rfgrt->rulesets->rules;

	/* The loop processes subsets that needs de-overlap */
	qh = &rfgrt->wqh;
	while (!STAILQ_EMPTY(qh)) {
		uint64_t measure_max = 0;
		int i, dim = DIM_INV, ack_rng_num = -1, rej_rng_num = -1;

		ent = STAILQ_FIRST(qh);
		//assert(ent->rule_num > 1 && ent->dims != (1 << DIM_MAX) - 1);

		if (ent->rule_num <= 1 || ent->dims == ((1 << DIM_MAX) - 1)) {
			goto err;
		}

		STAILQ_REMOVE_HEAD(qh, e);

		/* choose split dimension */
		for (i = 0; i < DIM_MAX; i++) {
			int j, k;
			uint64_t measure;
			struct rfg_rng_rid *raw;

			if (ent->dims & (1U << i)) {
				continue;
			}

			raw = rfgrt->raws[i];
			for (j = 0; j < ent->rule_num; j++) {
				int rid = ent->rule_id[j];
				uint64_t begin = rules[rid].dims[i][0];
				uint64_t end = rules[rid].dims[i][1];
				raw[j].value = ((end - begin) << 32) | begin;
				raw[j].rule_id = rid;
			}

			QSORT(rng_rid, raw, ent->rule_num);

			/* generate non-overlapping ranges of small sizes */
			measure = rfg_gen_min_range(&j, &k, rfgrt->rejs[i],
										rfgrt->acks[i], raw, ent->rule_num);
			if (measure > measure_max) {
				measure_max = measure;
				ack_rng_num = k;
				rej_rng_num = j;
				dim = i;
			}
		}

		/* process non-overlapping ranges of split dimension */
		//assert(dim != DIM_INV && ack_rng_num > 0 && rej_rng_num >= 0);
		if (dim == DIM_INV || ack_rng_num < 1 || rej_rng_num < 0) {
			goto err;
		}

		if (rfg_spawn(dim, rej_rng_num, ack_rng_num, rfgrt, ent)) {
			goto err;
		}

		free(ent->rule_id);
		free(ent);
	}

	return 0;

err:
	free(ent->rule_id);
	free(ent);

	return -ENOMEM;
}

static int rfg_gather(struct rfg_runtime *rfgrt)
{
	int i;
	int cur = rfgrt->cur & 0x1;
	int *rule_id = rfgrt->rule_ids[cur];
	int rule_num = rfgrt->rule_nums[cur];
	const struct rule_set *rulesets = rfgrt->rulesets;
	struct rule_set *p_srs = &rfgrt->subsets[rfgrt->cur];
	struct rule *rules = malloc((rule_num + 1) * sizeof(*rules));

	if (!rules) {
		return -ENOMEM;
	}

	QSORT(int, rule_id, rule_num);

	for (i = 0; i < rule_num; i++) {
		rules[i] = rulesets->rules[rule_id[i]];
	}

	rules[rule_num++] = rulesets->rules[rulesets->def_rule];
	rfgrt->rule_nums[cur] = 0;

	p_srs->rules = rules;
	p_srs->rule_num = rule_num;
	p_srs->def_rule = rulesets->def_rule;

	return 0;
}

static int rfg_spawn(int dim, int rej_rng_num, int ack_rng_num,
					 struct rfg_runtime *rfgrt, const struct rfg_queue_entry *ent)
{
	int i, j;
	int **rule_ids = rfgrt->rule_ids;
	int *rule_nums = rfgrt->rule_nums;
	int cur = rfgrt->cur & 0x1, exc = cur ^ 1;
	struct rfg_rng_rid *raw = rfgrt->raws[dim];
	struct rfg_rng_idx *ack = rfgrt->acks[dim];
	struct rfg_rng_idx *rej = rfgrt->rejs[dim];

	for (i = 0; i < rej_rng_num; i++) {
		for (j = rej[i].index[0]; j <= rej[i].index[1]; j++) {
			rule_ids[exc][rule_nums[exc]++] = raw[j].rule_id;
		}
	}

	for (i = 0; i < ack_rng_num; i++) {
		if (ack[i].index[0] == ack[i].index[1] ||
			(ent->dims | (1U << dim)) == (1 << DIM_MAX) - 1) {
			for (j = ack[i].index[0]; j <= ack[i].index[1]; j++) {
				rule_ids[cur][rule_nums[cur]++] = raw[j].rule_id;
			}
		}
		else {
			int rule_num = ack[i].index[1] - ack[i].index[0] + 1;
			int *rule_id = malloc(rule_num * sizeof(*rule_id));
			struct rfg_queue_entry *p_new_wqe = malloc(sizeof(*p_new_wqe));
			if (!rule_id || !p_new_wqe) {
				free(p_new_wqe);
				free(rule_id);
				return -ENOMEM;
			}

			for (rule_num = 0, j = ack[i].index[0]; j <= ack[i].index[1]; j++) {
				rule_id[rule_num++] = raw[j].rule_id;
			}

			p_new_wqe->rule_id = rule_id;
			p_new_wqe->rule_num = rule_num;
			p_new_wqe->dims = ent->dims | (1U << dim);
			STAILQ_INSERT_TAIL(&rfgrt->wqh, p_new_wqe, e);
		}
	}

	return 0;
}

static uint64_t rfg_gen_min_range(int *p_rej_rng_num, int *p_ack_rng_num,
								  struct rfg_rng_idx *rej, struct rfg_rng_idx *ack,
								  const struct rfg_rng_rid *raw, int num)
{
	/*
	 * | ack_0, ..., ack_m, ack_m+1, ..., ack_n |
	 * |<-- binary check ->|<-- linear check -->|
	 *
	 * chk_rng: boundary of all ack ranges
	 * bchk_num: number of binary checking ranges
	 */

	uint64_t last_value;
	uint32_t chk_rng[2];
	int i, last_overlap, bchk_num, rej_rng_num, ack_rng_num, ack_rule_num;

	/* The raw_0 is non-overlapping */
	last_value = raw[0].value;
	ack[0].range[0] = chk_rng[0] = last_value & UINT32_MAX;
	ack[0].range[1] = chk_rng[1] = chk_rng[0] + (last_value >> 32);
	ack[0].index[0] = 0;
	last_overlap = bchk_num = rej_rng_num = ack_rng_num = ack_rule_num = 0;

	for (i = 1; i < num; i++) {
		struct rfg_rng_idx key;
		uint32_t *rng = key.range;
		uint64_t value = raw[i].value;

		/* consecutive and identical */
		if (last_value == value) {
			continue;
		}

		/* check a new range */
		last_value = value;
		rng[0] = value & UINT32_MAX;
		rng[1] = rng[0] + (value >> 32);

		if (last_overlap) {
			rej[rej_rng_num++].index[1] = i - 1;
		}
		else {
			ack[ack_rng_num].index[1] = i - 1;
			ack_rule_num += i - ack[ack_rng_num++].index[0];
		}

		/* new range is overlapping */
		if (rng[0] <= chk_rng[1] && rng[1] >= chk_rng[0] &&
			rfg_check_overlap(&key, ack, ack_rng_num, bchk_num)) {
			rej[rej_rng_num].range[0] = rng[0];
			rej[rej_rng_num].range[1] = rng[1];
			rej[rej_rng_num].index[0] = i;
			last_overlap = 1;
			continue;
		}

		/* new range is non-overlapping */
		ack[ack_rng_num].range[0] = rng[0];
		ack[ack_rng_num].range[1] = rng[1];
		ack[ack_rng_num].index[0] = i;
		last_overlap = 0;

		if (!bchk_num && rng[0] <= chk_rng[1]) {
			bchk_num = ack_rng_num;
		}
		if (chk_rng[0] > rng[0]) {
			chk_rng[0] = rng[0];
		}
		if (chk_rng[1] < rng[1]) {
			chk_rng[1] = rng[1];
		}
	}

	if (last_overlap) {
		rej[rej_rng_num++].index[1] = i - 1;
	}
	else {
		ack[ack_rng_num].index[1] = i - 1;
		ack_rule_num += i - ack[ack_rng_num++].index[0];
	}

	*p_rej_rng_num = rej_rng_num;
	*p_ack_rng_num = ack_rng_num;

	return ((uint64_t)ack_rng_num << 32) | (uint64_t)ack_rule_num;
}

static int rfg_check_overlap(const struct rfg_rng_idx *p_key,
							 const struct rfg_rng_idx *ack, int ack_rng_num, int bchk_num)
{
	int i;

	//assert(ack && bchk_num <= ack_rng_num);

	if (ack == NULL || bchk_num > ack_rng_num) {
		return 0;
	}

	if (BSEARCH(rng_idx, p_key, ack, bchk_num) != -1) {
		return 1;
	}

	for (i = bchk_num; i < ack_rng_num; i++) {
		if (p_key->range[0] <= ack[i].range[1] &&
			p_key->range[1] >= ack[i].range[0]) {
			return 1;
		}
	}

	return 0;
}

////////////////////////////////////////////////////

int rf_group(struct partition *part, const struct partition *part_org)
{
	int ret;
	struct rfg_runtime rfg_rt;

	if (!part || !part_org || !part_org->subsets ||
		part_org->subset_num != 1 || part_org->rule_num <= 2) {
		return -EINVAL;
	}

	/* Init */
	ret = rfg_init(&rfg_rt, part_org->subsets);
	if (ret) {
		return ret;
	}

	/* Each loop forms a new group. */
	for (rfg_rt.cur = 0; rfg_rt.rule_nums[rfg_rt.cur & 0x1] &&
		 rfg_rt.cur < PART_MAX; rfg_rt.cur++) {
		/* trigger entry enqueue */
		ret = rfg_trigger(&rfg_rt);
		if (ret) {
			goto err;
		}

		/* replication free grouping */
		ret = rfg_process(&rfg_rt);
		if (ret) {
			goto err;
		}

		/* write loop result */
		ret = rfg_gather(&rfg_rt);
		if (ret) {
			goto err;
		}
	}

	if (rfg_rt.cur == PART_MAX) {
		fprintf(stderr, "Final group number exceeds %d\n", PART_MAX);
		ret = -ENOTSUP;
		goto err;
	}

	/* Write final result */
	part->subsets = realloc(rfg_rt.subsets,
							rfg_rt.cur * sizeof(*part->subsets));
	if (!part->subsets) {
		ret = -ENOMEM;
		goto err;
	}

	rfg_rt.subsets = NULL;
	part->subset_num = rfg_rt.cur;
	part->rule_num = part_org->rule_num;

	/* Term */
	rfg_terminate(&rfg_rt);

	return 0;

err:
	while (--rfg_rt.cur >= 0) {
		unload_rules(&rfg_rt.subsets[rfg_rt.cur]);
	}

	rfg_terminate(&rfg_rt);

	return ret;
}
