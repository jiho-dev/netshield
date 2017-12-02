/*
 *     Filename: rule_trace.h
 *  Description: Header file for rule and trace operations
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *               Chang Chen (ck-cc@hotmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __RULE_TRACE_H__
#define __RULE_TRACE_H__

#include <stdint.h>
#include <inttypes.h>
#include "buffer.h"

#define WUSTL_RULE_FMT_SCN \
	"@%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 "/%" SCNu32 \
	" %" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 "/%" SCNu32 \
	" %" SCNu32 " : %" SCNu32 \
	" %" SCNu32 " : %" SCNu32 \
	" %" SCNx32 "/%" SCNx32 "\n"

#define NS_RULE_FMT_SCN \
	"(%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 \
	":%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 \
	")(%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 \
	":%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32 \
	")(%" SCNu32 ":%" SCNu32 \
	")(%" SCNu32 ":%" SCNu32 \
	")(%" SCNu32 ":%" SCNu32 \
	")(%" SCNu32 ":%" SCNu32 ")(%c)(%[^\n]s)\n"

#define WUSTL_PKT_FMT_SCN \
	"%" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNu32 " %" SCNd32 "\n"

#define PART_HEAD_FMT_PRI \
	"#%" PRIu32 ",%" PRIu32 "\n"

#define PART_RULE_FMT_PRI \
	"@%" PRIu32 ",%" PRIu32 \
	",%" PRIu32 ",%" PRIu32 \
	",%" PRIu32 ",%" PRIu32 \
	",%" PRIu32 ",%" PRIu32 \
	",%" PRIu32 ",%" PRIu32 \
	",%" PRId32 "\n"

#define PART_HEAD_FMT_SCN \
	"#%" SCNu32 ",%" SCNu32 "\n"

#define PART_RULE_FMT_SCN \
	"@%" SCNu32 ",%" SCNu32 \
	",%" SCNu32 ",%" SCNu32 \
	",%" SCNu32 ",%" SCNu32 \
	",%" SCNu32 ",%" SCNu32 \
	",%" SCNu32 ",%" SCNu32 \
	",%" SCNd32 "\n"

#define RULE_MAX (1 << 17)  /* 128K */
#define PKT_MAX (1 << 17)   /* 128K */
#define PART_MAX (1 << 6)   /* 64 */


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

enum {
	RULE_FMT_INV		= -1,
	RULE_FMT_WUSTL		= 0,
	RULE_FMT_WUSTL_G	= 1,
	RULE_FMT_MAX		= 2,
	RULE_FMT_NS			= 3,
};

#define RULE_DROP 	0x0
#define RULE_ALLOW 	0x1
#define RULE_SNAT 	0x2
#define RULE_DISABLE 0x4

struct rule {
	uint32_t	dims[DIM_MAX][2];
	uint32_t	pri;
	uint32_t 	flags;
	char 		desc[64];
};

struct rule_set {
	struct rule *rules;
	uint32_t	rule_num;
	uint32_t	def_rule;
};

struct partition {
	struct rule_set *subsets;
	int				subset_num;
	int				rule_num;
};

struct packet {
	uint32_t	dims[DIM_MAX];
	int			match_rule;
	int			found;
};

struct trace {
	struct packet	*pkts;
	int				pkt_num;
};

struct shadow_range {
	uint32_t	*pnts;
	int			*cnts;
	int			point_num;
	int			total;
};

VECTOR(rule_vector, struct rule);


int load_rules(struct rule_set *p_rs, const char *s_rf, int fmt);
void unload_rules(struct rule_set *p_rs);

int load_trace(struct trace *p_t, const char *s_tf);
void unload_trace(struct trace *p_t);

int load_partition(struct partition *p_pa, const char *s_pf);
void unload_partition(struct partition *p_pa);
void dump_partition(const char *s_pf, const struct partition *p_pa);
int revert_partition(struct rule_set *p_rs, const struct partition *p_pa);

int split_range_rule(struct rule_vector *p_vector, const struct rule *p_rule);
int shadow_rules(struct shadow_range *srngs, int64_t *spnts, const uint32_t dim_rng[2], const int *rule_id, int rule_num, const struct rule *rules, int dim);

#endif /* __RULE_TRACE_H__ */
