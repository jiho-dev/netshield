#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <typedefs.h>
#include <ioctl_policy.h>
#include <fw_policy.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ioctl_session.h>
#include <nat.h>
#include <action.h>

//#include <rule_trace.h>
#include <hypersplit.h>
#include <rfg.h>

#include <parse_policy_json.h>

#define APPLY_FIREWALL 	0x01
#define APPLY_NAT 	 	0x02
#define SHOW_SESSION 	0x04

struct arg_opts {
	char	*s_rule_file;
	int		flags;
};

enum {
	IOCTL_START = 0,
	IOCTL_APPLY_FW_POLICY,
	IOCTL_DUMMY,
	IOCTL_SESSION_INFO,


	IOCTL_MAXNR
};

#define DEVICE "/dev/netshield/nsdev"

#define IP_FMT                  "%3u.%3u.%3u.%3u"
#if defined(__LITTLE_ENDIAN)
#define IPH(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define IPH(addr)   IPN(addr)
#else
#error Not defined Endian Mode !
#endif

////////////////////////////////////////


int send_to_kernel(fw_policy_t *fwp, int num, hypersplit_t *hs, int is_nat);
int parse_policy_json(policy_json_t *p, char *fname);
int get_session(void);
int apply_json_rule(fw_policy_t *fwp, int num, int is_nat);
int free_policy_json(policy_json_t *p);

////////////////////////////////////////

static void print_help(void)
{
	const char *s_help =
		"NetShield Control\n"
		"\n"
		"Valid options:\n"
		"  -r, --rule FILE  specify a rule file for building\n"
		"  -f, --firewall apply firewall rule to kernel\n"
		"  -n, --nat apply nat rule to kernel\n"
		"  -s, --session show session \n"
		"\n"
		"  -h, --help  display this help and exit\n"
		"\n";

	fprintf(stdout, "%s", s_help);

	return;
}

static void parse_args(struct arg_opts *argopts, int argc, char *argv[])
{
	int option;
	const char *s_opts = "r:hfns";
	const struct option opts[] = {
		{ "rule",	 required_argument, NULL, 'r' },
		{ "firewall",no_argument,		NULL, 'f' },
		{ "nat",	 no_argument,		NULL, 'n' },
		{ "session", no_argument,		NULL, 's' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ NULL,		 0,					NULL, 0	  }
	};

	assert(argopts && argv);

	if (argc < 2) {
		print_help();
		return;
	}

	while ((option = getopt_long(argc, argv, s_opts, opts, NULL)) != -1) {
		switch (option) {
		case 'r':
			if (access(optarg, F_OK) == -1) {
				perror(optarg);
				return;
			}

			argopts->s_rule_file = optarg;
			break;

		case 'f':
			argopts->flags |= APPLY_FIREWALL;
			break;

		case 'n':
			argopts->flags |= APPLY_NAT;
			break;

		case 's':
			argopts->flags |= SHOW_SESSION;
			break;

		case 'h':
			print_help();
			exit(0);

		default:
			print_help();
			return;
		}
	}
}

////////////////////////////////////////////////

#if 0
fw_policy_t* convert_fw_policy(struct partition			*pa, int is_nat)
{
	int i = 0, j = 0;
	int l = 0;
	fw_policy_t *fw = NULL;
	struct rule_set *ruleset;

	l = pa->rule_num * sizeof(fw_policy_t);
	printf("===== Ruleset Info ===== \n");
	printf("Num of subset: %d \n", pa->subset_num);
	printf("Num of Rule: %d \n", pa->rule_num);
	printf("Mem Length: %d \n", l);

	fw = malloc(l);
	if (fw == NULL) {
		printf("fw is NULL \n");
		return NULL;
	}

	memset(fw, 0, l);

	for (i = 0; i < pa->subset_num; i++) {
		ruleset = &pa->subsets[i];

		for (j = 0; j < ruleset->rule_num; j++) {
			int id;
			int l;
			fw_policy_t *f;
			struct rule *r = &ruleset->rules[j];

			id = r->pri;
			if (id > pa->rule_num) {
				printf("### out of range: %d\n", id);
				continue;
			}

			f = &fw[id];

			f->rule_idx = id;
			f->range.src.min = r->dims[DIM_SIP][0];
			f->range.src.max = r->dims[DIM_SIP][1];
			f->range.dst.min = r->dims[DIM_DIP][0];
			f->range.dst.max = r->dims[DIM_DIP][1];

			f->range.sp.min = r->dims[DIM_SPORT][0];
			f->range.sp.max = r->dims[DIM_SPORT][1];
			f->range.dp.min = r->dims[DIM_DPORT][0];
			f->range.dp.max = r->dims[DIM_DPORT][1];

			f->range.proto.min = r->dims[DIM_PROTO][0];
			f->range.proto.max = r->dims[DIM_PROTO][1];

			f->range.nic.min = r->dims[DIM_NIC][0];
			f->range.nic.max = r->dims[DIM_NIC][1];
			f->action = 0;
			f->nat_policy[0] = NULL;
			f->nat_policy[1] = NULL;

			if (r->flags & RULE_ALLOW) {
				// for allow
				f->action |= ACT_ALLOW;
				printf("Firewall action: 0x%lx \n", f->action);
			}
			else if (r->flags & RULE_SNAT) {
				// for SNAT
				f->action |= ACT_SNAT;
				printf("SNAT action: 0x%lx \n", f->action);
			}
			else {
				printf("No action: flags=0x%x \n", r->flags);
			}
			
			if (is_nat) {
				nat_policy_t *n = malloc(sizeof(nat_policy_t));

				memset(n, 0, sizeof(nat_policy_t));
				n->id = 1;
				n->flags = NATF_SNAT_NAPT;
				n->nic = 0;
				n->nip[0] = ntohl(inet_addr("1.1.1.3"));
				n->nip[1] = n->nip[0];
				n->nport[0] = 3000;
				n->nport[1] = 65535;

				f->nat_policy[0] = n;
			}

			l = strlen(r->desc);
			if (l > 0) {
				strncpy(f->desc, r->desc, 63);
			}
		}
	}

	return fw;
}


int apply_kernel(struct partition *pa, hypersplit_t *hs, int is_nat)
{
	fw_policy_t *fwp;

	fwp = convert_fw_policy(pa, is_nat);

	send_to_kernel(fwp, pa->rule_num, hs, is_nat);

	return 0;
}

int apply_rule(struct arg_opts *argopts)
{
	struct timespec starttime, stoptime;
	struct partition pa, pa_grp;
	hypersplit_t hypersplit;

	printf("Build Hypersplit \n");

	/*
	 * Loading classifier
	 */
	pa.subsets = calloc(1, sizeof(*pa.subsets));
	if (!pa.subsets) {
		perror("Cannot allocate memory for subsets");
		return -1;
	}

	if (load_rules(pa.subsets, argopts->s_rule_file, RULE_FMT_NS)) {
		return -1;
	}

	pa.subset_num = 1;
	pa.rule_num = pa.subsets[0].rule_num;

	// grouping
	printf("Grouping ... \n");
	fflush(NULL);

	if (pa.rule_num > 2) {
		if (rf_group(&pa_grp, &pa)) {
			printf("Error Grouping ... \n");
			return -1;
		}

		unload_partition(&pa);

		pa.subset_num = pa_grp.subset_num;
		pa.rule_num = pa_grp.rule_num;
		pa.subsets = pa_grp.subsets;

		pa_grp.subset_num = 0;
		pa_grp.rule_num = 0;
		pa_grp.subsets = NULL;
		unload_partition(&pa_grp);

		printf("subset_num=%d, rule=%d \n", pa.subset_num, pa.rule_num);
		fflush(NULL);
	}

	/*
	 * Building
	 */
	printf("Building ...\n");

	clock_gettime(CLOCK_MONOTONIC, &starttime);

	if (hs_build(&hypersplit, &pa)) {
		printf("Building fail\n");
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &stoptime);

	printf("Building pass\n");
	printf("Time for building: %" PRIu64 "(us)\n",
		   make_timediff(stoptime, starttime));

	if (argopts->flags & APPLY_FIREWALL) {
		printf("Apply Firewall rules into NetShield: %s \n", argopts->s_rule_file);
		apply_kernel(&pa, &hypersplit, 0);
	}
	else if (argopts->flags & APPLY_NAT) {
		printf("Apply NAT rules into NetShield: %s \n", argopts->s_rule_file);
		apply_kernel(&pa, &hypersplit, 1);
	}

	unload_partition(&pa);
	hs_destroy(&hypersplit);

	return 0;
}
#endif

int main(int argc, char *argv[])
{
	struct arg_opts argopts = {
		.s_rule_file	= NULL,
		.flags			= 0,
	};

	printf("\n=========================\n");
	printf("Start Processing Packet Classification Rules \n");

	parse_args(&argopts, argc, argv);

	if (argopts.flags & SHOW_SESSION) {
		get_session();
	}

	if (argopts.s_rule_file != NULL) {
		policy_json_t p;
		memset(&p, 0, sizeof(policy_json_t));

		parse_policy_json(&p, argopts.s_rule_file);
		if (p.policy[0]) {
			if (argopts.flags & APPLY_FIREWALL) {
				apply_json_rule(p.policy[0], p.num_policy[0], 0);
			}
		}

		if (p.policy[1]) {
			if (argopts.flags & APPLY_NAT) {
				apply_json_rule(p.policy[1], p.num_policy[1], 1);
			}
		}

		free_policy_json(&p);

		//apply_rule(&argopts);
	}

	return 0;
}
