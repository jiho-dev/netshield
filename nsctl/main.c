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

#include <ns_type_defs.h>
#include <ioctl_policy.h>
#include <fw_policy.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ioctl_session.h>

//#include <rule_trace.h>
#include <hypersplit.h>
#include <rfg.h>


#define APPLY_KERNEL 0x01
#define SHOW_SESSION 0x02

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

static void print_help(void)
{
	const char *s_help =
		"NetShield Control\n"
		"\n"
		"Valid options:\n"
		"  -r, --rule FILE  specify a rule file for building\n"
		"  -k, --kernel send rule to kernel\n"
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
	const char *s_opts = "r:hks";
	const struct option opts[] = {
		{ "rule",	 required_argument, NULL, 'r' },
		{ "kernel",	 no_argument,		NULL, 'k' },
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

		case 'k':
			argopts->flags |= APPLY_KERNEL;
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

static uint64_t make_timediff(const struct timespec stop,
							  const struct timespec start)
{
	return (stop.tv_sec * 1000000ULL + stop.tv_nsec / 1000)
		   - (start.tv_sec * 1000000ULL + start.tv_nsec / 1000);
}

void save_hypersplit(hypersplit_t *hypersplit)
{
	int fd;

	fd = open("hs.bin", O_WRONLY | O_TRUNC | O_CREAT, 0644);

	if (fd == -1) {
		printf("cannot open hs.bin \n");
		return;
	}

	ssize_t l = 0;

	l = write(fd, &hypersplit->tree_num, sizeof(int));
	l = write(fd, &hypersplit->def_rule, sizeof(int));

	if (l == 0) {
	}

	printf("Saving Hypersplit \n");
	printf("Num Tree: %d \n", hypersplit->tree_num);
	printf("Def Rule: %d \n", hypersplit->def_rule);

	int j, tmem = 0, tnode = 0;

	for (j = 0; j < hypersplit->tree_num; j++) {
		struct hs_tree *t = &hypersplit->trees[j];
		int mlen = t->inode_num * sizeof(struct hs_node);

		tmem += mlen;
		tnode += t->inode_num;

		printf("#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d \n",
			   j + 1, t->inode_num, mlen, t->depth_max);

		l = write(fd, &t->inode_num, sizeof(int));
		l = write(fd, &t->depth_max, sizeof(int));
		l = write(fd, &mlen, sizeof(int));
		l = write(fd, (void *)t->root_node, mlen);
	}

	close(fd);

	printf("Total: Node=%d, Mem=%d \n", tnode, tmem);
}

void* load_hypersplit(void)
{
	int fd;
	struct hypersplit_s *hs;
	ssize_t l = 0;

	l = sizeof(struct hypersplit_s);
	hs = malloc(l);

	if (hs == NULL) {
		return NULL;
	}

	memset(hs, 0, l);

	fd = open("hs.bin", O_RDONLY);

	if (fd == -1) {
		printf("cannot open hs.bin \n");
		return NULL;
	}

	read(fd, &hs->tree_num, sizeof(int));
	read(fd, &hs->def_rule, sizeof(int));

	printf("Loading Hypersplit \n");
	printf("Num Tree: %d \n", hs->tree_num);
	printf("Def Rule: %d \n", hs->def_rule);

	hs->trees = malloc(sizeof(struct hs_tree) * hs->tree_num);

	int j, tmem = 0, tnode = 0;

	for (j = 0; j < hs->tree_num; j++) {
		struct hs_tree *t = &hs->trees[j];
		int mlen;

		read(fd, &t->inode_num, sizeof(int));
		t->enode_num = t->inode_num + 1;

		read(fd, &t->depth_max, sizeof(int));
		read(fd, &mlen, sizeof(int));

		tnode += t->inode_num;
		tmem += mlen;

		if ((t->inode_num * sizeof(struct hs_node)) != mlen) {
			printf("something wrong: mlen=%d \n", mlen);
		}

		t->root_node = malloc(mlen);

		read(fd, (void *)t->root_node, mlen);

		printf("#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d \n",
			   j + 1, t->inode_num, mlen, t->depth_max);
	}

	close(fd);

	printf("Total: Node=%d, Mem=%d \n", tnode, tmem);

	return hs;
}

////////////////////////////////////////////////

int get_netshield_option_int(char *name)
{
	char buf[32] = { 0x0 };
	int value = 0;
	char proc[512];
	FILE *fd;

	sprintf(proc, "/proc/netshield/option/%s", name);

	fd = fopen(proc, "r");

	if (fd) {
		fgets(buf, 32, fd);
		value = atoi(buf);

		fclose(fd);
	}

	return value;
}

void get_netshield_option_str(char *name, char *msg, int msglen)
{
	char proc[512];
	FILE *fd;

	sprintf(proc, "/proc/netshield/option/%s", name);

	fd = fopen(proc, "r");

	if (fd && msg && msglen > 0) {
		fgets(msg, msglen, fd);
	}

	if (fd) {
		fclose(fd);
	}
}

fw_policy_t* convert_fw_policy(struct partition			*pa,
							   struct ioctl_policyset_s *ps)
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

			if (r->flags) {
				// for allow
				f->action |= 0x01;
			}

			l = strlen(r->desc);
			if (l > 0) {
				strncpy(f->desc, r->desc, 63);
			}
		}
	}

	return fw;
}

int send_to_kernel(struct partition *pa, hypersplit_t *hs)
{
	int fd, ret;
	struct ioctl_policyset_s ps;
	uint32_t tnode = 0;
	uint32_t tmem = 0;

	ps.fw_policy = convert_fw_policy(pa, &ps);
	ps.num_fw_policy = pa->rule_num;

	tmem = hs_tree_memory_size(hs, &tnode);
	ps.hs = hs;
	ps.num_hs_tree = hs->tree_num;
	ps.num_hs_node = tnode;
	ps.num_hs_mem = tmem;

	printf("===== HyperSplit Info ===== \n");
	printf("Total Tree: %d \n", hs->tree_num);
	printf("Total Node: %d \n", tnode);
	printf("Total Mem : %d \n", tmem);

#if 0
	int i;
	for (i = 0; i < hs->tree_num; i++) {
		int j, l;
		struct hs_tree *t = &hs->trees[i];
		uint8_t *p;

		l = sizeof(struct hs_node) * t->inode_num;
		p = (uint8_t *)t->root_node;

		printf("Tree %d: %p \n", i + 1, t);
		printf(" root_node: %p \n", t->root_node);
		printf(" inode_num: %d \n", t->inode_num);
		printf(" enode_num: %d \n", t->enode_num);
		printf(" depth_max: %d \n", t->depth_max);
		printf(" node len: %d \n", l);

		if (1) {
			char buf[100], b[10];

			memset(buf, 0, 100);

			for (j = 0; j < l; j++) {
				sprintf(b, "0x%02x ", p[j]);
				strcat(buf, b);

				if (j > 0 && (j % 8) == 7) {
					printf("%s\n", buf);
					memset(buf, 0, 100);
				}
			}

			printf("\n");
		}
	}
#endif

	fd = open(DEVICE, O_RDWR);
	if (fd == -1) {
		printf("File %s either does not exist or has been locked by another process\n", DEVICE);
		return -1;
	}

	ret = ioctl(fd, IOCTL_APPLY_FW_POLICY, (unsigned long)&ps);

	printf("Return of Apply: %d \n", ret);

#if 0
	if (ret == 0) {
		ioctl(fd, IOCTL_COMMIT_NEW_POLICY, (unsigned long)hs);
		printf("Commit New Policy\n");
	}
#endif

	close(fd);

	return 0;
}

int get_session(void)
{
	ioctl_get_sess_t ss;
	int fd = -1, ret = 0;
	int l, i;
	int sess_cnt = 0;

	sess_cnt = get_netshield_option_int("session_cnt");

	if (sess_cnt < 1) {
		printf("No Session\n");
		return 0;
	}

	fd = open(DEVICE, O_RDWR);
	if (fd == -1) {
		printf("File %s either does not exist or has been locked by another process\n", DEVICE);
		return -1;
	}

	ss.num_sess = sess_cnt;
	l = sizeof(ioctl_session_t) * sess_cnt;

	ss.sess = malloc(l);

	if (ss.sess == NULL) {
		printf("No memory for session \n");
		goto END;
	}

	ret = ioctl(fd, IOCTL_SESSION_INFO, (unsigned long)&ss);

	if (ret == 0) {
		printf("# of Session: %u \n", ss.num_sess);
		for (i = 0; i < ss.num_sess; i++) {
			ioctl_session_t *s = &ss.sess[i];

			printf("%3d:" IP_FMT ":%-5u -> " IP_FMT ":%-5u(%-2u) sid=%u, born=%u, timeout=%d \n",
				   i,
				   IPH(s->sk.src), s->sk.sp,
				   IPH(s->sk.dst), s->sk.dp, s->sk.proto,
				   s->sid,
				   s->born_time,
				   s->timeout
				   );
		}
	}

	if (ss.sess) {
		free(ss.sess);
	}

END:
	close(fd);

	return ret;
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

	if (argopts->flags & APPLY_KERNEL) {
		printf("Apply Hypersplit into NetShield: %s \n", argopts->s_rule_file);
		send_to_kernel(&pa, &hypersplit);
	}

	unload_partition(&pa);
	hs_destroy(&hypersplit);

	return 0;
}

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
		apply_rule(&argopts);
	}

	return 0;
}
