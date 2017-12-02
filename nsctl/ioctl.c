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

#define APPLY_FIREWALL 	0x01
#define APPLY_NAT 	 	0x02
#define SHOW_SESSION 	0x04

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

int send_to_kernel(fw_policy_t *fwp, int num, hypersplit_t *hs, int is_nat)
{
	int fd, ret;
	struct ioctl_policyset_s ps;
	uint32_t tnode = 0;
	uint32_t tmem = 0;

	if (is_nat) {
		ps.flags = POLICY_TYPE_NAT;
	}
	else {
		ps.flags = POLICY_TYPE_FIREWALL;
	}

	ps.policy = fwp;
	ps.num_policy = num;

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
				   IPH(s->skey.src), s->skey.sp,
				   IPH(s->skey.dst), s->skey.dp, s->skey.proto,
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
