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
#include <json-c/json.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>

#define _BSD_SOURCE
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

// https://json-c.github.io/json-c/json-c-0.10/doc/html/json__object_8h.html

typedef  struct json_object jobj_t;

void parse_ip_range(range128_t *r, jobj_t *j)
{
	jobj_t *i1=NULL, *i2=NULL;
	char *p1=NULL, *p2=NULL;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		p1 = (char*)json_object_get_string(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		p2 = (char*)json_object_get_string(i2);
	}

	r->min = p1 ? ntohl(inet_addr(p1)) : 0;
	r->max = p2 ? ntohl(inet_addr(p2)) : 0;
	if (r->max == 0) {
		r->max = (uint32_t)(~0);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_uint32_range(range32_t *r, jobj_t *j)
{
	jobj_t *i1=NULL, *i2=NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = (uint32_t)json_object_get_int(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = (uint32_t)json_object_get_int(i2);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_uint16_range(range16_t *r, jobj_t *j)
{
	jobj_t *i1=NULL, *i2=NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = (uint16_t)json_object_get_int(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = (uint16_t)json_object_get_int(i2);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_uint8_range(range8_t *r, jobj_t *j)
{
	jobj_t *i1=NULL, *i2=NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = (uint8_t)json_object_get_int(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = (uint8_t)json_object_get_int(i2);
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

void parse_action(fw_policy_t *fwp, jobj_t *j)
{
	char *p = NULL;

	p = (char*)json_object_get_string(j);

	if (strcmp(p, "allow") == 0) {
		fwp->action |= ACT_ALLOW;
	}
	else if (strcmp(p, "drop") == 0) {
		fwp->action |= ACT_DROP;
	}
	else if (strcmp(p, "snat") == 0) {
		fwp->action |= ACT_SNAT;
	}
}

void parse_state(fw_policy_t *fwp, jobj_t *j)
{
	char *p;

	p = (char*)json_object_get_string(j);

	if (strcmp(p, "enable") == 0) {
	}
	else {
		fwp->action |= ACT_DISABLE;
	}
}

int parse_nat_type(nat_policy_t *natp, jobj_t *j)
{
	char *p;

	p = (char*)json_object_get_string(j);

	if (strcmp(p, "snat_napt") == 0) {
		natp->flags |= NATF_SNAT_NAPT;
	}
	else if (strcmp(p, "snat_masking") == 0) {
		natp->flags |= NATF_SNAT_MASKING;
	}
	else if (strcmp(p, "snat_hash") == 0) {
		natp->flags |= NATF_SNAT_HASH;
	}
	else if (strcmp(p, "dnat_redir") == 0) {
		natp->flags |= NATF_DNAT_RDIR;
	}
	else if (strcmp(p, "dnat_local_redir") == 0) {
		natp->flags |= NATF_DNAT_LRDIR;
	}
	else {
		printf("Unknown NAT type: %s \n", p);
		return -1;
	}

	return 0;
}

int parse_nat_option(nat_policy_t *natp, jobj_t *jopt)
{
	char *p;

	int arr_len = json_object_array_length(jopt);

	if (arr_len < 1) {
		return 0;
	}

	for (int i=0; i<arr_len; i++) {
		jobj_t *j;

		j = json_object_array_get_idx(jopt, i);
		
		if (j == NULL) {
			continue;
		}

		p = (char*)json_object_get_string(j);

		if (strcmp(p, "arp_proxy") == 0) {
			natp->flags |= NATF_ARP_PROXY;
		}
		else if (strcmp(p, "dynamic_ip") == 0) {
			natp->flags |= NATF_DYNAMIC_IP;
		}
		else {
			printf("Unknown NAT option: %s \n", p);
		}
	}

	return 0;
}

uint32_t parse_nic_index(jobj_t *j_nic)
{
	uint32_t ifidx = 0;

	char *ifname = (char*)json_object_get_string(j_nic);

	if (ifname && strcmp(ifname, "any") != 0) {
		ifidx = if_nametoindex((const char *)ifname);
	}

	printf("nat nic: %s, %d \n", ifname, ifidx);

	return ifidx;
}

void parse_nic_range(range32_t *r, jobj_t *j)
{
	jobj_t *i1=NULL, *i2=NULL;

	r->min = 0;
	r->max = 0;

	if ((i1 = json_object_array_get_idx(j, 0))) {
		r->min = parse_nic_index(i1);
	}

	if ((i2 = json_object_array_get_idx(j, 1))) {
		r->max = parse_nic_index(i2);
	}

	if (r->max == 0) {
		r->max = 255;
	}

	if (i1) {
		//json_object_put(i1);
	}

	if (i2) {
		//json_object_put(i2);
	}
}

nat_policy_t* parse_nat(jobj_t *j_nat)
{
	nat_policy_t *n = malloc(sizeof(nat_policy_t));
	jobj_t *j;
	int ret;

	memset(n, 0, sizeof(nat_policy_t));

	if (!json_object_object_get_ex(j_nat, "type", &j)) {
		goto ERR;
	}
	ret = parse_nat_type(n, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	if (!json_object_object_get_ex(j_nat, "option", &j)) {
		goto ERR;
	}
	ret = parse_nat_option(n, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	if (json_object_object_get_ex(j_nat, "nic", &j)) {
		n->nic = parse_nic_index(j);
	}
	//json_object_put(j);

	if (!json_object_object_get_ex(j_nat, "nat_ip", &j)) {
		goto ERR;
	}
	parse_ip_range((range128_t*)&n->nip, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	if (!json_object_object_get_ex(j_nat, "nat_port", &j)) {
		goto ERR;
	}
	parse_uint16_range((range16_t*)&n->nport, j);
	//json_object_put(j);
	if (ret) {
		goto ERR;
	}

	return n;

ERR:
	if (n) {
		free(n);
	}

	return NULL;
}

void parse_natinfo(fw_policy_t *fwp, jobj_t *j)
{
	jobj_t *j_nat;

	if (json_object_object_get_ex(j, "snat", &j_nat)) {
		fwp->nat_policy[0] = parse_nat(j_nat);
		//json_object_put(j_nat);
	}

	if (json_object_object_get_ex(j, "dnat", &j_nat)) {
		fwp->nat_policy[1] = parse_nat(j_nat);
		//json_object_put(j_nat);
	}
}

int parse_firewall_policy(fw_policy_t *fwp, jobj_t *j_fwp)
{
	jobj_t *j;
	char *p;

	if (!json_object_object_get_ex(j_fwp, "desc", &j)) {
		return -1;
	}

	p = (char*)json_object_get_string(j);
	if (p) {
		strncpy(fwp->desc, p, 63);
	}
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "src_ip", &j)) {
		return -1;
	}
	parse_ip_range(&fwp->range.src, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "dst_ip", &j)) {
		return -1;
	}
	parse_ip_range(&fwp->range.dst, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "src_port", &j)) {
		return -1;
	}
	parse_uint16_range(&fwp->range.sp, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "dst_port", &j)) {
		return -1;
	}
	parse_uint16_range(&fwp->range.dp, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "protocol", &j)) {
		return -1;
	}
	parse_uint8_range(&fwp->range.proto, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "nic", &j)) {
		return -1;
	}
	parse_nic_range(&fwp->range.nic, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "action", &j)) {
		return -1;
	}
	parse_action(fwp, j);
	//json_object_put(j);

	if (!json_object_object_get_ex(j_fwp, "state", &j)) {
		return -1;
	}
	parse_state(fwp, j);
	//json_object_put(j);

	//////////////////////
	//natinfo
	
	if (json_object_object_get_ex(j_fwp, "nat_info", &j)) {
		parse_natinfo(fwp, j);
		//json_object_put(j);
	}

	return 0;
}

fw_policy_t* load_json_policy(jobj_t *j_fw_root, int *cnt)
{
	fw_policy_t *fwp = NULL, *f;

	int arr_len = json_object_array_length(j_fw_root);

	if (arr_len < 1) {
		printf("No Firewall Policy: %d \n", arr_len);
		return NULL;
	}

	fwp = calloc(arr_len, sizeof(fw_policy_t));

	if (!fwp) {
		return NULL;
	}

	for (int i=0; i<arr_len; i++) {
		jobj_t *j;
		
		f = &fwp[i];
		f->rule_id = i + 1;
		j = json_object_array_get_idx(j_fw_root, i);

		//printf("fwp[%d]: %s \n", i, json_object_get_string(j));

		if (parse_firewall_policy(f, j)) {
			free(fwp);
			return NULL;
		}
	}

	*cnt = arr_len;

	return fwp;
}


int parse_policy_json(policy_json_t *p, char *fname)
{
	enum json_type type;
	int f = -1;
	void *data = NULL;
	struct stat sb;

	f = open(fname, O_RDONLY);
	if (f == -1) {
		printf("Cannot open file: %s \n", fname);
		return -1;
	}

	if (fstat(f, &sb) == -1) {
		printf("Cannot read file info: %s \n", fname);
		goto END;
	}

	data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, f, 0); 
	if (data == MAP_FAILED) {
		printf("mmap error with %s \n", fname);
		goto END;
	}

	json_object *j_root = json_tokener_parse(data);

	if (j_root == NULL) {
		printf("cannot parse json file: %s \n", fname);
		goto END;
	}

	///////////////////////////
	jobj_t *j_id=NULL, *j_ver=NULL, *j_desc=NULL;
	jobj_t *j_policy=NULL, *j_fw=NULL, *j_nat=NULL;

	json_object_object_get_ex(j_root, "version", &j_ver);
	json_object_object_get_ex(j_root, "id", &j_id);
	json_object_object_get_ex(j_root, "desc", &j_desc);

	printf("ver:%s, id: %s, desc: %s \n", 
		   json_object_get_string(j_ver),
		   json_object_get_string(j_id),
		   json_object_get_string(j_desc));

	//json_object_put(j_ver);
	//json_object_put(j_id);
	//json_object_put(j_desc);

	///////////////////////////
	if (!json_object_object_get_ex(j_root, "policy", &j_policy)) {
		printf("No Policy \n");
		goto END;
	}

	///////////////////////////////////////////////////
	// Firewall
	if (!json_object_object_get_ex(j_policy, "firewall", &j_fw)) {
		printf("No Firewall Policy \n");
		goto END;
	}

	//printf("policy: %s \n", json_object_get_string(j_policy));

	type = json_object_get_type(j_fw);
	if (type != json_type_array) {
		printf("Wrong Firewall Policy \n");
		goto END;
	}

	if (json_object_array_length(j_fw) < 1) {
		printf("No Firewall Policy \n");
		goto END;
	}

	fw_policy_t *fw_policy = NULL, *nat_policy = NULL;

	fw_policy = load_json_policy(j_fw, &p->num_policy[0]);
	if (fw_policy) {
		p->policy[0] = fw_policy;
	}

	//json_object_put(j_fw);

	///////////////////////////////////////////////////
	// NAT
	if (json_object_object_get_ex(j_policy, "nat", &j_nat)) {
		//printf("policy: %s \n", json_object_get_string(j_policy));

		type = json_object_get_type(j_nat);

		if (type != json_type_array ||
			json_object_array_length(j_nat) < 1) {
			printf("Wrong NAT Policy \n");
		}
		else {
			nat_policy = load_json_policy(j_nat, &p->num_policy[1]);
			if (nat_policy) {
				p->policy[1] = nat_policy;
			}
		}

		//json_object_put(j_nat);
	}

	//printf("fw_policy=%p, nat_policy=%p \n", fw_policy, nat_policy);

END:

	json_object_put(j_root);

	if (data != NULL) {
		munmap(data, sb.st_size);
	}

	if (f != -1) {
		close(f);
	}

	return 0;
}

int free_policy_json(policy_json_t *p)
{
	int i, j;
	fw_policy_t *fwp, *f;

	if (p->policy[0]) {
		free(p->policy[0]);
	}

	if (p->policy[1]) {
		fwp = (fw_policy_t*)p->policy[1];

		for (i=0; i<p->num_policy[1]; i++) {
			f = &fwp[i];

			for (j = 0; j < 2; j++) {
				if (f->nat_policy[j]) {
					free(f->nat_policy[j]);
				}
			}
		}

		free(p->policy[1]);
	}

	return 0;
}

