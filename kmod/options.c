#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <session.h>
#include <version.h>
#include <options.h>
#include <ns_malloc.h>
#include <ns_sysctl.h>
#include <smgr.h>


//////////////////////////////////////////////////////

#define PROC_MIN_MAX	&proc_dointvec_minmax
#define PROC_LONG 		&proc_doulongvec_minmax

#define ATOMIC_SCNT_ALL 		1
#define ATOMIC_SCNT_MINE 		2
#define ATOMIC_SCNT_REMOTE 		3
#define ATOMIC_SCNT_LOCAL 		4
#define ATOMIC_SCNT_MAGIC 		5
#define ATOMIC_CURRENT_TIME 	6


DECLARE_DBG_LEVEL(2);
extern smgr_t		*g_smgr; 

//////////////////////////////////////////////////////

#ifdef CONFIG_NS_DEBUG
void dbgctl_register_proc(void);
void dbgctl_unregister_proc(void);
extern seqops_t seq_dbgctl_ops;
extern ctl_table_t dbgctl_opt[];
#endif

extern seqops_t seq_natip_ops;



int32_t show_session_count(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos);
int32_t show_atomic(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos);
int32_t show_session_state(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos);
int32_t show_version(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos);

void* 	seq_opt_tab_start(struct seq_file *s, loff_t *pos);
void* 	seq_opt_tab_next(struct seq_file *s, void *v, loff_t *pos);
void 	seq_opt_tab_stop(struct seq_file *s, void *v);
int32_t seq_opt_tab_show(struct seq_file *s, void *v);
char* 	nls_get_msg(uint32_t id);


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

static ctl_table_t ns_sysctl_root[] = {
	{
		.procname = "option", 	
		.data=NULL, 
		.maxlen=0, 
		.mode=0555, 
		.child=NULL,
		.proc_handler=NULL,
		.poll = NULL,
		.extra1 = NULL,
		.extra2 = NULL
	},

	{ .procname = NULL, .child=NULL, .proc_handler=NULL},
};

seqops_t seq_opt_ops = {
	.start = seq_opt_tab_start,
	.next = seq_opt_tab_next,
	.stop = seq_opt_tab_stop,
	.show = seq_opt_tab_show,
};

/////////////////////////////////////////////////////////////////////////

static seq_proc_t seq_proc_tab [] = {
	{"all_options",			&seq_opt_ops, 		NULL},
	{"nat_arp_proxy_list",	&seq_natip_ops, 		NULL},

	{.name = NULL},
};

/*** *INDENT-OFF* ***/
option_t ns_options [] __read_mostly = {
    // 1. Define modules
    // ----- name               value       min     max     mode        proc_handler
    OPT_ITEM(all_allow_log,     0,          0,      1,      O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(all_drop_log,      0,          0,      1,      O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(all_drop_log_skip_by_seq,1,    0,      1,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(info_log_interval, 60,         0,      86400,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(nat_arp_proxy,		1,          0,      1,  	O_W,        PROC_MIN_MAX),
    // 기능 항목 끝

    // 2. Define options
    OPT_ITEM(age_interval,      1,          1,      5,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(bl_btime,          30,         1,      86400,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(bl_log,            1,          0,      2,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(bl_log_param,      100,        5,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(current_time,      ATOMIC_CURRENT_TIME,0,0, 	O_A,        &show_atomic),
    OPT_ITEM(frag_pkt_drop_cnt, 0,          0,      0,      O_R,        PROC_MIN_MAX),

    OPT_ITEM(session_bucket_power,19,       15,     26,     O_W,        PROC_MIN_MAX),
    OPT_ITEM(session_cnt,       ATOMIC_SCNT_ALL,0,	0, 		O_A,        &show_atomic),
    OPT_ITEM(session_cnt_mine,  ATOMIC_SCNT_MINE,  0,0,     O_A,        &show_atomic),
    OPT_ITEM(session_cnt_remote,ATOMIC_SCNT_REMOTE,0,0,     O_A,        &show_atomic),
    OPT_ITEM(session_cnt_local, ATOMIC_SCNT_LOCAL, 0,0,     O_A,        &show_atomic),
    OPT_ITEM(session_state, 	0,          0,      0,      O_R,        &show_session_state),
    OPT_ITEM(session_max,       0,          0,      60000000,O_W,       PROC_MIN_MAX),
    OPT_ITEM(session_magic,     ATOMIC_SCNT_MAGIC, 0,0,     O_A,        &show_atomic),
    OPT_ITEM(session_max_warn,  95,        80,      99,     O_W,        PROC_MIN_MAX),

    OPT_ITEM(start_time,        0,          0,      0,      O_R,        PROC_MIN_MAX),

    OPT_ITEM(version,           NETSHIELD_VERSION_MAJ,0, 0,      O_R,        &show_version),

    OPT_ITEM(timeout_udp,       100,        0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_udp_reply, 10,         0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_icmp,      1,          0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_icmp_reply,3,          1,      300,    O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_unknown,   30,         0,      100000, O_W|O_U,    PROC_MIN_MAX),

    // for TCP protocol
    OPT_ITEM(drop_tcp_oow,      0,          0,      1,      O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_tcp,       3600,       0,      100000, O_W|O_U,    PROC_MIN_MAX),
    OPT_ITEM(timeout_syn_sent,  120,        1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_syn_rcv,   60,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_fin_wait,  120,        1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_close_wait,60,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_last_ack,  30,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_time_wait, 10,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_close,     10,         1,      65535,  O_W,        PROC_MIN_MAX),
    OPT_ITEM(timeout_max_retrans,300,       1,      65535,  O_W,        PROC_MIN_MAX),

	[OPT_MAX] = {.name=NULL}

};
/*** *INDENT-ON* ***/




////////////////////////////////////

uint32_t proc_get_atomic_value(int32_t idx)
{
	atomic_t *at = NULL;
	uint32_t val = 0;

	switch (idx) {
	case ATOMIC_SCNT_MINE:
		at = &g_smgr->mine;
		break;
	case ATOMIC_SCNT_REMOTE:
		at = &g_smgr->remote;
		break;
	case ATOMIC_SCNT_LOCAL:
		at = &g_smgr->local;
		break;
	case ATOMIC_SCNT_MAGIC:
		at = &g_smgr->magic_scnt;
		break;
	case ATOMIC_SCNT_ALL:
		at = &g_smgr->all;
		break;
	case ATOMIC_CURRENT_TIME:
		at = &g_current_time;
		break;
	default:
		break;
	}

	if (at) {
		val = atomic_read(at);
	}

	return val;
}

void* seq_opt_tab_start(struct seq_file *s, loff_t *pos)
{
	ENT_FUNC(3);

	if (*pos == 0) {
		// 이경우는 read을 시작 한 시점이다.
		// 그러므로 show()함수에서 헤더 라인 같이
		// 처음 한번 해야 할 경우를 위해서 1을 반환 한다.
		*pos = (loff_t)SEQ_START_TOKEN;
	}

	if (*pos >= sizeofa(ns_options))
		return NULL;

	return (void*)(u_long)(*pos);
}

void* seq_opt_tab_next(struct seq_file *s, void *v, loff_t *pos)
{
	ENT_FUNC(3);

	(*pos)++;

	if (*pos >= sizeofa(ns_options))
		return NULL;

	return (void*)(u_long)*pos;
}

void seq_opt_tab_stop(struct seq_file *s, void *v)
{
	ENT_FUNC(3);
}

int32_t seq_opt_tab_show(struct seq_file *s, void *v)
{
	u_long i;
	uint32_t val;
	char mode[32];

	i = (u_long)v;

	// first time
	if ( i == 1) {
		// title
		seq_printf(s, "%-3s %-24s %-5s %-10s %-7s %-10s %-16s %-16s %s\n",
				"Idx", "Name", "Mode", "Val", "Min", "Max", "List", "Group", "Desc");

		//return 0;
	}

	i--;

	if (i >= sizeofa(ns_options))
		return 0;

	if (ns_options[i].mode & O_A) {
		int32_t idx = (int32_t)ns_options[i].val;
		val = proc_get_atomic_value(idx);
	}
	else {
		val = (uint32_t)ns_options[i].val;
	}

	sprintf(mode, "%s%s",
			(ns_options[i].mode & O_U)?"U":"",
			(ns_options[i].mode & (O_R|O_A))?"RO":"RW");

	seq_printf(s, "%-3d %-24s %-5s %-10u %-7u %-10u %-16s %-16s %s\n",
			ns_options[i].msg_id+1,
			ns_options[i].name,
			mode,
			val,
			ns_options[i].min,
			ns_options[i].max,
			//ns_get_vlist(ns_options[i].msg_id),
			//ns_get_group(ns_options[i].msg_id),
			"",
			"",
			nls_get_msg(ns_options[i].msg_id)
			);

	return 0;
}

char* nls_get_msg(uint32_t id)
{

	return "";
}

int32_t show_atomic(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	size_t len, tmplen=0;
	char buf[256];
	ulong idx;
	uint32_t val;

	if (!table->data || !table->maxlen || !*lenp ||
		(*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write)
		return 0;

	len = 0;
	idx = (ulong)table->data;
	val = proc_get_atomic_value(idx);
	tmplen = sprintf(buf, "%u\n", val);

	if (copy_to_user(buffer, buf, tmplen)){
		return -EFAULT;
	}

	len += tmplen;

	*lenp = len;
	*ppos += len;

	return 0;
}

int32_t show_version(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	size_t len;
	char buf[30];

	if (!table->data || !table->maxlen || !*lenp ||
		(*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write)
		return 0;

	len = sprintf(buf, "V%d.%d%s",
#ifdef CONFIG_NS_DEBUG
			 NETSHIELD_VERSION_MAJ, NETSHIELD_VERSION_MIN, "-Debug\n");
#else
			 NETSHIELD_VERSION_MAJ, NETSHIELD_VERSION_MIN, "\n");
#endif

	if (copy_to_user(buffer, buf, len)){
		return -EFAULT;
	}

	*lenp = len;
	*ppos += len;

	return 0;
}

int32_t show_session_state(ctl_table_t *table, int32_t write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	size_t len, tmplen;
	char buf[256];

	if (!table->data || !table->maxlen || !*lenp ||
		(*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write)
		return 0;

	len = 0;
	tmplen = sprintf(buf, "All:%d Mine:%d Remote:%d Local:%d \n", 
					  atomic_read(&g_smgr->all),
					  atomic_read(&g_smgr->mine) - atomic_read(&g_smgr->local),
					  atomic_read(&g_smgr->remote),
					  atomic_read(&g_smgr->local)
					  );

	if (copy_to_user(buffer, buf, tmplen)){
		return -EFAULT;
	}

	len += tmplen;

	*lenp = len;
	*ppos += len;

	return 0;
}

///////////////////////////////////////////////////////////////

ctl_table_t* create_sysctl_table(void)
{
	ctl_table_t* tab;
	int32_t i;
	int32_t tab_size;

	tab_size = sizeofa(ns_options);
	tab = ns_malloc_kz(sizeof(ctl_table_t) * tab_size);
	if (tab == NULL)
		return NULL;

	for (i=0; i<tab_size; i++) {
		tab[i].procname = ns_options[i].name;

		if (tab[i].procname == NULL) {
			continue;
		}

		tab[i].maxlen = sizeof(int32_t);
		tab[i].proc_handler = ns_options[i].hproc;
		tab[i].data = &ns_options[i].val;
		tab[i].mode = MODE_RO;
		tab[i].extra1= &ns_options[i].min;
		tab[i].extra2= &ns_options[i].max;

		if (ns_options[i].mode & O_A) {
			tab[i].data = (void*)ns_options[i].val;
		}
		else if (ns_options[i].mode & O_W) {
			tab[i].mode = MODE_RW;
		}
	}

	return tab;
}

/////////////////////////////////////////////////////////////

void ns_register_proc(void)
{
	ctl_table_t *sysctl_opts;

	ns_init_proc_sys();
	sysctl_opts = create_sysctl_table();
	ns_sysctl_root[0].child = sysctl_opts;

	ns_register_sysctl_table(ns_sysctl_root);

#ifdef CONFIG_NS_DEBUG
	dbgctl_register_proc();
#endif

	// seq file system은 sysctl 보다 나중에 등록 되어야 한다.
	ns_register_seq_proc(seq_proc_tab);

}

void ns_unregister_proc(void)
{
	ns_unregister_seq_proc(seq_proc_tab);

#ifdef CONFIG_NS_DEBUG
	dbgctl_unregister_proc();
#endif

	ns_unregister_sysctl_table(ns_sysctl_root);

	ns_free(ns_sysctl_root[0].child);

	ns_clean_proc_sys();

}

