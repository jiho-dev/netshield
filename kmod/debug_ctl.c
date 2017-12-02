#include <include_os.h>

#include <typedefs.h>
#include <session.h>
#include <ns_macro.h>
#include <commands.h>
#include <ns_sysctl.h>
#include <misc.h>
#include <options.h>
#include <ns_malloc.h>
#include <ns_sysctl.h>
#include <debug_ctl.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

int32_t dbgctl_seq_proc_open(struct inode *inode, struct file *file);
void* 	dbgctl_seq_start(struct seq_file *s, loff_t *pos);
void* 	dbgctl_seq_next(struct seq_file *s, void *v, loff_t *pos);
void 	dbgctl_seq_stop(struct seq_file *s, void *v);
int32_t dbgctl_seq_show(struct seq_file *s, void *v);
int 	proc_do_pkt(ctl_table_t *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos);
void MurmurHash3_x86_32(const void *key, int len, uint32_t seed, void *out);

//////////////////////////////////////////////////////

extern debug_file_lev_t 	dbg_file_lev[];
extern debug_func_list_t	dbg_flist[];
extern int32_t 			dbg_file_lev_size;
extern int32_t 			dbg_flist_size;
ctl_table_t 			*dbgctl_tables;
static int32_t 			init_done=0;

ctl_table_t dbgctl_opt[] = {
	{
		.procname = "debug", 	
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

// for option table
seqops_t seq_dbgctl_ops = {
	.start = dbgctl_seq_start,
	.next = dbgctl_seq_next,
	.stop = dbgctl_seq_stop,
	.show = dbgctl_seq_show,
};


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */


void* dbgctl_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos == 0) {
		// 이경우는 read을 시작 한 시점이다.
		// 그러므로 show()함수에서 헤더 라인 같이 
		// 처음 한번 해야 할 경우를 위해서 1을 반환 한다.
		*pos = (loff_t)SEQ_START_TOKEN;
	}

	if (*pos > dbg_file_lev_size)
		return NULL;

	return (void*)(u_long)(*pos);
}

void* dbgctl_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;

	if (*pos > dbg_file_lev_size)
		return NULL;

	return (void*)(u_long)*pos;
}

void dbgctl_seq_stop(struct seq_file *s, void *v)
{
}

int32_t dbgctl_seq_show(struct seq_file *s, void *v)
{
	u_long i;

	i = (u_long)v;

	if (i == 1) {
		// first time
		seq_printf(s, "File Name       Level  \n");
		//return 0;
	}

	i --;

	if (i < dbg_file_lev_size) {
		seq_printf(s, "%-15.*s %-7d\n",
				   15, dbg_file_lev[i].name, 
				   *dbg_file_lev[i].level);
	}

	return 0;
}

int dbgctl_all_proc(ctl_table_t *table, int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{

	size_t len, tmp_len;
	char buf[256];
	debug_file_lev_t *flev;

	if (!table->data || !table->maxlen || !*lenp ||
		(*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	flev = (debug_file_lev_t*)table->data;

	if (write) {
		int i;

		table->data = flev->level;
		proc_dointvec(table, write, buffer, lenp, ppos);
		table->data = flev;

		for (i=0; i<dbg_flist_size; i++) {
			if (strcmp(dbg_flist[i].file, flev->name) == 0) {
				printk("change debug level for %s: %d -> %d \n", dbg_flist[i].func, dbg_flist[i].level, *flev->level);
				dbg_flist[i].level = *flev->level;
			}
		}

		return 0;
	}

	len = 0;

	tmp_len = sprintf(buf, "%d\n", *flev->level);

	if (copy_to_user(buffer, buf, tmp_len)){
		return -EFAULT;
	}

	len += tmp_len;
	*lenp = len;
	*ppos += len;

	return 0;
}

//////////////////////////////////////////////////////////
#define DBG_FN_HASH_BUK 	1023

struct list_head fn_bucket[DBG_FN_HASH_BUK];


////////////////////////////////////


inline uint32_t dbgctl_fn_hash(char* key, int32_t size)
{
	uint32_t hash;

	MurmurHash3_x86_32((const void *)key, size, 0x43606326, &hash);

	return (hash % DBG_FN_HASH_BUK);
	
}

debug_func_list_t* dbgctl_lookup_fn(char *fn_name)
{
	uint32_t hash;
	struct list_head* head;
	int32_t len;
	debug_func_list_t* fn;

	len = strlen(fn_name);
	hash = dbgctl_fn_hash(fn_name, len);

	head = &fn_bucket[hash];

	list_for_each_entry(fn, head, list) {

		if (strcmp(fn->func, fn_name) == 0) {
			return fn;
		}
	}

	return NULL;
}

int32_t dbgctl_add_fn(debug_func_list_t* fn)
{
	int32_t len;
	uint32_t hash;

	len = strlen(fn->func);
	hash = dbgctl_fn_hash(fn->func, len);
	list_add_tail(&fn->list, &fn_bucket[hash]);

	return 0;
}


//////////////////////////////////////////////////////

int dbgctl_get_fn_count(char* file_name)
{
	int i;
	int fcnt=0;

	for (i=0; i<dbg_flist_size; i++) {

		if (strcmp(dbg_flist[i].file, file_name) == 0)
			fcnt ++;
	}

	return fcnt;
}

debug_func_list_t* dbgctl_get_fn_level(char* func_name)
{
	int i;

	for (i=0; i<dbg_flist_size; i++) {

		if (strcmp(dbg_flist[i].func, func_name) == 0)
			return &dbg_flist[i];
	}

	return NULL;
}

debug_file_lev_t* dbgctl_find_file_level(char* name)
{
	int32_t i;

	for (i=0; i<dbg_file_lev_size; i++) {
		if (strcmp(dbg_file_lev[i].name, name) == 0)
			return &dbg_file_lev[i];
	}

	return NULL;
}

void dbgctl_init_all_node(debug_file_lev_t* file_lev, ctl_table_t* tab, int32_t cnt)
{
	tab[0].procname = "all";
	tab[0].data = file_lev;
	tab[0].maxlen = sizeof(int32_t);
	tab[0].mode = MODE_RW;
	tab[0].proc_handler = &dbgctl_all_proc;
	tab[0].child = NULL;

	// terminate
	tab[cnt-1].procname = 0;
}

int32_t dbgctl_create_child_tab(void)
{
	ctl_table_t* tab=NULL;
	int32_t fcnt=0,i;
	debug_file_lev_t *file_lev;

	// 각 파일 별로 함수 갯수 만큼 ctl_table_t을 만들어서 메모리를 준비 한다.
	for (i=0; i<dbg_file_lev_size; i++) {
		fcnt = dbgctl_get_fn_count(dbg_file_lev[i].name);

		tab = NULL;
		tab =  ns_malloc_kz(sizeof(ctl_table_t) * (fcnt+2));
		// 초기화 한다.
		// 여기서 all node가 생성 된다.
		dbgctl_init_all_node(&dbg_file_lev[i], tab, fcnt+2);

		dbg_file_lev[i].tab =  tab;
		dbg_file_lev[i].cnt = fcnt;
		dbg_file_lev[i].idx = 1;
	}

	fcnt = dbg_flist_size;

	for (i=0; i<fcnt; i++) {
		file_lev = dbgctl_find_file_level(dbg_flist[i].file);
		if (file_lev == NULL)
			continue;

		INIT_LIST_HEAD(&dbg_flist[i].list);
		dbg_flist[i].parent = file_lev;
		// function의 초기 레벨은 파일 레벨이다.
		dbg_flist[i].level = *file_lev->level;

		if (file_lev->tab == NULL)
			continue;

		dbgctl_add_fn(&dbg_flist[i]);

		tab = &file_lev->tab[file_lev->idx];

		tab->procname = dbg_flist[i].func;
		tab->data = &dbg_flist[i].level;
		tab->maxlen = sizeof(int32_t);
		tab->mode = MODE_RW;
		tab->proc_handler = &proc_dointvec;
		tab->child = NULL;

		file_lev->idx ++;
	}

	return 0;
}

ctl_table_t* dbgctl_create_table(void)
{
	ctl_table_t* tab;
	int32_t i;
	int32_t tab_size;

	dbgctl_create_child_tab();

	// for end of table
	tab_size = dbg_file_lev_size;

	tab = ns_malloc_kz(sizeof(ctl_table_t) * (tab_size+1));
	if (tab == NULL)
		return NULL;

	for (i=0; i<tab_size; i++) {

		tab[i].procname = dbg_file_lev[i].name;
		tab[i].data = NULL;//dbg_file_lev[i].level;
		tab[i].maxlen = 0;//sizeof(int32_t);
		tab[i].mode = MODE_RW;
		tab[i].proc_handler = NULL;//&proc_dointvec;
		tab[i].child = dbg_file_lev[i].tab;
	}

	// end of table
	tab[i].procname = 0;

	return tab;
}
        
void dbgctl_register_proc(void)
{
	int32_t i;

	for (i=0; i<DBG_FN_HASH_BUK; i++) {
		INIT_LIST_HEAD(&fn_bucket[i]);
	}

	dbgctl_tables = dbgctl_create_table();
	dbgctl_opt[0].child = dbgctl_tables;

	ns_register_sysctl_table(dbgctl_opt);

	init_done = 1;
}

void dbgctl_unregister_proc(void)
{
	int32_t i;

	init_done = 0;

	ns_unregister_sysctl_table(dbgctl_opt);

	if (dbgctl_tables) {
		for (i=0; i<dbg_file_lev_size; i++) {
			if (dbgctl_tables[i].child)
				ns_free(dbgctl_tables[i].child);
		}

		ns_free(dbgctl_tables);
	}
}

//////////////////////////////////////////

int32_t dbgctl_compare_level(int32_t file_level, char* func, int32_t f_level)
{
	debug_func_list_t *f;

	if (file_level <= 0)
		return 0;

	if (init_done)
		f = dbgctl_lookup_fn(func);
	else
		f = dbgctl_get_fn_level(func);

	if (f == NULL)
		return 0;

	if (f->level >= f_level) {
		return 1;
	}

	return 0;
}

