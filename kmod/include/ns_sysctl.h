#ifndef _NS_SYSCT_H__
#define _NS_SYSCT_H__


#define MODE_RW 		0644
#define MODE_RO 		0444

#define O_N 			0x00000000
#define O_W				0x00000001 		// read/write
#define O_R 			0x00000002 		// read only
#define O_A 			0x00000004 		// atomic read only
#define O_U				0x00000010 		// user accessable


typedef struct _seq_proc_s {
	char 			*name;
	void 			*seq_op;
	void 			*data;
} seq_proc_t;

/////////////////////////////////////////////////


int32_t ns_init_proc_sys(void);
void 	ns_clean_proc_sys(void);
int32_t ns_register_sysctl_table(ctl_table_t *table);
void 	ns_unregister_sysctl_table(struct ctl_table *table);
void 	ns_register_seq_proc(seq_proc_t* big_tab);
void 	ns_unregister_seq_proc(seq_proc_t* seqtab);

#endif
