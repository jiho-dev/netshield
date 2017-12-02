#ifndef __NS_COMMAND_H__
#define __NS_COMMAND_H__

#include <ns_task.h>

typedef void 	(*CB_TYPE0)(void);
typedef int32_t (*CB_TYPE1)(void);
typedef int32_t (*CB_TYPE2)(ns_task_t*);

#define NSCMD_IDX(x)			NSCMD_IDX_##x
#define CMD_ITEM(n,s,r,i,c,a)  \
	[NSCMD_IDX(n)] =  {.name=__STR(n), .short_name=__STR(s), .init=i, .clean=c, .age=a, .run=r}

#define append_cmd(n, c)  nscmd_append(&((n)->cmd), NSCMD_IDX(c));
#define prepend_cmd(n, c)  nscmd_prepend(&((n)->cmd), NSCMD_IDX(c));

typedef struct nscmd_module_s {
	char* 		name;
	char* 		short_name;
	CB_TYPE1	init;
	CB_TYPE0	clean;
	CB_TYPE1	age;
	CB_TYPE2	run;
} nscmd_module_t;

// command 를 추가 할때 추가 해야 함.
enum nscmd_index{
	NSCMD_IDX(frag),
	NSCMD_IDX(inet),
	NSCMD_IDX(tinfo),

	NSCMD_IDX(smgr_fast),
	NSCMD_IDX(smgr_slow),
	NSCMD_IDX(smgr_timeout),

	NSCMD_IDX(pmgr),
	NSCMD_IDX(nsdev),
	NSCMD_IDX(timer),
	NSCMD_IDX(nat),
	NSCMD_IDX(arpp),

	NS_CMD_MAX
};

//////////////////////////////////////////////////////

extern nscmd_module_t		nscmd_module_list[];

//////////////////////////////////////////////////////

char* 	nscmd_get_module_short_name(int32_t id);
int32_t nscmd_init_module(void);
void 	nscmd_clean_module(void);
int32_t nscmd_append(nscmd_t* c, uint8_t cmd);
int32_t nscmd_prepend(nscmd_t* c, uint8_t cmd);
nscmd_module_t* nscmd_pop(nscmd_t* c);

#endif
