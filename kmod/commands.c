#include <include_os.h>

#include <ns_type_defs.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <smgr.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <commands.h>
#include <log.h>
#include <extern.h>
#include <version.h>
#include <misc.h>
#include <inline.h>
#include <options.h>
#include <khypersplit.h>
#include <pmgr.h>
#include <ns_ioctl.h>


//////////////////////////////////////////////////////

struct timer_list	g_kernel_timer;
DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

extern int32_t parse_inet_protocol(ns_task_t *nstask);
extern int32_t init_task_info(ns_task_t *nstask);
extern int32_t frag_main(ns_task_t *nstask);
void ns_register_proc(void);
void ns_unregister_proc(void);

//////////////////////////////////////////////////////

/*** *INDENT-OFF* ***/
nscmd_module_t nscmd_module_list[] __read_mostly =
{
	//  name            short_name  run                 init                clean           age
	CMD_ITEM(nsdev,      NSDEV,      NULL,              nsdev_init,         nsdev_clean,    NULL),
	CMD_ITEM(timer,      TIMER,      NULL,              nstimer_init,       nstimer_clean,  nstimer_ageing),
	CMD_ITEM(inet,       IN,         parse_inet_protocol,NULL,               NULL,           NULL),
	CMD_ITEM(tinfo,      TI,         init_task_info,     NULL,               NULL,           NULL),
	CMD_ITEM(frag,       FR,         frag_main,          NULL,               NULL,           NULL),
	CMD_ITEM(smgr_fast,	SMGR_FAST, 	smgr_fast_main,  	smgr_init,           smgr_clean,     NULL),
	CMD_ITEM(smgr_slow, SMGR_SLOW,  smgr_slow_main,    	NULL,    		       NULL,     NULL),
	CMD_ITEM(smgr_timeout,SMGR_TIMEOUT,smgr_timeout,    NULL,               NULL,           NULL),
	CMD_ITEM(pmgr, 		PMGR_MAIN, 	pmgr_main,         pmgr_init,           pmgr_clean,     NULL),

	[NS_CMD_MAX] = {.name=NULL, .short_name= NULL, .run=NULL, .init=NULL, .clean=NULL, .age=NULL}

};

/*** *INDENT-ON* ***/


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

int32_t nscmd_append(nscmd_t* c, uint8_t cmd)
{
	int8_t next = (c->tail + 1) % MAX_CMDS;

	if (c->head == next) {
		ns_err("The NetShield cmd stack is overflowed. head=%d, tail=%d", c->head, c->tail);
		return -1;
	}

	c->tail = next;
	c->stack[c->tail] = cmd;

	return 0;
}

int32_t nscmd_prepend(nscmd_t* c, uint8_t cmd)
{
	int8_t prev = (c->head -1) % MAX_CMDS;

	if (c->tail == prev) {
		ns_err("The NetShield cmd stack is underflowed. head=%d, tail=%d", c->head, c->tail);
		return -1;
	}

	// pop시에는 head를 증가한 다음 데이터를 가져가므로
	// 현재의 head 포인터는 old 포인터이다.
	// 그러므로 현재 포인터에 넣고 head를 감소해야 한다.
	c->stack[c->head] = cmd;
	c->head = prev;

	return 0;
}

nscmd_module_t* nscmd_pop(nscmd_t* c)
{
	uint8_t cmd;

	if (c->head == c->tail) {
		DBG(4, "The NetShield cmd stack is empty. head=%d, tail=%d", c->head, c->tail);
		return NULL;
	}

	c->head = (c->head + 1) % MAX_CMDS;
	cmd = c->stack[c->head];

	return &nscmd_module_list[cmd];
}

////////////////////////////////////

void nscmd_callback_timer(unsigned long data)
{
	int32_t i;
	uint32_t t;
	nscmd_module_t* c;

	// 기준 시간을 증가 한다.
	t = nstimer_inc_time();

	for (i=0; i<NS_CMD_MAX; i++) {
		c = &nscmd_module_list[i];
		if (!c->age)
			continue;

		c->age();
	}

	// run on every minute
	if (t > 60 && (t % 60) == 0) {
	}

	g_kernel_timer.expires  = jiffies + (HZ*GET_OPT_VALUE(age_interval));
	add_timer(&g_kernel_timer);
}

char* nscmd_get_module_short_name(int32_t id)
{
	if (id < 0 || id >= NS_CMD_MAX) 
		return NULL;

	return nscmd_module_list[id].short_name;
}

int32_t nscmd_run_command(ns_task_t *nstask)
{
	int32_t ret = NS_ACCEPT;
	nscmd_module_t *cmd = NULL;
	session_t *si;

	ENT_FUNC(3);

	while ((cmd = nscmd_pop(&nstask->cmd)) != NULL) {
		DBG(5, "Run module: %s", cmd->name);

		if (cmd->run == NULL) {
			continue;
		}

		ret = cmd->run(nstask);

		if (ret == NS_ACCEPT) {
			continue;
		}
		else if (ret == NS_QUEUE) {
			// ns_task_t is stored into wait_list by wthread
			FUNC_TEST_MSG(4, "Queued by : %s", cmd->name);

			break;
		}
		else if (ret == NS_STOLEN) {
			// error or something
			DBG(5, "Stolen by : %s", cmd->name);
			break;
		}
		else if (ret == NS_DROP || ret == NS_DEL_SESSION) {
			FUNC_TEST_MSG(4, "Droped by : %s", cmd->name);
			break;
		}
		else if (ret == NS_STOP) {
			ret = NS_ACCEPT;
			break;
		}
		else {
			DBG(0, "Unknown result : module=%s, ret=%d", cmd->name, ret);
		}
	}

	// and then, finalize packet
	if (ret == NS_STOLEN || ret == NS_QUEUE) {
		return ret;
	}

	si = nstask->si;

#if 0
	// ACCEPT/DROP 모두 통계 생성
	if (GET_OPT_VALUE(wst)) {
		wst_main(nstask, ret);
	}
#endif

	if (likely(nstask->si)) {
		session_release(nstask->si);
		nstask->si = NULL;
	}

	if (ret == NS_DEL_SESSION) {
		if (si) {
			smgr_delete_session(si, 0);
		}

		ret = NS_DROP;
	}

	return ret;
}

int32_t nscmd_init_module(void)
{
	int32_t i;
	nscmd_module_t* c;

	// 1. 각 컴퍼넌트 초기화
	// 모든 모듈의 초기화는 여기서 수행 한다.

	for (i=0; i<NS_CMD_MAX; i++) {
		c = &nscmd_module_list[i];
		if (!c->init)
			continue;

		if (c->init()) {
			return -1;
		}
	}
	
	// 2. timer 등록
	init_timer(&g_kernel_timer);

	g_kernel_timer.expires  = jiffies + (HZ*GET_OPT_VALUE(age_interval));
	g_kernel_timer.data     = 0;
	g_kernel_timer.function = &nscmd_callback_timer;

	add_timer(&g_kernel_timer);

	// 3. sysctl 관련 등록
	ns_register_proc();

	return 0;
}

void nscmd_clean_module(void)
{
	int32_t i;
	nscmd_module_t* c;

	// 1. sysctl 제거
	ns_unregister_proc();

	// 2. timer 제거
	del_timer(&g_kernel_timer);

	// 3. 각 컴퍼넌트 제거

	for (i=NS_CMD_MAX-1; i>=0; i--) {

		c = &nscmd_module_list[i];
		if (!c->clean)
			continue;

		c->clean();
	}
}
