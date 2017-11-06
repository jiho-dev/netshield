#ifndef __NS_TIMER_H__
#define __NS_TIMER_H__

#define MAX_TIMEOUT 	86400	// 1 day in seconds
#define BASE_START_TIME 5000

extern atomic_t g_current_time;

typedef struct nstimer_s {
	hlist_node_t tm_hlist;
	spinlock_t 	lock;

	uint32_t    timeout;
	uint32_t	timestamp;

	uint16_t 	bktidx;
	uint16_t 	dummy;

} __attribute__((packed, aligned(4))) nstimer_t;


#ifdef __KERNEL__
static inline uint32_t nstimer_get_time(void)
{
	return (uint32_t)atomic_read(&g_current_time);
}

static inline uint32_t nstimer_inc_time(void)
{
	return (uint32_t)atomic_inc_return(&g_current_time);
}
#endif


//////////////////////////////////////////////////////

int32_t nstimer_ageing(void);
int32_t nstimer_change_timeout(nstimer_t* tnode, uint32_t new_time);
int32_t nstimer_init(void);
void 	nstimer_clean(void);
int32_t nstimer_insert(nstimer_t* new, uint32_t timeout);
void 	nstimer_remove(nstimer_t* tnode);
int32_t nstimer_get_timeout(uint32_t cur_time, uint32_t timeout, uint32_t timestamp);


#endif
