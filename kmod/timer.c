#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <timer.h>
#include <session.h>
#include <hashed_llist.h>
#include <smgr.h>

#define MAX_AGING			3607
//#define MAX_AGING			61  	// for testing and debugging

//////////////////////////////////////////////////////

atomic_t g_current_time;
hll_t	g_timer_htable[MAX_AGING];
int32_t	g_mismatch_bktidx=0;

DECLARE_DBG_LEVEL(2);
extern uint32_t 	netshield_running;


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

uint32_t nstimer_get_bucket_index(uint32_t t)
{
	return t % MAX_AGING;
}

hll_t* nstimer_get_bucket(uint32_t idx)
{
	return &g_timer_htable[nstimer_get_bucket_index(idx)];
}

void nstimer_set_timeout(nstimer_t *tnode, uint32_t t)
{
	tnode->timeout = t;
}

void nstimer_set_timestamp(nstimer_t *tnode, uint32_t t)
{
	tnode->timestamp	= t;
}

int32_t nstimer_unlink(nstimer_t *tnode)
{
	hll_t *h;

	if (hlist_unhashed(&tnode->tm_hlist)) {
		// Timeout에 의해서 삭제 되는 경우 Timer List에서 삭제되어 있다.
		return -1;
	}

	h = nstimer_get_bucket(tnode->bktidx);

	ns_rw_lock_irq(&h->lock) {
		hlist_del_rcu(&tnode->tm_hlist);
		INIT_HLIST_NODE(&tnode->tm_hlist);
		atomic_dec(&h->count);
	} ns_rw_unlock_irq(&h->lock);

	return 0;
}

int32_t nstimer_link(nstimer_t *tnode, uint32_t offset)
{
	hll_t *h;

	if (!hlist_unhashed(&tnode->tm_hlist)) {
		return -1;
	}

	h = nstimer_get_bucket(offset);

	ns_rw_lock_irq(&h->lock) {
		hlist_add_head_rcu(&tnode->tm_hlist, &h->head);
		tnode->bktidx = nstimer_get_bucket_index(offset);
		atomic_inc(&h->count);
	} ns_rw_unlock_irq(&h->lock);

	return 0;
}

int32_t nstimer_move(nstimer_t* tnode, uint32_t current_time, uint32_t offset)
{
	session_t *si = NULL;

	ENT_FUNC(3);

	si = container_of(tnode, session_t, timer);
	offset += current_time;

	if (!hlist_unhashed(&tnode->tm_hlist)) {
		// 매달려 있는데, 재삽입 위치가 동일 위치이면..
		if (tnode->bktidx == nstimer_get_bucket_index(offset)) {
			dbg(9, "Try to insert into same pos : pos=%u, bktidx=%u", 
				nstimer_get_bucket_index(offset), tnode->bktidx);
			return 1;
		}

		if (nstimer_unlink(tnode)) {
			DBG_CALLER(0);
		}
	}

	if (nstimer_link(tnode, offset)) {
		DBG_CALLER(0);
	}

	return 0;
}

nstimer_t* nstimer_pop(hll_t *hll, uint32_t cur_time)
{
	hlist_head_t *head = &hll->head;
	hlist_node_t *hnode;
	nstimer_t *tnode = NULL;
	int32_t loop_cnt=0, all_cnt;

	while (1) {
		if (hlist_empty(head)) {
			return NULL;
		}

		all_cnt = atomic_read(&hll->count);
		if (all_cnt <= 0) {
			dbg(0, "Empty bucket: time=%u, count=%d, first=0x%p", 
				cur_time, atomic_read(&hll->count), hll->head.first);
			return NULL;
		}

		ns_rd_lock_irq() {
			hnode = rcu_dereference(head->first);
		} ns_rd_unlock_irq();

		if (hnode == NULL) {
			return NULL;
		}

		loop_cnt ++;

		if (loop_cnt > all_cnt) {
			dbg(0, "Out of loop count: time=%u, count=%d, loop=0x%d, first=0x%p", 
				cur_time, atomic_read(&hll->count), loop_cnt, head->first);
			return NULL;
		}

		tnode = container_of(hnode, nstimer_t, tm_hlist);

		// nstimer_change_timeout()과 경쟁해서 잡는다.
		if (!ns_rw_trylock_irq(&tnode->lock)) {
			// 다른데서 사용중이다.
			dbg(5, "Can't grab tnode:tnode=0x%p, locked=0x%x, all=%d, loop=%d, solt_idx=%d, cur=%d", 
				tnode, spin_is_locked(&tnode->lock), all_cnt, loop_cnt, tnode->bktidx, cur_time);

			tnode = NULL;
		} 
		else if (tnode->bktidx != nstimer_get_bucket_index(cur_time)) {
			dbg(9, "Different bucket:tnode=0x%p bktidx=%u, cur=%u:%d", 
				tnode, tnode->bktidx, cur_time, nstimer_get_bucket_index(cur_time));

			g_mismatch_bktidx ++;

			// XXX: 현재 bucket에 있으므로, bktidx는 무시하고 bucket에서 꺼낸다.
			ns_rw_lock_irq(&hll->lock) {
				hlist_del_rcu(&tnode->tm_hlist);
				INIT_HLIST_NODE(&tnode->tm_hlist);
				atomic_dec(&hll->count);
				tnode->bktidx = nstimer_get_bucket_index(cur_time);
			} ns_rw_unlock_irq(&hll->lock);

			return tnode;
		}
		else if (nstimer_unlink(tnode)) {
			session_t *si = NULL;
			int32_t refcnt = 0;

			si = container_of(tnode, session_t, timer);
			refcnt = atomic_read(&si->refcnt);

			dbg(0, "Cant' unlink: first=0x%p, refcnt=%d, si->flags=0x%x", 
				hll->head.first, refcnt, si->flags);

			ns_rw_unlock_irq(&tnode->lock);

		}
		else {
			return tnode;
		}
	}

	return NULL;
}

/////////////////////////////////////////////////

int32_t nstimer_get_lifetime(uint32_t cur_time, uint32_t timeout, uint32_t timestamp)
{
	int32_t age;

	// 시간이 2^32 값을 넘어서 리셋 됨.
	if (cur_time < timestamp) {
		DBG_CALLER(0);

		age = timeout - ((~0 - timestamp) + cur_time);

		dbg(0, "overflow timer bucket: cur_time=%u, timestamp=%u, bktidx=%u", 
			cur_time, timestamp, nstimer_get_bucket_index(cur_time));
	}
	else {
		age = timeout - (cur_time - timestamp);
	}

	return age;
}

int32_t nstimer_insert(nstimer_t* new, uint32_t timeout)
{
	session_t* si = NULL;
	uint32_t t;

	ENT_FUNC(3);

	si = container_of(new, session_t, timer);
	session_hold(si);

	if (timeout > MAX_TIMEOUT)
		timeout = MAX_TIMEOUT;

	INIT_HLIST_NODE(&new->tm_hlist);
	ns_init_lock(&new->lock);

	t = nstimer_get_time();
	nstimer_set_timeout(new, timeout);
	nstimer_set_timestamp(new, t);

	if (si->born_time != t) {
		// 생성 시간과 timestamp를 설정하는 시간이 다를 수 있다.
		si->born_time = t; 		
	}

	nstimer_move(new, t, timeout);

	dbg(9, "si=0x%p, lft=0x%p, cur_time=%u, timeout=%u, timestampe=%u", 
		si, new, t, timeout, new->timestamp);

	return 0;
}

void nstimer_remove(nstimer_t* tnode)
{
	session_t* si = NULL;

	// disable this tnode
	si = container_of(tnode, session_t, timer);
	si->flags |= SFLAG_LFTF_EXPIRE;

	nstimer_unlink(tnode);
	session_release(si);
}

int32_t nstimer_change_timeout(nstimer_t* tnode, uint32_t new_timeout)
{
	uint32_t cur_time;
	session_t* si = NULL;
	int32_t ret = 0;

	ENT_FUNC(3);

	si = container_of(tnode, session_t, timer);

	if (si->flags & SFLAG_LFTF_EXPIRE) {
		dbg(9, "Not in Time table: tnode=0x%p, cpuid=%d, si->flag=0x%x, timeout=%u->%u, ref=%d", 
			tnode, smp_processor_id(), si->flags, tnode->timeout, new_timeout, atomic_read(&si->refcnt));

		return 0;
	}

	if (new_timeout > MAX_TIMEOUT)
		new_timeout = MAX_TIMEOUT;

	cur_time = nstimer_get_time();

	// 1초 단위 시간안에 수많은 패킷이 들어오는 경우...
	if (cur_time == tnode->timestamp 
		&& new_timeout == tnode->timeout) {
		return 0;
	}

	// cache update 방지...
	if (cur_time != tnode->timestamp) {
		nstimer_set_timestamp(tnode, cur_time);
		ret = 1;
	}

	// if new_timeout is zero, this session will not be expired.
	// So it is alive forever. See the fwr_t.timeout
	if (new_timeout == 0) {
		nstimer_set_timeout(tnode, 0);
		return ret;
	}

	// timeout이 변경이 없는 경우 노드를 욺기지 않음.
	// XXX: 노드를 옮기지 않는 경우 버킷안에 노드가 쌓여 있게 된다.
	//      그러면, 쌓인 노드를 처리 할때 패킷이 빠지는 증상이 있다.
	//      이를 해결하기 위해서는 매번 옳기는 건 어떨까나?
	if (new_timeout == tnode->timeout) {
		return ret;
	}

	nstimer_set_timeout(tnode, new_timeout);

	dbg(6, "After: timeout=%u, timestamp=%u",
		tnode->timeout, tnode->timestamp);

	// 경쟁해서 선점하는 경우에만 lft 관련 처리를 진행한다.
	// -. 여러 cpu에서 동시에 동일한 세션을 참조 해서 패킷을 처리 할 때
	// -. 패킷을 처리하는 cpu와 LFT timer를 처리하는 cpu간에 경쟁을 한다.
	if (!ns_rw_trylock_irq(&tnode->lock)) {
		dbg(5, "Treated by nstimer_main(): tnode=0x%p, locked=0x%x", tnode, spin_is_locked(&tnode->lock));
		return 0;
	}

	nstimer_move(tnode, cur_time, new_timeout);

	ns_rw_unlock_irq(&tnode->lock);

	return 2;
}

// 현재 tick time의 리스트를 검사하여 timeout인 리스트를 삭제한다.
int32_t nstimer_main(void)
{
	hlist_head_t *head;
	nstimer_t* tnode;
	int32_t lifetime;
	uint32_t del_cnt = 0, refcnt;
	uint32_t cur_time;
	uint32_t count = 0, all;
	session_t* si = NULL;
	hll_t *h;

	cur_time = nstimer_get_time();
	h = nstimer_get_bucket(cur_time);
	head = &h->head;
	all = atomic_read(&h->count);

	while (netshield_running) {
		tnode = nstimer_pop(h, cur_time);
		if (tnode == NULL)
			break;

		si = container_of(tnode, session_t, timer);
		refcnt = atomic_read(&si->refcnt);
		if (refcnt < 1) {
			dbg(0, "Abnormal tnode: 0x%p, flag=0x%x, refcnt=%d, curtime=%u", 
				si, si->flags, refcnt, cur_time);

			ns_rw_unlock_irq(&tnode->lock);
			continue;
		}

		// alive forever ?
		if (tnode->timeout == 0) {
			// move to previous bucket because of avoiding infinite loop
			nstimer_move(tnode, cur_time, MAX_AGING-1);
			ns_rw_unlock_irq(&tnode->lock);
			continue;
		}

		lifetime = nstimer_get_lifetime(cur_time, tnode->timeout, tnode->timestamp);

		dbg(6, "lft=0x%p, lastuse=%u, timeout=%u, cur_time=%u, lifetime=%d", 
			tnode, tnode->timestamp, tnode->timeout, cur_time, lifetime);

		// now, end of life
		if (lifetime <= 0) {
			if (si->flags & SFLAG_LFTF_EXPIRE) {
				if (refcnt >= 1) {
					dbg(0, "This tnode was still referenced: refcnt=%d", refcnt);
				}
				else {
					// INFO: 어떤 상황인지 잘 모르겠지만,
					// 이런 상황이 발생한다.
					// 이 노드는 매우 비정상적인 노드로 간주되어 아무런 처리도 하지 않는다.
					dbg(0, "This tnode expired already: si=0x%p, si->flags=0x%x, lifetime=%d, refcnt=%d", 
						si, si->flags, lifetime, atomic_read(&si->refcnt));
				}
			}
			else {
				// 삭제 예정이므로 세션 검색에서 제외 한다.
				si->flags |= SFLAG_LFTF_EXPIRE;
				smgr_delete_session(si, SMGR_DEL_SAVE_LOG);
				ns_rw_unlock_irq(&tnode->lock);

				del_cnt++;
			}
		}
		else {
			// move to previous bucket because of avoiding infinite loop
			if (tnode->bktidx == nstimer_get_bucket_index(cur_time + lifetime)) {
				dbg(5, "Move to previous bucket: cur_time=%d, lifetime=%d, bucket_idx=%d",
					cur_time, lifetime, tnode->bktidx);
				lifetime --;
			}

			nstimer_move(tnode, cur_time, lifetime);
			ns_rw_unlock_irq(&tnode->lock);
		}

		count++;
		if (count > (all+10)) {
			// 어떤 이유에서인지 모르지만,
			// 무한 loop를 도는 경우가 발생한다.
			// 정확한 이유를 파악하기 전까지 루프 횟수를 제한한다.
			dbg(0, "Out of max count: all=%u, count=%u, current_count=%u !!!!!", 
				all, count, atomic_read(&h->count));
			break;
		}
	} // end of while loop

	dbg(4, "all=%u, del_cnt=%u, count=%u, cur_node_cnt=%u",
		all, del_cnt, count, atomic_read(&h->count));

	return del_cnt;
}

int32_t nstimer_ageing(void) 
{
	int32_t ret = 0;

	g_mismatch_bktidx = 0;

	ret = nstimer_main();

	if (g_mismatch_bktidx) {
		dbg(0, "Mismatch Bucket Index: %d", g_mismatch_bktidx);
	}

	return ret;
}

int32_t nstimer_init(void)
{
	int32_t i;

	// g_current_time이 2^32 이 되었을때 문제점을 파악하기 위해서
	// 아래의 값을 설정 한다.
	//atomic_set(&g_current_time, ~0 - 20);

	// 그러나 값이 2^32에서 증가하여 0이 되었을때
	// 이 값을 이용하여 인덱스를 구하는 곳에서 문제가 생긴다.
	// 특히, nstimer_get_bucket_index()에서 2^32 일때의 idx와 0일때의 idx는 많이 차이가 난다.
	// 그러므로 ageing 인덱스가 바로 다음 값을 가질수 없는 문제가 있다.
	// 그러나 2^32초는 약 136년 이므로 overflow가 생기 가능성이 희박하다.
	//atomic_set(&g_current_time, 0);

	// 20130405 patrick
	// 세션 동기화시 전달 받은 세션의 timestamp를 계산하기 위해서는 
	// 현재 시간 보다 앞의 값을 사용해야 한다.
	// 그러므로 현재 시간이 0 부터 시작하면 현재 시간의 이전 값을 계산하기 어려워 진다.
	// 그래서 현재 시간을 5000초에서 시작 한다.
	atomic_set(&g_current_time, BASE_START_TIME);

	for (i = 0; i < MAX_AGING; i++) {
		INIT_HLIST_HEAD(&g_timer_htable[i].head);
		ns_init_lock(&g_timer_htable[i].lock);
		atomic_set(&g_timer_htable[i].count, 0);
	}

	return 0;
}

void nstimer_clean(void)
{

}

