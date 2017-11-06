#ifndef __HASH_LINKED_LIST_H
#define __HASH_LINKED_LIST_H


typedef struct _hash_linked_list {
	hlist_head_t head;
	spinlock_t 	lock;
	atomic_t 	count;
} hll_t;

////////////////////////////////////////////////////////////

#define HLL_DECLARE_TEMPLET(name, table, obj_type, member_name, \
							key_len, lookup_callback, destroy_callback) \
		\
		\
/* 해쉬 노드를 구한다. */ 		\
hll_t* name##_get_hash_slot(const char *key, uint32_t *hash) \
{ \
	uint32_t idx; \
	idx = MurmurHash3_x86_32(key, key_len, 0) % sizeofa(table); \
	if (hash) \
		*hash = idx; \
	return &table[idx]; \
} 		\
		\
		\
/* 해쉬 테이블을 초기화 한다. */ 		\
int32_t name##_init_table(void) \
{ \
	int32_t i; \
	for (i=0; i<sizeofa(table); i++) {  \
		INIT_HLIST_HEAD(&table[i].head); \
		ns_init_lock(&table[i].lock); \
		atomic_set(&table[i].count, 0); \
	} \
	return 0; \
} 		\
		\
		\
/* 해쉬 테이블 데이터를 삭제 한다. */ 		\
void name##_destroy(struct rcu_head *head) \
{ \
	obj_type *_obj; \
	_obj = container_of(head, obj_type, rcu); \
	if (_obj) { \
		if (destroy_callback(_obj)) \
			wfree(_obj); \
	} \
} 		\
		\
		\
/* 참조 카운트를 증가 한다. */ \
void name##_hold(obj_type *obj) \
{ \
	if (obj) \
		atomic_inc(&obj->refcnt); \
}		\
		\
		\
/* 참조 카운트를 감소하고 0이면 삭제 한다. */ \
void name##_release(obj_type *obj) \
{ \
	if (obj != NULL && atomic_dec_and_test(&obj->refcnt)) { \
		call_rcu(&obj->rcu, name##_destroy); \
	} \
}		\
		\
		\
/* 해쉬 테이블의 모든 객체를 삭제 한다. */ \
void name##_clean_table(void) \
{ \
	int32_t i; \
	struct hlist_head *head; \
	struct hlist_node *pos; \
	obj_type *_obj=NULL; \
	hll_t *hh; \
	for (i = 0; i < sizeofa(table); i++) { \
		hh = &table[i]; \
		head = &hh->head; \
		ns_rw_lock_irq(&hh->lock) { \
			hlist_for_each_entry_safe(_obj, pos, head, member_name) { \
				hlist_del_rcu(&_obj->member_name); \
				name##_release(_obj); \
				/*call_rcu(&_obj->rcu, name##_destroy);*/  \
			} \
		} ns_rw_unlock_irq(&hh->lock); \
	} \
	synchronize_rcu(); \
} 		\
		\
		\
/* 해쉬 테이블에서 객체를 검색 한다. */ 		\
obj_type* name##_lookup(void *key, void *data) \
{ \
	struct hlist_head *head; \
	struct hlist_node *pos; \
	uint32_t idx=0; \
	obj_type *_obj=NULL; \
	hll_t *hh; \
	int32_t found=0; \
	hh = name##_get_hash_slot((const char*)key, &idx); \
	wise_rd_lock_irq() { \
		head = &hh->head; \
		hlist_for_each_entry_rcu(_obj, head, member_name) { \
			if (lookup_callback(_obj, key, data)) { \
				name##_hold(_obj); \
				found=1; \
				break; \
			} \
		} \
	} wise_rd_unlock_irq(); \
	return found?_obj:NULL; \
} 		\
		\
		\
/* 해쉬 테이블에 객체를 추가 한다. */		\
int32_t name##_add_obj(void* key, obj_type *obj) \
{ \
	uint32_t idx=0; \
	hll_t *hh; \
	hh = name##_get_hash_slot((const char*)key, &idx); \
	ns_rw_lock_irq(&hh->lock) { \
		hlist_add_head_rcu(&obj->member_name, &hh->head); \
		name##_hold(obj); \
	} ns_rw_unlock_irq(&hh->lock); \
	return 0; \
} 		\
		\
		\
/* 해쉬 테이블에서 객체를 삭제 한다. 참조 카운트 0이 아닌 경우는 리스트에서만 삭제 된다. */ \
void name##_delete_obj(void* key, obj_type *obj) \
{ \
	uint32_t idx=0; \
	hll_t* hh; \
	hh = name##_get_hash_slot(key, &idx); \
	ns_rw_lock_irq(&hh->lock) { \
		hlist_del_rcu(&obj->member_name); \
		name##_release(obj); \
	} ns_rw_unlock_irq(&hh->lock); \
}

#endif
