#ifndef __BUCKETIZED_CUCKOO_HASHING_H__
#define __BUCKETIZED_CUCKOO_HASHING_H__

/*
 * enable parallel cuckoo
 */
#define BCHT_WIDTH 1

/*
 * enable bucket locking
 */
//#define BCHT_LOCK_FINEGRAIN    1

////////////////////////////////

/*
 * The maximum number of cuckoo operations per insert,
 * we use 128 in the submission
 * now change to 500
 */
#define BCHT_MAX_CUCKOO_COUNT 	500
#define BCHT_SLOT_SIZE 			4
#define BCHT_LOCK_COUNT 		8192
#define BCHT_LOCK_MASK 			(BCHT_LOCK_COUNT - 1)

/* Initial power multiplier for the hash table */
#define BCHT_HASHPOWER_DEFAULT 	25

#define BCHT_IS_SLOT_EMPTY(bcht, i, j) 	(bcht->buckets[i].tags[j] == 0)
#define BCHT_IS_TAG_EQUAL(bcht, i, j, tag) ((bcht->buckets[i].tags[j] & bcht->tag_mask) == tag)

#define BCHT_RET_PTR_ERR 		((void*)-1)

//  keyver array has 8192 buckets,
#define BCHT_KEYVER_COUNT 		((unsigned long int)1 << (13))
#define BCHT_KEYVER_MASK  		(BCHT_KEYVER_COUNT - 1)
#define BCHT_READ_KEYVER(bcht, lock) 	__sync_fetch_and_add(&bcht->keyver_array[lock & BCHT_KEYVER_MASK], 0)
#define BCHT_INC_KEYVER(bcht, lock) 	__sync_fetch_and_add(&bcht->keyver_array[lock & BCHT_KEYVER_MASK], 1)

/////////////////////////////////////////////////

typedef int32_t (*bcht_cmp_key)(const void *key, const void *data);
typedef uint8_t 	tag_t;
typedef spinlock_t 	bcht_spinlock_t;

#if 0
typedef struct cuckoo_slot_s {
	uint32_t	hash;
	//uint32_t  notused;
	ValueType	data;
}  __attribute__((__packed__)) bcht_slot_t;
#else
typedef void *bcht_slot_t;
#endif

typedef struct bcht_bucket_s {
	tag_t			tags[BCHT_SLOT_SIZE];   // 4 bytes
	bcht_slot_t		slots[BCHT_SLOT_SIZE];  // 32 bytes
}__attribute__((packed, aligned(4)))  bcht_bucket_t; // 36 bytes
 
typedef struct bcht_path_s {
	size_t		cp_buckets[BCHT_WIDTH];
	size_t		cp_slot_idxs[BCHT_WIDTH];
	bcht_slot_t	cp_slots[BCHT_WIDTH];
} bcht_path_t;

typedef struct bucketized_cuckoo_hashtable_ {
	bcht_bucket_t 	*buckets;
	bcht_cmp_key 	cb_cmp_key;
	bcht_path_t		*cuk_path;

	bcht_spinlock_t	*fg_locks;
	bcht_spinlock_t	wlock;
	uint32_t keyver_array[BCHT_KEYVER_COUNT];

	uint32_t	idx_victim;
	uint32_t	num_error;
	uint32_t	num_kick;
	uint32_t	num_items;
	uint32_t	num_moves;

	uint32_t	hash_power;
	uint64_t	hash_size;
	uint64_t	hash_mask;

	uint64_t	tag_power;
	uint64_t	tag_mask;
} bcht_t;


//////////////////////////////////////////////////////

bcht_t* bcht_init_hash_table(const int32_t hash_power, bcht_cmp_key cmp_key);
void 	bcht_destroy_hash_table(bcht_t *bcht);
void* 	bcht_find(bcht_t *bcht, const uint32_t hash, const char *key);
int32_t bcht_insert(bcht_t *bcht, const uint32_t hash, void *data);
void* 	bcht_delete(bcht_t *bcht, const uint32_t hash, const char *key);


#endif
