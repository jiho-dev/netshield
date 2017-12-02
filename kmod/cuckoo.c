#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <log.h>
#include <ns_malloc.h>
#include <cuckoo.h>

/*  Bucketized Cuckoo Hashtable(BCHT) */

DECLARE_DBG_LEVEL(6);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

static inline
size_t index_hash(const uint32_t hv, const uint32_t hashpower)
{
	return hv >> (32 - hashpower);
}

static inline
size_t alt_index(const size_t index, const tag_t tag, const uint64_t tagmask, const uint64_t hashmask)
{
	// 0x5bd1e995 is the hash constant from MurmurHash3
	return (index ^ ((tag & tagmask) * 0x5bd1e995)) & hashmask;
}

static inline
tag_t tag_hash(const uint32_t hv, const uint64_t tagmask)
{
	uint32_t r = hv & tagmask;

	return (tag_t)r + (r == 0);
}

static inline size_t keyver_index(const size_t i1, const size_t i2) 
{
    return i1 <  i2 ? i1 : i2;
}
/////////////////////////////////////////////////

#ifdef BCHT_LOCK_FINEGRAIN
static void fg_lock(bcht_t *bcht, uint32_t i1, uint32_t i2)
{
	uint32_t j1, j2;

	j1 = i1 & BCHT_LOCK_MASK;
	j2 = i2 & BCHT_LOCK_MASK;

	//__builtin_prefetch((const void*)&bcht->fg_locks[j1], 0, 1);
	//__builtin_prefetch((const void*)&bcht->fg_locks[j2], 0, 1);

	if (j1 < j2) {
		ns_rw_lock(&bcht->fg_locks[j1]);
		ns_rw_lock(&bcht->fg_locks[j2]);
	}
	else if (j1 > j2) {
		ns_rw_lock(&bcht->fg_locks[j2]);
		ns_rw_lock(&bcht->fg_locks[j1]);
	}
	else {
		ns_rw_lock(&bcht->fg_locks[j1]);
	}
}

static void fg_unlock(bcht_t *bcht, uint32_t i1, uint32_t i2)
{
	uint32_t j1, j2;

	j1 = i1 & BCHT_LOCK_MASK;
	j2 = i2 & BCHT_LOCK_MASK;

	if (j1 < j2) {
		ns_rw_unlock(&bcht->fg_locks[j2]);
		ns_rw_unlock(&bcht->fg_locks[j1]);
	}
	else if (j1 > j2) {
		ns_rw_unlock(&bcht->fg_locks[j1]);
		ns_rw_unlock(&bcht->fg_locks[j2]);
	}
	else {
		ns_rw_unlock(&bcht->fg_locks[j1]);
	}
}
#endif

static inline
uint32_t cuckoo_read_even_count(bcht_t *bcht, size_t kidx)
{
	uint32_t c;

	do {
		c = BCHT_READ_KEYVER(bcht, kidx);
	} while (c & 1);

	return c;
}

static inline 
int32_t cuckoo_changed_count(bcht_t *bcht, size_t kidx, uint32_t c)
{
	return (c != BCHT_READ_KEYVER(bcht, kidx));
}

/*
 * Try to read bucket i and check if the given tag is there
 */
static inline 
void* try_read(bcht_t *bcht, const char *key, tag_t tag, size_t bkidx, size_t kidx)
{
	uint32_t vs;
	volatile uint32_t tmp;
	int32_t sidx;
	void *result = NULL;
	void *data = NULL;

	do {
START:
		vs = cuckoo_read_even_count(bcht, kidx);
		__builtin_prefetch(&(bcht->buckets[bkidx]));
		tmp = *((uint32_t *)&(bcht->buckets[bkidx]));

		for (sidx = 0; sidx < BCHT_SLOT_SIZE; sidx++) {
			if (tag != ((uint8_t *)&tmp)[sidx]) {
				continue;
			}

			/* volatile __m128i p, q; */
			/* p = _mm_loadu_si128((__m128i const *) &buckets[i].slots[0]); */
			/* q = _mm_loadu_si128((__m128i const *) &buckets[i].slots[2]); */
			/* void *slots[4]; */

			/* _mm_storeu_si128((__m128i *) slots, p); */
			/* _mm_storeu_si128((__m128i *) (slots + 2), q); */
			/* void *data = slots[j]; */

			if (cuckoo_changed_count(bcht, kidx, vs)) {
				goto START;
			}

			result = NULL;
			data = bcht->buckets[bkidx].slots[sidx];
			__builtin_prefetch(data);

			if (data && bcht->cb_cmp_key((const void *)key, data) == 1) {
				result = data;
				break;
			}
		}

	} while (cuckoo_changed_count(bcht, kidx, vs));

	return result;
}

/*
 * Try to add an void to bucket i,
 * return true on success and false on failure
 */
static int32_t try_add(bcht_t *bcht, void *data, tag_t tag, size_t bkidx, size_t kidx)
{
	size_t j;

	for (j = 0; j < BCHT_SLOT_SIZE; j++) {
		if (BCHT_IS_SLOT_EMPTY(bcht, bkidx, j)) {
			// make the key odd
			BCHT_INC_KEYVER(bcht, kidx);

#ifdef BCHT_LOCK_FINEGRAIN
			fg_lock(bcht, bkidx, bkidx);
#endif

			bcht->buckets[bkidx].tags[j] = tag;
			bcht->buckets[bkidx].slots[j] = data;
			bcht->num_items++;

			// make the key even
			BCHT_INC_KEYVER(bcht, kidx);

#ifdef BCHT_LOCK_FINEGRAIN
			fg_unlock(bcht, bkidx, bkidx);
#endif
			return 1;
		}
	}

	return 0;
}

static void* try_del(bcht_t *bcht, const char *key, tag_t tag, size_t bkidx, size_t kidx)
{
	size_t j;
	void *data = NULL;

	for (j = 0; j < BCHT_SLOT_SIZE; j++) {
		if (!BCHT_IS_TAG_EQUAL(bcht, bkidx, j, tag)) {
			continue;
		}

		data = bcht->buckets[bkidx].slots[j];

		if (data == NULL) {
			// found but no data
			return NULL;
		}

		// call _compare_key()
		if (bcht->cb_cmp_key((const void *)key, data) == 1) {

#ifdef BCHT_LOCK_FINEGRAIN
			fg_lock(bcht, bkidx, bkidx);
#endif

			BCHT_INC_KEYVER(bcht, kidx);

			bcht->buckets[bkidx].tags[j] = 0;
			bcht->buckets[bkidx].slots[j] = 0;
			bcht->num_items--;

			BCHT_INC_KEYVER(bcht, kidx);

#ifdef BCHT_LOCK_FINEGRAIN
			fg_unlock(bcht, bkidx, bkidx);
#endif

			return data;
		}
	}

	return BCHT_RET_PTR_ERR;
}

/*
 * Make bucket  from[idx] slot[whichslot] available to insert a new void
 * return idx on success, -1 otherwise
 * @param from:   the array of bucket index
 * @param whichslot: the slot available
 * @param  depth: the current cuckoo depth
 */
static int32_t path_search(bcht_t *bcht, size_t depth_start, size_t *cp_index)
{
	int32_t depth = depth_start;

	while ((bcht->num_kick < BCHT_MAX_CUCKOO_COUNT) &&
		   (depth >= 0) && (depth < BCHT_MAX_CUCKOO_COUNT - 1)) {
		size_t *from = &(bcht->cuk_path[depth].cp_buckets[0]);
		size_t *to = &(bcht->cuk_path[depth + 1].cp_buckets[0]);

		/*
		 * Check if any slot is already free
		 */
		size_t idx;
		for (idx = 0; idx < BCHT_WIDTH; idx++) {
			size_t i = from[idx];
			size_t j;
			for (j = 0; j < BCHT_SLOT_SIZE; j++) {
				if (BCHT_IS_SLOT_EMPTY(bcht, i, j)) {
					bcht->cuk_path[depth].cp_slot_idxs[idx] = j;
					*cp_index = idx;

					return depth;
				}
			}

			// pick the victim item
			bcht->idx_victim++;
			j = bcht->idx_victim % BCHT_SLOT_SIZE;

			bcht->cuk_path[depth].cp_slot_idxs[idx] = j;
			bcht->cuk_path[depth].cp_slots[idx] = bcht->buckets[i].slots[j];
			to[idx] = alt_index(i, bcht->buckets[i].tags[j],
								bcht->tag_mask, bcht->hash_mask);
		}

		bcht->num_kick += BCHT_WIDTH;
		depth++;
	}

	return -1;
}

static int32_t move_backward(bcht_t *bcht, size_t depth_start, size_t idx)
{
	int32_t depth = depth_start;

	while (depth > 0) {
		size_t i1 = bcht->cuk_path[depth - 1].cp_buckets[idx];
		size_t i2 = bcht->cuk_path[depth].cp_buckets[idx];

		size_t j1 = bcht->cuk_path[depth - 1].cp_slot_idxs[idx];
		size_t j2 = bcht->cuk_path[depth].cp_slot_idxs[idx];

		/*
		 * We plan to kick out j1, but let's check if it is still there;
		 * there's a small chance we've gotten scooped by a later cuckoo.
		 * If that happened, just... try again.
		 */

		if (bcht->buckets[i1].slots[j1] !=
			bcht->cuk_path[depth - 1].cp_slots[idx]) {
			/* try again */
			return depth;
		}

		if (BCHT_IS_SLOT_EMPTY(bcht, i2, j2)) {
			size_t kidx   = keyver_index(i1, i2);
			BCHT_INC_KEYVER(bcht, kidx);

#ifdef BCHT_LOCK_FINEGRAIN
			fg_lock(bcht, i1, i2);
#endif

			bcht->buckets[i2].tags[j2] = bcht->buckets[i1].tags[j1];
			bcht->buckets[i2].slots[j2] = bcht->buckets[i1].slots[j1];

			bcht->buckets[i1].tags[j1] = 0;
			bcht->buckets[i1].slots[j1] = 0;

			bcht->num_moves++;

			BCHT_INC_KEYVER(bcht, kidx);

#ifdef BCHT_LOCK_FINEGRAIN
			fg_unlock(bcht, i1, i2);

#endif
			depth--;
		}
	}

	return depth;
}

static int32_t cuckoo(bcht_t *bcht, int32_t depth)
{
	int32_t cur;
	size_t idx;

	bcht->num_kick = 0;

	while (1) {
		cur = path_search(bcht, depth, &idx);
		if (cur < 0) {
			return -1;
		}

		cur = move_backward(bcht, cur, idx);
		if (cur == 0) {
			return idx;
		}

		depth = cur - 1;
	}

	return -1;
}

///////////////////////////////////////////////////////

bcht_t *
bcht_init_hash_table(const int32_t hash_power, bcht_cmp_key cmp_key)
{
	bcht_t *bcht;
	int32_t len = sizeof(bcht_t);
#ifdef BCHT_LOCK_FINEGRAIN
	size_t i=0;
#endif

	ENT_FUNC(3);

	bcht = ns_malloc_k(len);
	//bcht = ns_malloc_v(len);
	if (bcht == NULL) {
		DBG(0, "Cuckoo is NULL");
		return NULL;
	}

	memset(bcht, 0, len);

	bcht->hash_power = BCHT_HASHPOWER_DEFAULT;
	if (hash_power) {
		bcht->hash_power = hash_power;
	}

	bcht->hash_size = (uint64_t)1 << (bcht->hash_power);
	bcht->hash_mask = bcht->hash_size - 1;

	/*
	 * tagpower: number of bits per tag
	 */
	bcht->tag_power = sizeof(tag_t) * 8;
	bcht->tag_mask = ((uint64_t)1 << bcht->tag_power) - 1;

	len = bcht->hash_size * sizeof(bcht_bucket_t);

	DBG(4, "Cuckoo Hashtable Size: hash_size=%llu, power=%u, bucket_size=%d, len=%d path_len=%d", 
		bcht->hash_size, bcht->hash_power, 
		(int)sizeof(bcht_bucket_t),
		len,  (int)sizeof(bcht_path_t) * BCHT_MAX_CUCKOO_COUNT);

	//bcht->buckets = ns_malloc_k(len);
	bcht->buckets = ns_malloc_v(len);
	if (bcht->buckets == NULL) {
		DBG(0, "Buckets is NULL");
		goto FAIL;
	}

	memset(bcht->buckets, 0, len);

	len = sizeof(bcht_path_t) * BCHT_MAX_CUCKOO_COUNT;
	//bcht->cuk_path = ns_malloc_k(len);
	bcht->cuk_path = ns_malloc_v(len);
	if (bcht->cuk_path == NULL) {
		DBG(0, "Cuckoo Path is NULL");
		goto FAIL;
	}

	memset(bcht->cuk_path, 0, len);

#ifdef BCHT_LOCK_FINEGRAIN
	len = sizeof(bcht_spinlock_t) * BCHT_LOCK_COUNT;
	DBG(0, "lock len=%d ", len);
	bcht->fg_locks = ns_malloc_k(len);
	if (bcht->fg_locks == NULL) {
		DBG(0, "FG Lock is NULL");
		goto FAIL;
	}

	for (i = 0; i < BCHT_LOCK_COUNT; i++) {
		ns_init_lock(&bcht->fg_locks[i]);
	}
#endif

	ns_init_lock(&bcht->wlock);

    len = sizeof(uint32_t) * BCHT_KEYVER_COUNT;
    memset(bcht->keyver_array, 0, len);

	bcht->cb_cmp_key = NULL;
	if (cmp_key) {
		bcht->cb_cmp_key = cmp_key;
	}

	return bcht;

FAIL:
	ns_err("Fail init Bucket Cuckoo Hashtable");

	if (bcht) {
		if (bcht->buckets) {
			ns_free_v(bcht->buckets);
		}

		if (bcht->cuk_path) {
			ns_free_v(bcht->cuk_path);
		}

#ifdef BCHT_LOCK_FINEGRAIN
		if (bcht->fg_locks) {
			ns_free((void *)bcht->fg_locks);
		}
#endif

		ns_free(bcht);
	}

	return NULL;
}

void bcht_destroy_hash_table(bcht_t *bcht)
{
	if (bcht->buckets) {
		ns_free_v(bcht->buckets);
	}

	if (bcht->cuk_path) {
		ns_free_v(bcht->cuk_path);
	}

#ifdef BCHT_LOCK_FINEGRAIN
	if (bcht->fg_locks) {
		ns_free((void *)bcht->fg_locks);
	}
#endif

	ns_free(bcht);
}

void* bcht_find(bcht_t *bcht, const uint32_t hash, const char *key)
{
	tag_t tag;
	size_t i1, i2;
	void *result = NULL;
	size_t kidx;

	tag = tag_hash(hash, bcht->tag_mask);
	i1 = index_hash(hash, bcht->hash_power);
	i2 = alt_index(i1, tag, bcht->tag_mask, bcht->hash_mask);
	kidx = keyver_index(i1, i2);

#ifdef BCHT_LOCK_FINEGRAIN
	fg_lock(bcht, i1, i2);
#endif

	result = try_read(bcht, key, tag, i1, kidx);
	if (result == NULL) {
		result = try_read(bcht, key, tag, i2, kidx);
	}

#ifdef BCHT_LOCK_FINEGRAIN
	fg_unlock(bcht, i1, i2);
#endif

	return result;
}

// need to be protected by cache_lock
void* bcht_delete(bcht_t *bcht, const uint32_t hash, const char *key)
{
	tag_t tag;
	size_t i1, i2, kidx;
	void *data;

	tag = tag_hash(hash, bcht->tag_mask);
	i1 = index_hash(hash, bcht->hash_power);
	i2 = alt_index(i1, tag, bcht->tag_mask, bcht->hash_mask);
	kidx = keyver_index(i1, i2);

	ns_rw_lock(&bcht->wlock);

	data = try_del(bcht, key, tag, i1, kidx);

	if (data == BCHT_RET_PTR_ERR) {
		data = try_del(bcht, key, tag, i2, kidx);
	}

	ns_rw_unlock(&bcht->wlock);

	return data;
}

// need to be protected by cache_lock
int32_t bcht_insert(bcht_t *bcht, const uint32_t hash, void *data)
{
	tag_t tag;
	size_t i1, i2, kidx;
	int32_t ret = 0;
	int32_t bkidx;
	size_t depth = 0;
	size_t j;

	//hash = cuckoo_hash(key, klen);
	tag = tag_hash(hash, bcht->tag_mask);
	i1 = index_hash(hash, bcht->hash_power);
	i2 = alt_index(i1, tag, bcht->tag_mask, bcht->hash_mask);
	kidx = keyver_index(i1, i2);

	ns_rw_lock(&bcht->wlock);

	if (try_add(bcht, data, tag, i1, kidx) ||
		try_add(bcht, data, tag, i2, kidx)) {
		ret = 1;
		goto END;
	}

	for (bkidx = 0; bkidx < BCHT_WIDTH; bkidx++) {
		if (bkidx < BCHT_WIDTH / 2) {
			bcht->cuk_path[depth].cp_buckets[bkidx] = i1;
		}
		else {
			bcht->cuk_path[depth].cp_buckets[bkidx] = i2;
		}
	}

	bkidx = cuckoo(bcht, depth);
	if (bkidx >= 0) {
		i1 = bcht->cuk_path[depth].cp_buckets[bkidx];
		j = bcht->cuk_path[depth].cp_slot_idxs[bkidx];

		if (bcht->buckets[i1].slots[j] == 0 &&
			try_add(bcht, data, tag, i1, kidx)) {
			ret = 1;
			goto END;
		}
	}

	bcht->num_error++;

END:
	ns_rw_unlock(&bcht->wlock);

	return ret;
}

void bcht_print_hashtable_info(bcht_t *bcht)
{
#if 0
	size_t total_size = 0;

	ns_log("hash table is full (hashpower = %d, \
		num_items = %u, load factor = %.2f), \
		need to increase hashpower\n",
		   bcht->hash_power,
		   bcht->num_items,
		   1.0 * bcht->num_items / BCHT_SLOT_SIZE / bcht->hash_size);

	ns_log("num_items = %u\n", bcht->num_items);
	ns_log("index table size = %zu\n", bcht->hash_size);
	ns_log("hashtable size = %zu KB\n", 
		   bcht->hash_size * sizeof(bcht_bucket_t) / 1024);
	ns_log("hashtable load factor= %.5f\n", 
		   1.0 * bcht->num_items / BCHT_SLOT_SIZE / bcht->hash_size);
	total_size += bcht->hash_size * sizeof(bcht_bucket_t);
	ns_log("total_size = %zu KB\n", total_size / 1024);
	ns_log("moves per insert = %.2f\n", 
		   (double)bcht->num_moves / bcht->num_items);

	ns_log("\n");
#endif
}


