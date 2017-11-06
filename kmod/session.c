#include <include_os.h>

#include <ns_type_defs.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <commands.h>
#include <log.h>
//#include <extern.h>
#include <misc.h>
#include <ns_malloc.h>
#include <options.h>
#include <cuckoo.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);
extern struct kmem_cache	*netshield_scache;

//////////////////////////////////////////////////////

void MurmurHash3_x86_32(const void *key, int len, uint32_t seed, void *out);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

// return value
// 1: match 
// 0: no match
// -1: error
static int session_match_key(const void *key, const void *data)
{
	sk_t *sk1 = (sk_t *)key;
	const session_t *si = (const session_t*)data;
	const sk_t *sk2 = NULL;

	if (data == NULL) {
		return -1;
	}

	sk2 = &si->sk;

#if 0
	DBGKEY(9, "SK1", (sk_t*)sk1);
	DBGKEY(9, "SK2", (sk_t*)sk2);
	DBG(9, "hashkey1=0x%x, hashkey2=0x%x", sk1->hashkey, sk2->hashkey);
#endif

	if (sk1->hashkey != sk2->hashkey) {
		return 0;
	}

	if ((sk1->src ^ sk1->dst) == (sk2->src ^ sk2->dst) &&
		(sk1->sp  ^ sk1->dp)  == (sk2->sp  ^ sk2->dp) &&
		sk1->proto == sk2->proto) {

		if (sk1->src == sk2->dst) {
			sk1->flags |= SKF_REVERSE_MATCHED;
			DBG(5, "SKEY matched Reverse Direction");
		}

		return 1;
	}

	return 0;
}

uint32_t session_make_hash(sk_t *sk)
{
#define NS_HASH_SIZE 19

	struct hashdata_s{
		uint128_t ip; 	// 16 Bytes
		uint16_t port; 	// 2 Bytes
		uint8_t proto; 	// 1 Bytes
	};

	struct hashdata_s k;
	uint32_t hash = 0;

	k.ip    = sk->src ^ sk->dst;
	k.port  = sk->sp  ^ sk->dp;
	k.proto = sk->proto;

	MurmurHash3_x86_32((const void *)&k, NS_HASH_SIZE, 0x43606326, &hash);

	return hash;
}

session_t *session_alloc(void)
{
	session_t *si;

	// alloc session
	si = (session_t *)ns_cache_malloc_a(netshield_scache);
	ns_mem_assert(si, "session_t", return NULL);

	memset(si, 0, sizeof(session_t));

	init_rcu_head(&si->rcu);
	INIT_LIST_HEAD(&si->alist);
	//INIT_LIST_HEAD(&si->rlist);
	//INIT_LIST_HEAD(&si->avlist);

	si->flags = SFLAG_MINE | SFLAG_ALIVE;

	return si;
}

void session_free(session_t *si)
{
	dbg(0, "Free Session: 0x%p", si);

	ns_cache_free(netshield_scache, si);
}


void session_hold(session_t *si)
{
	if (si) {
		atomic_inc(&si->refcnt);
	}
}

void session_release(session_t *si)
{
	int32_t ref;

	if (si == NULL) {
		return;
	}

	ref = atomic_dec_return(&si->refcnt);
	if (ref > 0) {
		// still alive
		return;
	}
	else if (ref < 0) {
		// reenter ??
		ns_log("Reenter here while 0x%p is still deleting", si);
		return;
	}

	session_free(si);
}

int32_t session_insert(void *stab, session_t *si)
{
	int32_t ret;

	ret = bcht_insert((bcht_t*)stab, si->sk.hashkey, (void*)si);
	session_hold(si);

	return ret;
}

int32_t session_remove(void *stab, session_t *si)
{
	session_t *si1 = NULL;

	si1 = bcht_delete((bcht_t*)stab, si->sk.hashkey, (const char*)&si->sk);

	if (si != si1) {
		// what is this?
		return -1;
	}

	session_release(si);

	// XXX: free the session table
	
	return 0;
}

session_t* session_search(void *stab, sk_t *sk)
{
	session_t *si;

	ENT_FUNC(3);

	si = (session_t*)bcht_find(stab, sk->hashkey, (const char*)sk);

	// call session_release() after using it
	if (si) {
		session_hold(si);
	}

	return si;
}

void* session_init(void)
{
	int32_t hash_power;
	void *stab;

	ENT_FUNC(3);

	hash_power = GET_OPT_VALUE(session_bucket_power);

	stab = (void*)bcht_init_hash_table(hash_power, session_match_key);

	if (stab == NULL) {
		ns_err("Fail initialize Session table");
	}

	return (void*)stab;
}

void session_clean(void *stab)
{
	ENT_FUNC(3);

	bcht_destroy_hash_table(stab);
}
