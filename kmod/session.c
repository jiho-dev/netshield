#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <session.h>
#include <log.h>
#include <ns_malloc.h>
#include <options.h>
#include <cuckoo.h>
#include <action.h>


//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);
extern struct kmem_cache	*netshield_scache;

//////////////////////////////////////////////////////

void MurmurHash3_x86_32(const void *skey, int len, uint32_t seed, void *out);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

// return value
// 1: match 
// 0: no match
// -1: error
static int session_match_key(const void *skey, const void *data)
{
	skey_t *skey1 = (skey_t *)skey;
	const session_t *si = (const session_t*)data;
	const skey_t *skey2 = NULL;
	const natinfo_t *natinfo = &si->natinfo;

	if (data == NULL) {
		return -1;
	}

	skey2 = &si->skey;

#if 0
	DBGKEY(9, "skey1", (skey_t*)skey1);
	DBGKEY(9, "skey2", (skey_t*)skey2);
	dbg(0, "pkt hashkey:0x%x, si hashkey(0x%x:0x%x), act=0x%llx, %d:%d", 
		skey1->hashkey, 
		skey2->hashkey, natinfo->hashkey, si->action,
		skey1->proto, skey2->proto);
#endif

	if ((skey1->hashkey == skey2->hashkey) && 
		(skey1->proto == skey2->proto) &&
		(skey1->src ^ skey1->dst) == (skey2->src ^ skey2->dst) &&
		(skey1->sp  ^ skey1->dp)  == (skey2->sp  ^ skey2->dp)) {

		if (skey1->src == skey2->dst) {
			skey1->flags |= SKF_REVERSE_MATCHED;
			//dbg(5, "SKEY matched Reverse Direction");
		}

		return 1;
	}

	if ((si->action & ACT_NAT) && 
		(skey1->hashkey == natinfo->hashkey) && 
		(skey1->proto == skey2->proto)) {

		//dbg(0, "R: hashkey1=0x%x, hashkey2=0x%x", skey1->hashkey, natinfo->hashkey);

		if ((si->action & ACT_SINGLE_NAT) &&
			(skey1->src ^ skey1->dst) == (skey2->dst ^ natinfo->ip[0]) &&
			(skey1->sp  ^ skey1->dp)  == (skey2->dp  ^ natinfo->port[0])) {
			// matching nat session is always reversed matching.
			skey1->flags |= SKF_REVERSE_MATCHED;
			return 1;
		}

		if ((si->action & ACT_BNAT) &&
			(skey1->src ^ skey1->dst) == (natinfo->ip[0] ^ natinfo->ip[1]) &&
			(skey1->sp  ^ skey1->dp)  == (natinfo->port[0]  ^ natinfo->port[1])) {
			// matching nat session is always reversed matching.
			skey1->flags |= SKF_REVERSE_MATCHED;
			return 1;
		}
	}

	return 0;
}

uint32_t session_make_hash(skey_t *skey)
{
	struct hashdata_s k;
	uint32_t hash = 0;

	k.ip    = skey->src ^ skey->dst;
	k.port  = skey->sp  ^ skey->dp;
	k.proto = skey->proto;

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
	dbg(5, "Free Session: 0x%p", si);

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
		ns_log("Reenter here while 0x%p is still deleting: %d", si, ref);
		return;
	}

	// it must be the top of deleting it.
	// set I'm dead
	si->flags &= ~SFLAG_ALIVE;

	// NAT 세션 인경우 NAT 정보를 반환 한다.
	if (si->action & ACT_NAT_RELEASE) {
		if (si->mp_nat.policy) {
			nat_release_info(si, si->mp_nat.policy);
		}
	}

	session_free(si);
}

int32_t session_insert(void *stab, session_t *si)
{
	int32_t ret = 0;

	si->skey.hashkey = session_make_hash(&si->skey);
	ret = bcht_insert((bcht_t*)stab, si->skey.hashkey, (void*)si);

	if (ret == 0) {
		ns_err("Fail to insert new Firewall session into Session Table");
		return -1;
	}

	session_hold(si);

	if (si->action & ACT_NAT) {
		si->natinfo.hashkey = nat_make_hash(si);

		ret = bcht_insert((bcht_t*)stab, si->natinfo.hashkey, (void*)si);
		if (ret == 0) {
			ns_err("Fail to insert new NAT session into Session Table");
			return -1;
		}

		session_hold(si);
	}

	return ret;
}

int32_t session_remove(void *stab, session_t *si)
{
	session_t *si1 = NULL;

	si1 = bcht_delete((bcht_t*)stab, si->skey.hashkey, (const char*)&si->skey);

	if (si != si1) {
		ns_err("Mismatch session: 0x%p != 0x%p", si, si1);
		// what is this?
		return -1;
	}

	if (si->action & ACT_NAT) {
		si1 = bcht_delete((bcht_t*)stab, si->natinfo.hashkey, (const char*)&si->skey);

		if (si != si1) {
			ns_err("Mismatch session: 0x%p != 0x%p", si, si1);
		}
		else {
			session_release(si);
		}
	}

	session_release(si);

	// XXX: free the session table
	
	return 0;
}

session_t* session_search(void *stab, skey_t *skey)
{
	session_t *si;

	ENT_FUNC(3);

	si = (session_t*)bcht_find(stab, skey->hashkey, (const char*)skey);

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
