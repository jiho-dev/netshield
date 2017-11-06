#include <linux/netshield_hook.h>

netshield_hook_t   	*netshield_hook_op[AF_MAX];
// session memory cache for NetShield
struct kmem_cache 	*netshield_scache; 	

static void netshield_create_cache(int32_t size, char* name, struct kmem_cache** cache)
{
	if (size > 0 && cache != NULL && *cache == NULL) {
		*cache = kmem_cache_create(name, size, 0, SLAB_DESTROY_BY_RCU, NULL);
	}
}

void netshield_create_sem_cache(int32_t size)
{
	netshield_create_cache(size, "ns_sess_cache", &netshield_scache);
}

///////////////////////////////////////////////

static int __init netshield_hook_init(void)
{

	return 0;
}

static void netshield_hook_exit(void)
{

}

///////////////////////////////////////////

EXPORT_SYMBOL(netshield_hook_op);
EXPORT_SYMBOL(netshield_scache);
EXPORT_SYMBOL(netshield_create_sem_cache);

subsys_initcall(netshield_hook_init);
//module_init(netshield_init);
module_exit(netshield_hook_exit);


