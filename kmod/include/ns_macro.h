#ifndef __NS_MACRO_H_
#define __NS_MACRO_H_


#define __STR(x) 					#x
#define sizeofa( x ) 				(sizeof(x) / sizeof(x[0]))
#define sizeofm(TYPE, MEMBER) 		sizeof(((TYPE *) 0)->MEMBER)
#define lengthof(TYPE, MEMBER) 		(offsetof(TYPE, MEMBER) + sizeofm(TYPE, MEMBER))
#define MAC(addr) \
	(uint8_t)(((unsigned char *)addr)[0]), \
	(uint8_t)(((unsigned char *)addr)[1]), \
	(uint8_t)(((unsigned char *)addr)[2]), \
	(uint8_t)(((unsigned char *)addr)[3]), \
	(uint8_t)(((unsigned char *)addr)[4]), \
	(uint8_t)(((unsigned char *)addr)[5])
#define IPN(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#if defined(__LITTLE_ENDIAN)
#define IPH(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define IPH(addr) 	IPN(addr)
#else
#error Not defined Endian Mode !
#endif

#ifndef MAC_FMT
#define MAC_FMT 				"%02X:%02X:%02X:%02X:%02X:%02X"
#endif
#define IP_FMT 					"%u.%u.%u.%u"
#define SKEY_FMT				":" IP_FMT ":%d->" IP_FMT ":%d(%d)"
#define IP6_FMT 				"%pI6c"
#define SKEY_FMT6				"[" IP6_FMT "-%d->" IP6_FMT "-%d(%d)]"

#define ISREQ(u) 				(!!(u->flags & TASK_FLAG_REQ))
#define ISRES(u) 				( !(u->flags & TASK_FLAG_REQ))
#define bzero(a, b) 			memset((a), 0, (b))

#define PREFETCH(a,rw,l) 		__builtin_prefetch(a, rw, l)
#define ASSERT_COMPILE(e)		BUILD_BUG_ON(e)
#define IS_DST_LOCAL(_dst) 		(((struct rtable*)_dst)->rt_flags & RTCF_LOCAL)
#define IS_INCLUDE_IP(ip,mask,src) ((ip&mask) == (src&mask))
#define IS_IPV6(__k)			(((__k)->flags & SKF_IPV6)?FUNC_FLAG_IPV6:0)
#define SKEY(_k)				IPH((_k)->src4), (_k)->sp, IPH((_k)->dst4), (_k)->dp, (_k)->proto
#define MAKE_BIT(v)				(!!(v))
#define IS_LOCALOUT(u)			(u->flags & NST_FLAG_HOOK_LOCAL_OUT)
#define IS_DST_VPN(dst)			((dst)->obsolete == -1)


///////////////////////////////////////////
// 
/* INFO: LOCK은 반드시 아래와 같은 스티일로 코딩 해야 한다.
*
*  ns_rw_lock_irq() {
*	 something(...)
*  } ns_rw_unlock_irq();
*
*/
// 데이터를 write를 해야 하는 경우 사용
// _irq는 soft-irq(Bottom-Half) 상태에서 사용
#define	ns_rw_trylock_irq(l) spin_trylock_bh(l)
#define	ns_rw_lock_irq(l) 	spin_lock_bh(l);
#define	ns_rw_unlock_irq(l) spin_unlock_bh(l);
#define	ns_rw_lock(l)		spin_lock(l);
#define	ns_rw_unlock(l)		spin_unlock(l);

// 데이터를 읽기만 하는 경우 사용
#define	ns_rd_lock_irq()	rcu_read_lock_bh();
#define	ns_rd_unlock_irq() 	rcu_read_unlock_bh();
#define	ns_rd_lock()		rcu_read_lock();
#define	ns_rd_unlock()		rcu_read_unlock();

#define ns_init_lock(l) 	spin_lock_init(l)
///////////////////////////////////////////////////////////


#define IS_SYN_ONLY(t) 		(t->syn && !(t->rst|t->fin|t->ack))
#define IS_ACK_ONLY(t) 		(t->ack && !(t->rst|t->fin|t->syn))
#define IS_SYN_ACK(t) 		(t->syn && t->ack && !(t->rst|t->fin))

#define KER_VER_LT(maj,mid,min) (LINUX_VERSION_CODE <  KERNEL_VERSION(maj,mid,min))
#define KER_VER_LE(maj,mid,min) (LINUX_VERSION_CODE <= KERNEL_VERSION(maj,mid,min))
#define KER_VER_GT(maj,mid,min) (LINUX_VERSION_CODE > KERNEL_VERSION(maj,mid,min))

#define CMP_MAC_HI(mac1, mac2) 	(*(uint32_t*)mac1 == *(uint32_t*)mac2)
#define CMP_MAC_LO(mac1, mac2) 	(*(uint16_t*)&mac1[4] == *(uint16_t*)&mac2[4])
#define CMP_MAC(mac1, mac2) (CMP_MAC_HI(mac1, mac2) && CMP_MAC_LO(mac1, mac2))
#define CTL_TAB_ITEM(n, d, l, m, c, h) {.procname=n, .data=d, .maxlen=l, .mode=m, .child=c, .proc_handler=h}

#define ns_copy_ipv6(d,s) 	memcpy((d), (s), 16)
#define PROTO(nstask) 				(nstask)->key.proto

#if 0
#define wsnprintf(buf, buflen, maxlen, fmt, args...) \
	do { \
		int32_t __len; \
		__len = snprintf((*(buf)), maxlen-(*(buflen)), fmt, ##args); \
		(*(buf)) += __len; (*(buflen)) += __len; \
	} while(0);
#endif

#define ns_bug(fmt, args...)	ns_log_print(-1, LOG_LEV_ERR, "NetShield BUG: " NS_FUNC_FMT fmt, NS_FUNC_PARAM, ##args)


//////////////////////////////////////////////////////////////////
// debug messages 
// PRE_DBG_NAME will be defined in Makefile

#define NS_FUNC_FMT 				"%s(%d): "
#define NS_FUNC_PARAM 			__FUNCTION__,__LINE__

#ifdef CONFIG_NS_DEBUG

extern int32_t dbgctl_compare_level(int32_t file_level, char* func, int32_t f_level);
extern void _dump_hex(const uint8_t *data, int len);
extern void dump_pkt(char* func, int32_t line, iph_t *iph, uint8_t inic);

#define ns_err(fmt, args...) 	ns_log_print(-1, LOG_LEV_ERR, "NetShield ERR: " NS_FUNC_FMT fmt, NS_FUNC_PARAM, ##args)
#define ns_warn(fmt, args...) 	ns_log_print(-1, LOG_LEV_WARN, "NetShield WARN: " NS_FUNC_FMT fmt, NS_FUNC_PARAM, ##args)
#define ns_log(fmt, args...)	ns_log_print(-1, LOG_LEV_INFO, "NetShield INFO: " NS_FUNC_FMT fmt, NS_FUNC_PARAM, ##args)

#ifdef __KERNEL__
#define OUT_MSG(fmt, args...) 	printk("NetShield: " NS_FUNC_FMT fmt "\n", NS_FUNC_PARAM, ##args)
#else
#define OUT_MSG(fmt, args...) 	printf("NetShield: " NS_FUNC_FMT fmt "\n", NS_FUNC_PARAM, ##args)
#endif

#define DBG_NAME(n)				dbg_level_ ## n
#define CMP_LEV(file_l, func_l) dbgctl_compare_level(file_l, (char*)__FUNCTION__, func_l)
#define _DECL_DBG_LEVEL(n, l) 	int32_t DBG_NAME(n) = l
#define DECLARE_DBG_LEVEL(l)	_DECL_DBG_LEVEL(PRE_DBG_NAME, l)

#define _DBG(n, l,fmt, args...)	if (CMP_LEV(DBG_NAME(n), l)) {OUT_MSG(fmt, ##args);}
#define DBG(l,fmt, args...) 	_DBG(PRE_DBG_NAME, l, fmt, ##args)
#define dbg(l,fmt, args...) 	_DBG(PRE_DBG_NAME, l, fmt, ##args)

#define _DUMP_PKT(n,l,iph,inic)	if (CMP_LEV(DBG_NAME(n),l)) {dump_pkt((char*)__FUNCTION__, __LINE__, iph, inic);}
#define DUMP_PKT(l,iph,inic)	_DUMP_PKT(PRE_DBG_NAME, l, iph, inic)
#define PRINT_SZ(s) 			OUT_MSG("%s=%d", __STR(s), (int32_t)sizeof(s))
#define _DBG_CODE(n, l, code)  	if (CMP_LEV(DBG_NAME(n),l)) { code;}
#define DBG_CODE(l, code) 		_DBG_CODE(PRE_DBG_NAME, l, code)
#define DBG_CODE_START(l) 		DBG_CODE(l,

#define	_DBGKEY(n, l, msg, _kkk) 	\
	if (CMP_LEV(DBG_NAME(n),l)) {	\
		skey_t* _k = _kkk;  			\
		uint32_t _ss = (uint32_t)_k->src; \
		uint32_t _dd = (uint32_t)_k->dst; \
		OUT_MSG(__STR(msg) SKEY_FMT, IPH(_ss), _k->sp, \
		IPH(_dd), _k->dp, _k->proto); \
	}
#define DBGKEY(l, msg, _kk) 	_DBGKEY(PRE_DBG_NAME, l, msg, _kk)

#define	_DBGKEY6(n, l, msg, _kkk) 	\
	if (CMP_LEV(DBG_NAME(n),l)) {	\
		skey_t* _k = _kkk; ip6_t _s, _d;\
		_s.a64[0] = htonll(_k->src6.a64[0]); \
		_s.a64[1] = htonll(_k->src6.a64[1]); \
		_d.a64[0] = htonll(_k->dst6.a64[0]); \
		_d.a64[1] = htonll(_k->dst6.a64[1]); \
		OUT_MSG(__STR(msg) SKEY_FMT6, &_s, _k->sp, &_d, _k->dp, _k->proto); \
	}
#define DBGKEY6(l, msg, _kk) 	_DBGKEY6(PRE_DBG_NAME, l, msg, _kk)

#define _DBGKEYH(n, l, msg, k) 		\
	if (CMP_LEV(DBG_NAME(n),l)){	\
		uint32_t* _kk = (uint32_t*)k; \
		OUT_MSG(__STR(msg) " Hex: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x", \
		_kk[0], _kk[1], _kk[2], _kk[3], _kk[4]); \
	}
#define DBGKEYH(l, msg, k) 		_DBGKEYH(PRE_DBG_NAME, l, msg, k)

#if 0
#define _DBG_CALLER(n, l,msg) 	\
	if (CMP_LEV(DBG_NAME(n),l)){		\
		char __buf[128]; 		\
		sprintf(__buf, \
		"NetShield: " NS_FUNC_FMT "Caller: %%s: %s \n", \
		NS_FUNC_PARAM, msg); \
		__print_symbol_simple(__buf, (unsigned long) __builtin_return_address(0)) \
	}
#else
#define _DBG_CALLER(n, l,msg) 	\
	if (CMP_LEV(DBG_NAME(n),l)){		\
		char __buf[128]; 		\
		sprintf(__buf, \
		"NetShield: " NS_FUNC_FMT "%s \n", \
		NS_FUNC_PARAM, msg); \
		printk("%s", __buf); \
	}
#endif

#define DBG_CALLER(l) 		_DBG_CALLER(PRE_DBG_NAME, l, "")
#define ENT_FUNC(l)			_DBG_CALLER(PRE_DBG_NAME, l, "Enter")
#define	FUNC_TEST_MSG(l,fmt, args...)	_DBG(PRE_DBG_NAME, l, fmt, ##args)
#define dbg_dump_hex(data, len) _dump_hex(data, len)



#else

#define DECLARE_DBG_LEVEL(x)
#define OUT_MSG(fmt, args... )
#define DBG(l,fmt, args...)
#define dbg(l,fmt, args...)
#define	FUNC_TEST_MSG(l,fmt, args...)
#define DUMP_PKT(l,iph,inic)	
#define PRINT_SZ(s)
#define DBG_CALLER(l)
#define ENT_FUNC(l)
#define DBGKEYH(l, msg, k)
#define DBGKEY(l, msg, k)
#define DBGKEY6(l, msg, _kk)
#define _DBG_CODE(n, l, code) 
#define DBG_CODE(l, code) 		_DBG_CODE(PRE_DBG_NAME, l, code)
#define DBG_CODE_START(l) 		DBG_CODE(l,
#define ns_err(fmt, args...) 	ns_log_print(-1, LOG_LEV_ERR, "NetShield ERR: " fmt , ##args)
#define ns_warn(fmt, args...) 	ns_log_print(-1, LOG_LEV_WARN, "NetShield WARN: " fmt , ##args)
#define ns_log(fmt, args...)	ns_log_print(-1, LOG_LEV_INFO, "NetShield INFO: " fmt , ##args)
#define dbg_dump_hex(data, len) do { } while (0)

#endif // CONFIG_NS_DEBUG
#endif
