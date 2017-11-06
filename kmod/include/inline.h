#ifndef __INLINE_H
#define __INLINE_H


#ifdef __KERNEL__

static inline void tcp_csum(iph_t* iph, tph_t* th, int32_t len)
{
	th->check = tcp_v4_check(len, iph->saddr, iph->daddr, 
							 csum_partial((char *)th, len, 0));
}

static inline void ip_csum(iph_t* iph)
{
	// ip checksum
	ip_send_check(iph);
}

#else // !__KERNEL__

static inline void tcp_csum(iph_t* iph, tph_t* th, int32_t len)
{
	//th->check = tcp_v4_check(len, iph->saddr, iph->daddr, csum_partial((char *)th, len, 0)); 
}

static inline void ip_csum(iph_t* iph)
{
	// ip checksum
	//ip_send_check(iph);
}

#endif // __KERNEL__

static inline int32_t is_little(void)
{
	int32_t i = 1;
	char *p = (char *) &i;
	if (p[0] == 1) // Lowest address contains the least significant byte
		return 1;
	else
		return 0;
}

static inline void flag_init(uint32_t *v, uint32_t f)
{
	(*v) = (f);
}

static inline void flag_add(uint32_t *v, uint32_t f)
{
	(*v) |= (f);
}

static inline void flag_remove(uint32_t *v, uint32_t f)
{
	(*v) &= ~(f);
}

static inline uint32_t flag_get(uint32_t *v, uint32_t f)
{
	return ((*v) & (f));
}

static inline uint32_t flag_get_exact(uint32_t *v, uint32_t f)
{
	return (((*v) & (f)) == (f));
}

static inline int32_t is_same_endian(int32_t is_big)
{
	return (is_little() == !is_big);
}


#endif
