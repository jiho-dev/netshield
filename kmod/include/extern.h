#ifndef __EXTERN_H_
#define __EXTERN_H_


int32_t netshield_main(netshield_hook_state_t *state);
int32_t netshield_post_main(netshield_hook_state_t *state);
int32_t netshield_init(void);
void  	netshield_clean(void);
void  	netshield_enable(void);
void  	netshield_disable(void);


#endif
