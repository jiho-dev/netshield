#ifndef __NETSHIELD_HOOK_H__
#define __NETSHIELD_HOOK_H__

#ifdef CONFIG_NETSHIELD_HOOK

#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

//////////////////////////////////////////////////////////

typedef int (*OKFN)(struct net *, struct sock *, struct sk_buff*);

typedef struct netshield_hook_state_s {
	int32_t pf;
	unsigned int hook;
	struct net *net;
	struct sock *sk;
	struct sk_buff *skb;
	struct net_device *in;
	struct net_device *out; 
	int call_okfn;
	OKFN okfn; 
} netshield_hook_state_t;

typedef int (*NS_CB_MAIN)(netshield_hook_state_t *state);

typedef struct _netshield_hook_t {
	int32_t pf;
	NS_CB_MAIN ns_main;
} netshield_hook_t;

extern netshield_hook_t	*netshield_hook_op[AF_MAX];

///////////////////////////////////////////////////////

static inline int register_netshield_hook(netshield_hook_t* h)
{
	if (h == NULL || h->pf >= AF_MAX)
		return -1;

	netshield_hook_op[h->pf] = h;

	return 0;
}

static inline void unregister_netshield_hook(int32_t pf)
{
	if (pf < 0 || pf >= AF_MAX)
		return;

	netshield_hook_op[pf] = NULL;
}

static inline int netshield_hook(u_int8_t pf, 
			  unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *),
			  int cond, int call_okfn)
{
	netshield_hook_t *nshook_op;
	netshield_hook_state_t state;

	state.pf = pf;
	state.hook = hook;
	state.sk = sk;
	state.net = net;
	state.skb = skb;
	state.in = indev;
	state.out = outdev;
	state.okfn = okfn;
	state.call_okfn = call_okfn;

	nshook_op = netshield_hook_op[pf];

	if (!cond || nshook_op == NULL || nshook_op->ns_main == NULL) {
		// netshield 모듈이 내려가면 라우터로 동작 한다.
		if (call_okfn)
			return okfn(net, sk, skb);
		else 
			return 1;
	}

	return nshook_op->ns_main(&state);
}

static inline int
NF_HOOK_COND(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	     struct sk_buff *skb, struct net_device *in, struct net_device *out,
	     int (*okfn)(struct net *, struct sock *, struct sk_buff *),
	     bool cond)
{
	return netshield_hook(pf, hook, net, sk, skb, in, out, okfn, cond, 1);
}

static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	struct sk_buff *skb, struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	return netshield_hook(pf, hook, net, sk, skb, in, out, okfn, 1, 1);
}

static inline int
nf_hook(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	struct sk_buff *skb, struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	return netshield_hook(pf, hook, net, sk, skb, in, out, okfn, 1, 1);
}

#endif

#endif
