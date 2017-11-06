#include <include_os.h>

#include <ns_type_defs.h>
#include <skey.h>
#include <timer.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <log.h>
#include <misc.h>

//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);

uint16_t parse_ip_options(iph_t* iph);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

int32_t build_skey(iph_t *iph, sk_t *key, int32_t *pkt_len, uint32_t *flags)
{
	int32_t hlen = *pkt_len;
	uint8_t *data = (uint8_t *)iph + hlen;
	tph_t *t = NULL;
	uph_t *u = NULL;
	ich_t *ic = NULL;
	int32_t ret = 0;

	ENT_FUNC(3);

	// 패킷 정보를 이용해서 룰 검색 데이터를 만든다.
	// 영역 검사 등 비교를 위해서는 host order로 저장 되어야 한다.
	key->src = ntohl(iph->saddr);
	key->dst = ntohl(iph->daddr);
	key->proto = iph->protocol;

	switch (iph->protocol) {
	case IPPROTO_UDP:
		u = (uph_t *)data;
		*pkt_len += sizeof(uph_t);

		key->sp = ntohs(u->source);
		key->dp = ntohs(u->dest);

		break;

	case IPPROTO_TCP:
		t = (tph_t *)data;
		*pkt_len += sizeof(tph_t);

		key->sp = ntohs(t->source);
		key->dp = ntohs(t->dest);

		break;

	case IPPROTO_ICMP: 
		{
			uint8_t icmp_type[2] = {0 , 0};

			ic = (ich_t *)data;
			*pkt_len += sizeof(ich_t);

			/*
			 *	18 is the highest 'known' ICMP type. Anything else is a mystery
			 *	RFC 1122: 3.2.2  Unknown ICMP messages types MUST be silently  discarded.
			 *	from netfilter
			 */

			if (ic->type > NR_ICMP_TYPES) {
				ret = -1;
				ns_err("Invalid ICMP type : %d", ic->type);
				break;
			}

			// icmp type
			icmp_type[0] = ic->type;
			icmp_type[1] = 0;
			key->sp = 0;

			switch (ic->type) {
			case ICMP_ECHOREPLY:
			case ICMP_ECHO:
				// icmp id를 채운다.
				key->sp = ntohs(ic->un.echo.id);
				icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
				break;

			case 9:
			case 10:
				break;

			case ICMP_TIMESTAMP:
			case ICMP_TIMESTAMPREPLY:
				*pkt_len += 12;
				icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
				break;

			case ICMP_INFO_REQUEST:
			case ICMP_INFO_REPLY:
				icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
				break;

			case ICMP_ADDRESS:
			case ICMP_ADDRESSREPLY:
				icmp_type[1] = ns_get_inv_icmp_type(ic->type, 0);
				*pkt_len += 4;
				break;

			case ICMP_DEST_UNREACH:
			case ICMP_SOURCE_QUENCH:
			case ICMP_REDIRECT:
			case ICMP_TIME_EXCEEDED:
			case ICMP_PARAMETERPROB:
				*pkt_len += (sizeof(iph_t) + 8);
				*flags |= TASK_FLAG_ICMPERR;

				break;

			default:
				break;
			}

			key->dp = icmp_type[0] ^ icmp_type[1];
		}
		break;

	default:
		// 나머지 프로토콜은 src/dst ip만으로 구분한다.
		key->sp = 0;
		key->dp = 0;

		break;
	}

	return ret;
}

int32_t parse_inet_protocol(ns_task_t *nstask)
{
	skb_t *skb = nstask->pkt;
	iph_t *iph;
	int32_t dlen;

	ENT_FUNC(3);

	iph = ns_iph(skb);

	// XXX dlen과 iph->tot_len이 같은지 검사해야 한다 !
	dlen = skb->len;

	nstask->ip_hlen = iph->ihl << 2;
	// is this correct length ?
	if (nstask->ip_hlen > dlen) {
		return NS_DROP;
	}

	nstask->ip_dlen = dlen - nstask->ip_hlen;
	// no more IP data
	if (nstask->ip_dlen < 1) {
		nstask->ip_dlen = 0;

		return NS_ACCEPT;
	}

	ns_set_transport_header(nstask->pkt, (uint8_t *)iph, nstask->ip_hlen);
	nstask->l4_hlen = 0;
	nstask->l4_dlen = 0;

	nstask->iopt = parse_ip_options(iph);

	switch (iph->protocol) {
		case IPPROTO_TCP:
			nstask->l4_hlen = ns_tcph(nstask->pkt)->doff << 2;
			break;

		case IPPROTO_UDP:
			nstask->l4_hlen = sizeof(uph_t);
			break;

		case IPPROTO_ICMP:
			nstask->l4_hlen = sizeof(ich_t);
			break;

#if 0
		case IPPROTO_AH:
			nstask->l4_hlen = sizeof(ah_t);
			break;

		case IPPROTO_ESP:
			nstask->l4_hlen = sizeof(esp_t);
			break;
#endif

		default:
			break;
	}

	// invalid L4 Header length
	if (nstask->l4_hlen > nstask->ip_dlen) {
		dbg(5, "invalid IP packet !");

		return NS_DROP;
	}

	nstask->l4_dlen = nstask->ip_dlen - nstask->l4_hlen;
	nstask->l4_data = (char *)ns_raw(nstask->pkt) + nstask->l4_hlen;

#if 0
	if (iph->protocol == IPPROTO_TCP && parse_tcp_options(nstask)) {
		return NS_DROP;
	}
#endif

	FUNC_TEST_MSG(4, "Packet length info: ip_len=%d, ip_hlen=%d, ip_dlen=%d, l4_dlen=%d, l4_hlen=%d",
			ns_iplen(nstask->pkt), nstask->ip_hlen, nstask->ip_dlen, nstask->l4_dlen, nstask->l4_hlen);

	return NS_ACCEPT;
}

int32_t init_task_info(ns_task_t *nstask)
{
	skb_t *skb = nstask->pkt;
	iph_t *iph;
	int32_t pkt_len;
	int32_t ret = NS_ACCEPT;

	ENT_FUNC(3);

	iph = ns_iph(nstask->pkt);
	// 패킷 사이즈를 검사할 크기
	pkt_len = nstask->ip_hlen;

	ret = build_skey(iph, &nstask->key, &pkt_len, &nstask->flags);

	if (unlikely(ret == 0 && nstask->flags & TASK_FLAG_ICMPERR)) {
		uint32_t f;
		uint128_t swap_ip;
		uint16_t swap_port;

		FUNC_TEST_MSG(4, "build_skey for icmp error");

		// icmp error 패킷에는 원본 패킷이 실려 있다.
		iph = (iph_t *)(ns_raw(nstask->pkt) + sizeof(ich_t));

		DUMP_PKT(4, iph, nstask->key.inic);

		// icmp error 패킷은 이후 모든 처리를 데이터 부분에 실려 있는 
		// 패킷을 기준으로 처리 한다.
		// nat 인 경우는 별도의 처리가 필요 하다.
		pkt_len = nstask->ip_hlen;
		ret = build_skey(iph, &nstask->key, &pkt_len, &f);

		// 역방향 키를 찾기 위해서 키를 뒤집는다.
		// 이때 NAT도 역방향 키가 검색 된다.

		// swap ip
		swap_ip = nstask->key.src;
		nstask->key.src = nstask->key.dst;
		nstask->key.dst = swap_ip;

		// swap port
		swap_port = nstask->key.sp;
		nstask->key.sp = nstask->key.dp;
		nstask->key.dp = swap_port;
	}

	// for debugging
	if (1) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			if (nstask->key.sp == 22 || nstask->key.dp == 22) {
				return NS_STOP;
			}
			break;

		case IPPROTO_UDP:
			return NS_STOP;
			break;

		case IPPROTO_ICMP:
			break;

		default:
			break;
		}

	}

	if (ret != 0) {
		// some error
		dbg(5, "ret=%d", ret);
		ret = NS_DROP;
	}
	else if (!pskb_may_pull(skb, pkt_len)) {
		ret = 1;
		ns_err("Abnormal sized packet: SRC=" IP_FMT " DST=" IP_FMT " PROTO=%d hsize=%d dsize=%d",
				IPN(iph->saddr), IPN(iph->daddr), iph->protocol, nstask->ip_hlen, 0);
		ret = NS_ACCEPT;
	}
	else {
		ret = NS_ACCEPT;
	}

	DBGKEY(4, KEY, &nstask->key);

	return ret;
}

uint16_t parse_ip_options(iph_t* iph)
{
	uint8_t 	*optp;
	int32_t    	optslen = 0;
	int32_t    	optsdone = 0;
	int32_t    	olen;
	uint16_t  	ip_opt_flags = 0;

	optslen = iph->ihl * 4 - sizeof(iph_t);
	if (optslen < 1)
		return 0;

	optp = (uint8_t*) iph + sizeof(iph_t);

	while (optsdone < optslen) {
		switch(*optp) {
		case IPOPT_END:
			/*end of option list - RFC791*/
			optsdone = optslen;
			break;

		case IPOPT_NOOP:
			/* No op*/
			optp++;
			optsdone++;
			break;

		case IPOPT_SEC:
		case 133:
			/*Security - see RFC1108*/
			/*we sanity check this, but otherwise pass it normally*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_SEC;
			break;

		case IPOPT_LSRR:
			/*Loose Source and Record Route - RFC791*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_LSRR;
			break;

		case IPOPT_SSRR:
			/*Strict Source and Record Route - RFC791*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_SSRR;
			break;

		case IPOPT_RR:
			/*Record Route - RFC791*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_RR;
			break;

		case IPOPT_SID:
			/*Stream ID - RFC791*/
			/*we sanity check this, but otherwise pass it normally*/
			optp++;
			olen=*optp;
			if (olen!=4) {
				dbg(2, "Incorrect stream ID length: %d", olen);
				return ip_opt_flags;
			}
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_SID;
			break;

		case IPOPT_TIMESTAMP:
			/*Internet timestamp - RFC791*/
			/*harmless...*/
			optp++;
			olen=*optp;
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_TIMESTAMP;
			break;

		case IPOPT_RA:
			/*Router Alert - See RFC2113*/
			/*we sanity check this, but otherwise pass it normally*/
			optp++;
			olen=*optp;
			if (olen!=4) {
				dbg(0, "Incorrect router alert length: %d", olen);
				return ip_opt_flags;
			}
			optp+=olen-1;
			optsdone+=olen;
			ip_opt_flags |= WIPOPT_RA;
			break;

		default:
			optp ++;
			optsdone++;
			dbg(0, "unknown option type: %d", *optp);
			break;
		}

		if (optsdone>optslen) {
			dbg(0, "bogus variable-length IP option");
		}
	}

	return ip_opt_flags;
}

