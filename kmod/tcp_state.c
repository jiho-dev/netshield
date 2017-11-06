#include <include_os.h>

#include <ns_type_defs.h>
#include <skey.h>
#include <timer.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <tcp_state.h>
#include <options.h>

//////////////////////////////////////////////////////

atomic_t g_tcp_asbuf_cnt;

static const u_long *tcps_timeout[TCPS_MAX] = { 
	&GET_OPT_VALUE(timeout_close), 		// listen , 10 sec
	&GET_OPT_VALUE(timeout_syn_sent),		// syn sent , 120 sec
	&GET_OPT_VALUE(timeout_syn_rcv),		// syn received , 60 sec
	NULL,							// established , 3600 sec
	&GET_OPT_VALUE(timeout_close_wait), 	// close wait , 60 sec
	&GET_OPT_VALUE(timeout_fin_wait),	  	// fin wait_1 , 120 sec
	&GET_OPT_VALUE(timeout_close_wait), 	// closing 	, 60 sec
	&GET_OPT_VALUE(timeout_last_ack), 	// last ack , 30 sec
	&GET_OPT_VALUE(timeout_last_ack),	  	// fin wait_2 , 30 sec
	&GET_OPT_VALUE(timeout_time_wait), 	// time wait , 10 sec
	&GET_OPT_VALUE(timeout_close), 		// closed , 10 sec
};

static const char *tcps_name[TCPS_MAX] = { 
	"LISTEN",
	"SYN_SENT",
	"SYN_RCVD",
	"ESTABLISHED",
	"CLOSE_WAIT",
	"FIN_WAIT_1",
	"CLOSING",
	"LAST_ACK",
	"FIN_WAIT_2",
	"TIME_WAIT",
	"CLOSED",
};

DECLARE_DBG_LEVEL(2);


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */


//////////////////////////////////////////////////////////////

int32_t parse_tcp_options(ns_task_t* nstask)
{
	uint8_t buff[40];
	uint8_t *ptr;
	int32_t length = nstask->l4_hlen - sizeof(struct tcphdr);
	int32_t opsize, i;
	uint32_t tmp;

	if (length < 1)
		return 0;

	ptr = skb_header_pointer(nstask->pkt, nstask->ip_hlen + sizeof(struct tcphdr), length, buff);
	if (ptr == NULL)
		return -1;

	nstask->topt.td_scale = nstask->topt.flags = nstask->topt.sack = 0;

	while (length > 0) {
		int32_t opcode=*ptr++;

		switch (opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;

		default:
			opsize=*ptr++;

			if (opsize < 2) /* "silly options" */
				return 0;

			if (opsize > length)
				break;	/* don't parse partial options */

			switch(opcode) {
			case TCPOPT_SACK_PERM:
				if (opsize == TCPOLEN_SACK_PERM)
					nstask->topt.flags |= TOPT_FLAG_SACK_PERM;
				break;

			case TCPOPT_WINDOW:
				if (opsize == TCPOLEN_WINDOW) {
					nstask->topt.td_scale = *(uint8_t *)ptr;

					if (nstask->topt.td_scale > 14) {
						/* See RFC1323 */
						nstask->topt.td_scale = 14;
					}

					nstask->topt.flags |= TOPT_FLAG_WINDOW_SCALE;
				}
				break;

			case TCPOPT_MSS:
				if(opsize == TCPOLEN_MSS) {
					nstask->topt.mss = ntohs(get_unaligned((__u16 *)ptr));
					nstask->topt.flags |= TOPT_FLAG_MSS;
				}
				break;

			case TCPOPT_SACK:
				if ( (opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
					&& !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK)) {

					for (i = 0; i < (opsize - TCPOLEN_SACK_BASE); i += TCPOLEN_SACK_PERBLOCK) {
						tmp = ntohl(*((u_int32_t *)(ptr+i)+1));

						if (after(tmp, nstask->topt.sack)) {
							nstask->topt.flags |= TOPT_FLAG_SACK;
							nstask->topt.sack = tmp;
						}
					}
				}

				break;

			case TCPOPT_TIMESTAMP:
				if (opsize == TCPOLEN_TIMESTAMP) {
					uint32_t *tsecr;

					nstask->topt.flags |= TOPT_FLAG_TIMESTAMP;
					tsecr = (uint32_t*)ptr;

					//opt_rx->rcv_tsval = get_unaligned_be32(ptr);
					nstask->topt.tsval = ntohl(*tsecr);
				}

			} // end of opcode

			ptr += opsize - 2;
			length -= opsize;
		}
	}

	return 0;
}

uint32_t optlen(const uint8_t *opt, uint32_t offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0) return 1;
	else return opt[offset+1];
}

#define get_nic_mtu(pkt)  ((pkt->dst) ? (pkt->dst->dev->mtu) : ((pkt->dev) ? (pkt->dev->mtu) : 1492))

int32_t tcp_mss_main(ns_task_t* nstask) 
{
	return NS_ACCEPT;
}

void dump_tcp_state(tph_t *th, tcpst_t *tcpst, int32_t dir, uint16_t nstate, uint32_t changed)
{
	uint16_t c_st, s_st;
	char buf[256];

	c_st = tcpst->tseq[0].state;
	s_st = tcpst->tseq[1].state;

	snprintf(buf, 256, "%s(%c%c%c%c%c): SRC: %s, DST: %s, NEW: %s(%c), seq=%u, ack=%u", 
			 dir?"RES":"REQ",
			 th->syn?'S':' ', th->ack?'A':' ', th->fin?'F':' ', th->rst?'R':' ', th->psh?'P':' ', 
			 tcps_name[c_st],
			 tcps_name[s_st],
			 tcps_name[nstate], changed?'C':' ', 
			 ntohl(th->seq), ntohl(th->ack_seq));

	dbg(0, "TCPST=>%s", buf);

	dbg(0, "SRC: end=%u, maxend=%u, DST: end=%u, maxend=%u", 
		tcpst->tseq[0].end, tcpst->tseq[0].maxend,
		tcpst->tseq[1].end, tcpst->tseq[1].maxend);
}

uint32_t tcp_track_states(ns_task_t *nstask, uint32_t *timeout)
{
	skb_t* skb = nstask->pkt;
	int32_t dir = ISRES(nstask);
	iph_t *iph = ns_iph(skb);
	struct tcphdr *th, _tcph;
	session_t* si = nstask->si;
	tcpst_t *tcpst = &si->tcpst;
	uint16_t ostate, nstate;
	uint32_t dlen;
	uint32_t changed=0;

	th = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return 0;

	/*
	dir == 0 : a packet from source to dest
	dir == 1 : a packet from dest to source
	 */

	ostate = tcpst->tseq[!dir].state;
	nstate = tcpst->tseq[dir].state;
	dlen = nstask->l4_dlen;

	if (th->rst) {
#if 0
		if (th->psh && dlen == 0) {
			nstate = TCPS_CLOSED;
		}
		else {
			nstate = TCPS_CLOSE_WAIT;
		}

#else
		// reset 일때는 세션을 무조건 닫는다.
		nstate = TCPS_TIME_WAIT;
		tcpst->tseq[!dir].state = TCPS_TIME_WAIT;
		changed = 1;
#endif

		goto END;
	}

	switch (nstate) {
	case TCPS_LISTEN: /* 0 */
		if (th->syn && th->ack) {
			// 'dir' received an S and sends SA in response, LISTEN -> SYN_RECEIVED
			nstate = TCPS_SYN_RECEIVED;
		}
		else if (th->syn && !th->ack) {
			// 'dir' sent S, LISTEN -> SYN_SENT
			nstate = TCPS_SYN_SENT;
		}
		else if (!th->syn && !th->fin && !th->rst && th->ack) {
			/*
			 * we saw an A, guess 'dir' is in ESTABLISHED mode
			 */
			nstate = TCPS_ESTABLISHED;
		}
		break;

	case TCPS_SYN_SENT: /* 1 */
		if (th->syn && !th->ack) {
			/*
			 * A retransmitted SYN packet.  
			 */
		}
		else if (!th->syn && !th->fin && th->ack) {
			/*
			 * we see an A from 'dir' which is in SYN_SENT
			 * state: 'dir' sent an A in response to an SA
			 * which it received, SYN_SENT -> ESTABLISHED
			 */
			nstate = TCPS_ESTABLISHED;
		}
		else if (th->fin) {
			/*
			 * we see an F from 'dir' which is in SYN_SENT
			 * state and wants to close its side of the
			 * connection; SYN_SENT -> FIN_WAIT_1
			 */
			nstate = TCPS_FIN_WAIT_1;
		}
		else if (th->syn && th->ack) {
			/*
			 * we see an SA from 'dir' which is already in
			 * SYN_SENT state, this means we have a
			 * simultaneous open; SYN_SENT -> SYN_RECEIVED
			 */
			nstate = TCPS_SYN_RECEIVED;
		}
		break;

	case TCPS_SYN_RECEIVED: /* 2 */
		if (!th->syn && !th->fin && th->ack) {
			/*
			 * we see an A from 'dir' which was in
			 * SYN_RECEIVED state so it must now be in
			 * established state, SYN_RECEIVED ->ESTABLISHED
			 */
			nstate = TCPS_ESTABLISHED;
		}
		else if (th->syn && th->ack) {
			/*
			 * We see an SA from 'dir' which is already in
			 * SYN_RECEIVED state.
			 */
		}
		else if (th->fin) {
			/*
			 * we see an F from 'dir' which is in
			 * SYN_RECEIVED state and wants to close its
			 * side of the connection; SYN_RECEIVED -> FIN_WAIT_1
			 */
			nstate = TCPS_FIN_WAIT_1;
		}
		break;

	case TCPS_ESTABLISHED: /* 3 */
		if (th->fin) {
			/*
			 * 'dir' closed its side of the connection;
			 * this gives us a half-closed connection;
			 * ESTABLISHED -> FIN_WAIT_1
			 */
			if (0 /*GET_OPT_VALUE(dsync)*/) {
				// 세션 동기화인 경우 마지막 단계로 진입
				nstate = TCPS_TIME_WAIT;
			}
			else {
				if (ostate == TCPS_FIN_WAIT_1) {
					nstate = TCPS_CLOSING;
				} 
				else {
					nstate = TCPS_FIN_WAIT_1;
				}
			}
		} 
		else if (th->ack) {
			/*
			 * an ACK, should we exclude other flags here?
			 */
			if (/*GET_OPT_VALUE(dsync) &&*/ ostate == TCPS_TIME_WAIT) {
				nstate = TCPS_TIME_WAIT;
			}
			else if (ostate == TCPS_FIN_WAIT_1) {
				/*
				 * We know the other side did an active
				 * close, so we are ACKing the recvd
				 * FIN packet (does the window matching
				 * code guarantee this?) and go into
				 * CLOSE_WAIT state; this gives us a
				 * half-closed connection
				 */
				nstate = TCPS_CLOSE_WAIT;
				// 반대편은 FIN_WAIT_2로 변경
				tcpst->tseq[!dir].state = TCPS_FIN_WAIT_2;
			} 
			else if (ostate < TCPS_CLOSE_WAIT) {
				/*
				 * still a fully established connection,
				 * then reset timeout
				 */
				nstate = TCPS_ESTABLISHED;
			}
		}
		break;

	case TCPS_CLOSE_WAIT: /* 4 */
		if (th->fin) {
			/*
			 * application closed and 'dir' sent a FIN,
			 * we're now going into LAST_ACK state
			 */
			nstate = TCPS_LAST_ACK;
		} 
		else {
			/*
			 * we remain in CLOSE_WAIT because the other
			 * side has closed already and we did not
			 * close our side yet; reset timeout
			 */
			nstate = TCPS_CLOSE_WAIT;
		}
		break;

	case TCPS_FIN_WAIT_1: /* 5 */
		if (th->ack && ostate > TCPS_CLOSE_WAIT) {
			/*
			 * if the other side is not active anymore
			 * it has sent us a FIN packet that we are
			 * ack'ing now with an ACK; this means both
			 * sides have now closed the connection and
			 * we go into TIME_WAIT
			 */
			/*
			 * XXX: how do we know we really are ACKing
			 * the FIN packet here? does the window code
			 * guarantee that?
			 */
			nstate = TCPS_TIME_WAIT;
		} 
		else {
			/*
			 * we closed our side of the connection
			 * already but the other side is still active
			 * (ESTABLISHED/CLOSE_WAIT); continue with
			 * this half-closed connection
			 */
			nstate = TCPS_FIN_WAIT_1;
		}
		break;

	case TCPS_CLOSING: /* 6 */
		if (!th->fin && th->ack) {
			nstate = TCPS_TIME_WAIT;
		}
		break;

	case TCPS_LAST_ACK: /* 7 */
#if 0
		if (th->ack) {
			if (th->psh || dlen) {
				/*
				 * there is still data to be delivered,
				 * reset timeout
				 */
				//rval = 1;
			}
			else {
				//rval = 2;
			}
		}
		/*
		 * we cannot detect when we go out of LAST_ACK state to
		 * CLOSED because that is based on the reception of ACK
		 * packets; ipfilter can only detect that a packet
		 * has been sent by a host
		 */
#endif
		break;

	case TCPS_FIN_WAIT_2: /* 8 */
		if (th->ack) {
			nstate = TCPS_TIME_WAIT;
			tcpst->tseq[!dir].state = TCPS_TIME_WAIT;
		}
		break;

	case TCPS_TIME_WAIT: /* 9 */
#if 0
		/* we're in 2MSL timeout now */
		if (ostate == TCPS_LAST_ACK) {
			nstate = TCPS_CLOSED;
		}
#endif
		// 강제로 상태를 변경 한다.
		changed = 1;
		break;

	case TCPS_CLOSED: /* 10 */
		break;

	default :
		break;
	}

END:

	if (changed == 0) {
		changed = tcpst->tseq[!dir].state != ostate || tcpst->tseq[dir].state  != nstate;
	}

	tcpst->tseq[dir].state = nstate;
	if (nstate == TCPS_ESTABLISHED && tcpst->tseq[!dir].state != TCPS_ESTABLISHED) {
		// 반대편 상태도 ESTABLISHED로 만든다.
		tcpst->tseq[!dir].state = TCPS_ESTABLISHED;
	}

	if (tcps_timeout[nstate] == NULL) {
		*timeout = si->timeout;
	}
	else {
		*timeout = *tcps_timeout[nstate];
	}

	//dump_tcp_state(th, tcpst, dir, nstate, changed);

	return changed;
}

uint32_t tcp_init_seq(ns_task_t *nstask)
{
	tph_t *th;
	tcpst_t *tcpst;

	ENT_FUNC(3);

	th = ns_tcph(nstask->pkt);
	tcpst = &nstask->si->tcpst;

	// 다음 패킷의 시작 seq
	tcpst->tseq[0].end = ntohl(th->seq) + nstask->l4_dlen + (th->syn + th->fin);
	tcpst->tseq[0].maxwin = ntohs(th->window);

	if (tcpst->tseq[0].maxwin == 0) {
		tcpst->tseq[0].maxwin = 1;
	}

	/* SYN에 의해 세션이 생성된 경우가 아니면
	 * maxend값과 peer의 maxwind 값을 예측할 수 없으므로 TS_MAXACKWINDOW 만큼 더해준다. */
	if (th->syn && !th->ack) {
		tcpst->tseq[0].maxend = tcpst->tseq[0].end;
		tcpst->tseq[1].maxwin = 1;
	} 
	else {
		tcpst->tseq[0].maxend = tcpst->tseq[0].end + TS_MAXACKWINDOW;
		tcpst->tseq[1].maxwin = TS_MAXACKWINDOW;
		tcpst->tseq[1].end = ntohl(th->ack_seq);
		tcpst->tseq[1].maxend = tcpst->tseq[1].end + tcpst->tseq[0].maxwin;
	}

	/* TCP window scale option이 있으면 플래그를 설정한다.
	 * syn이 설정되어 있을 때만 해당 옵션이 존재한다. */
	if (th->syn) {
		if ((nstask->topt.flags & TOPT_FLAG_WINDOW_SCALE) && 
			nstask->topt.td_scale != 0) {
			tcpst->tseq[0].wscale = nstask->topt.td_scale;
			tcpst->tseq[0].flags = TS_WSCALE_SEEN | TS_WSCALE_FIRST;
		}

		if ((nstask->topt.flags & TOPT_FLAG_SACK_PERM)) {
			tcpst->tseq[0].flags |= TS_SACK_PERMIT;
		}
	}

	return 0;
}

uint32_t tcp_track_seq(ns_task_t *nstask)
{
	skb_t* skb = nstask->pkt;
	int32_t dir = ISRES(nstask);
	iph_t *iph = ns_iph(skb);
	struct tcphdr *th, _tcph;
	session_t* si = nstask->si;
	tcpst_t *tcpst = &si->tcpst;
	tseq_t *ts_req, *ts_res;
	uint32_t seq, seq_min, ack, end;
	uint16_t win;
	int32_t ackskew;

	th = skb_header_pointer(skb, iph->ihl * 4, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return 0;

	/*
	dir == 0 : a packet from source to dest
	dir == 1 : a packet from dest to source
	 */
	ts_req = &tcpst->tseq[dir];  // fdata
	ts_res = &tcpst->tseq[!dir]; // tdata

	seq = ntohl(th->seq);
	ack = ntohl(th->ack_seq);

	// SYN이 설정되어 있으면 window scale 적용을 받지 않는다.
	if (th->syn)
		win = ntohs(th->window);
	else 
		win = ntohs(th->window) << ts_req->wscale;

	// zero window인 경우 window probing packet을 위해 1로 설정한다.
	if (win == 0)
		win = 1;

	// window scale이 설정되어 있으면 SYN 패킷이 아닌 경우에 적용한다.
	if (!th->syn && (ts_req->flags & TS_WSCALE_FIRST)) {
		if ((ts_res->flags & TS_WSCALE_SEEN)) {
			ts_req->flags  &= ~TS_WSCALE_FIRST;
			ts_req->maxwin = win;
		} 
		else {
			ts_req->wscale = 0;
			ts_req->flags = 0;
			ts_res->wscale = 0;
			ts_res->flags = 0;
		}
	}

	/* 다음에 와야 할 sequence number.
	 * SYN이나 FIN이 설정되어 있으면 1을 더하고
	 * 그렇지 않으면 TCP 데이터 길이를 더한다. */
	end = seq;
	if (th->syn || th->fin)
		end += 1;
	else 
		end += nstask->l4_dlen;

	// sender의 TCP 상태 정보가 설정되어 있지 않으면 현재 패킷 정보로 초기화한다.
	if (ts_req->end == 0) {
		ts_req->end = end;
		ts_req->maxwin = 1;

		// SYN+ACK인 경우 maxend도 유효한 값으로 초기화한다.
		if (th->syn && th->ack) {
			ts_req->maxend = end + win;
		}
	}

	if (!th->ack) {
		// ack가 없으면 ack값을 세팅해서 정상으로 간주한다.
		ack = ts_res->end;
	} 
	else if ((th->rst && th->ack) && (ack == 0)) {
		/* 간혹, RST 패킷에 ack값이 0으로 오는 경우가 있는데
		 * 이때에는 ack값을 세팅해서 정상으로 간주한다 */
		ack = ts_res->end;
	}

	/* data가 없는 경우, seq는 유효하다고 판단
	 * lower bound < seq < uppder bound 가 되도록 seq를 세팅한다.*/
	if (seq == end) {
		seq = end = ts_req->end;
	}

	/* maxend 는 end보다 항상 커야 한다. maxend가 잘못된 값으로
	 * 세팅되어있는 경우 보정해준다. */
	if (ts_req->end >= ts_req->maxend) {
		ts_req->maxend = ts_req->end + ts_res->maxwin;
	}

	ackskew = ts_res->end - ack;

	if (ts_req->end < ts_res->maxwin) {
		seq_min = 0;
	} else {
		seq_min = ts_req->end - ts_res->maxwin;
	}

	/* seq와 ack가 유효한지 검사한다.
	 *
	 * SYN패킷에 의해 정상적으로 생성된 세션인 경우 다음의 식을 만족해야한다.
	 *
	 * 1) max{seq + len} - Peer's max{max(win, 1)} <= seq <= Peer's max{ack + max(win, 1)} - len
	 * 2) max{seq + len} - TS_MAXACKWINDOW <= ack <= Peer's max{seq + len}
	 *
	 *
	 * Connection 중간에 생성된 세션은 peer's TCP정보가 세팅되지 않았으면
	 * 정상으로 간주한다.
	 *
	 * 강력한 TCP제어인 경우에만 검사를 하고 보통 수준의 TCP제어이면
	 * 항상 유효하다고 판단한다.
	 *
	 * ps.
	 * 1) Real Stateful TCP Packet Filtering in IP Filter 논문 참조
	 * 2) ipfilter 4.0 참조,
	 *
	 * */

	if ((end > ts_req->maxend) || (seq < seq_min)) {
		return 1;
	}

	if (ackskew < -(TS_MAXACKWINDOW << ts_req->wscale) || 
		ackskew > (TS_MAXACKWINDOW << ts_req->wscale)) {
		return 1;
	}

	/* fragment패킷으로 인해(total length를 미리 알수 없다)
	 * ackskew < 0 인 경우가 생길 수 있기 때문에
	 * ack의 upper bound를 Peer's max{seq + len} 으로 하지 않고
	 * TS_MAXACKWINDOW를 고려해 loose하게 정한다.
	 * */

	if (ackskew < 0) {
		ts_res->end = ack;
	}

	// tcp상태정보를 update한다.
	if (ts_req->maxwin < win) {
		ts_req->maxwin = win;
	}

	if (end > ts_req->end) {
		ts_req->end = end;
	}

	if (ack + win >= ts_res->maxend) {
		ts_res->maxend = ack + win;
	}

	// SYN+ACK 패킷의 window scale option을 조사한다.
	if (th->syn && th->ack) {
		/* window scale option이 있는 경우 플래그 세팅
		 * 없는 경우 peer의 window scale옵션 취소 */

		if (nstask->topt.flags & TOPT_FLAG_WINDOW_SCALE &&
			nstask->topt.td_scale != 0) {
			ts_req->wscale = nstask->topt.td_scale;
			ts_req->flags   = TS_WSCALE_SEEN | TS_WSCALE_FIRST;
		} 

		if ((nstask->topt.flags & TOPT_FLAG_SACK_PERM)) {
			ts_req->flags |= TS_SACK_PERMIT;
		}
	}

	return 0;
}
