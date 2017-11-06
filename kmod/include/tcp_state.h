#ifndef __TCP_STATE_H__
#define __TCP_STATE_H__

/*
 * TCP States
 */

enum {
	TCPS_LISTEN			= 0,	/* listening for connection */
	TCPS_SYN_SENT		= 1,	/* active, have sent syn */
	TCPS_SYN_RECEIVED	= 2,	/* have send and received syn */
	/* states < TCPS_ESTABLISHED are those where connections not established */

	TCPS_ESTABLISHED	= 3,	/* established */
	TCPS_CLOSE_WAIT	 	= 4, 	/* rcvd fin, waiting for close */

	/* states > TCPS_CLOSE_WAIT are those where user has closed */
	TCPS_FIN_WAIT_1		= 5,	/* have closed, sent fin */
	TCPS_CLOSING		= 6,	/* closed xchd FIN; await FIN ACK */
	TCPS_LAST_ACK	 	= 7,	/* had fin and close; await FIN ACK */

	/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
	TCPS_FIN_WAIT_2	 	= 8,	/* have closed, fin is acked */
	TCPS_TIME_WAIT		= 9, 	/* in 2*msl quiet wait after close */
	TCPS_CLOSED			= 10, 	/* closed */

	TCPS_MAX			= 11
};


uint32_t tcp_track_states(ns_task_t *nstask, uint32_t *timeout);
uint32_t tcp_init_seq(ns_task_t *nstask);
uint32_t tcp_track_seq(ns_task_t *nstask);


#endif
