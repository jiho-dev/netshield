#ifndef __OPTIONS_H__
#define __OPTIONS_H__


typedef struct {
	char		*name;
	u_long 		val;
	uint32_t	min;
	uint32_t	max;
	uint32_t	mode;
	void 		*hproc;
	uint32_t 	msg_id;
} option_t;

extern option_t ns_options[];

#define OPT_ITEM_IDX(x)				OPT_IDX_##x
#define OPT_ITEM(n,v,m,x,mo,h)  	[OPT_ITEM_IDX(n)] = {\
	.name=__STR(n),\
	.val=v,\
	.min=m,\
	.max=x,\
	.mode=mo,\
	.hproc=h,\
	.msg_id=OPT_ITEM_IDX(n),\
}

#define GET_OPT_VALUE(x)	 (ns_options[OPT_ITEM_IDX(x)].val)
#define SET_OPT_VALUE(x, v)	 (ns_options[OPT_ITEM_IDX(x)].val = v)
#define GET_OPT_MAX_VALUE(x) (ns_options[OPT_ITEM_IDX(x)].max)

// option 항목이 추가 되는 경우 추가 한다.
enum opt_idx {
	OPT_ITEM_IDX(all_allow_log),
	OPT_ITEM_IDX(all_drop_log),
	OPT_ITEM_IDX(all_drop_log_skip_by_seq),
	OPT_ITEM_IDX(info_log_interval),
	OPT_ITEM_IDX(nat_arp_proxy),

	//
	OPT_ITEM_IDX(age_interval),
	OPT_ITEM_IDX(bl_btime),
	OPT_ITEM_IDX(bl_log),
	OPT_ITEM_IDX(bl_log_param),
	OPT_ITEM_IDX(current_time),
	OPT_ITEM_IDX(frag_pkt_drop_cnt),

	OPT_ITEM_IDX(session_bucket_power),
	OPT_ITEM_IDX(session_cnt),
	OPT_ITEM_IDX(session_cnt_mine),
	OPT_ITEM_IDX(session_cnt_remote),
	OPT_ITEM_IDX(session_cnt_local),
	OPT_ITEM_IDX(session_state),
	OPT_ITEM_IDX(session_max),
	OPT_ITEM_IDX(session_magic),
	OPT_ITEM_IDX(session_max_warn),
	OPT_ITEM_IDX(start_time),
	OPT_ITEM_IDX(version),


	OPT_ITEM_IDX(timeout_udp),   
	OPT_ITEM_IDX(timeout_udp_reply),   
	OPT_ITEM_IDX(timeout_icmp),   
	OPT_ITEM_IDX(timeout_icmp_reply), 
	OPT_ITEM_IDX(timeout_unknown),   

	OPT_ITEM_IDX(drop_tcp_oow),   
	OPT_ITEM_IDX(timeout_tcp),   
	OPT_ITEM_IDX(timeout_syn_sent),   
	OPT_ITEM_IDX(timeout_syn_rcv),    
	OPT_ITEM_IDX(timeout_fin_wait),  
	OPT_ITEM_IDX(timeout_close_wait), 
	OPT_ITEM_IDX(timeout_last_ack),   
	OPT_ITEM_IDX(timeout_time_wait),  
	OPT_ITEM_IDX(timeout_close),      
	OPT_ITEM_IDX(timeout_max_retrans),

	OPT_MAX

};



#endif
