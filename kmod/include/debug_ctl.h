#ifndef __DEBUG_CTL_H__
#define __DEBUG_CTL_H__


#ifdef CONFIG_NS_DEBUG

typedef struct {
	uint32_t	*level;
	char		*name;
	ctltab_t 	*tab;
	int32_t 	cnt;
	int32_t 	idx;
} debug_file_lev_t;

typedef struct {
	char *file;
	char *func;

	list_head_t 	list;
	int32_t 		level;
	debug_file_lev_t *parent;

} debug_func_list_t;

#endif

#endif
