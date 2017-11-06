#ifndef __NS_LOG_H__
#define __NS_LOG_H__

enum {
	LOG_ACT_ALLOW = 0,
	LOG_ACT_DROP,
	LOG_ACT_REPLACE,
	LOG_ACT_FORWARD,
	LOG_ACT_BLACKLIST,

	LOG_ACT_MAX
};

enum {
	LOG_STAT_OPEN = 0,
	LOG_STAT_CLOSE,
	LOG_STAT_INFO,
	LOG_STAT_EXCEPTION,

	LOG_STAT_MAX
};

enum {
	LOG_LEV_ERR = 0,
	LOG_LEV_WARN,
	LOG_LEV_INFO,
	LOG_LEV_DEBUG,

	LOG_LEV_MAX
};

enum {
	LOG_KIND_GENERAL = 0,
	LOG_KIND_SECURITY,
	LOG_KIND_DEBUG,
	LOG_KIND_ALERT,

	LOG_KIND_MAX
};


//////////////////////////////////////////////////////

int32_t ns_log_print(int32_t id, int32_t lev, const char* fmt, ...);

#endif
