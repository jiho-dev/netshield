#include <include_os.h>

#include <ns_type_defs.h>
#include <skey.h>
#include <timer.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <commands.h>
#include <log.h>
#include <extern.h>
#include <version.h>
#include <misc.h>


#define	KLOG_MAX_BUF	501
#define	LOG_ID_MAX	2
#define	LOG_MODULE_MAX	2

//////////////////////////////////////////////////////

DECLARE_DBG_LEVEL(2);



/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

///////////////////////////////////////////

#if 0
static int dec2hexstr(char *buf, uint32_t num, size_t len)
{
	int i = len - 1;
	unsigned int b = 16;
	unsigned char c;
	unsigned char tmp[len];

	if (buf == NULL || len == 0)
		return -1;

	tmp[i--] = '\0';

	while (i >= 0) {
		c = (unsigned char)(num % b);
		if (c < 10)
			c += '0';
		else
			c = c - 10 + 'A';
		tmp[i--] = c;
		num /= b;
		if (num == 0)
			break;
	}

	sprintf(buf, "%s", &tmp[i+1]);

	return 0;
}
#endif

int32_t ns_log_print(int32_t id, int32_t lev, const char* fmt, ...)
{
	va_list args;
	int len;
	char buf[KLOG_MAX_BUF+1];

	va_start(args, fmt);
	len = vscnprintf(buf, KLOG_MAX_BUF, fmt, args);
	va_end(args);

	printk("%s\n", buf);

	DBG(0, "%s", buf);

	return 0;
}

