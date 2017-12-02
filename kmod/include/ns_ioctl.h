#ifndef __NS_IOCTL_H_
#define __NS_IOCTL_H_

#define 	NSIOCTL_MAGIC 		'n'
#define  	NSIOCTL(n) 			_IOWR(NSIOCTL_MAGIC, n, void*)

enum {
	IOCTL_START = 0,
	IOCTL_APPLY_POLICY,
	IOCTL_DUMMY, 				// 2번은 인식하지 못한다. ?????
	IOCTL_SESSION_INFO,


	IOCTL_MAXNR
};

#define NSDEV_MAJOR              230
#define NSDEV_DIR_NAME       	 "netshield"
#define NSDEV_MAIN_NAME       	 "nsdev"

enum {
	NSDEV_MAIN = 1,
	NSDEV_SESSION = 2,

	NSDEV_MAX
};


typedef struct _ns_device {
	struct cdev	cdev[NSDEV_MAX];
} nsdev_t;


////////////////////////////////////////////////////

int32_t nsdev_init(void);
void 	nsdev_clean(void);


#endif
