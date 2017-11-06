#include <include_os.h>

#include <ns_type_defs.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ns_task.h>
#include <ns_macro.h>
#include <log.h>
#include <extern.h>
#include <version.h>
#include <misc.h>
#include <options.h>
#include <ns_malloc.h>
#include <ns_ioctl.h>
#include <khypersplit.h>
#include <pmgr.h>

//////////////////////////////////////////////////////
nsdev_t  			 nsdev;
struct fasync_struct *nsdev_async_q[2];

int32_t nsdev_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr);
static struct notifier_block nsdev_ipaddr_noti = {
	.notifier_call = nsdev_inetaddr_event,
};

int32_t nsdev_netdev_event(struct notifier_block *this, unsigned long event, void *ptr);
static struct notifier_block nsdev_netdev_noti = {
	.notifier_call = nsdev_netdev_event,
};

DECLARE_DBG_LEVEL(2);
extern uint32_t		netshield_running;

//////////////////////////////////////////////////////


int32_t nsdev_open(struct inode *inode, struct file *filp);
ssize_t nsdev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
int32_t nsdev_release(struct inode *inode, struct file *filp);
int32_t nsdev_mmap_kmem(struct file * file, struct vm_area_struct * vma);
long 	nsdev_ioctl(struct file *filp, uint32_t cmd, unsigned long arg);
int32_t nsdev_main_ioctl(uint32_t cmd, unsigned long arg);
int32_t nsdev_fasync(int32_t fd, struct file *filp, int32_t on);

int32_t smgr_setup_session_info(char* arg);


/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

///////////////////////////////////////////////////////////////
// callback handler

static struct file_operations nsdev_fops = {
	.open 	= nsdev_open,
	.read 	= nsdev_read,
	.release= nsdev_release,
	.fasync = nsdev_fasync,
	//.mmap 	= nsdev_mmap_kmem,
	.owner 	= THIS_MODULE,
	.unlocked_ioctl 	= nsdev_ioctl,
};

int32_t nsdev_open(struct inode *inode, struct file *filp)
{
	int32_t minor;
	
	ENT_FUNC(3);

	minor = iminor(inode);

	if (minor >= NSDEV_MAX)
		return -ENODEV;

	return 0;
}

ssize_t nsdev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	int32_t	minor;
	struct inode *inode = file_inode(filp);

	ENT_FUNC(3);

	minor = iminor(inode);
	if (minor >= NSDEV_MAX)
		return -ENODEV;

	if (minor == NSDEV_SESSION) {
		// do something for sessions
	}

	return 0;
}

int32_t nsdev_get_async_qidx(int32_t minor)
{
#if 0
	switch(minor) {
	}
#endif

	return -1;
}

int32_t nsdev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

int32_t nsdev_fasync(int32_t fd, struct file *filp, int32_t on)
{
	int32_t ret = 0;
	int32_t	minor;
	int32_t qidx=-1;
	struct inode *inode = file_inode(filp);

	minor = iminor(inode);
	if (minor >= NSDEV_MAX)
		return -ENODEV;

	qidx = nsdev_get_async_qidx(minor);

	if (qidx != -1) {
		ret = fasync_helper(fd, filp, on, &nsdev_async_q[qidx]);

		DBG(5, "ret=%d, qidx=%d, on=%d, queue=0x%p",
			ret,
			qidx, on,
			nsdev_async_q[qidx]);
	}
	
	return ret;
}

void nsdev_send_sgio(int32_t minor)
{
	int32_t qidx=-1;

	qidx = nsdev_get_async_qidx(minor);

	if (qidx != -1 && nsdev_async_q[qidx] != NULL) {
		kill_fasync(&nsdev_async_q[qidx], SIGIO, POLL_IN);
	}
}

///////////////////////////////////////////

int32_t nsdev_init(void)
{
	int32_t ret = 0;

	ret = register_chrdev(NSDEV_MAJOR, NSDEV_MAIN_NAME, &nsdev_fops);
	if (ret < 0) {
		ns_err("Could not regiger %s", NSDEV_MAIN_NAME);
		return ret;
	}
	else {
		ns_log("Register /dev/%s/%s", NSDEV_DIR_NAME, NSDEV_MAIN_NAME);
	}

	register_netdevice_notifier(&nsdev_netdev_noti);
	register_inetaddr_notifier(&nsdev_ipaddr_noti);

	return 0;
}

void nsdev_clean(void)
{
	unregister_netdevice_notifier(&nsdev_netdev_noti);
	unregister_inetaddr_notifier(&nsdev_ipaddr_noti);
	unregister_chrdev(NSDEV_MAJOR, NSDEV_MAIN_NAME);
}

////////////////////////////////

int32_t nsdev_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	// refer to fib_inetaddr_event()
	uint32_t ip;
	struct in_ifaddr *ifa = (struct in_ifaddr*)ptr;
	netdev_t* dev = ifa->ifa_dev->dev;;

	ip = ns_get_nic_ip(dev->ifindex);

	DBG(5, "%s: event=%lu, IP=" IP_FMT, dev->name, event, IPH(ip));

	switch (event) {
	case NETDEV_UP:
	case NETDEV_CHANGEADDR:
		if (dev) {
		}
		break;
	case NETDEV_DOWN:
		break;
	}

	return NOTIFY_DONE;
}

int32_t nsdev_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	// refer to fib_netdev_event()
	struct net_device *dev = ptr;
	//uint32_t ip;

	//ip = ns_get_nic_ip(dev->ifindex);
	//DBG(5, "%s: event=%lu, %u", dev->name, event, ip);
	
	if (!netshield_running)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
	case NETDEV_CHANGEADDR:
		if (dev) {
		}
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

////////////////////////////////

long nsdev_ioctl(struct file *filp, uint32_t cmd, unsigned long arg)
{
	int32_t	minor=0;
	struct inode *inode = NULL;

	ENT_FUNC(3);

	inode = file_inode(filp);
	if (inode == NULL) {
		dbg(0, "inode is NULL");
		return 0;
	}

	minor = iminor(inode);
	cmd = _IOC_NR(cmd);

	DBG(5, "nsdev ioctl: minor=%d, cmd=%d", minor, cmd);

	switch(minor) {
	case NSDEV_MAIN:
		return nsdev_main_ioctl(cmd, arg);

	default:
		ns_err("Not supported subsystem ioctl: %d", minor);
		return -ENODEV;
	};

	return 0;
}

int32_t nsdev_main_ioctl(uint32_t cmd, unsigned long arg)
{
	int32_t err = 0, ret = 0;

	ENT_FUNC(3);

	DBG(5, "IOCTL CMD: %d", cmd);

	err = 0;

	switch(cmd) {
	case IOCTL_START:
		return 0;

	case IOCTL_APPLY_FW_POLICY:
		return pmgr_apply_fw_policy((char*)arg);

	case IOCTL_SESSION_INFO:
		return smgr_setup_session_info((char*)arg);

	default: 
		return -EINVAL;
	}

	return ret;
}


