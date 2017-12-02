#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <ns_sysctl.h>
#include <log.h>

//////////////////////////////////////////////////////

struct proc_dir_entry *ns_proc_root;


DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

ssize_t ns_proc_sysctl_read(struct file *, char __user *, size_t, loff_t *);
ssize_t ns_proc_sysctl_write(struct file *, const char __user *, size_t, loff_t *);
int     ns_proc_sysctl_open(struct inode *, struct file *);
int32_t ns_proc_seq_open(struct inode *inode, struct file *file);

struct file_operations ns_proc_sysctl_ops = {
	.open 	= ns_proc_sysctl_open,
	.read 	= ns_proc_sysctl_read,
	.write 	= ns_proc_sysctl_write,
};

struct file_operations ns_proc_seq_ops = {
	.open		= ns_proc_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release
};

/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

int use_table(struct ctl_table_header *p)
{
	if (unlikely(p->unregistering))
		return 0;

	p->used++;
	return 1;
}

void unuse_table(struct ctl_table_header *p)
{
	if (!--p->used)
		if (unlikely(p->unregistering))
			complete(p->unregistering);
}

int test_perm(int mode, int op)
{
#if 0
	if (!current->euid)
		mode >>= 6;
	else if (in_egroup_p(0))
		mode >>= 3;
	if ((mode & op & 0007) == op)
		return 0;
	return -EACCES;
#else
	return 0;
#endif
}

int ctl_perm(struct ctl_table *table, int op)
{
#if 0
	int error;
	error = security_sysctl(table, op);
	if (error)
		return error;
#endif
	return test_perm(table->mode, op);
}

void register_proc_table(struct ctl_table *table, struct proc_dir_entry *root)
{
	struct proc_dir_entry *de;
	mode_t mode;

	for (; table->procname; table++) {
		/* Can't do anything without a proc name. */
		if (!table->procname)
			continue;

		/* Maybe we can't do anything with it... */
		if (!table->proc_handler && !table->child) {
			printk(KERN_WARNING "NS_SYSCTL: Can't register %s\n",
				table->procname);
			continue;
		}

		mode = table->mode;
		de = NULL;

		if (table->proc_handler) {
			de = proc_create_data(table->procname, mode, root, 
								  &ns_proc_sysctl_ops, table);
		}
		else {
			de = proc_mkdir_data(table->procname, mode, root, table);
		}

		if (de && table->child) {
			register_proc_table(table->child, de);
		}
	}
}

void unregister_proc_table(struct ctl_table *table, struct proc_dir_entry *root)
{
	//proc_remove(root);
}

ssize_t ns_sysctl_read_write(int write, struct file * file, char __user * buf, size_t count, loff_t *ppos)
{
	int op;
	struct ctl_table *table;
	size_t res;
	ssize_t error = -ENOTDIR;
	struct inode *inode;
	
	inode = file_inode(file);
	table = (struct ctl_table*)PDE_DATA(inode);

	if (!table || !table->proc_handler)
		goto out;

	error = -EPERM;
	op = (write ? 002 : 004);
	if (ctl_perm(table, op))
		goto out;

	/* careful: calling conventions are nasty here */
	res = count;
	error = (*table->proc_handler)(table, write, buf, &res, ppos);
	if (!error)
		error = res;
out:

	return error;
}

int ns_proc_sysctl_open(struct inode *inode, struct file *file)
{
	if (file->f_mode & FMODE_WRITE) {
		/*
		 * sysctl entries that are not writable,
		 * are _NOT_ writable, capabilities or not.
		 */
		if (!(inode->i_mode & S_IWUSR))
			return -EPERM;
	}

	return 0;
}

ssize_t ns_proc_sysctl_read(struct file * file, char __user * buf, size_t count, loff_t *ppos)
{
	return ns_sysctl_read_write(0, file, buf, count, ppos);
}

ssize_t ns_proc_sysctl_write(struct file * file, const char __user * buf, size_t count, loff_t *ppos)
{
	return ns_sysctl_read_write(1, file, (char __user *) buf, count, ppos);
}

int32_t ns_proc_seq_open(struct inode *inode, struct file *file)
{
	int32_t ret;
	seq_proc_t* seqp;
	struct seq_file *seq;

	seqp = (seq_proc_t*)PDE_DATA(inode);

	ret = seq_open(file, seqp->seq_op);

	if (ret == 0) {
		seq = (struct seq_file*)file->private_data;
		if (seq) {
			seq->private = seqp->data;
		}
	}

	return ret;
}

///////////////////////////////////////////////////

void ns_register_seq_proc(seq_proc_t* seqtab)
{
	struct proc_dir_entry *de;
	int mode = 0644;

	for (; seqtab->name; seqtab++) {
		de = proc_create_data(seqtab->name, mode, ns_proc_root, &ns_proc_seq_ops, seqtab);

		if (de == NULL) {
			ns_err("Can't register proc table: %s", seqtab->name);
			continue;
		}
	}
}

void ns_unregister_seq_proc(seq_proc_t* seqtab)
{
	for (; seqtab->name; seqtab++) {
		remove_proc_entry(seqtab->name, ns_proc_root);
	}
}

/////////////////////////////

int32_t ns_register_sysctl_table(struct ctl_table *table)
{
	register_proc_table(table, ns_proc_root);

	return 0;
}

void ns_unregister_sysctl_table(struct ctl_table *table)
{
	unregister_proc_table(table, ns_proc_root);
}

int ns_init_proc_sys(void)
{
	ns_proc_root = proc_mkdir("netshield", NULL);
	return 0;
}

void ns_clean_proc_sys(void)
{
	proc_remove(ns_proc_root);
}

