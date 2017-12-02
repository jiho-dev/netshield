#include <include_os.h>

#include <typedefs.h>
#include <ns_macro.h>
#include <session.h>
#include <ns_task.h>
#include <log.h>
#include <misc.h>
#include <khypersplit.h>
#include <ns_malloc.h>
#include <pmgr.h>
#include <ioctl_policy.h>

/* Hypersplit Packet Classification */

DECLARE_DBG_LEVEL(5);

/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

void hypersplit_free(hypersplit_t *hs)
{
#if 0
	int32_t i;

	if (hs == NULL || hs->trees) {
		return;
	}

	for (i = 0; i < hs->tree_num; i++) {
		struct hs_tree *t = &hs->trees[i];

		if (t->root_node) {
			ns_free_v(t->root_node);
		}
	}

	ns_free(hs->trees);
#endif
}

uint32_t hypersplit_get_memory_size(hypersplit_t *hypersplit, uint32_t *total_node)
{
	size_t tmem = 0;
	uint32_t nodes = 0;
	int32_t j;

	if (!hypersplit || !hypersplit->trees) {
		return 0;
	}


	tmem += (sizeof(struct hs_tree) * hypersplit->tree_num);

	for (j = 0; j < hypersplit->tree_num; j++) {
		struct hs_tree *t = &hypersplit->trees[j];

		tmem += (t->inode_num * sizeof(struct hs_node));
		nodes += t->inode_num;
	}

	if (total_node) {
		*total_node = nodes;
	}

	return tmem;
}

int32_t hypersplit_load(ioctl_policyset_t *ioctl_ps, policyset_t *ps)
{
	uint32_t l = 0;
	//int32_t ret = -1;
	int32_t i, tmem = 0, tnode = 0;
	struct hs_tree *user_trees;
	hypersplit_t *hs = &ps->hypersplit;
	uint8_t *p;

	if (hs == NULL) {
		return -1;
	}

	DBG(5, "Loading Hypersplit: 0x%p", ioctl_ps->hs);

	memset(hs, 0, sizeof(hypersplit_t));

	// read hypersplit_t
	if (ns_copy_from_user(hs, ioctl_ps->hs, sizeof(hypersplit_t))) {
		return -1;
	}

	DBG(5, "Num Tree: %d", hs->tree_num);
	DBG(5, "Def Rule: %d", hs->def_rule);
	DBG(5, "Tree Mem Len: %u", ioctl_ps->num_hs_mem);

	// 트리 전체 메모리를 할당 한다.
	p = ns_malloc_v(ioctl_ps->num_hs_mem);
	ns_mem_assert(p, "HyperSplit mem", return -1);
	ps->hs_mem = p;

	// to make sure all the page assigned
	memset(p, 0, l);

	user_trees = hs->trees;
	hs->trees = (struct hs_tree*)p;

	// read all trees
	l = sizeof(struct hs_tree) * hs->tree_num;
	DBG(5, "Trees : 0x%p, len=%d", user_trees, l);

	if (ns_copy_from_user(hs->trees, user_trees, l)) {
		return -1;
	}

	tmem += l;
	p += l;

	for (i=0; i<hs->tree_num; i++) {
		struct hs_tree *dt = &hs->trees[i];
		struct hs_tree *st = &user_trees[i];

		DBG(5, "Tree %d: %p", i+1, st);
		DBG(5, " root_node: %p", st->root_node);
		DBG(5, " inode_num: %d", st->inode_num);
		DBG(5, " enode_num: %d", st->enode_num);
		DBG(5, " depth_max: %d", st->depth_max);

		l = sizeof(struct hs_node) * st->inode_num;
		DBG(5, " node len: %u", l);

		dt->root_node = (struct hs_node*)p;

		memset(dt->root_node, 0, l);
		tmem += l;
		p += l;
		tnode += st->inode_num;

		// read nodes of each tree
		if (ns_copy_from_user(dt->root_node, st->root_node, l)) {
			return -1;
		}

		if (0) {
			int32_t j;
			uint8_t *p;
			char buf[100], b[6];
			p = (int8_t*)dt->root_node;

			memset(buf, 0, 100);

			for (j=0; j < l; j++) {
				sprintf(b, "0x%02x ", p[j]);
				strcat(buf, b);

				if (j > 0 && (j%8) == 7) {
					printk("%s\n", buf);
					memset(buf, 0, 100);
				}
			}

			printk("\n");
		}
	}


	DBG(5, "Total: Node=%d, Mem=%d", tnode, tmem);

	return 0;

#if 0
ERROR:

	if (hs->trees) {
		for (i = 0; i < hs->tree_num; i++) {
			struct hs_tree *t = &hs->trees[i];

			if (t->root_node) {
				ns_free_v(t->root_node);
			}
		}

		ns_free(hs->trees);
	}

	return ret;
#endif
}

int32_t hypersplit_load_old1(char *hsmem, hypersplit_t *hs)
{
	uint32_t l = 0;
	int32_t ret = -1;
	int32_t i, tmem = 0, tnode = 0;
	struct hs_tree *user_trees;

	if (hs == NULL) {
		return -1;
	}

	memset(hs, 0, sizeof(hypersplit_t));

	DBG(5, "Loading Hypersplit: 0x%p", hsmem);

	if (ns_copy_from_user(hs, hsmem, sizeof(hypersplit_t))) {
		return -1;
	}

	l = sizeof(struct hs_tree) * hs->tree_num;
	tmem += l;
	user_trees = hs->trees;

	DBG(5, "Num Tree: %d", hs->tree_num);
	DBG(5, "Def Rule: %d", hs->def_rule);
	DBG(5, "Trees : 0x%p", user_trees);
	DBG(5, "Tree Mem Len: %u", l);

	for (i=0; i<hs->tree_num; i++) {
		struct hs_tree *t = &user_trees[i];
		DBG(5, "Tree %d: %p", i+1, t);
		DBG(5, " root_node: %p", t->root_node);
		DBG(5, " inode_num: %d", t->inode_num);
		DBG(5, " enode_num: %d", t->enode_num);
		DBG(5, " depth_max: %d", t->depth_max);
		DBG(5, " node len: %d", (int32_t)sizeof(struct hs_node) * t->inode_num);
	}

	hs->trees = ns_malloc_k(l);
	if (hs->trees == NULL) {
		return -1;
	}

	memset(hs->trees, 0, l);

	if (ns_copy_from_user(hs->trees, user_trees, l)) {
		goto ERROR;
	}

	for (i = 0; i < hs->tree_num; i++) {
		struct hs_tree *dt = &hs->trees[i];
		struct hs_tree *st = &user_trees[i];

		l = sizeof(struct hs_node) * st->inode_num;
		dt->root_node = ns_malloc_k(l);
		if (dt->root_node == NULL) {
			goto ERROR;
		}

		memset(dt->root_node, 0, l);
		tmem += l;
		tnode += st->inode_num;

		if (ns_copy_from_user(dt->root_node, st->root_node, l)) {
			return -1;
		}

		if (0) {
			int32_t j;
			uint8_t *p;
			p = (int8_t*)dt->root_node;
			for (j=0; j < l; j++) {
				printk("0x%02x ", p[j]);

				if (j > 0 && (j%8) == 7) {
					printk("\n");
				}
			}

			printk("\n");
		}
#if 0
		hsmem += sizeof(int32_t);

		if (ns_copy_from_user(&t->depth_max, hsmem, sizeof(int32_t))) {
			return -1;
		}
		hsmem += sizeof(int32_t);

		if (ns_copy_from_user(&mlen, hsmem, sizeof(int32_t))) {
			return -1;
		}
		hsmem += sizeof(int32_t);

		t->enode_num = t->inode_num + 1;

		tnode += t->inode_num;
		tmem += mlen;

		if ((t->inode_num * sizeof(struct hs_node)) != mlen) {
			DBG(5, "something wrong: mlen=%d", mlen);
			goto ERROR;
		}

		t->root_node = ns_malloc_v(mlen);
		if (t->root_node == NULL) {
			goto ERROR;
		}

		if (ns_copy_from_user(t->root_node, hsmem, mlen)) {
			return -1;
		}
		hsmem += mlen;

		DBG(5, "#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d",
			i + 1, t->inode_num, mlen, t->depth_max);
#endif
	}


	DBG(5, "Total: Node=%d, Mem=%d", tnode, tmem);

	return 0;

ERROR:

	if (hs->trees) {
		for (i = 0; i < hs->tree_num; i++) {
			struct hs_tree *t = &hs->trees[i];

			if (t->root_node) {
				ns_free_v(t->root_node);
			}
		}

		ns_free(hs->trees);
	}

	return ret;
}

int32_t old_hypersplit_load(char *hsmem, hypersplit_t *hs)
{
	uint32_t l = 0;
	int32_t ret = -1;
	int32_t j, tmem = 0, tnode = 0;

	if (hs == NULL) {
		return -1;
	}

	memset(hs, 0, sizeof(hypersplit_t));

	DBG(5, "Loading Hypersplit \n");

	if (ns_copy_from_user(&hs->tree_num, hsmem, sizeof(int32_t))) {
		return -1;
	}
	hsmem += sizeof(int32_t);

	if (ns_copy_from_user(&hs->def_rule, hsmem, sizeof(int32_t))) {
		return -1;
	}
	hsmem += sizeof(int32_t);

	l = sizeof(struct hs_tree) * hs->tree_num;

	DBG(5, "Num Tree: %d \n", hs->tree_num);
	DBG(5, "Def Rule: %d \n", hs->def_rule);
	DBG(5, "Tree Mem Len: %u \n", l);

	hs->trees = ns_malloc_k(l);
	if (hs->trees == NULL) {
		return -1;
	}

	for (j = 0; j < hs->tree_num; j++) {
		struct hs_tree *t = &hs->trees[j];
		int32_t mlen=0;

		memset(t, 0, sizeof(struct hs_tree));

		if (ns_copy_from_user(&t->inode_num, hsmem, sizeof(int32_t))) {
			return -1;
		}
		hsmem += sizeof(int32_t);

		if (ns_copy_from_user(&t->depth_max, hsmem, sizeof(int32_t))) {
			return -1;
		}
		hsmem += sizeof(int32_t);

		if (ns_copy_from_user(&mlen, hsmem, sizeof(int32_t))) {
			return -1;
		}
		hsmem += sizeof(int32_t);

		t->enode_num = t->inode_num + 1;

		tnode += t->inode_num;
		tmem += mlen;

		if ((t->inode_num * sizeof(struct hs_node)) != mlen) {
			DBG(5, "something wrong: mlen=%d \n", mlen);
			goto ERROR;
		}

		t->root_node = ns_malloc_v(mlen);
		if (t->root_node == NULL) {
			goto ERROR;
		}

		if (ns_copy_from_user(t->root_node, hsmem, mlen)) {
			return -1;
		}
		hsmem += mlen;

		DBG(5, "#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d \n",
			j + 1, t->inode_num, mlen, t->depth_max);
	}


	DBG(5, "Total: Node=%d, Mem=%d \n", tnode, tmem);

	return 0;

ERROR:

	if (hs->trees) {
		for (j = 0; j < hs->tree_num; j++) {
			struct hs_tree *t = &hs->trees[j];

			if (t->root_node) {
				ns_free_v(t->root_node);
			}
		}

		ns_free(hs->trees);
	}

	return ret;
}

uint32_t hypersplit_search(hypersplit_t *hs, pktinfo_t *pkt)
{
	uint32_t i, pri;
	uint32_t id, offset;
	const struct hs_node *node, *root_node;

	if (hs == NULL) {
		return HS_NO_RULE;
	}

	offset = hs->def_rule + 1;
	pri = hs->def_rule;

	for (i = 0; i < hs->tree_num; i++) {
		id = offset;
		root_node = hs->trees[i].root_node;

		do {
			node = root_node + id - offset;

			if (pkt->dims[node->dim] <= node->threshold) {
				id = node->lchild;
			}
			else {
				id = node->rchild;
			}

		} while (id >= offset);

		if (id < pri) {
			pri = id;
		}
	}

	if (pri == hs->def_rule) {
		return HS_NO_RULE;
	}

	return pri;
}
