#ifndef _LINUX_INTERVAL_TREE_H
#define _LINUX_INTERVAL_TREE_H

#include <linux/rbtree.h>

typedef struct rb_root rbt_root_t;

//typedef __uint128_t uint128_t;
//typedef __int128    int128_t;

typedef uint32_t 	itvt_val_t;
//typedef uint64_t 	itvt_val_t;
//typedef uint128_t itvt_val_t;

typedef struct interval_tree_node {
	struct rb_node rb;
	itvt_val_t start;
	itvt_val_t last;
	itvt_val_t __subtree_last;
	uint32_t 	idx;

} itvt_node_t;

extern void
interval_tree_insert(struct interval_tree_node *node, struct rb_root *root);

extern void
interval_tree_remove(struct interval_tree_node *node, struct rb_root *root);

extern struct interval_tree_node *
interval_tree_iter_first(struct rb_root *root, itvt_val_t start, itvt_val_t last);

extern struct interval_tree_node *
interval_tree_iter_next(struct interval_tree_node *node, itvt_val_t start, itvt_val_t last);

#endif	/* _LINUX_INTERVAL_TREE_H */
