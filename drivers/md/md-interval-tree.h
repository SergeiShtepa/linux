/* SPDX-License-Identifier: GPL-2.0 */

#ifndef DM_INTERVAL_TREE_H
#define DM_INTERVAL_TREE_H

#include <linux/rbtree.h>

struct serial_info {
	struct rb_node node;
	sector_t start;		/* start sector of rb node */
	sector_t last;		/* end sector of rb node */
	sector_t _subtree_last; /* highest sector in subtree of rb node */
};

void md_rb_insert(struct serial_info *node, struct rb_root_cached *root);
void md_rb_remove(struct serial_info *node, struct rb_root_cached *root);

struct serial_info *md_rb_iter_first(struct rb_root_cached *root, sector_t start, sector_t last);
struct serial_info *md_rb_iter_next(struct serial_info *node, sector_t start, sector_t last);

#endif
