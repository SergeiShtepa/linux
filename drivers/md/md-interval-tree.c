// SPDX-License-Identifier: GPL-2.0-only
#include <linux/interval_tree_generic.h>
#include "md-interval-tree.h"

#define START(node) ((node)->start)
#define LAST(node) ((node)->last)
INTERVAL_TREE_DEFINE(struct serial_info, node, sector_t, _subtree_last,
		     START, LAST,, md_rb);
