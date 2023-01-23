/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BLKSNAP_DIFF_BUFFER_H
#define __BLKSNAP_DIFF_BUFFER_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/blkdev.h>

struct diff_area;

/**
 * struct diff_buffer - Difference buffer.
 * @link:
 *	The list header allows to create a pool of the diff_buffer structures.
 * @size:
 *	Count of bytes in the buffer.
 * @page_count:
 *	The number of pages reserved for the buffer.
 * @pages:
 *	An array of pointers to pages.
 *
 * Describes the memory buffer for a chunk in the memory.
 */
struct diff_buffer {
	struct list_head link;
	size_t size;
	size_t page_count;
	struct page *pages[0];
};

struct diff_buffer *diff_buffer_take(struct diff_area *diff_area,
				     const bool is_nowait);
void diff_buffer_release(struct diff_area *diff_area,
			 struct diff_buffer *diff_buffer);
void diff_buffer_cleanup(struct diff_area *diff_area);
#endif /* __BLKSNAP_DIFF_BUFFER_H */
