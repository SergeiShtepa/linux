/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BLKSNAP_DIFF_IO_H
#define __BLKSNAP_DIFF_IO_H

#include <linux/workqueue.h>
#include <linux/completion.h>

struct diff_buffer;

/**
 * struct diff_region - Describes the location of the chunks data on
 *	difference storage.
 * @bdev:
 *	The target block device.
 * @sector:
 *	The sector offset of the region's first sector.
 * @count:
 *	The count of sectors in the region.
 */
struct diff_region {
	struct block_device *bdev;
	sector_t sector;
	sector_t count;
};

/**
 * struct diff_io - Structure for I/O maintenance.
 * @error:
 *	Zero if the I/O operation is successful, or an error code if it fails.
 * @bio_count:
 *      The count of I/O units in request.
 * @is_write:
 *	Indicates that a write operation is being performed.
 * @work:
 *      The &struct work_struct allows to schedule execution of an I/O operation
 *      in a separate process.
 * @notify_cb:
 *      A pointer to the callback function that will be executed when
 *      the I/O execution is completed.
 * @ctx:
 *      The context for the callback function &notify_cb.
 *
 * The request to perform an I/O operation is executed for a region of sectors.
 * Such a region may contain several bios. It is necessary to notify about the
 * completion of processing of all bios. The diff_io structure allows to do it.
 */
struct diff_io {
	int error;
	atomic_t bio_count;
	bool is_write;

        struct work_struct work;
        void (*notify_cb)(void *ctx);
        void *ctx;
};

int diff_io_init(void);
void diff_io_done(void);

static inline void diff_io_free(struct diff_io *diff_io)
{
	kfree(diff_io);
}

struct diff_io *diff_io_new_async(bool is_write, const bool is_nowait,
        void (*notify_cb)(void *ctx), void *ctx);

static inline struct diff_io *diff_io_new_async_read(
        void (*notify_cb)(void *ctx), void *ctx, const bool is_nowait)
{
	return diff_io_new_async(false, is_nowait, notify_cb, ctx);
};
static inline struct diff_io *diff_io_new_async_write(
        void (*notify_cb)(void *ctx), void *ctx, const bool is_nowait)
{
	return diff_io_new_async(true, is_nowait, notify_cb, ctx);
};

int diff_io_do(struct diff_io *diff_io, struct diff_region *diff_region,
	       struct diff_buffer *diff_buffer, const bool is_nowait);
#endif /* __BLKSNAP_DIFF_IO_H */
