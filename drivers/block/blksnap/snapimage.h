/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BLKSNAP_SNAPIMAGE_H
#define __BLKSNAP_SNAPIMAGE_H

#include <linux/blk-mq.h>
#include <linux/kthread.h>

struct tracker;

/**
 * struct snapimage - Snapshot image block device.
 *
 * @capacity:
 *	The size of the snapshot image in sectors must be equal to the size
 *	of the original device at the time of taking the snapshot.
 * @worker:
 *	A pointer to the &struct task of the worker thread that process I/O
 *      units.
 * @queue_lock:
 *      Lock for &queue.
 * @queue:
 *	A queue of I/O units waiting to be processed.
 * @disk:
 *	A pointer to the &struct gendisk for the image block device.
 * @diff_area:
 *	A pointer to the owned &struct diff_area.
 * @cbt_map:
 *	A pointer to the owned &struct cbt_map.
 *
 * The snapshot image is presented in the system as a block device. But
 * when reading or writing a snapshot image, the data is redirected to
 * the original block device or to the block device of the difference storage.
 *
 * The module does not prohibit reading and writing data to the snapshot
 * from different threads in parallel. To avoid the problem with simultaneous
 * access, it is enough to open the snapshot image block device with the
 * FMODE_EXCL parameter.
 */
struct snapimage {
	sector_t capacity;

	struct task_struct *worker;
	spinlock_t queue_lock;
	struct bio_list queue;

	struct gendisk *disk;
};

void snapimage_free(struct snapimage *snapimage);
int snapimage_create(struct tracker *tracker);
#endif /* __BLKSNAP_SNAPIMAGE_H */
