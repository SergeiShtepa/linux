/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023 Veeam Software Group GmbH */
#ifndef __BLKSNAP_DIFF_AREA_H
#define __BLKSNAP_DIFF_AREA_H

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/blkdev.h>
#include <linux/xarray.h>
#include "event_queue.h"

struct diff_storage;
struct chunk;
struct tracker;

/**
 * struct diff_area - Describes the difference area for one original device.
 *
 * @kref:
 *	The reference counter allows to manage the lifetime of an object.
 * @orig_bdev:
 *	A pointer to the structure of an opened block device.
 * @diff_storage:
 *	Pointer to difference storage for storing difference data.
 * @chunk_shift:
 *	Power of 2 used to specify the chunk size. This allows to set different
 *	chunk sizes for huge and small block devices.
 * @chunk_count:
 *	Count of chunks. The number of chunks into which the block device
 *	is divided.
 * @chunk_map:
 *	A map of chunks.
 * @store_queue_lock:
 *	This spinlock guarantees consistency of the linked lists of chunks
 *	queue.
 * @store_queue:
 *	The queue of chunks waiting to be stored to the difference storage.
 * @store_queue_count:
 *	The number of chunks in the store queue.
 * @store_queue_work:
 *	The workqueue work item. This worker limits the number of chunks
 *	that store their data in RAM.
 * @free_diff_buffers_lock:
 *	This spinlock guarantees consistency of the linked lists of
 *	free difference buffers.
 * @free_diff_buffers:
 *	Linked list of free difference buffers allows to reduce the number
 *	of buffer allocation and release operations.
 * @physical_blksz:
 *	The physical block size for the snapshot image is equal to the
 *	physical block size of the original device.
 * @logical_blksz:
 *	The logical block size for the snapshot image is equal to the
 *	logical block size of the original device.
 * @free_diff_buffers_count:
 *	The number of free difference buffers in the linked list.
 * @corrupt_flag:
 *	The flag is set if an error occurred in the operation of the data
 *	saving mechanism in the diff area. In this case, an error will be
 *	generated when reading from the snapshot image.
 * @error_code:
 *	The error code that caused the snapshot to be corrupted.
 * @tracker:
 *	Back pointer to the tracker for this diff_area
 *
 * The &struct diff_area is created for each block device in the snapshot.
 * It is used to save the differences between the original block device and
 * the snapshot image. That is, when writing data to the original device,
 * the differences are copied as chunks to the difference storage.
 * Reading and writing from the snapshot image is also performed using
 * &struct diff_area.
 *
 * The xarray has a limit on the maximum size. This can be especially
 * noticeable on 32-bit systems. This creates a limit in the size of
 * supported disks.
 *
 * For example, for a 256 TiB disk with a block size of 65536 bytes, the
 * number of elements in the chunk map will be equal to 2 with a power of 32.
 * Therefore, the number of chunks into which the block device is divided is
 * limited.
 *
 * The store queue allows to postpone the operation of storing a chunks data
 * to the difference storage and perform it later in the worker thread.
 *
 * The linked list of difference buffers allows to have a certain number of
 * "hot" buffers. This allows to reduce the number of allocations and releases
 * of memory.
 *
 *
 */
struct diff_area {
	struct kref kref;
	struct block_device *orig_bdev;
	struct diff_storage *diff_storage;
        struct tracker *tracker;

	unsigned long chunk_shift;
	unsigned long chunk_count;
	struct xarray chunk_map;

	spinlock_t store_queue_lock;
	struct list_head store_queue;
	atomic_t store_queue_count;
	struct work_struct store_queue_work;

	spinlock_t free_diff_buffers_lock;
	struct list_head free_diff_buffers;
	atomic_t free_diff_buffers_count;

	unsigned int physical_blksz;
	unsigned int logical_blksz;

	unsigned long corrupt_flag;
	int error_code;
        bool store_queue_processing;
};

struct diff_area *diff_area_new(struct tracker *tracker,
				struct diff_storage *diff_storage);
void diff_area_free(struct kref *kref);
static inline struct diff_area *diff_area_get(struct diff_area *diff_area)
{
	kref_get(&diff_area->kref);
	return diff_area;
};
static inline void diff_area_put(struct diff_area *diff_area)
{
	kref_put(&diff_area->kref, diff_area_free);
};

void diff_area_set_corrupted(struct diff_area *diff_area, int err_code);
static inline bool diff_area_is_corrupted(struct diff_area *diff_area)
{
	return !!diff_area->corrupt_flag;
};
static inline sector_t diff_area_chunk_sectors(struct diff_area *diff_area)
{
	return (sector_t)(1ull << (diff_area->chunk_shift - SECTOR_SHIFT));
};
bool diff_area_cow(struct bio *bio, struct diff_area *diff_area,
		   struct bvec_iter *iter);

bool diff_area_submit_chunk(struct diff_area *diff_area, struct bio *bio);
void diff_area_rw_chunk(struct kref *kref);

#endif /* __BLKSNAP_DIFF_AREA_H */
