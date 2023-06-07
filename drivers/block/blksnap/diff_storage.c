// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-storage: " fmt

#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

/**
 * struct storage_bdev - Information about the opened block device.
 *
 * @link:
 *	Allows to combine structures into a linked list.
 * @bdev:
 *	A pointer to an open block device.
 * @bdev_path:
 *	A path to the block device.
 */
struct storage_bdev {
	struct list_head link;
	struct block_device *bdev;
	char bdev_path[];
};

/**
 * struct storage_block - A storage unit reserved for storing differences.
 *
 * @link:
 *	Allows to combine structures into a linked list.
 * @bdev:
 *	A pointer to a block device.
 * @sector:
 *	The number of the first sector of the range of allocated space for
 *	storing the difference.
 * @count:
 *	The count of sectors in the range of allocated space for storing the
 *	difference.
 * @used:
 *	The count of used sectors in the range of allocated space for storing
 *	the difference.
 */
struct storage_block {
	struct list_head link;
	struct block_device *bdev;
	sector_t sector;
	sector_t count;
	sector_t used;
};

static inline void diff_storage_event_low(struct diff_storage *diff_storage)
{
	struct blksnap_event_low_free_space data = {
		.requested_nr_sect = get_diff_storage_minimum(),
	};

	diff_storage->requested += data.requested_nr_sect;
	pr_debug("Diff storage low free space. Portion: %llu sectors, requested: %llu\n",
		data.requested_nr_sect, diff_storage->requested);
	event_gen(&diff_storage->event_queue, GFP_NOIO,
		  blksnap_event_code_low_free_space, &data, sizeof(data));
}

struct diff_storage *diff_storage_new(void)
{
	struct diff_storage *diff_storage;

	diff_storage = kzalloc(sizeof(struct diff_storage), GFP_KERNEL);
	if (!diff_storage)
		return NULL;

	kref_init(&diff_storage->kref);
	spin_lock_init(&diff_storage->lock);
	INIT_LIST_HEAD(&diff_storage->storage_bdevs);
	INIT_LIST_HEAD(&diff_storage->empty_blocks);
	INIT_LIST_HEAD(&diff_storage->filled_blocks);

	event_queue_init(&diff_storage->event_queue);
	diff_storage_event_low(diff_storage);

	return diff_storage;
}

static inline struct storage_block *
first_empty_storage_block(struct diff_storage *diff_storage)
{
	return list_first_entry_or_null(&diff_storage->empty_blocks,
					struct storage_block, link);
};

static inline struct storage_block *
first_filled_storage_block(struct diff_storage *diff_storage)
{
	return list_first_entry_or_null(&diff_storage->filled_blocks,
					struct storage_block, link);
};

static inline struct storage_bdev *
first_storage_bdev(struct diff_storage *diff_storage)
{
	return list_first_entry_or_null(&diff_storage->storage_bdevs,
					struct storage_bdev, link);
};

void diff_storage_free(struct kref *kref)
{
	struct diff_storage *diff_storage =
		container_of(kref, struct diff_storage, kref);
	struct storage_block *blk;
	struct storage_bdev *storage_bdev;

	while ((blk = first_empty_storage_block(diff_storage))) {
		list_del(&blk->link);
		kfree(blk);
	}

	while ((blk = first_filled_storage_block(diff_storage))) {
		list_del(&blk->link);
		kfree(blk);
	}

	while ((storage_bdev = first_storage_bdev(diff_storage))) {
		blkdev_put(storage_bdev->bdev, FMODE_READ | FMODE_WRITE);
		list_del(&storage_bdev->link);
		kfree(storage_bdev);
	}
	event_queue_done(&diff_storage->event_queue);

	kfree(diff_storage);
}

static struct block_device *diff_storage_bdev_by_path(
	struct diff_storage *diff_storage, const char *bdev_path)
{
	struct block_device *bdev = NULL;
	struct storage_bdev *storage_bdev;

	spin_lock(&diff_storage->lock);
	list_for_each_entry(storage_bdev, &diff_storage->storage_bdevs, link) {
		if (strcmp(storage_bdev->bdev_path, bdev_path) == 0) {
			bdev = storage_bdev->bdev;
			break;
		}
	}
	spin_unlock(&diff_storage->lock);

	return bdev;
}

static struct block_device *diff_storage_add_storage_bdev(
	struct diff_storage *diff_storage, const char *bdev_path)
{
	struct block_device *bdev;
	struct storage_bdev *storage_bdev;

	bdev = blkdev_get_by_path(bdev_path, FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(bdev)) {
		pr_err("Failed to open device. errno=%d\n",
		       abs((int)PTR_ERR(bdev)));
		return bdev;
	}

	storage_bdev = kzalloc(sizeof(struct storage_bdev) +
			       strlen(bdev_path) + 1, GFP_KERNEL);
	if (!storage_bdev) {
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&storage_bdev->link);
	storage_bdev->bdev = bdev;
	strcpy(storage_bdev->bdev_path, bdev_path);

	spin_lock(&diff_storage->lock);
	list_add_tail(&storage_bdev->link, &diff_storage->storage_bdevs);
	spin_unlock(&diff_storage->lock);

	return bdev;
}

static inline int diff_storage_add_range(struct diff_storage *diff_storage,
					 struct block_device *bdev,
					 sector_t sector, sector_t count)
{
	struct storage_block *storage_block;

	pr_debug("Add range to diff storage: [%u:%u] %llu:%llu\n",
		 MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), sector, count);

	storage_block = kzalloc(sizeof(struct storage_block), GFP_KERNEL);
	if (!storage_block)
		return -ENOMEM;

	INIT_LIST_HEAD(&storage_block->link);
	storage_block->bdev = bdev;
	storage_block->sector = sector;
	storage_block->count = count;

	spin_lock(&diff_storage->lock);
	list_add_tail(&storage_block->link, &diff_storage->empty_blocks);
	diff_storage->capacity += count;
	spin_unlock(&diff_storage->lock);

	return 0;
}

int diff_storage_append_block(struct diff_storage *diff_storage,
			      const char *bdev_path,
			      struct blksnap_sectors __user *ranges,
			      unsigned int range_count)
{
	int ret;
	int inx;
	struct block_device *bdev;
	struct blksnap_sectors range;

	pr_debug("Append %u blocks\n", range_count);

	bdev = diff_storage_bdev_by_path(diff_storage, bdev_path);
	if (!bdev) {
		bdev = diff_storage_add_storage_bdev(diff_storage, bdev_path);
		if (IS_ERR(bdev))
			return PTR_ERR(bdev);
	}

	for (inx = 0; inx < range_count; inx++) {
		if (unlikely(copy_from_user(&range, ranges+inx, sizeof(range))))
			return -EINVAL;

		ret = diff_storage_add_range(diff_storage, bdev,
					     range.offset,
					     range.count);
		if (unlikely(ret))
			return ret;
	}

	if (atomic_read(&diff_storage->low_space_flag) &&
	    (diff_storage->capacity >= diff_storage->requested))
		atomic_set(&diff_storage->low_space_flag, 0);

	return 0;
}

static inline bool is_halffull(const sector_t sectors_left)
{
	return sectors_left <=
		((get_diff_storage_minimum() >> 1) & ~(PAGE_SECTORS - 1));
}

struct diff_region *diff_storage_new_region(struct diff_storage *diff_storage,
					   sector_t count,
					   unsigned int logical_blksz)
{
	int ret = 0;
	struct diff_region *diff_region;
	sector_t sectors_left;

	if (atomic_read(&diff_storage->overflow_flag))
		return ERR_PTR(-ENOSPC);

	diff_region = kzalloc(sizeof(struct diff_region), GFP_NOIO);
	if (!diff_region)
		return ERR_PTR(-ENOMEM);

	spin_lock(&diff_storage->lock);
	do {
		struct storage_block *storage_block;
		sector_t available;
		struct request_queue *q;

		storage_block = first_empty_storage_block(diff_storage);
		if (unlikely(!storage_block)) {
			atomic_inc(&diff_storage->overflow_flag);
			ret = -ENOSPC;
			break;
		}

		q = storage_block->bdev->bd_queue;
		if (logical_blksz < q->limits.logical_block_size) {
			pr_err("Incompatibility of block sizes was detected.");
			ret = -ENOTBLK;
			break;
		}

		available = storage_block->count - storage_block->used;
		if (likely(available >= count)) {
			diff_region->bdev = storage_block->bdev;
			diff_region->sector =
				storage_block->sector + storage_block->used;
			diff_region->count = count;

			storage_block->used += count;
			diff_storage->filled += count;
			break;
		}

		list_del(&storage_block->link);
		list_add_tail(&storage_block->link,
			      &diff_storage->filled_blocks);
		/*
		 * If there is still free space in the storage block, but
		 * it is not enough to store a piece, then such a block is
		 * considered used.
		 * We believe that the storage blocks are large enough
		 * to accommodate several pieces entirely.
		 */
		diff_storage->filled += available;
	} while (1);
	sectors_left = diff_storage->requested - diff_storage->filled;
	spin_unlock(&diff_storage->lock);

	if (ret) {
		pr_err("Cannot get empty storage block\n");
		diff_storage_free_region(diff_region);
		return ERR_PTR(ret);
	}

	if (is_halffull(sectors_left) &&
	    (atomic_inc_return(&diff_storage->low_space_flag) == 1))
		diff_storage_event_low(diff_storage);

	return diff_region;
}
