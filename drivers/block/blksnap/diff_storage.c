// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-storage: " fmt

#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/fiemap.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

#define FIEMAP_EXTENTS_LIMIT (PAGE_SIZE / sizeof(struct fiemap_extent))

#define FIEMAP_ALLOWED_FLAGS (FIEMAP_EXTENT_LAST |				\
			      FIEMAP_EXTENT_UNWRITTEN |				\
			      FIEMAP_EXTENT_MERGED)

#define DIFF_STORAGE_MODE (FMODE_READ | FMODE_WRITE | FMODE_EXCL)
#define DIFF_STORAGE_FILE_FLAGS (S_KERNEL_FILE | S_IMMUTABLE | S_SWAPFILE)

/**
 * struct storage_bdev - Information about the opened block device.
 *
 * @link:
 *	Allows to combine structures into a linked list.
 * @bdev:
 *	A pointer to an open block device.
 */
struct storage_bdev {
	struct list_head link;
	struct block_device *bdev;
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

/**
 * !!! TODO
 */
struct storage_file {
	struct list_head link;
	struct file *file;
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
	INIT_LIST_HEAD(&diff_storage->files);

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

static inline void storage_file_free(struct storage_file *st)
{
	int err;
	struct path filepath;
	struct inode *parent;

	if (st && st->file) {

		/* clear flags */
		inode_lock(st->file->f_inode);
		st->file->f_inode->i_flags &= ~DIFF_STORAGE_FILE_FLAGS;
		inode_unlock(st->file->f_inode);

		filepath = st->file->f_path;
		path_get(&filepath);

		fput(st->file);

		/* remove file */
		parent = filepath.dentry->d_parent->d_inode;
		inode_lock(parent);
		err = vfs_unlink(mnt_idmap(filepath.mnt), parent,
				 filepath.dentry, NULL);
		inode_unlock(parent);
		if (err)
			pr_err("Failed to unlink difference storage file");
		path_put(&filepath);
	}
	kfree(st);
}

void diff_storage_free(struct kref *kref)
{
	struct diff_storage *diff_storage =
		container_of(kref, struct diff_storage, kref);
	struct storage_block *blk;
	struct storage_bdev *storage_bdev;
	struct storage_file *st;

	while ((blk = first_empty_storage_block(diff_storage))) {
		list_del(&blk->link);
		kfree(blk);
	}

	while ((blk = first_filled_storage_block(diff_storage))) {
		list_del(&blk->link);
		kfree(blk);
	}

	while ((storage_bdev = first_storage_bdev(diff_storage))) {
		blkdev_put(storage_bdev->bdev, DIFF_STORAGE_MODE);
		list_del(&storage_bdev->link);
		kfree(storage_bdev);
	}

	while ((st = list_first_entry_or_null(&diff_storage->files,
					      struct storage_file, link))) {

		list_del(&st->link);
		storage_file_free(st);
	}

	event_queue_done(&diff_storage->event_queue);

	kfree(diff_storage);
}

static int diff_storage_add_storage_bdev(struct diff_storage *diff_storage,
					 struct block_device *new_bdev)
{
	int ret = 0;
	struct storage_bdev *storage_bdev;
	struct block_device *bdev = NULL;

	storage_bdev = kzalloc(sizeof(struct storage_bdev), GFP_KERNEL);
	if (!storage_bdev)
		return -ENOMEM;

	INIT_LIST_HEAD(&storage_bdev->link);
	storage_bdev->bdev = new_bdev;

	spin_lock(&diff_storage->lock);
	list_for_each_entry(storage_bdev, &diff_storage->storage_bdevs, link) {
		if (storage_bdev->bdev == new_bdev) {
			bdev = storage_bdev->bdev;
			break;
		}
	}
	if (bdev)
		ret = -EALREADY;
	else
		list_add_tail(&storage_bdev->link, &diff_storage->storage_bdevs);
	spin_unlock(&diff_storage->lock);

	if (ret)
		kfree(storage_bdev);

	return ret;

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
	int ret = 0;
	int inx;
	struct block_device *bdev;

	pr_debug("Append '%s' block device\n", bdev_path);

	bdev = blkdev_get_by_path(bdev_path, DIFF_STORAGE_MODE, diff_storage);
	if (IS_ERR(bdev)) {
		pr_err("Failed to open device. errno=%ld\n", PTR_ERR(bdev));
		return PTR_ERR(bdev);
	}

	ret = diff_storage_add_storage_bdev(diff_storage, bdev);
	if (ret) {
		blkdev_put(bdev, DIFF_STORAGE_MODE);
		return ret;
	}

	if (!ranges)
		ret = diff_storage_add_range(diff_storage, bdev,
					     0, bdev_nr_sectors(bdev));
	else {
		for (inx = 0; inx < range_count; inx++) {
			struct blksnap_sectors range;

			if (unlikely(copy_from_user(&range, ranges+inx, sizeof(range))))
				return -EINVAL;

			ret = diff_storage_add_range(diff_storage, bdev,
						     range.offset, range.count);
			if (unlikely(ret))
				break;
		}
	}
	if (!ret) {
		if (atomic_read(&diff_storage->low_space_flag) &&
		    (diff_storage->capacity >= diff_storage->requested))
			atomic_set(&diff_storage->low_space_flag, 0);
	}
	return ret;
}

static int append_file(struct diff_storage *diff_storage, struct file *file)
{
	int ret = 0;
	int inx;
	struct fiemap_extent *ext = NULL;
	loff_t logical_ofs = 0ull;
	struct inode *inode = file_inode(file);

	if (!inode->i_op->fiemap) {
		pr_err("Fiemap operation is not supported\n");
		return -EOPNOTSUPP;
	}

	inode_lock(inode);
	inode->i_flags |= DIFF_STORAGE_FILE_FLAGS;
	inode_unlock(inode);

	ext = kcalloc(FIEMAP_EXTENTS_LIMIT, sizeof(struct fiemap_extent),
		      GFP_NOIO);
	if (!ext)
		return -ENOMEM;

	pr_debug("File size: %llu\n", inode->i_size);
#if 0
	{/* check extents count */
		struct fiemap_extent_info fieinfo = {
			.fi_flags = 0,
			.fi_extents_mapped = 0,
			.fi_extents_max = 0,
			.fi_extents_start = NULL,
			.fi_kern_extents = NULL,
		};

		ret = inode->i_op->fiemap(inode, &fieinfo, logical_ofs,
					    inode->i_size - logical_ofs);
		if (ret)
			pr_err("Failed to call fiemap operation, ret=%d\n", ret);
		else
			pr_debug("Found %d extents\n", fieinfo.fi_extents_mapped);
	}
#endif
	while (!ret && (logical_ofs < inode->i_size)) {
		struct fiemap_extent_info fieinfo = {
			.fi_flags = 0,
			.fi_extents_mapped = 0,
			.fi_extents_max = FIEMAP_EXTENTS_LIMIT,
			.fi_extents_start = NULL,
			.fi_kern_extents = ext,
		};

		ret = inode->i_op->fiemap(inode, &fieinfo, logical_ofs,
					    inode->i_size - logical_ofs);
		if (ret) {
			pr_err("Failed to call fiemap operation, ret=%d\n", ret);
			break;
		}
		pr_debug("Found %d extents\n", fieinfo.fi_extents_mapped);

		for (inx = 0; inx < fieinfo.fi_extents_mapped; inx++) {
			sector_t sector_start, sector_end;
			struct fiemap_extent *ext_entry = ext + inx;

			if (ext_entry->fe_flags & ~FIEMAP_ALLOWED_FLAGS) {
				ret = -EINVAL;
				pr_err("Extent has unacceptable flags\n");
				break;
			}

			sector_start = DIV_ROUND_UP_ULL(
				ext_entry->fe_physical, SECTOR_SIZE);
			sector_end = DIV_ROUND_DOWN_ULL(
				ext_entry->fe_physical + ext_entry->fe_length,
				SECTOR_SIZE);
			logical_ofs = ext_entry->fe_logical + ext_entry->fe_length;

			ret = diff_storage_add_range(
				diff_storage, file->f_inode->i_sb->s_bdev,
				sector_start, sector_end - sector_start);

			if (ret) {
				pr_err("Failed to add range to difference storage\n");
				break;
			}
		}
	}
	kfree(ext);
	return ret;
}

int diff_storage_append_file(struct diff_storage *diff_storage,
			     const char *fname)
{
	int ret;
	struct storage_file *st = NULL;
	struct file *fl;

	st = kzalloc(sizeof(struct storage_file), GFP_NOIO);
	if (!st)
		return -ENOMEM;

	fl = filp_open(fname, O_CREAT | O_RDWR | O_LARGEFILE | O_EXCL,
		       S_IRUSR | S_IWUSR);
	if (IS_ERR(fl)) {
		ret = PTR_ERR(fl);
		goto fail;
	}
	st->file = fl;

	if (!S_ISREG(st->file->f_inode->i_mode)) {
	    	pr_err("The difference storage file must be a regular file\n");

		ret = -EBADF;
		goto fail;
	}

	if (i_size_read(st->file->f_inode) == 0ull) {
		if (!st->file->f_op->fallocate) {
			pr_err("Fallocate operation is not supported\n");
			ret = -EOPNOTSUPP;
			goto fail;
		}

		ret = st->file->f_op->fallocate(st->file, 0, 0,
			(loff_t)get_diff_storage_minimum() << SECTOR_SHIFT);
		if (ret)
			goto fail;
	}

	ret = append_file(diff_storage, st->file);
	if (ret)
		goto fail;

	spin_lock(&diff_storage->lock);
	list_add_tail(&st->link, &diff_storage->files);
	spin_unlock(&diff_storage->lock);
	return 0;
fail:
	storage_file_free(st);
	return ret;
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
