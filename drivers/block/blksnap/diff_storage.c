// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-storage: " fmt

#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

/**
 * struct storage_bdev - Information about the opened files.
 *
 * @link:
 *	Allows to combine structures into a linked list.
 * @file:
 *	A pointer to an open file.
 */
struct storage_bdev {
	struct list_head link;
	struct file *file;
};

/**
 * struct storage_block - A storage unit reserved for storing differences.
 *
 * @link:
 *	Allows to combine structures into a linked list.
 * @file:
 *	A pointer to a file.
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
	struct file *file;
	sector_t sector;
	sector_t count;
	sector_t used;
};

static inline struct storage_block *storage_block_new(struct file *file,
	sector_t sector, sector_t count)
{
	struct storage_block *storage_block = kzalloc(
				sizeof(struct storage_block), GFP_KERNEL);

	if (storage_block) {
		INIT_LIST_HEAD(&storage_block->link);
		storage_block->file = get_file(file);
		storage_block->sector = sector;
		storage_block->count = count;
	}
	return storage_block;
}

static inline void storage_block_free(struct storage_block *blk)
{
	fput(blk->file);
	kfree(blk);
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

void diff_storage_free(struct kref *kref)
{
	struct diff_storage *diff_storage =
		container_of(kref, struct diff_storage, kref);
	struct storage_block *blk;

	while ((blk = first_empty_storage_block(diff_storage))) {
		list_del(&blk->link);
		storage_block_free(blk);
	}

	while ((blk = first_filled_storage_block(diff_storage))) {
		list_del(&blk->link);
		storage_block_free(blk);
	}

	event_queue_done(&diff_storage->event_queue);

	kfree(diff_storage);
}

/*
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);

diff_storage_read(struct file *file, struct kiocb *iocb, struct iov_iter *iter)
{
	iocb->ki_filp = file;

	file->f_op->read_iter();
	file->f_op->write_iter();
	//generic_file_read_iter(
	//generic_file_write_iter(

}

{
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	loff_t offset = 0, len;

	ret = vfs_fallocate(file, mode, offset, len);
	vfs_fsync(file, 1);


	file = fget(fd);
	fput(file);
}
*/

int diff_storage_append_file(struct diff_storage *diff_storage, unsigned int fd)
{
	int ret = 0;
	struct storage_block *blk;
	struct file *file;

	pr_debug("Append file\n");
	file = fget(fd);
	if (!file) {
		pr_err("Invalid file descriptor\n");
		return -EINVAL;
	}

	loff_t len = i_size_read(file_inode(file));
	if (len < (1ull << get_chunk_minimum_shift())) {
		pr_err("The file is too small.\n");
		ret = -EFAULT;
		goto out;
	}


	blk = storage_block_new(file, 0, len >> SECTOR_SHIFT);
	if (unlikely(!blk)) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock(&diff_storage->lock);
	list_add_tail(&blk->link, &diff_storage->empty_blocks);
	diff_storage->capacity += len >> SECTOR_SHIFT;
	spin_unlock(&diff_storage->lock);

	if (atomic_read(&diff_storage->low_space_flag) &&
	    (diff_storage->capacity >= diff_storage->requested))
		atomic_set(&diff_storage->low_space_flag, 0);
out:
	fput(file);
	return ret;
}

static inline bool is_halffull(const sector_t sectors_left)
{
	return sectors_left <=
		((get_diff_storage_minimum() >> 1) & ~(PAGE_SECTORS - 1));
}

int diff_storage_alloc(struct diff_storage *diff_storage, sector_t count,
		       unsigned int logical_blksz, struct file **file,
		       sector_t *sector)
{
	int ret = 0;
	sector_t sectors_left;

	if (atomic_read(&diff_storage->overflow_flag))
		return -ENOSPC;

	spin_lock(&diff_storage->lock);
	do {
		struct storage_block *storage_block;
		sector_t available;

		storage_block = first_empty_storage_block(diff_storage);
		if (unlikely(!storage_block)) {
			atomic_inc(&diff_storage->overflow_flag);
			ret = -ENOSPC;
			break;
		}

		/*
		 TODO: add real block size check
		if (unlikely(logical_blksz < SECTOR_SIZE)) {
			pr_err("Incompatibility of block sizes was detected.");
			ret = -ENOTBLK;
			break;
		}
		*/

		available = storage_block->count - storage_block->used;
		if (likely(available >= count)) {
			*file = storage_block->file;
			*sector = storage_block->sector + storage_block->used;

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

	if (!ret && is_halffull(sectors_left) &&
	    (atomic_inc_return(&diff_storage->low_space_flag) == 1))
		diff_storage_event_low(diff_storage);

	return ret;
}
