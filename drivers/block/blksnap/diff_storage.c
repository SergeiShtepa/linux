// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-storage: " fmt

#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/blkdev.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

static void diff_storage_reallocate_work(struct work_struct *work)
{
	int ret;
	sector_t req_sect;
	struct diff_storage *diff_storage = container_of(
		work, struct diff_storage, reallocate_work);
	bool stop = false;

	do {
		spin_lock(&diff_storage->lock);
		req_sect = diff_storage->requested;
		spin_unlock(&diff_storage->lock);
#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
		if (unlikely(!diff_storage->file)) {
			pr_warn("Reallocating is allowed only for a regular file\n");
			return;
		}
#endif
		ret = vfs_fallocate(diff_storage->file, 0, 0,
				    (loff_t)(req_sect << SECTOR_SHIFT));
		if (ret) {
			pr_err("Failed to fallocate difference storage file\n");
			return;
		}

		spin_lock(&diff_storage->lock);
		diff_storage->capacity = req_sect;
		if (diff_storage->capacity >= diff_storage->requested) {
			atomic_set(&diff_storage->low_space_flag, 0);
			stop = true;
		}
		spin_unlock(&diff_storage->lock);

		pr_debug("Diff storage reallocate. Capacity: %llu sectors\n",
			 req_sect);
	} while (!stop);
}

static void diff_storage_event_low(struct diff_storage *diff_storage)
{
	sector_t req_sect;

	spin_lock(&diff_storage->lock);
	if (diff_storage->capacity < diff_storage->limit) {
		req_sect = min(get_diff_storage_minimum(),
			diff_storage->limit - diff_storage->capacity);

		diff_storage->requested += req_sect;
	} else
		req_sect = 0;
	spin_unlock(&diff_storage->lock);

	pr_debug("The size of the difference storage was %llu MiB\n",
		 diff_storage->capacity >> (20 - SECTOR_SHIFT));
	pr_debug("The limit is %llu MiB\n",
		 diff_storage->limit >> (20 - SECTOR_SHIFT));

	if (req_sect == 0) {
		pr_info("The limit size of the difference storage has been reached\n");
		atomic_inc(&diff_storage->overflow_flag);
		return;
	}

	pr_debug("Diff storage low free space. Portion: %llu sectors, requested: %llu\n",
		 req_sect, diff_storage->requested);

	queue_work(system_wq, &diff_storage->reallocate_work);
}

static inline bool is_halffull(const sector_t sectors_left)
{
	return sectors_left <=
		((get_diff_storage_minimum() >> 1) & ~(PAGE_SECTORS - 1));
}

static inline void check_halffull(struct diff_storage *diff_storage,
				  const sector_t sectors_left)
{
	if (is_halffull(sectors_left) &&
	    (atomic_inc_return(&diff_storage->low_space_flag) == 1))
		diff_storage_event_low(diff_storage);
}

struct diff_storage *diff_storage_new(void)
{
	struct diff_storage *diff_storage;

	diff_storage = kzalloc(sizeof(struct diff_storage), GFP_KERNEL);
	if (!diff_storage)
		return NULL;

	kref_init(&diff_storage->kref);
	spin_lock_init(&diff_storage->lock);
	diff_storage->limit = 0;

	INIT_WORK(&diff_storage->reallocate_work, diff_storage_reallocate_work);
	event_queue_init(&diff_storage->event_queue);

	return diff_storage;
}

void diff_storage_free(struct kref *kref)
{
	struct diff_storage *diff_storage =
		container_of(kref, struct diff_storage, kref);

	flush_work(&diff_storage->reallocate_work);


#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
	if (diff_storage->bdev)
		blkdev_put(diff_storage->bdev, diff_storage);
#endif

	if (diff_storage->file)
		fput(diff_storage->file);
	event_queue_done(&diff_storage->event_queue);
	kfree(diff_storage);
}

static inline bool unsupported_files(const umode_t m)
{
	return (S_ISCHR(m) || S_ISFIFO(m) || S_ISSOCK(m));
}

#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
static void diff_storage_mark_dead(struct block_device *bdev)
{
	struct diff_storage *diff_storage = bdev->bd_holder;

	spin_lock(&diff_storage->lock);
	diff_storage->bdev = NULL;
	spin_unlock(&diff_storage->lock);
}

static const struct blk_holder_ops diff_storage_hops = {
	.mark_dead = diff_storage_mark_dead,
};
#endif

int diff_storage_set_diff_storage(struct diff_storage *diff_storage,
				  unsigned int fd, sector_t limit)
{
	int ret = 0;
	struct file *file;
	sector_t sectors_left;
#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
	struct block_device *bdev = NULL;
#endif
	umode_t mode;

	file = fget(fd);
	if (!file) {
		pr_err("Invalid file descriptor\n");
		return -EINVAL;
	}

	mode = file_inode(file)->i_mode;
	if (unsupported_files(mode)) {
		pr_err("The difference storage can only be a regular file or a block device\n");
		ret = -EINVAL;
		goto fail_fput;
	}

#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
	if (S_ISBLK(mode)) {
		dev_t dev_id = file_inode(file)->i_rdev;

		pr_debug("Open block device %d:%d\n",
			MAJOR(dev_id), MINOR(dev_id));
		bdev = blkdev_get_by_dev(dev_id,
				BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_EXCL,
				diff_storage, &diff_storage_hops);
		if (IS_ERR(bdev)) {
			pr_err("Cannot open block device %d:%d\n",
				MAJOR(dev_id), MINOR(dev_id));
			ret = PTR_ERR(bdev);
			goto fail_fput;
		}
	}
#endif

	spin_lock(&diff_storage->lock);
	diff_storage->dev_id = S_ISBLK(mode) ?
		file_inode(file)->i_rdev : file_inode(file)->i_sb->s_dev;

#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
	if (bdev) {
		diff_storage->bdev = bdev;
		diff_storage->file = NULL;
		diff_storage->capacity = diff_storage->requested =
			bdev_nr_sectors(bdev);
		pr_debug("A block device is selected for difference storage\n");
	} else {
		diff_storage->bdev = NULL;
		diff_storage->file = get_file(file);
		diff_storage->capacity = diff_storage->requested =
			i_size_read(file_inode(file)) >> SECTOR_SHIFT;
		pr_debug("A regular file is selected for difference storage\n");
	}
#else
	diff_storage->file = get_file(file);
	diff_storage->capacity = diff_storage->requested =
		i_size_read(file_inode(file)) >> SECTOR_SHIFT;
#endif

	diff_storage->limit = limit;

	sectors_left = diff_storage->requested - diff_storage->filled;
	spin_unlock(&diff_storage->lock);

	check_halffull(diff_storage, sectors_left);
fail_fput:
	fput(file);
	return ret;
}

int diff_storage_alloc(struct diff_storage *diff_storage, sector_t count,
#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
			struct block_device **bdev,
#endif
			struct file **file, sector_t *sector)

{
	sector_t sectors_left;

	if (atomic_read(&diff_storage->overflow_flag))
		return -ENOSPC;

	spin_lock(&diff_storage->lock);
#if defined(CONFIG_BLKSNAP_DIFF_BLKDEV)
	*bdev = diff_storage->bdev;
#endif
	*file = diff_storage->file;
	*sector = diff_storage->filled;

	diff_storage->filled += count;

	sectors_left = diff_storage->requested - diff_storage->filled;
	spin_unlock(&diff_storage->lock);

	check_halffull(diff_storage, sectors_left);

	return 0;
}
