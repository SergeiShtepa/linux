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
#if 0
static inline int diff_storage_unlink_file(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;

	return vfs_unlink(&nop_mnt_idmap, d_inode(dentry->d_parent),
			  dentry, NULL);
}
#endif
void diff_storage_free(struct kref *kref)
{
	struct diff_storage *diff_storage =
		container_of(kref, struct diff_storage, kref);

	flush_work(&diff_storage->reallocate_work);

	if (diff_storage->file) {
#if 0
		//can fail with: null-ptr-deref in __fput+0xef
		int ret;

		ret = diff_storage_unlink_file(diff_storage->file);
		if (ret)
			pr_err("Failed to unlink difference storage file\n");
#endif
		fput(diff_storage->file);
	}
	event_queue_done(&diff_storage->event_queue);
	kfree(diff_storage);
}

int diff_storage_set_file(struct diff_storage *diff_storage,
			     unsigned int fd, sector_t limit)
{
	int ret = 0;
	struct file *file;
	sector_t sectors_left;

	pr_debug("Append file\n");
	file = fget(fd);
	if (!file) {
		pr_err("Invalid file descriptor\n");
		return -EINVAL;
	}

	spin_lock(&diff_storage->lock);
	diff_storage->capacity = diff_storage->requested =
		i_size_read(file_inode(file)) >> SECTOR_SHIFT;
	diff_storage->file = get_file(file);
	diff_storage->limit = limit;

	sectors_left = diff_storage->requested - diff_storage->filled;
	spin_unlock(&diff_storage->lock);

	check_halffull(diff_storage, sectors_left);

	fput(file);
	return ret;
}

int diff_storage_alloc(struct diff_storage *diff_storage, sector_t count,
		       struct file **file, sector_t *sector)
{
	sector_t sectors_left;

	if (atomic_read(&diff_storage->overflow_flag))
		return -ENOSPC;

	spin_lock(&diff_storage->lock);

	*file = diff_storage->file;
	*sector = diff_storage->filled;

	diff_storage->filled += count;

	sectors_left = diff_storage->requested - diff_storage->filled;
	spin_unlock(&diff_storage->lock);

	check_halffull(diff_storage, sectors_left);

	return 0;
}
