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

static void diff_storage_event_low(struct diff_storage *diff_storage)
{

	sector_t requested_nr_sect;

	spin_lock(&diff_storage->lock);
	requested_nr_sect = min(get_diff_storage_minimum(),
		diff_storage->limit - diff_storage->capacity);

	diff_storage->requested += requested_nr_sect;
	spin_unlock(&diff_storage->lock);

	pr_debug("Diff storage low free space. Portion: %llu sectors, requested: %llu\n",
		requested_nr_sect, diff_storage->requested);

	/*
	TODO: resize file
	*/

	spin_lock(&diff_storage->lock);
	diff_storage->capacity += requested_nr_sect;

	if (atomic_read(&diff_storage->low_space_flag) &&
	    (diff_storage->capacity >= diff_storage->requested))
		atomic_set(&diff_storage->low_space_flag, 0);

	spin_unlock(&diff_storage->lock);
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

	event_queue_init(&diff_storage->event_queue);
	diff_storage_event_low(diff_storage);

	return diff_storage;
}

void diff_storage_free(struct kref *kref)
{
	struct diff_storage *diff_storage =
		container_of(kref, struct diff_storage, kref);

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

int diff_storage_append_file(struct diff_storage *diff_storage,
			     unsigned int fd, sector_t limit)
{
	int ret = 0;
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

	spin_lock(&diff_storage->lock);
	diff_storage->file = file;
	diff_storage->capacity += len >> SECTOR_SHIFT;
	diff_storage->limit = limit;
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
		       struct file **file, sector_t *sector)
{
	int ret = 0;
	sector_t sectors_left;

	if (atomic_read(&diff_storage->overflow_flag))
		return -ENOSPC;

	spin_lock(&diff_storage->lock);

	*file = diff_storage->file;
	*sector = diff_storage->filled;

	diff_storage->filled += count;

	sectors_left = diff_storage->requested - diff_storage->filled;
	spin_unlock(&diff_storage->lock);

	if (!ret && is_halffull(sectors_left) &&
	    (atomic_inc_return(&diff_storage->low_space_flag) == 1))
		diff_storage_event_low(diff_storage);

	return 0;
}
