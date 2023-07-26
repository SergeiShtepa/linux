// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-area: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

static inline sector_t diff_area_chunk_offset(struct diff_area *diff_area,
					      sector_t sector)
{
	return sector & ((1ull << (diff_area->chunk_shift - SECTOR_SHIFT)) - 1);
}

static inline unsigned long diff_area_chunk_number(struct diff_area *diff_area,
						   sector_t sector)
{
	return (unsigned long)(sector >>
			       (diff_area->chunk_shift - SECTOR_SHIFT));
}

static inline sector_t chunk_sector(struct chunk *chunk)
{
	return (sector_t)(chunk->number)
	       << (chunk->diff_area->chunk_shift - SECTOR_SHIFT);
}

static inline sector_t last_chunk_size(sector_t sector_count, sector_t capacity)
{
	sector_t capacity_rounded = round_down(capacity, sector_count);

	if (capacity > capacity_rounded)
		sector_count = capacity - capacity_rounded;

	return sector_count;
}

static inline unsigned long long count_by_shift(sector_t capacity,
						unsigned long long shift)
{
	unsigned long long shift_sector = (shift - SECTOR_SHIFT);

	return round_up(capacity, (1ull << shift_sector)) >> shift_sector;
}

static inline struct chunk *chunk_alloc(struct diff_area *diff_area,
					unsigned long number)
{
	struct chunk *chunk;

	chunk = kzalloc(sizeof(struct chunk), GFP_NOIO);
	if (!chunk)
		return NULL;

	INIT_LIST_HEAD(&chunk->link);
	sema_init(&chunk->lock, 1);
	chunk->diff_area = NULL;
	chunk->number = number;
	chunk->state = CHUNK_ST_NEW;

	chunk->sector_count = diff_area_chunk_sectors(diff_area);
	/*
	 * The last chunk has a special size.
	 */
	if (unlikely((number + 1) == diff_area->chunk_count)) {
		chunk->sector_count = bdev_nr_sectors(diff_area->orig_bdev) -
					(chunk->sector_count * number);
	}

	return chunk;
}

static inline void chunk_free(struct diff_area *diff_area, struct chunk *chunk)
{
	down(&chunk->lock);
	if (chunk->diff_buffer)
		diff_buffer_release(diff_area, chunk->diff_buffer);
	up(&chunk->lock);
	kfree(chunk);
}

static void diff_area_calculate_chunk_size(struct diff_area *diff_area)
{
	unsigned long count;
	unsigned long shift = get_chunk_minimum_shift();
	sector_t capacity;
	sector_t min_io_sect;

	min_io_sect = (sector_t)(bdev_io_min(diff_area->orig_bdev) >>
		SECTOR_SHIFT);
	capacity = bdev_nr_sectors(diff_area->orig_bdev);
	pr_debug("Minimal IO block %llu sectors\n", min_io_sect);
	pr_debug("Device capacity %llu sectors\n", capacity);

	count = count_by_shift(capacity, shift);
	pr_debug("Chunks count %lu\n", count);
	while ((count > get_chunk_maximum_count()) ||
		((1ul << (shift - SECTOR_SHIFT)) < min_io_sect)) {
		shift++;
		count = count_by_shift(capacity, shift);
		pr_debug("Chunks count %lu\n", count);
	}

	diff_area->chunk_shift = shift;
	diff_area->chunk_count = (unsigned long)DIV_ROUND_UP_ULL(capacity,
					(1ul << (shift - SECTOR_SHIFT)));
}

void diff_area_free(struct kref *kref)
{
	unsigned long inx = 0;
	struct chunk *chunk;
	struct diff_area *diff_area =
		container_of(kref, struct diff_area, kref);

	might_sleep();

	flush_work(&diff_area->store_queue_work);
	xa_for_each(&diff_area->chunk_map, inx, chunk)
		if (chunk)
			chunk_free(diff_area, chunk);
	xa_destroy(&diff_area->chunk_map);

	if (diff_area->orig_bdev) {
		blkdev_put(diff_area->orig_bdev, NULL);
		diff_area->orig_bdev = NULL;
	}

	/* Clean up free_diff_buffers */
	diff_buffer_cleanup(diff_area);

	kfree(diff_area);
}

static inline bool diff_area_store_one(struct diff_area *diff_area)
{
	struct chunk *iter, *chunk = NULL;

	spin_lock(&diff_area->store_queue_lock);
	list_for_each_entry(iter, &diff_area->store_queue, link) {
		if (!down_trylock(&iter->lock)) {
			chunk = iter;
			atomic_dec(&diff_area->store_queue_count);
			list_del_init(&chunk->link);
			chunk->diff_area = diff_area_get(diff_area);
			break;
		}
		/*
		 * If it is not possible to lock a chunk for writing,
		 * then it is currently in use, and we try to clean up the
		 * next chunk.
		 */
	}
	spin_unlock(&diff_area->store_queue_lock);
	if (!chunk)
		return false;

	if (chunk->state != CHUNK_ST_IN_MEMORY) {
		/*
		 * There cannot be a chunk in the store queue whose buffer has
		 * not been read into memory.
		 */
		chunk_up(chunk);
		pr_warn("Cannot release empty buffer for chunk #%ld",
			chunk->number);
		return true;
	}

	if (diff_area_is_corrupted(diff_area)) {
		chunk_store_failed(chunk, 0);
		return true;
	}

	if (!chunk->snapshot_bdev) {
		int ret;

		ret = diff_storage_alloc(diff_area->diff_storage,
					 chunk->sector_count,
					 diff_area->logical_blksz,
					 &chunk->snapshot_bdev,
					 &chunk->snapshot_sector);
		if (ret) {
			pr_debug("Cannot get store for chunk #%ld\n",
				 chunk->number);
			chunk_store_failed(chunk, ret);
			return true;
		}
	}
	chunk_store(chunk);
	return true;
}

static void diff_area_store_queue_work(struct work_struct *work)
{
	struct diff_area *diff_area = container_of(
		work, struct diff_area, store_queue_work);

	while (diff_area_store_one(diff_area))
		;
}

struct diff_area *diff_area_new(dev_t dev_id, struct diff_storage *diff_storage)
{
	int ret = 0;
	struct diff_area *diff_area = NULL;
	struct block_device *bdev;

	pr_debug("Open device [%u:%u]\n", MAJOR(dev_id), MINOR(dev_id));

	bdev = blkdev_get_by_dev(dev_id, FMODE_READ | FMODE_WRITE, NULL, NULL);
	if (IS_ERR(bdev)) {
		int err = PTR_ERR(bdev);

		pr_err("Failed to open device. errno=%d\n", abs(err));
		return ERR_PTR(err);
	}

	diff_area = kzalloc(sizeof(struct diff_area), GFP_KERNEL);
	if (!diff_area) {
		blkdev_put(bdev, NULL);
		return ERR_PTR(-ENOMEM);
	}

	kref_init(&diff_area->kref);
	diff_area->orig_bdev = bdev;
	diff_area->diff_storage = diff_storage;

	diff_area_calculate_chunk_size(diff_area);
	if (diff_area->chunk_shift > get_chunk_maximum_shift()) {
		pr_info("The maximum allowable chunk size has been reached.\n");
		return ERR_PTR(-EFAULT);
	}
	pr_debug("The optimal chunk size was calculated as %llu bytes for device [%d:%d]\n",
		 (1ull << diff_area->chunk_shift),
		 MAJOR(diff_area->orig_bdev->bd_dev),
		 MINOR(diff_area->orig_bdev->bd_dev));

	xa_init(&diff_area->chunk_map);

	spin_lock_init(&diff_area->store_queue_lock);
	INIT_LIST_HEAD(&diff_area->store_queue);
	atomic_set(&diff_area->store_queue_count, 0);
	INIT_WORK(&diff_area->store_queue_work, diff_area_store_queue_work);

	spin_lock_init(&diff_area->free_diff_buffers_lock);
	INIT_LIST_HEAD(&diff_area->free_diff_buffers);
	atomic_set(&diff_area->free_diff_buffers_count, 0);

	diff_area->physical_blksz = bdev->bd_queue->limits.physical_block_size;
	diff_area->logical_blksz = bdev->bd_queue->limits.logical_block_size;
	diff_area->corrupt_flag = 0;

	if (!diff_storage->capacity) {
		pr_err("Difference storage is empty\n");
		pr_err("In-memory difference storage is not supported\n");
		ret = -EFAULT;
	}

	if (ret) {
		diff_area_put(diff_area);
		return ERR_PTR(ret);
	}

	return diff_area;
}

static inline unsigned int chunk_limit(struct chunk *chunk,
				       struct bvec_iter *iter)
{
	sector_t chunk_ofs = iter->bi_sector - chunk_sector(chunk);
	sector_t chunk_left = chunk->sector_count - chunk_ofs;

	return min(iter->bi_size, (unsigned int)(chunk_left << SECTOR_SHIFT));
}

/*
 * Implements the copy-on-write mechanism.
 */
bool diff_area_cow(struct bio *bio, struct diff_area *diff_area,
		   struct bvec_iter *iter)
{
	bool nowait = bio->bi_opf & REQ_NOWAIT;
	struct bio *chunk_bio = NULL;
	LIST_HEAD(chunks);
	int ret = 0;

	while (iter->bi_size) {
		unsigned long nr = diff_area_chunk_number(diff_area,
							  iter->bi_sector);
		struct chunk *chunk = xa_load(&diff_area->chunk_map, nr);
		unsigned int len;

		if (!chunk) {
			chunk = chunk_alloc(diff_area, nr);
			if (!chunk) {
				diff_area_set_corrupted(diff_area, -EINVAL);
				ret = -ENOMEM;
				goto fail;
			}

			ret = xa_insert(&diff_area->chunk_map, nr, chunk,
					GFP_NOIO);
			if (likely(!ret)) {
				/* new chunk has been added */
			} else if (ret == -EBUSY) {
				/* another chunk has just been created */
				chunk_free(diff_area, chunk);
				chunk = xa_load(&diff_area->chunk_map, nr);
				WARN_ON_ONCE(!chunk);
				if (unlikely(!chunk)) {
					ret = -EINVAL;
					diff_area_set_corrupted(diff_area, ret);
					goto fail;
				}
			} else if (ret) {
				pr_err("Failed insert chunk to chunk map\n");
				chunk_free(diff_area, chunk);
				diff_area_set_corrupted(diff_area, ret);
				goto fail;
			}
		}

		if (nowait) {
			if (down_trylock(&chunk->lock)) {
				ret = -EAGAIN;
				goto fail;
			}
		} else {
			ret = down_killable(&chunk->lock);
			if (unlikely(ret))
				goto fail;
		}
		chunk->diff_area = diff_area_get(diff_area);

		len = chunk_limit(chunk, iter);
		if (chunk->state == CHUNK_ST_NEW) {
			if (nowait) {
				/*
				 * If the data of this chunk has not yet been
				 * copied to the difference storage, then it is
				 * impossible to process the I/O write unit with
				 * the NOWAIT flag.
				 */
				chunk_up(chunk);
				ret = -EAGAIN;
				goto fail;
			}

			/*
			 * Load the chunk asynchronously.
			 */
			ret = chunk_load_and_postpone_io(chunk, &chunk_bio);
			if (ret) {
				chunk_up(chunk);
				goto fail;
			}
			list_add_tail(&chunk->link, &chunks);
		} else {
			/*
			 * The chunk has already been:
			 *   - failed, when the snapshot is corrupted
			 *   - read into the buffer
			 *   - stored into the diff storage
			 * In this case, we do not change the chunk.
			 */
			chunk_up(chunk);
		}
		bio_advance_iter_single(bio, iter, len);
	}

	if (chunk_bio) {
		/* Postpone bio processing in a callback. */
		chunk_load_and_postpone_io_finish(&chunks, chunk_bio, bio);
		return true;
	}
	/* Pass bio to the low level */
	return false;

fail:
	if (chunk_bio) {
		chunk_bio->bi_status = errno_to_blk_status(ret);
		bio_endio(chunk_bio);
	}

	if (ret == -EAGAIN) {
		/*
		 * The -EAGAIN error code means that it is not possible to
		 * process a I/O unit with a flag REQ_NOWAIT.
		 * I/O unit processing is being completed with such error.
		 */
		bio->bi_status = BLK_STS_AGAIN;
		bio_endio(bio);
		return true;
	}
	/* In any other case, the processing of the I/O unit continues.	*/
	return false;
}

static void orig_clone_endio(struct bio *bio)
{
	struct bio *orig_bio = bio->bi_private;

	if (unlikely(bio->bi_status != BLK_STS_OK))
		bio_io_error(orig_bio);
	else
		bio_endio(orig_bio);
}

static void orig_clone_bio(struct diff_area *diff_area, struct bio *bio)
{
	struct bio *new_bio;
	struct block_device *bdev = diff_area->orig_bdev;
	sector_t chunk_limit;

	new_bio = chunk_alloc_clone(bdev, bio);
	WARN_ON(!new_bio);

	chunk_limit = diff_area_chunk_sectors(diff_area) -
		      diff_area_chunk_offset(diff_area, bio->bi_iter.bi_sector);

	new_bio->bi_iter.bi_sector = bio->bi_iter.bi_sector;
	new_bio->bi_iter.bi_size = min_t(unsigned int,
			bio->bi_iter.bi_size, chunk_limit << SECTOR_SHIFT);

	bio_set_flag(new_bio, BIO_FILTERED);
	new_bio->bi_end_io = orig_clone_endio;
	new_bio->bi_private = bio;

	bio_advance(bio, new_bio->bi_iter.bi_size);
	bio_inc_remaining(bio);

	submit_bio_noacct(new_bio);
}

bool diff_area_submit_chunk(struct diff_area *diff_area, struct bio *bio)
{
	int ret;
	struct chunk *chunk;
	unsigned long nr = diff_area_chunk_number(diff_area,
						  bio->bi_iter.bi_sector);

	chunk = xa_load(&diff_area->chunk_map, nr);
	/*
	 * If this chunk is not in the chunk map, then the COW algorithm did
	 * not access this part of the disk space, and writing to the snapshot
	 * in this part was also not performed.
	 */
	if (!chunk) {
		if (op_is_write(bio_op(bio))) {
			/*
			 * To process a write bio, we need to allocate a new
			 * chunk.
			 */
			chunk = chunk_alloc(diff_area, nr);
			WARN_ON_ONCE(!chunk);
			if (unlikely(!chunk))
				return false;

			ret = xa_insert(&diff_area->chunk_map, nr, chunk,
					GFP_NOIO);
			if (likely(!ret)) {
				/* new chunk has been added */
			} else if (ret == -EBUSY) {
				/* another chunk has just been created */
				chunk_free(diff_area, chunk);
				chunk = xa_load(&diff_area->chunk_map, nr);
				WARN_ON_ONCE(!chunk);
				if (unlikely(!chunk))
					return false;
			} else if (ret) {
				pr_err("Failed insert chunk to chunk map\n");
				chunk_free(diff_area, chunk);
				return false;
			}
		} else {
			/*
			 * To read, we simply redirect the bio to the original
			 * block device.
			 */
			orig_clone_bio(diff_area, bio);
			return true;
		}
	}

	if (down_killable(&chunk->lock))
		return false;
	chunk->diff_area = diff_area_get(diff_area);

	if (unlikely(chunk->state == CHUNK_ST_FAILED)) {
		pr_err("Chunk #%ld corrupted\n", chunk->number);
		chunk_up(chunk);
		return false;
	}
	if (chunk->state == CHUNK_ST_IN_MEMORY) {
		/*
		 * Directly copy data from the in-memory chunk or
		 * copy to the in-memory chunk for write operation.
		 */
		chunk_copy_bio(chunk, bio, &bio->bi_iter);
		chunk_up(chunk);
		return true;
	}
	if ((chunk->state == CHUNK_ST_STORED) || !op_is_write(bio_op(bio))) {
		/*
		 * Read data from the chunk on difference storage.
		 */
		chunk_clone_bio(chunk, bio);
		chunk_up(chunk);
		return true;
	}
	/*
	 * Starts asynchronous loading of a chunk from the original block device
	 * or difference storage and schedule copying data to (or from) the
	 * in-memory chunk.
	 */
	if (chunk_load_and_schedule_io(chunk, bio)) {
		chunk_up(chunk);
		return false;
	}
	return true;
}

static inline void diff_area_event_corrupted(struct diff_area *diff_area)
{
	struct blksnap_event_corrupted data = {
		.dev_id_mj = MAJOR(diff_area->orig_bdev->bd_dev),
		.dev_id_mn = MINOR(diff_area->orig_bdev->bd_dev),
		.err_code = abs(diff_area->error_code),
	};

	event_gen(&diff_area->diff_storage->event_queue, GFP_NOIO,
		  blksnap_event_code_corrupted, &data,
		  sizeof(struct blksnap_event_corrupted));
}

void diff_area_set_corrupted(struct diff_area *diff_area, int err_code)
{
	if (test_and_set_bit(0, &diff_area->corrupt_flag))
		return;

	diff_area->error_code = err_code;
	diff_area_event_corrupted(diff_area);

	pr_err("Set snapshot device is corrupted for [%u:%u] with error code %d\n",
	       MAJOR(diff_area->orig_bdev->bd_dev),
	       MINOR(diff_area->orig_bdev->bd_dev), abs(err_code));
}
