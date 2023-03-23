// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-area: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_area.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

static inline unsigned long chunk_number(struct diff_area *diff_area,
					 sector_t sector)
{
	return (unsigned long)(sector >>
			       (diff_area->chunk_shift - SECTOR_SHIFT));
};

static inline sector_t chunk_sector(struct chunk *chunk)
{
	return (sector_t)(chunk->number)
	       << (chunk->diff_area->chunk_shift - SECTOR_SHIFT);
}

static inline void recalculate_last_chunk_size(struct chunk *chunk)
{
	sector_t capacity;

	capacity = bdev_nr_sectors(chunk->diff_area->orig_bdev);
	if (capacity > round_down(capacity, chunk->sector_count))
		chunk->sector_count =
			capacity - round_down(capacity, chunk->sector_count);
}

static inline unsigned long long count_by_shift(sector_t capacity,
						unsigned long long shift)
{
	unsigned long long shift_sector = (shift - SECTOR_SHIFT);

	return round_up(capacity, (1ull << shift_sector)) >> shift_sector;
}

static void diff_area_calculate_chunk_size(struct diff_area *diff_area)
{
	unsigned long long count;
	unsigned long long shift = min(get_chunk_minimum_shift(),
				       get_chunk_maximum_shift());
	sector_t capacity;
	sector_t min_io_sect;

	min_io_sect = (sector_t)(bdev_io_min(diff_area->orig_bdev) >>
		SECTOR_SHIFT);
	capacity = bdev_nr_sectors(diff_area->orig_bdev);
	pr_debug("Minimal IO block %llu sectors\n", min_io_sect);
	pr_debug("Device capacity %llu sectors\n", capacity);

	count = count_by_shift(capacity, shift);
	pr_debug("Chunks count %llu\n", count);
	while ((count > get_chunk_maximum_count()) ||
		((1ull << (shift - SECTOR_SHIFT)) < min_io_sect)) {
		if (shift >= get_chunk_maximum_shift()) {
			pr_info("The maximum allowable chunk size has been reached.\n");
			break;
		}
		shift = shift + 1ull;
		count = count_by_shift(capacity, shift);
		pr_debug("Chunks count %llu\n", count);
	}

	diff_area->chunk_shift = shift;
	diff_area->chunk_count = count;

	pr_debug("The optimal chunk size was calculated as %llu bytes for device [%d:%d]\n",
		 (1ull << diff_area->chunk_shift),
		 MAJOR(diff_area->orig_bdev->bd_dev),
		 MINOR(diff_area->orig_bdev->bd_dev));
}

void diff_area_free(struct diff_area *diff_area)
{
	unsigned long inx = 0;
	struct chunk *chunk;

	might_sleep();

	flush_work(&diff_area->store_queue_work);
	xa_for_each(&diff_area->chunk_map, inx, chunk)
		chunk_free(chunk);
	xa_destroy(&diff_area->chunk_map);

	if (diff_area->orig_bdev) {
		blkdev_put(diff_area->orig_bdev, FMODE_READ | FMODE_WRITE);
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
		up(&chunk->lock);
		pr_warn("Cannot release empty buffer for chunk #%ld",
			chunk->number);
		return true;
	}

	if (diff_area_is_corrupted(diff_area)) {
		chunk_store_failed(chunk, 0);
		return true;
	}

	if (!chunk->diff_region) {
		struct diff_region *diff_region;

		diff_region = diff_storage_new_region(
			diff_area->diff_storage,
			diff_area_chunk_sectors(diff_area),
			diff_area->logical_blksz);

		if (IS_ERR(diff_region)) {
			pr_debug("Cannot get store for chunk #%ld\n",
				 chunk->number);
			chunk_store_failed(chunk, PTR_ERR(diff_region));
			return true;
		}
		chunk->diff_region = diff_region;
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
	unsigned long number;
	struct chunk *chunk;

	pr_debug("Open device [%u:%u]\n", MAJOR(dev_id), MINOR(dev_id));

	bdev = blkdev_get_by_dev(dev_id, FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(bdev)) {
		int err = PTR_ERR(bdev);

		pr_err("Failed to open device. errno=%d\n", abs(err));
		return ERR_PTR(err);
	}

	diff_area = kzalloc(sizeof(struct diff_area), GFP_KERNEL);
	if (!diff_area) {
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
		return ERR_PTR(-ENOMEM);
	}

	diff_area->orig_bdev = bdev;
	diff_area->diff_storage = diff_storage;

	diff_area_calculate_chunk_size(diff_area);
	pr_debug("Chunk size %llu in bytes\n", 1ull << diff_area->chunk_shift);
	pr_debug("Chunk count %lu\n", diff_area->chunk_count);

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

	/*
	 * Allocating all chunks in advance allows to avoid doing this in
	 * the process of filtering bio.
	 * In addition, the chunk structure has an rw semaphore that allows
	 * to lock data of a single chunk.
	 * Different threads can read, write, or dump their data to diff storage
	 * independently of each other, provided that different chunks are used.
	 */
	for (number = 0; number < diff_area->chunk_count; number++) {
		chunk = chunk_alloc(diff_area, number);
		if (!chunk) {
			pr_err("Failed allocate chunk\n");
			ret = -ENOMEM;
			break;
		}
		chunk->sector_count = diff_area_chunk_sectors(diff_area);

		ret = xa_insert(&diff_area->chunk_map, number, chunk,
				GFP_KERNEL);
		if (ret) {
			pr_err("Failed insert chunk to chunk map\n");
			chunk_free(chunk);
			break;
		}
	}
	if (!diff_storage->capacity) {
		pr_err("Difference storage is empty\n");
		pr_err("In-memory difference storage is not supported\n");
		ret = -EFAULT;
	}

	if (ret) {
		diff_area_free(diff_area);
		return ERR_PTR(ret);
	}

	recalculate_last_chunk_size(chunk);

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
		unsigned long nr = chunk_number(diff_area, iter->bi_sector);
		struct chunk *chunk = xa_load(&diff_area->chunk_map, nr);
		unsigned int len;

		if (!chunk) {
			diff_area_set_corrupted(diff_area, -EINVAL);
			ret = -EINVAL;
			goto fail;
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

		len = chunk_limit(chunk, iter);
		if (chunk->state == CHUNK_ST_NEW) {
			if (nowait) {
				/*
				 * If the data of this chunk has not yet been
				 * copied to the difference storage, then it is
				 * impossible to process the I/O write unit with
				 * the NOWAIT flag.
				 */
				up(&chunk->lock);
				ret = -EAGAIN;
				goto fail;
			}

			/*
			 * Load the chunk asynchronously.
			 */
			ret = chunk_load_and_postpone_io(chunk, &chunk_bio);
			if (ret) {
				up(&chunk->lock);
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
			up(&chunk->lock);
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

	if (ret == -EAGAIN){
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

bool diff_area_submit_chunk(struct diff_area *diff_area, struct bio *bio)
{
	struct chunk *chunk;

	chunk = xa_load(&diff_area->chunk_map,
			chunk_number(diff_area, bio->bi_iter.bi_sector));
	if (unlikely(!chunk))
		return false;

	if (down_killable(&chunk->lock))
		return false;

	if (unlikely(chunk->state == CHUNK_ST_FAILED)) {
		pr_err("Chunk #%ld corrupted\n", chunk->number);
		pr_debug("sector=%llu, size=%llu, count=%lu\n",
			 bio->bi_iter.bi_sector,
			 (1Ull << diff_area->chunk_shift),
			 diff_area->chunk_count);
		up(&chunk->lock);
		return false;
	}
	if (chunk->state == CHUNK_ST_IN_MEMORY) {
		/*
		 * Directly copy data from the in-memory chunk or
		 * copy to the in-memory chunk for write operation.
		 */
		chunk_copy_bio(chunk, bio, &bio->bi_iter);
		up(&chunk->lock);
		return true;
	}
	if ((chunk->state == CHUNK_ST_STORED) || !op_is_write(bio_op(bio))) {
		/*
		 * Read data from the chunk on difference storage.
		 */
		chunk_clone_bio(chunk, bio);
		up(&chunk->lock);
		return true;
	}
	/*
	 * Starts asynchronous loading of a chunk from the original block device
	 * or difference storage and schedule copying data to (or from) the
	 * in-memory chunk.
	 */
	if (chunk_load_and_schedule_io(chunk, bio)) {
		up(&chunk->lock);
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
