// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-area: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "chunk.h"
#include "diff_area.h"
#include "diff_buffer.h"
#include "diff_storage.h"

extern int chunk_minimum_shift;
extern int chunk_maximum_count;
extern int chunk_maximum_in_cache;

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
	unsigned long long shift = chunk_minimum_shift;
	unsigned long long count;
	sector_t capacity;
	sector_t min_io_sect;

	min_io_sect = (sector_t)(bdev_io_min(diff_area->orig_bdev) >>
		SECTOR_SHIFT);
	capacity = bdev_nr_sectors(diff_area->orig_bdev);
	pr_debug("Minimal IO block %llu sectors\n", min_io_sect);
	pr_debug("Device capacity %llu sectors\n", capacity);

	count = count_by_shift(capacity, shift);
	pr_debug("Chunks count %llu\n", count);
	while ((count > chunk_maximum_count) ||
		((1ull << (shift - SECTOR_SHIFT)) < min_io_sect)) {
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

	flush_work(&diff_area->cache_release_work);
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

static struct chunk *diff_area_lock_and_get_chunk_from_cache(
					struct diff_area *diff_area)
{
	struct chunk *iter;
	struct chunk *chunk = NULL;

	spin_lock(&diff_area->caches_lock);
	list_for_each_entry(iter, &diff_area->cache_queue, cache_link) {
		if (!down_trylock(&iter->lock)) {
			chunk = iter;
			break;
		}
		/*
		 * If it is not possible to lock a chunk for writing,
		 * then it is currently in use, and we try to clean up the
		 * next chunk.
		 */
	}
	if (likely(chunk)) {
		atomic_dec(&diff_area->cache_count);
		list_del_init(&chunk->cache_link);
	}
	spin_unlock(&diff_area->caches_lock);

	return chunk;
}

static void diff_area_cache_release(struct diff_area *diff_area)
{
	struct chunk *chunk;

	while ((atomic_read(&diff_area->cache_count) > chunk_maximum_in_cache) &&
	       (chunk = diff_area_lock_and_get_chunk_from_cache(diff_area))) {

		/*
		 * There cannot be a chunk in the cache whose buffer is
		 * not ready.
		 */
		if (WARN(!chunk_state_check(chunk, CHUNK_ST_BUFFER_READY),
			 "Cannot release empty buffer for chunk #%ld",
			 chunk->number)) {
			up(&chunk->lock);
			continue;
		}

		/*
		 * Skip storing data into the diff storage if it is already
		 * stored there and there is no flag DIRTY.
 		 */
		if (chunk_state_check(chunk, CHUNK_ST_STORE_READY) &&
		    !chunk_state_check(chunk, CHUNK_ST_DIRTY)) {
			chunk_diff_buffer_release(chunk);
			up(&chunk->lock);
			continue;
		}

		if (diff_area_is_corrupted(diff_area)) {
			chunk_store_failed(chunk, 0);
			continue;
		}

		if (!chunk->diff_region) {
			struct diff_region *diff_region;

			diff_region = diff_storage_new_region(
				diff_area->diff_storage,
				diff_area_chunk_sectors(diff_area));

			if (IS_ERR(diff_region)) {
				pr_debug("Cannot get store for chunk #%ld\n",
					 chunk->number);
				chunk_store_failed(chunk, PTR_ERR(diff_region));
				continue;
			}
			chunk->diff_region = diff_region;
		}
		chunk_store(chunk);
	}
}

static void diff_area_cache_release_work(struct work_struct *work)
{
	struct diff_area *diff_area = container_of(
		work, struct diff_area, cache_release_work);

	diff_area_cache_release(diff_area);
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

	spin_lock_init(&diff_area->caches_lock);
	INIT_LIST_HEAD(&diff_area->cache_queue);
	atomic_set(&diff_area->cache_count, 0);
	INIT_WORK(&diff_area->cache_release_work, diff_area_cache_release_work);

	spin_lock_init(&diff_area->free_diff_buffers_lock);
	INIT_LIST_HEAD(&diff_area->free_diff_buffers);
	atomic_set(&diff_area->free_diff_buffers_count, 0);

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

/*
 * Implements the copy-on-write mechanism.
 */
int diff_area_copy(struct diff_area *diff_area, sector_t sector, sector_t count,
		   const bool nowait)
{
	int ret = 0;
	sector_t offset;
	struct chunk *chunk;
	struct diff_buffer *diff_buffer;
	sector_t area_sect_first;
	sector_t chunk_sectors = diff_area_chunk_sectors(diff_area);

	area_sect_first = round_down(sector, chunk_sectors);
	for (offset = area_sect_first; offset < (sector + count);
	     offset += chunk_sectors) {
		chunk = xa_load(&diff_area->chunk_map,
				chunk_number(diff_area, offset));
		if (!chunk) {
			diff_area_set_corrupted(diff_area, -EINVAL);
			return -EINVAL;
		}
		if (nowait) {
			if (down_trylock(&chunk->lock))
				return -EAGAIN;
		} else {
			ret = down_killable(&chunk->lock);
			if (unlikely(ret))
				return ret;
		}

		if (chunk_state_check(chunk, CHUNK_ST_FAILED |
			CHUNK_ST_BUFFER_READY | CHUNK_ST_STORE_READY)) {
			/*
			 * The chunk has already been:
			 * - failed, when the snapshot is corrupted
			 * - read into the buffer
			 * - stored into the diff storage
			 * In this case, we do not change the chunk.
			 */
			up(&chunk->lock);
			continue;
		}
		if (nowait) {
			/*
			 * If the data of this chunk has not yet been copyed to
			 * the difference storage, then it is impossible to
			 * process the I/O write unit with the NOWAIT flag.
			 */
			up(&chunk->lock);
			return -EAGAIN;
		}


		if (unlikely(chunk_state_check(chunk,
			CHUNK_ST_LOADING | CHUNK_ST_STORING))) {

			pr_err("Invalid chunk state\n");
			ret = -EFAULT;
			goto fail_unlock_chunk;
		}

		diff_buffer = diff_buffer_take(chunk->diff_area);
		if (IS_ERR(diff_buffer)) {
			ret = PTR_ERR(diff_buffer);
			goto fail_unlock_chunk;
		}
		WARN(chunk->diff_buffer, "Chunks buffer has been lost");
		chunk->diff_buffer = diff_buffer;

		/*
		 * Starts asynchronous loading of a chunk from
		 * the original block device.
		 */
		chunk_load(chunk);
	}

	return ret;
fail_unlock_chunk:
	WARN_ON(!chunk);
	chunk_store_failed(chunk, ret);
	return ret;
}

int diff_area_wait(struct diff_area *diff_area, sector_t sector, sector_t count)
{
	int ret = 0;
	sector_t offset;
	struct chunk *chunk;
	sector_t area_sect_first;
	sector_t chunk_sectors = diff_area_chunk_sectors(diff_area);

	area_sect_first = round_down(sector, chunk_sectors);
	for (offset = area_sect_first; offset < (sector + count);
	     offset += chunk_sectors) {
		chunk = xa_load(&diff_area->chunk_map,
				chunk_number(diff_area, offset));
		if (!chunk) {
			diff_area_set_corrupted(diff_area, -EINVAL);
			return -EINVAL;
		}
		WARN_ON(chunk_number(diff_area, offset) != chunk->number);
		ret = down_killable(&chunk->lock);
		if (unlikely(ret))
			return ret;

		if (chunk_state_check(chunk, CHUNK_ST_FAILED)) {
			up(&chunk->lock);
			ret = -EFAULT;
			break;
		}

		if (chunk_state_check(chunk,
			CHUNK_ST_BUFFER_READY | CHUNK_ST_STORE_READY)) {
			/*
			 * The chunk has already been:
			 * - read from original device
			 * - stored into the diff storage
			 */
			up(&chunk->lock);
			continue;
		}
	}

	return ret;
}

static struct chunk *diff_area_image_get_chunk(
	struct diff_area *diff_area, sector_t sector)
{
	unsigned long new_chunk_number = chunk_number(diff_area, sector);
	struct chunk *chunk;
	int ret;

	chunk = xa_load(&diff_area->chunk_map, new_chunk_number);
	if (unlikely(!chunk))
		return ERR_PTR(-EINVAL);

	ret = down_killable(&chunk->lock);
	if (ret)
		return ERR_PTR(ret);

	if (unlikely(chunk_state_check(chunk, CHUNK_ST_FAILED))) {
		pr_err("Chunk #%ld corrupted\n", chunk->number);

		pr_debug("new_chunk_number=%ld\n", new_chunk_number);
		pr_debug("sector=%llu\n", sector);
		pr_debug("Chunk size %llu in bytes\n",
		       (1ull << diff_area->chunk_shift));
		pr_debug("Chunk count %lu\n", diff_area->chunk_count);

		ret = -EIO;
		goto fail_unlock_chunk;
	}

	return chunk;

fail_unlock_chunk:
	pr_err("Failed to load chunk #%ld\n", chunk->number);
	up(&chunk->lock);
	return ERR_PTR(ret);
}

void diff_area_submit_bio(struct diff_area *diff_area, struct bio *bio)
{
	struct chunk *chunk;

	while (bio->bi_iter.bi_size) {
		chunk = diff_area_image_get_chunk(diff_area,
						  bio->bi_iter.bi_sector);
		if (IS_ERR(chunk))
			goto fail;

		if (chunk_state_check(chunk, CHUNK_ST_BUFFER_READY))
			chunk_submit_bio(chunk, bio);
		else if (chunk_state_check(chunk, CHUNK_ST_STORE_READY) ||
			 !op_is_write(bio_op(bio)))
			chunk_clone_bio(chunk, bio);
		else {
			pr_err("Failed to submit bio: invalid chunk state\n");
			up(&chunk->lock);
			goto fail;
		}

		up(&chunk->lock);
	}
	bio_endio(bio);
	return;
fail:
	bio_io_error(bio);
}

static inline void diff_area_event_corrupted(struct diff_area *diff_area)
{
	struct blksnap_event_corrupted data = {
		.dev_id = {
			.major = MAJOR(diff_area->orig_bdev->bd_dev),
			.minor = MINOR(diff_area->orig_bdev->bd_dev)
		},
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
