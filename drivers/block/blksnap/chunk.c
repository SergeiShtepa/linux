// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-chunk: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_area.h"
#include "diff_storage.h"

struct chunk_bio {
	struct work_struct work;
	struct chunk *chunk;
	struct bio bio;
};

struct bio_set chunk_io_bioset;
struct bio_set chunk_clone_bioset;

extern int chunk_maximum_in_cache;

static inline sector_t chunk_sector(struct chunk *chunk)
{
	return (sector_t)(chunk->number)
	       << (chunk->diff_area->chunk_shift - SECTOR_SHIFT);
}

void chunk_diff_buffer_release(struct chunk *chunk)
{
	if (unlikely(!chunk->diff_buffer))
		return;

	chunk_state_unset(chunk, CHUNK_ST_BUFFER_READY);
	diff_buffer_release(chunk->diff_area, chunk->diff_buffer);
	chunk->diff_buffer = NULL;
}

void chunk_store_failed(struct chunk *chunk, int error)
{
	struct diff_area *diff_area = chunk->diff_area;

	chunk_state_set(chunk, CHUNK_ST_FAILED);
	chunk_diff_buffer_release(chunk);
	diff_storage_free_region(chunk->diff_region);
	chunk->diff_region = NULL;

	up(&chunk->lock);
	if (error)
		diff_area_set_corrupted(diff_area, error);
};

void chunk_schedule_caching(struct chunk *chunk)
{
	int in_cache_count = 0;
	struct diff_area *diff_area = chunk->diff_area;

	might_sleep();

	spin_lock(&diff_area->caches_lock);

	/*
	 * The locked chunk cannot be in the cache.
	 * If the check reveals that the chunk is in the cache, then something
	 * is wrong in the algorithm.
	 */
	if (WARN(!list_is_first(&chunk->cache_link, &chunk->cache_link),
		 "The chunk already in the cache")) {
		spin_unlock(&diff_area->caches_lock);
		chunk_store_failed(chunk, 0);
		return;
	}

	list_add_tail(&chunk->cache_link, &diff_area->cache_queue);
	in_cache_count = atomic_inc_return(&diff_area->cache_count);

	spin_unlock(&diff_area->caches_lock);

	up(&chunk->lock);

	/* Initiate the cache clearing process */
	if (in_cache_count > chunk_maximum_in_cache)
		queue_work(system_wq, &diff_area->cache_release_work);
}

void chunk_submit_bio(struct chunk *chunk, struct bio *bio)
{
	unsigned int chunk_ofs =
		(bio->bi_iter.bi_sector - chunk_sector(chunk)) << SECTOR_SHIFT;
	unsigned int chunk_left = chunk->diff_buffer->size - chunk_ofs;

	while (chunk_left && bio->bi_iter.bi_size) {
		struct bio_vec bvec = bio_iter_iovec(bio, bio->bi_iter);
		unsigned int page_ofs = offset_in_page(chunk_ofs);
		struct page *page;
		unsigned int len;

		page = chunk->diff_buffer->pages[chunk_ofs >> PAGE_SHIFT];
		len = min3(bvec.bv_len,
			   chunk_left,
			   (unsigned int)PAGE_SIZE - page_ofs);

		if (op_is_write(bio_op(bio))) {
			/* from bio to buffer */
			memcpy_page(page, page_ofs,
				    bvec.bv_page, bvec.bv_offset,
				    len);
		} else {
			/* from buffer to bio */
			memcpy_page(bvec.bv_page, bvec.bv_offset,
				    page, page_ofs,
				    len);
		}

		chunk_ofs += len;
		chunk_left -= len;
		bio_advance_iter_single(bio, &bio->bi_iter, len);
	}
}

static void chunk_clone_endio(struct bio *bio)
{
	struct bio *orig_bio = bio->bi_private;

	if (unlikely(bio->bi_status != BLK_STS_OK))
		bio_io_error(orig_bio);
	else
		bio_endio(orig_bio);
}

void chunk_clone_bio(struct chunk *chunk, struct bio *bio)
{
	struct bio *new_bio;
	struct block_device *bdev;
	sector_t chunk_ofs;
	sector_t sector;
	unsigned int size;

	if (chunk_state_check(chunk, CHUNK_ST_STORE_READY)) {
		bdev = chunk->diff_region->bdev;
		sector = chunk->diff_region->sector;
	} else {
		bdev = chunk->diff_area->orig_bdev;
		sector = chunk_sector(chunk);
	}
	chunk_ofs = bio->bi_iter.bi_sector - chunk_sector(chunk);
	sector += chunk_ofs;
	size = min_t(unsigned int,
		     bio->bi_iter.bi_size,
		     (chunk->sector_count - chunk_ofs) << SECTOR_SHIFT);

	new_bio = bio_alloc_clone(bdev, bio, GFP_NOIO, &chunk_clone_bioset);
	new_bio->bi_iter.bi_sector = sector;
	new_bio->bi_iter.bi_size = size;
	bio_set_flag(new_bio, BIO_FILTERED);
	new_bio->bi_end_io = chunk_clone_endio;
	new_bio->bi_private = bio;

	bio_advance(bio, size);
	bio_inc_remaining(bio);

	submit_bio_noacct(new_bio);
}

static void chunk_notify_load(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk = cbio->chunk;

	if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
		chunk_store_failed(chunk, -EIO);
		goto out;
	}

	if (likely(chunk_state_check(chunk, CHUNK_ST_LOADING))) {
		chunk_state_unset(chunk, CHUNK_ST_LOADING);
		chunk_state_set(chunk, CHUNK_ST_BUFFER_READY);
		chunk_schedule_caching(chunk);
		goto out;
	}

	if (chunk_state_check(chunk, CHUNK_ST_FAILED))
		pr_err("Chunk in a failed state\n");
	else
		pr_err("invalid chunk state 0x%x\n", atomic_read(&chunk->state));
	up(&chunk->lock);
out:
	bio_put(&cbio->bio);
}

static void chunk_notify_store(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk = cbio->chunk;

	if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
		chunk_store_failed(chunk, -EIO);
		goto out;
	}

	if (unlikely(chunk_state_check(chunk, CHUNK_ST_FAILED))) {
		pr_err("Chunk in a failed state\n");
		chunk_store_failed(chunk, 0);
		goto out;
	}

	if (chunk_state_check(chunk, CHUNK_ST_STORING)) {
		chunk_state_unset(chunk, CHUNK_ST_STORING);
		chunk_state_set(chunk, CHUNK_ST_STORE_READY);

		if (chunk_state_check(chunk, CHUNK_ST_DIRTY))
			chunk_state_unset(chunk, CHUNK_ST_DIRTY);

		chunk_diff_buffer_release(chunk);
	} else
		pr_err("invalid chunk state 0x%x\n", atomic_read(&chunk->state));
	up(&chunk->lock);
out:
	bio_put(&cbio->bio);
}

struct chunk *chunk_alloc(struct diff_area *diff_area, unsigned long number)
{
	struct chunk *chunk;

	chunk = kzalloc(sizeof(struct chunk), GFP_KERNEL);
	if (!chunk)
		return NULL;

	INIT_LIST_HEAD(&chunk->cache_link);
	sema_init(&chunk->lock, 1);
	chunk->diff_area = diff_area;
	chunk->number = number;
	atomic_set(&chunk->state, 0);
	return chunk;
}

void chunk_free(struct chunk *chunk)
{
	if (unlikely(!chunk))
		return;

	down(&chunk->lock);
	chunk_diff_buffer_release(chunk);
	diff_storage_free_region(chunk->diff_region);
	chunk_state_set(chunk, CHUNK_ST_FAILED);
	up(&chunk->lock);

	kfree(chunk);
}

static void chunk_io_endio(struct bio *bio)
{
	struct chunk_bio *cbio = container_of(bio, struct chunk_bio, bio);

	queue_work(system_wq, &cbio->work);
}

static inline unsigned short calc_max_vecs(sector_t left)
{
	return bio_max_segs(round_up(left, PAGE_SECTORS) / PAGE_SECTORS);
}

void chunk_store(struct chunk *chunk)
{
	struct block_device *bdev = chunk->diff_region->bdev;
	sector_t sector = chunk->diff_region->sector;
	sector_t count = chunk->diff_region->count;
	unsigned int page_idx = 0;
	struct bio *bio;
	struct chunk_bio *cbio;

	chunk_state_set(chunk, CHUNK_ST_STORING);

	bio = bio_alloc_bioset(bdev, calc_max_vecs(count),
			       REQ_OP_WRITE | REQ_SYNC | REQ_FUA, GFP_NOIO,
			       &chunk_io_bioset);
	bio->bi_iter.bi_sector = sector;
	bio_set_flag(bio, BIO_FILTERED);

	while (count) {
		sector_t portion = min_t(sector_t, count, PAGE_SECTORS);
		unsigned int bytes = portion << SECTOR_SHIFT;

		if (bio_add_page(bio, chunk->diff_buffer->pages[page_idx],
				 bytes, 0) != bytes) {
			struct bio *next;

			next = bio_alloc_bioset(bdev,
					calc_max_vecs(count),
					REQ_OP_WRITE | REQ_SYNC | REQ_FUA,
					GFP_NOIO, &chunk_io_bioset);
			next->bi_iter.bi_sector = bio_end_sector(bio);
			bio_set_flag(next, BIO_FILTERED);
			bio_chain(bio, next);
			submit_bio_noacct(bio);
			bio = next;
		}
		page_idx++;
		count -= portion;
	}

	cbio = container_of(bio, struct chunk_bio, bio);

	INIT_WORK(&cbio->work, chunk_notify_store);
	cbio->chunk = chunk;
	bio->bi_end_io = chunk_io_endio;
	bio->bi_private = NULL;
	submit_bio_noacct(bio);
}

static void __chunk_load(struct chunk *chunk, struct block_device *bdev,
			 sector_t sector, sector_t count)
{
	unsigned int page_idx = 0;
	struct bio *bio;
	struct chunk_bio *cbio;

	chunk_state_set(chunk, CHUNK_ST_LOADING);

	bio = bio_alloc_bioset(bdev, calc_max_vecs(count),
			       REQ_OP_READ, GFP_NOIO, &chunk_io_bioset);
	bio->bi_iter.bi_sector = sector;
	bio_set_flag(bio, BIO_FILTERED);

	while (count) {
		sector_t portion = min_t(sector_t, count, PAGE_SECTORS);
		unsigned int bytes = portion << SECTOR_SHIFT;

		if (bio_add_page(bio, chunk->diff_buffer->pages[page_idx],
				 bytes, 0) != bytes) {
			struct bio *next;

			next = bio_alloc_bioset(bdev, calc_max_vecs(count),
						REQ_OP_READ, GFP_NOIO,
						&chunk_io_bioset);
			next->bi_iter.bi_sector = bio_end_sector(bio);
			bio_set_flag(next, BIO_FILTERED);
			bio_chain(bio, next);
			submit_bio_noacct(bio);
			bio = next;
		}
		page_idx++;
		count -= portion;
	}

	cbio = container_of(bio, struct chunk_bio, bio);
	INIT_WORK(&cbio->work, chunk_notify_load);
	cbio->chunk = chunk;

	bio->bi_end_io = chunk_io_endio;
	bio->bi_private = NULL;
	submit_bio_noacct(bio);
}

void chunk_load(struct chunk *chunk)
{
	if (chunk_state_check(chunk, CHUNK_ST_STORE_READY))
		__chunk_load(chunk,
			     chunk->diff_region->bdev,
			     chunk->diff_region->sector,
			     chunk->diff_region->count);
	else
		__chunk_load(chunk,
			     chunk->diff_area->orig_bdev,
			     chunk_sector(chunk),
			     chunk->sector_count);
}

int __init chunk_init(void)
{
	int ret;

	ret = bioset_init(&chunk_io_bioset, 64,
			  offsetof(struct chunk_bio, bio),
			  BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
	if (!ret)
		ret = bioset_init(&chunk_clone_bioset, 64, 0,
				  BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
	return ret;
}

void chunk_done(void)
{
	bioset_exit(&chunk_io_bioset);
	bioset_exit(&chunk_clone_bioset);
}
