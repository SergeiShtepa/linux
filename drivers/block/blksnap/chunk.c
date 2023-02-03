// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-chunk: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_area.h"
#include "diff_storage.h"

struct bio_set chunk_io_bioset;

extern int chunk_maximum_in_cache;

void chunk_diff_buffer_release(struct chunk *chunk)
{
	if (unlikely(!chunk->diff_buffer))
		return;

	//pr_debug("DEBUG! %s #%lu", __func__, chunk->number);

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

	//pr_debug("DEBUG! %s #%lu", __func__, chunk->number);
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

static void chunk_notify_load(struct chunk *chunk)
{
	struct image_rw_ctx *image_rw_ctx = chunk->image_rw_ctx;
	int error = chunk->error;

	chunk->image_rw_ctx = NULL;

	if (unlikely(error)) {
		atomic_inc(&image_rw_ctx->error_cnt);
		chunk_store_failed(chunk, error);
	} else {
		//pr_debug("DEBUG! %s original loaded chunk #%lu\n", __func__, chunk->number);
		if (likely(chunk_state_check(chunk, CHUNK_ST_LOADING))) {
			chunk_state_unset(chunk, CHUNK_ST_LOADING);
			chunk_state_set(chunk, CHUNK_ST_BUFFER_READY);
			chunk_schedule_caching(chunk);
		} else {
			if (chunk_state_check(chunk, CHUNK_ST_FAILED))
				pr_err("Chunk in a failed state\n");
			else
				pr_err("invalid chunk state 0x%x\n", atomic_read(&chunk->state));
			up(&chunk->lock);
		}
	}
	if (image_rw_ctx)
		kref_put(&image_rw_ctx->kref, diff_area_rw_chunk);
}

static void chunk_notify_store(struct chunk *chunk)
{
	int error = chunk->error;

	if (unlikely(error)) {
		chunk_store_failed(chunk, error);
		return;
	}

	if (unlikely(chunk_state_check(chunk, CHUNK_ST_FAILED))) {
		pr_err("Chunk in a failed state\n");
		chunk_store_failed(chunk, 0);
		return;
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
	atomic_set(&chunk->diff_buffer_holder, 0);
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

static void chunk_io_notify_cb(struct work_struct *work)
{
	struct chunk *chunk = container_of(work, struct chunk, work);

	if (chunk->is_write)
		chunk_notify_store(chunk);
	else
		chunk_notify_load(chunk);
}

static void chunk_io_endio(struct bio *bio)
{
	struct chunk *chunk = bio->bi_private;

	if (bio->bi_status != BLK_STS_OK)
		chunk->error = -EIO;

	queue_work(system_wq, &chunk->work);
	bio_put(bio);
}

static inline unsigned short calc_max_vecs(sector_t left)
{
	return bio_max_segs(round_up(left, PAGE_SECTORS) / PAGE_SECTORS);
}

void chunk_io(struct chunk *chunk, bool is_write,
		struct diff_region *diff_region)
{
	struct diff_buffer *diff_buffer = chunk->diff_buffer;
	unsigned int page_idx = 0;
	sector_t left = diff_region->count;
	unsigned int opf;
	struct bio *bio;

	if (is_write) {
		opf = REQ_OP_WRITE | REQ_SYNC | REQ_FUA;
		chunk_state_set(chunk, CHUNK_ST_STORING);
	} else {
		opf = REQ_OP_READ;
		chunk_state_set(chunk, CHUNK_ST_LOADING);
	}

	chunk->is_write = is_write;
	INIT_WORK(&chunk->work, chunk_io_notify_cb);

	bio = bio_alloc_bioset(diff_region->bdev, calc_max_vecs(left), opf,
			       GFP_NOIO, &chunk_io_bioset);
	bio->bi_iter.bi_sector = diff_region->sector;
	bio_set_flag(bio, BIO_FILTERED);

	while (left) {
		sector_t count = min_t(sector_t, left, PAGE_SECTORS);
		unsigned int bytes = count << SECTOR_SHIFT;

		if (bio_add_page(bio, diff_buffer->pages[page_idx], bytes, 0) !=
				bytes) {
			struct bio *next;

			next = bio_alloc_bioset(diff_region->bdev,
						calc_max_vecs(left), opf,
						GFP_NOIO, &chunk_io_bioset);
			next->bi_iter.bi_sector = bio_end_sector(bio);
			bio_set_flag(next, BIO_FILTERED);
			bio_chain(bio, next);
			submit_bio_noacct(bio);
			bio = next;
		}
		page_idx++;
		left -= count;
	}

	bio->bi_end_io = chunk_io_endio;
	bio->bi_private = chunk;
	submit_bio_noacct(bio);
}

int __init chunk_init(void)
{
	return bioset_init(&chunk_io_bioset, 64, 0,
			   BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
}

void chunk_done(void)
{
	bioset_exit(&chunk_io_bioset);
}
