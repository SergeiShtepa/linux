// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-chunk: " fmt

#include <linux/slab.h>
#include <linux/dm-io.h>
#include <linux/sched/mm.h>
#include "chunk.h"
#include "diff_io.h"
#include "diff_buffer.h"
#include "diff_area.h"
#include "diff_storage.h"

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

static void chunk_notify_load(void *ctx)
{
	struct chunk *chunk = ctx;
	struct image_rw_ctx *image_rw_ctx = chunk->image_rw_ctx;
	int error = chunk->diff_io->error;

	might_sleep();

	diff_io_free(chunk->diff_io);
	chunk->diff_io = NULL;
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

	atomic_dec(&chunk->diff_area->pending_io_count);
}

static void chunk_notify_store(void *ctx)
{
	struct chunk *chunk = ctx;
	int error = chunk->diff_io->error;

	diff_io_free(chunk->diff_io);
	chunk->diff_io = NULL;

	might_sleep();

	if (unlikely(error)) {
		chunk_store_failed(chunk, error);
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
	atomic_dec(&chunk->diff_area->pending_io_count);
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

/*
 * Starts asynchronous storing of a chunk to the  difference storage.
 */
int chunk_async_store_diff(struct chunk *chunk, const bool is_nowait)
{
	int ret;
	struct diff_io *diff_io;
	struct diff_region *region = chunk->diff_region;

	if (WARN(!list_is_first(&chunk->cache_link, &chunk->cache_link),
		 "The chunk already in the cache"))
		return -EINVAL;

	diff_io = diff_io_new_async_write(chunk_notify_store, chunk, is_nowait);
	if (unlikely(!diff_io)) {
		if (is_nowait)
			return -EAGAIN;
		else
			return -ENOMEM;
	}

	WARN_ON(chunk->diff_io);
	chunk->diff_io = diff_io;
	chunk_state_set(chunk, CHUNK_ST_STORING);
	atomic_inc(&chunk->diff_area->pending_io_count);

	ret = diff_io_do(chunk->diff_io, region, chunk->diff_buffer, is_nowait);
	if (ret) {
		atomic_dec(&chunk->diff_area->pending_io_count);
		diff_io_free(chunk->diff_io);
		chunk->diff_io = NULL;
	}

	return ret;
}

/*
 * Starts asynchronous loading of a chunk from the original block device.
 */
int chunk_async_load_orig(struct chunk *chunk, const bool is_nowait)
{
	int ret;
	struct diff_io *diff_io;
	struct diff_region region = {
		.bdev = chunk->diff_area->orig_bdev,
		.sector = (sector_t)(chunk->number) *
			  diff_area_chunk_sectors(chunk->diff_area),
		.count = chunk->sector_count,
	};

	diff_io = diff_io_new_async_read(chunk_notify_load, chunk, is_nowait);
	if (unlikely(!diff_io)) {
		if (is_nowait)
			return -EAGAIN;
		else
			return -ENOMEM;
	}

	WARN_ON(chunk->diff_io);
	chunk->diff_io = diff_io;
	chunk_state_set(chunk, CHUNK_ST_LOADING);
	atomic_inc(&chunk->diff_area->pending_io_count);

	ret = diff_io_do(chunk->diff_io, &region, chunk->diff_buffer, is_nowait);
	if (ret) {
		atomic_dec(&chunk->diff_area->pending_io_count);
		diff_io_free(chunk->diff_io);
		chunk->diff_io = NULL;
	}
	return ret;
}

/*
 * Performs asynchronous loading of a chunk from the difference storage.
 */
int chunk_async_load_diff(struct chunk *chunk, const bool is_nowait)
{
	int ret;
	struct diff_io *diff_io;
	struct diff_region *region = chunk->diff_region;

	if (WARN(!list_is_first(&chunk->cache_link, &chunk->cache_link),
		 "The chunk already in the cache"))
		return -EINVAL;

	diff_io = diff_io_new_async_read(chunk_notify_load,
					 chunk, is_nowait);
	if (unlikely(!diff_io)) {
		if (is_nowait)
			return -EAGAIN;
		else
			return -ENOMEM;
	}

	WARN_ON(chunk->diff_io);
	chunk->diff_io = diff_io;
	chunk_state_set(chunk, CHUNK_ST_LOADING);
	atomic_inc(&chunk->diff_area->pending_io_count);

	ret = diff_io_do(chunk->diff_io, region, chunk->diff_buffer, is_nowait);
	if (ret) {
		atomic_dec(&chunk->diff_area->pending_io_count);
		diff_io_free(chunk->diff_io);
		chunk->diff_io = NULL;
	}

	return ret;
}
