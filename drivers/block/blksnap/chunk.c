// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-chunk: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_area.h"
#include "diff_storage.h"
#include "params.h"

struct chunk_bio {
	struct work_struct work;
	struct list_head chunks;
	struct bio *orig_bio;
	struct bvec_iter orig_iter;
	struct bio bio;
};

struct bio_set chunk_io_bioset;
struct bio_set chunk_clone_bioset;

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

void chunk_schedule_storing(struct chunk *chunk)
{
	int queue_count = 0;
	struct diff_area *diff_area = chunk->diff_area;

	might_sleep();

	spin_lock(&diff_area->store_queue_lock);

	/*
	 * The locked chunk cannot be in the queue.
	 * If the check reveals that the chunk is in the queue, then something
	 * is wrong in the algorithm.
	 */
	if (WARN(!list_is_first(&chunk->link, &chunk->link),
		 "The chunk already in the queue")) {
		spin_unlock(&diff_area->store_queue_lock);
		chunk_store_failed(chunk, 0);
		return;
	}

	list_add_tail(&chunk->link, &diff_area->store_queue);
	queue_count = atomic_inc_return(&diff_area->store_queue_count);

	spin_unlock(&diff_area->store_queue_lock);

	up(&chunk->lock);

	/* Initiate the queue clearing process */
	if (queue_count > get_chunk_maximum_in_queue())
		queue_work(system_wq, &diff_area->store_queue_work);
}

void chunk_copy_bio(struct chunk *chunk, struct bio *bio,
		    struct bvec_iter *iter)
{
	unsigned int chunk_ofs, chunk_left;

	chunk_ofs = (iter->bi_sector - chunk_sector(chunk)) << SECTOR_SHIFT;
	chunk_left = chunk->diff_buffer->size - chunk_ofs;
	while (chunk_left && iter->bi_size) {
		struct bio_vec bvec = bio_iter_iovec(bio, *iter);
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
		bio_advance_iter_single(bio, iter, len);
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

static inline sector_t chunk_offset(struct chunk *chunk, struct bio *bio)
{
	return bio->bi_iter.bi_sector - chunk_sector(chunk);
}

static inline void chunk_limit_iter(struct chunk *chunk, struct bio *bio,
				    sector_t sector, struct bvec_iter *iter)
{
	sector_t chunk_ofs = chunk_offset(chunk, bio);

	iter->bi_sector = sector + chunk_ofs;
	iter->bi_size = min_t(unsigned int,
			bio->bi_iter.bi_size,
			(chunk->sector_count - chunk_ofs) << SECTOR_SHIFT);
}

static inline unsigned int chunk_limit(struct chunk *chunk, struct bio *bio)
{
	unsigned int chunk_ofs, chunk_left;

	chunk_ofs = (unsigned int)chunk_offset(chunk, bio) << SECTOR_SHIFT;
	chunk_left = chunk->diff_buffer->size - chunk_ofs;

	return min(bio->bi_iter.bi_size, chunk_left);
}

void chunk_clone_bio(struct chunk *chunk, struct bio *bio)
{
	struct bio *new_bio;
	struct block_device *bdev;
	sector_t sector;

	if (chunk_state_check(chunk, CHUNK_ST_STORE_READY)) {
		bdev = chunk->diff_region->bdev;
		sector = chunk->diff_region->sector;
	} else {
		bdev = chunk->diff_area->orig_bdev;
		sector = chunk_sector(chunk);
	}

	new_bio = bio_alloc_clone(bdev, bio, GFP_NOIO, &chunk_clone_bioset);
	chunk_limit_iter(chunk, bio, sector, &new_bio->bi_iter);
	bio_set_flag(new_bio, BIO_FILTERED);
	new_bio->bi_end_io = chunk_clone_endio;
	new_bio->bi_private = bio;

	bio_advance(bio, new_bio->bi_iter.bi_size);
	bio_inc_remaining(bio);

	submit_bio_noacct(new_bio);
}

static inline void chunk_list_store_fail(struct list_head *chunks, int err)
{
	struct chunk *chunk;

	while (!list_empty(chunks)){
		chunk = list_first_entry(chunks, struct chunk, link);
		list_del_init(&chunk->link);
		chunk_store_failed(chunk, err);
	}
}

static void notify_load_and_schedule_io(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk;

	if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
		chunk_list_store_fail(&cbio->chunks, -EIO);
		goto out;
	}

	while (!list_empty(&cbio->chunks)){
		chunk = list_first_entry(&cbio->chunks, struct chunk, link);
		list_del_init(&chunk->link);

		if (chunk_state_check(chunk, CHUNK_ST_FAILED)) {
			up(&chunk->lock);
			continue;
		}

		chunk_state_set(chunk, CHUNK_ST_BUFFER_READY);

		chunk_copy_bio(chunk, cbio->orig_bio, &cbio->orig_iter);
		bio_endio(cbio->orig_bio);

		chunk_schedule_storing(chunk);
	}
out:
	bio_put(&cbio->bio);
}

static void notify_load_and_postpone_io(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk;

	if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
		chunk_list_store_fail(&cbio->chunks, -EIO);
		goto out;
	}

	while (!list_empty(&cbio->chunks)){
		chunk = list_first_entry(&cbio->chunks, struct chunk, link);
		list_del_init(&chunk->link);

		if (chunk_state_check(chunk, CHUNK_ST_FAILED)) {
			up(&chunk->lock);
			continue;
		}

		chunk_state_set(chunk, CHUNK_ST_BUFFER_READY);
		chunk_schedule_storing(chunk);
	}
out:
	/* submit the original bio fed into the tracker */
	submit_bio_noacct_nocheck(cbio->orig_bio);

	bio_put(&cbio->bio);
}

static void chunk_notify_store(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk;

	if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
		chunk_list_store_fail(&cbio->chunks, -EIO);
		goto out;
	}

	while (!list_empty(&cbio->chunks)){
		chunk = list_first_entry(&cbio->chunks, struct chunk, link);
		list_del_init(&chunk->link);

		if (unlikely(chunk_state_check(chunk, CHUNK_ST_FAILED))) {
			pr_err("Chunk in a failed state\n");
			chunk_store_failed(chunk, 0);
			continue;
		}

		chunk_state_set(chunk, CHUNK_ST_STORE_READY);

		chunk_diff_buffer_release(chunk);
		up(&chunk->lock);
	}
out:
	bio_put(&cbio->bio);
}

struct chunk *chunk_alloc(struct diff_area *diff_area, unsigned long number)
{
	struct chunk *chunk;

	chunk = kzalloc(sizeof(struct chunk), GFP_KERNEL);
	if (!chunk)
		return NULL;

	INIT_LIST_HEAD(&chunk->link);
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

void chunk_submit_bio(struct bio *bio)
{
	bio->bi_end_io = chunk_io_endio;
	submit_bio_noacct(bio);
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
	INIT_LIST_HEAD(&cbio->chunks);
	list_add_tail(&chunk->link, &cbio->chunks);
	cbio->orig_bio = NULL;
	chunk_submit_bio(bio);
}

static struct bio *__chunk_load(struct chunk *chunk)
{
	struct diff_buffer *diff_buffer;
	unsigned int page_idx = 0;
	struct bio *bio;
	struct block_device *bdev;
	sector_t sector, count;

	diff_buffer = diff_buffer_take(chunk->diff_area);
	if (IS_ERR(diff_buffer))
		return ERR_CAST(diff_buffer);
	chunk->diff_buffer = diff_buffer;

	if (chunk_state_check(chunk, CHUNK_ST_STORE_READY)) {
		bdev = chunk->diff_region->bdev;
		sector = chunk->diff_region->sector;
		count = chunk->diff_region->count;
	} else {
		bdev = chunk->diff_area->orig_bdev;
		sector = chunk_sector(chunk);
		count = chunk->sector_count;
	}

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
	return bio;
}

int chunk_load_and_postpone_io(struct chunk *chunk, struct bio **chunk_bio)
{
	struct bio *prev = *chunk_bio, *bio;

	bio = __chunk_load(chunk);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	if (prev) {
		bio_chain(prev, bio);
		submit_bio_noacct(prev);
	}

	*chunk_bio = bio;
	return 0;
}

void chunk_load_and_postpone_io_finish(struct list_head *chunks,
				struct bio *chunk_bio, struct bio *orig_bio)
{
	struct chunk_bio *cbio;

	cbio = container_of(chunk_bio, struct chunk_bio, bio);
	INIT_LIST_HEAD(&cbio->chunks);
	while (!list_empty(chunks)) {
		struct chunk *it;

		it = list_first_entry(chunks, struct chunk, link);
		list_del_init(&it->link);

		list_add_tail(&it->link, &cbio->chunks);
	}
	INIT_WORK(&cbio->work, notify_load_and_postpone_io);
	cbio->orig_bio = orig_bio;
	chunk_submit_bio(chunk_bio);
}

int chunk_load_and_schedule_io(struct chunk *chunk, struct bio *orig_bio)
{
	struct chunk_bio *cbio;
	struct bio *bio;

	bio = __chunk_load(chunk);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	cbio = container_of(bio, struct chunk_bio, bio);
	INIT_LIST_HEAD(&cbio->chunks);
	list_add_tail(&chunk->link, &cbio->chunks);
	INIT_WORK(&cbio->work, notify_load_and_schedule_io);
	cbio->orig_bio = orig_bio;
	if (orig_bio) {
		cbio->orig_iter = orig_bio->bi_iter;
		bio_advance_iter_single(orig_bio, &orig_bio->bi_iter,
					chunk_limit(chunk, orig_bio));
		bio_inc_remaining(orig_bio);
	}
	chunk_submit_bio(bio);
	return 0;
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
