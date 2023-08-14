// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Veeam Software Group GmbH */
#define pr_fmt(fmt) KBUILD_MODNAME "-chunk: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include "chunk.h"
#include "diff_buffer.h"
#include "diff_storage.h"
#include "params.h"

struct chunk_bio {
	struct work_struct work;
	struct list_head chunks;
	struct bio *orig_bio;
	struct bvec_iter orig_iter;
	struct bio bio;
};

static struct bio_set chunk_io_bioset;
static struct bio_set chunk_clone_bioset;

static inline sector_t chunk_sector(struct chunk *chunk)
{
	return (sector_t)(chunk->number)
	       << (chunk->diff_area->chunk_shift - SECTOR_SHIFT);
}

void chunk_store_failed(struct chunk *chunk, int error)
{
	struct diff_area *diff_area = diff_area_get(chunk->diff_area);

	WARN_ON_ONCE(chunk->state != CHUNK_ST_NEW &&
		     chunk->state != CHUNK_ST_IN_MEMORY);
	chunk->state = CHUNK_ST_FAILED;

	if (likely(chunk->diff_buffer)) {
		diff_buffer_release(diff_area, chunk->diff_buffer);
		chunk->diff_buffer = NULL;
	}

	chunk_up(chunk);
	if (error)
		diff_area_set_corrupted(diff_area, error);
	diff_area_put(diff_area);
};

static void chunk_schedule_storing(struct chunk *chunk)
{
	struct diff_area *diff_area = diff_area_get(chunk->diff_area);
	int queue_count;

	WARN_ON_ONCE(chunk->state != CHUNK_ST_NEW &&
		     chunk->state != CHUNK_ST_STORED);
	chunk->state = CHUNK_ST_IN_MEMORY;

	spin_lock(&diff_area->store_queue_lock);
	list_add_tail(&chunk->link, &diff_area->store_queue);
	queue_count = atomic_inc_return(&diff_area->store_queue_count);
	spin_unlock(&diff_area->store_queue_lock);

	chunk_up(chunk);

	/* Initiate the queue clearing process */
	if (queue_count > get_chunk_maximum_in_queue())
		queue_work(system_wq, &diff_area->store_queue_work);
	diff_area_put(diff_area);
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
		unsigned int iov_idx = chunk_ofs >> PAGE_SHIFT;
		void *iov_base;
		unsigned int len;

		iov_base = chunk->diff_buffer->vec[iov_idx].iov_base;
		len = min3(bvec.bv_len,
			   chunk_left,
			   (unsigned int)PAGE_SIZE - page_ofs);

		if (op_is_write(bio_op(bio))) {
			/* from bio to buffer */
			memcpy_from_page(iov_base + page_ofs,
					 bvec.bv_page, bvec.bv_offset, len);
		} else {
			/* from buffer to bio */
			memcpy_to_page(bvec.bv_page, bvec.bv_offset,
				       iov_base + page_ofs, len);
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

struct bio *chunk_alloc_clone(struct block_device *bdev, struct bio *bio)
{
	return bio_alloc_clone(bdev, bio, GFP_NOIO, &chunk_clone_bioset);
}

/*
 * The data from bio is read to the diff file or read from it.
 */
int chunk_diff_bio(struct chunk *chunk, struct bio *bio)
{
	int ret = 0;
	loff_t pos;
	bool is_write = op_is_write(bio_op(bio));
	size_t count;
	ssize_t len;
	unsigned int nbytes = 0;
	unsigned int chunk_ofs, chunk_left;
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct iov_iter iov_iter;


	if (is_write)
		file_start_write(chunk->diff_file);

	bio_for_each_segment(bvec, bio, iter) {
		chunk_ofs = (iter.bi_sector - chunk_sector(chunk)) << SECTOR_SHIFT;
		chunk_left = (chunk->sector_count << SECTOR_SHIFT) - chunk_ofs;
		pos = (chunk->diff_ofs_sect << SECTOR_SHIFT) + chunk_ofs;

		iov_iter_bvec(&iov_iter, is_write ? ITER_SOURCE : ITER_DEST, &bvec, 1, bvec.bv_len);
		len = is_write ? vfs_iter_write(chunk->diff_file, &iov_iter, &pos, 0)
			       : vfs_iter_read(chunk->diff_file, &iov_iter, &pos, 0);

		if (len == bvec.bv_len) {
			nbytes += len;
			continue;
		}

		if (len < 0)
			ret = len;
		else if (len != count)
			ret = -EIO;
		break;
	}

	if (is_write)
		file_end_write(chunk->diff_file);
	bio_advance(bio, nbytes);
	return ret;
}

/*
 * Redirects bio to the original block device.
 */
void chunk_origin_bio(struct chunk *chunk, struct bio *bio)
{
	sector_t sector;
	struct bio *new_bio;
	struct block_device *bdev;

	bdev = chunk->diff_area->orig_bdev;
	sector = chunk_sector(chunk);

	new_bio = chunk_alloc_clone(bdev, bio);
	WARN_ON(!new_bio);

	chunk_limit_iter(chunk, bio, sector, &new_bio->bi_iter);
	new_bio->bi_end_io = chunk_clone_endio;
	new_bio->bi_private = bio;

	bio_advance(bio, new_bio->bi_iter.bi_size);
	bio_inc_remaining(bio);

	submit_bio_noacct(new_bio);
}

static inline struct chunk *get_chunk_from_cbio(struct chunk_bio *cbio)
{
	struct chunk *chunk = list_first_entry_or_null(&cbio->chunks,
						       struct chunk, link);

	if (chunk)
		list_del_init(&chunk->link);
	return chunk;
}

static void notify_load_and_schedule_io(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk;

	while ((chunk = get_chunk_from_cbio(cbio))) {
		if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
			chunk_store_failed(chunk, -EIO);
			continue;
		}
		if (chunk->state == CHUNK_ST_FAILED) {
			chunk_up(chunk);
			continue;
		}

		chunk_copy_bio(chunk, cbio->orig_bio, &cbio->orig_iter);
		bio_endio(cbio->orig_bio);

		chunk_schedule_storing(chunk);
	}

	bio_put(&cbio->bio);
}

static void notify_load_and_postpone_io(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk;

	while ((chunk = get_chunk_from_cbio(cbio))) {
		if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
			chunk_store_failed(chunk, -EIO);
			continue;
		}
		if (chunk->state == CHUNK_ST_FAILED) {
			chunk_up(chunk);
			continue;
		}

		chunk_schedule_storing(chunk);
	}

	/* submit the original bio fed into the tracker */
	submit_bio_noacct_nocheck(cbio->orig_bio);
	bio_put(&cbio->bio);
}

static void chunk_notify_store(struct chunk *chunk, int err)
{
	if (err) {
		chunk_store_failed(chunk, err);
		return;
	}

	WARN_ON_ONCE(chunk->state != CHUNK_ST_IN_MEMORY);
	chunk->state = CHUNK_ST_STORED;

	if (chunk->diff_buffer) {
		diff_buffer_release(chunk->diff_area,
				    chunk->diff_buffer);
		chunk->diff_buffer = NULL;
	}
	chunk_up(chunk);
}
#if 0
static void chunk_notify_store(struct work_struct *work)
{
	struct chunk_bio *cbio = container_of(work, struct chunk_bio, work);
	struct chunk *chunk;

	while ((chunk = get_chunk_from_cbio(cbio))) {
		if (unlikely(cbio->bio.bi_status != BLK_STS_OK)) {
			chunk_store_failed(chunk, -EIO);
			continue;
		}

		WARN_ON_ONCE(chunk->state != CHUNK_ST_IN_MEMORY);
		chunk->state = CHUNK_ST_STORED;

		if (chunk->diff_buffer) {
			diff_buffer_release(chunk->diff_area,
					    chunk->diff_buffer);
			chunk->diff_buffer = NULL;
		}
		chunk_up(chunk);
	}

	bio_put(&cbio->bio);
}
#endif
static void chunk_io_endio(struct bio *bio)
{
	struct chunk_bio *cbio = container_of(bio, struct chunk_bio, bio);

	queue_work(system_wq, &cbio->work);
}

static void chunk_submit_bio(struct bio *bio)
{
	bio->bi_end_io = chunk_io_endio;
	submit_bio_noacct(bio);
}

static inline unsigned short calc_max_vecs(sector_t left)
{
	return bio_max_segs(round_up(left, PAGE_SECTORS) / PAGE_SECTORS);
}

/*
 * Synchronously loading of chunk from diff file or store in it.
 */
void chunk_diff_write(struct chunk *chunk)
{
	loff_t pos = chunk->diff_ofs_sect << SECTOR_SHIFT;
	size_t length = chunk->sector_count << SECTOR_SHIFT;
	struct iov_iter iov_iter;
	ssize_t len;
	int err = 0;

	iov_iter_kvec(&iov_iter, ITER_SOURCE, chunk->diff_buffer->vec,
		      chunk->diff_buffer->nr_segs, length);
	file_start_write(chunk->diff_file);
	while (length) {
		len = vfs_iter_write(chunk->diff_file, &iov_iter, &pos, 0);
		if (len < 0) {
			err = (int)len;
			pr_debug("vfs_iter_write complete with error code %zd", len);
			break;
		}
		length -= len;
	}
	file_end_write(chunk->diff_file);
	chunk_notify_store(chunk, err);
}

#if 0
void chunk_store(struct chunk *chunk)
{
	struct block_device *bdev = chunk->snapshot_bdev;
	sector_t sector = chunk->diff_ofs_sect;
	sector_t count = chunk->sector_count;
	unsigned int page_idx = 0;
	struct bio *bio;
	struct chunk_bio *cbio;

	bio = bio_alloc_bioset(bdev, calc_max_vecs(count),
			       REQ_OP_WRITE | REQ_SYNC | REQ_FUA, GFP_NOIO,
			       &chunk_io_bioset);
	bio->bi_iter.bi_sector = sector;

	while (count) {
		struct bio *next;
		sector_t portion = min_t(sector_t, count, PAGE_SECTORS);
		unsigned int bytes = portion << SECTOR_SHIFT;

		if (bio_add_page(bio, chunk->diff_buffer->pages[page_idx],
				 bytes, 0) == bytes) {
			page_idx++;
			count -= portion;
			continue;
		}

		/* Create next bio */
		next = bio_alloc_bioset(bdev, calc_max_vecs(count),
					REQ_OP_WRITE | REQ_SYNC | REQ_FUA,
					GFP_NOIO, &chunk_io_bioset);
		next->bi_iter.bi_sector = bio_end_sector(bio);
		bio_chain(bio, next);
		submit_bio_noacct(bio);
		bio = next;
	}

	cbio = container_of(bio, struct chunk_bio, bio);

	INIT_WORK(&cbio->work, chunk_notify_store);
	INIT_LIST_HEAD(&cbio->chunks);
	list_add_tail(&chunk->link, &cbio->chunks);
	cbio->orig_bio = NULL;
	chunk_submit_bio(bio);
}
#endif

static struct bio *chunk_origin_load_async(struct chunk *chunk)
{
	struct block_device *bdev;
	struct bio *bio = NULL;
	struct diff_buffer *diff_buffer;
	unsigned int iov_idx = 0;
	sector_t sector, count = chunk->sector_count;

	diff_buffer = diff_buffer_take(chunk->diff_area);
	if (IS_ERR(diff_buffer))
		return ERR_CAST(diff_buffer);
	chunk->diff_buffer = diff_buffer;

	bdev = chunk->diff_area->orig_bdev;
	sector = chunk_sector(chunk);

	bio = bio_alloc_bioset(bdev, calc_max_vecs(count),
			       REQ_OP_READ, GFP_NOIO, &chunk_io_bioset);
	bio->bi_iter.bi_sector = sector;

	while (count) {
		struct bio *next;
		sector_t portion = min_t(sector_t, count, PAGE_SECTORS);
		unsigned int bytes = portion << SECTOR_SHIFT;
		struct page *pg;

		pg = virt_to_page(chunk->diff_buffer->vec[iov_idx].iov_base);
		if (bio_add_page(bio, pg, bytes, 0) == bytes) {
			iov_idx++;
			count -= portion;
			continue;
		}

		/* Create next bio */
		next = bio_alloc_bioset(bdev, calc_max_vecs(count),
					REQ_OP_READ, GFP_NOIO,
					&chunk_io_bioset);
		next->bi_iter.bi_sector = bio_end_sector(bio);
		bio_chain(bio, next);
		submit_bio_noacct(bio);
		bio = next;
	}

	return bio;
}

/*
 * Load the chunk asynchronously.
 */
int chunk_load_and_postpone_io(struct chunk *chunk, struct bio **chunk_bio)
{
	struct bio *prev = *chunk_bio, *bio;

	bio = chunk_origin_load_async(chunk);
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

bool chunk_load_and_schedule_io(struct chunk *chunk, struct bio *orig_bio)
{
	struct chunk_bio *cbio;
	struct bio *bio;

	bio = chunk_origin_load_async(chunk);
	if (IS_ERR(bio)) {
		chunk_up(chunk);
		return false;
	}

	cbio = container_of(bio, struct chunk_bio, bio);
	INIT_LIST_HEAD(&cbio->chunks);
	list_add_tail(&chunk->link, &cbio->chunks);
	INIT_WORK(&cbio->work, notify_load_and_schedule_io);
	cbio->orig_bio = orig_bio;
	cbio->orig_iter = orig_bio->bi_iter;
	bio_advance_iter_single(orig_bio, &orig_bio->bi_iter,
				chunk_limit(chunk, orig_bio));
	bio_inc_remaining(orig_bio);

	chunk_submit_bio(bio);
	return true;
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
