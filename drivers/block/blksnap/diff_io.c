// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-diff-io: " fmt

#include <linux/blkdev.h>
#include <linux/slab.h>
#include "diff_io.h"
#include "diff_buffer.h"

struct bio_set diff_io_bioset;

int diff_io_init(void)
{
	return bioset_init(&diff_io_bioset, 64, 0,
			   BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
}

void diff_io_done(void)
{
	bioset_exit(&diff_io_bioset);
}

static void diff_io_notify_cb(struct work_struct *work)
{
	struct diff_io_async *async =
		container_of(work, struct diff_io_async, work);

	might_sleep();
	async->notify_cb(async->ctx);
}

static void diff_io_endio(struct bio *bio)
{
	struct diff_io *diff_io = bio->bi_private;

	if (bio->bi_status != BLK_STS_OK)
		diff_io->error = -EIO;

	if (diff_io->is_sync_io)
		complete(&diff_io->notify.sync.completion);
	else
		queue_work(system_wq, &diff_io->notify.async.work);

	bio_put(bio);
}

static inline struct diff_io *diff_io_new(bool is_write, bool is_nowait)
{
	struct diff_io *diff_io;
	gfp_t gfp_mask = is_nowait ? (GFP_NOIO | GFP_NOWAIT) : GFP_NOIO;

	diff_io = kzalloc(sizeof(struct diff_io), gfp_mask);
	if (unlikely(!diff_io))
		return NULL;

	diff_io->error = 0;
	diff_io->is_write = is_write;

	return diff_io;
}

struct diff_io *diff_io_new_sync(bool is_write)
{
	struct diff_io *diff_io;

	diff_io = diff_io_new(is_write, false);
	if (unlikely(!diff_io))
		return NULL;

	diff_io->is_sync_io = true;
	init_completion(&diff_io->notify.sync.completion);
	return diff_io;
}

struct diff_io *diff_io_new_async(bool is_write, bool is_nowait,
				  void (*notify_cb)(void *ctx), void *ctx)
{
	struct diff_io *diff_io;

	diff_io = diff_io_new(is_write, is_nowait);
	if (unlikely(!diff_io))
		return NULL;

	diff_io->is_sync_io = false;
	INIT_WORK(&diff_io->notify.async.work, diff_io_notify_cb);
	diff_io->notify.async.ctx = ctx;
	diff_io->notify.async.notify_cb = notify_cb;
	return diff_io;
}

static inline bool check_page_aligned(sector_t sector)
{
	return !(sector & ((1ull << (PAGE_SHIFT - SECTOR_SHIFT)) - 1));
}

static inline unsigned short calc_page_count(sector_t sectors)
{
	return round_up(sectors, PAGE_SECTORS) / PAGE_SECTORS;
}

int diff_io_do(struct diff_io *diff_io, struct diff_region *diff_region,
	       struct diff_buffer *diff_buffer, const bool is_nowait)
{
	int ret = 0;
	struct bio *bio = NULL;
	struct page **current_page_ptr;
	unsigned short nr_iovecs;
	sector_t processed = 0;
	unsigned int opf = REQ_SYNC |
		(diff_io->is_write ? REQ_OP_WRITE | REQ_FUA : REQ_OP_READ);
	gfp_t gfp_mask = GFP_NOIO | (is_nowait ? GFP_NOWAIT : 0);

	if (unlikely(!check_page_aligned(diff_region->sector))) {
		pr_err("Difference storage block should be aligned to PAGE_SIZE\n");
		ret = -EINVAL;
		goto fail;
	}

	nr_iovecs = calc_page_count(diff_region->count);
	if (unlikely(nr_iovecs > diff_buffer->page_count)) {
		pr_err("The difference storage block is larger than the buffer size\n");
		ret = -EINVAL;
		goto fail;
	}

	bio = bio_alloc_bioset(diff_region->bdev, nr_iovecs, opf, gfp_mask,
			       &diff_io_bioset);
	if (unlikely(!bio)) {
		if (is_nowait)
			ret = -EAGAIN;
		else
			ret = -ENOMEM;
		goto fail;
	}

	bio_set_flag(bio, BIO_FILTERED);

	bio->bi_end_io = diff_io_endio;
	bio->bi_private = diff_io;
	bio->bi_iter.bi_sector = diff_region->sector;
	current_page_ptr = diff_buffer->pages;
	while (processed < diff_region->count) {
		sector_t bvec_len_sect;
		unsigned int bvec_len;

		bvec_len_sect = min_t(sector_t, PAGE_SECTORS,
				      diff_region->count - processed);
		bvec_len = (unsigned int)(bvec_len_sect << SECTOR_SHIFT);

		if (bio_add_page(bio, *current_page_ptr, bvec_len, 0) == 0) {
			bio_put(bio);
			return -EFAULT;
		}

		current_page_ptr++;
		processed += bvec_len_sect;
	}
	submit_bio_noacct(bio);

	if (diff_io->is_sync_io)
		wait_for_completion_io(&diff_io->notify.sync.completion);

	return 0;
fail:
	if (bio)
		bio_put(bio);
	return ret;
}

