/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023 Veeam Software Group GmbH */
#ifndef __BLKSNAP_CHUNK_H
#define __BLKSNAP_CHUNK_H

#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>

struct diff_area;
struct diff_region;

enum chunk_st_bits {
	__CHUNK_ST_FAILED,
	__CHUNK_ST_DIRTY,
	__CHUNK_ST_BUFFER_READY,
	__CHUNK_ST_STORE_READY,
	__CHUNK_ST_LOADING,
	__CHUNK_ST_STORING,
};

/**
 * enum chunk_st - Possible states for a chunk.
 *
 * @CHUNK_ST_FAILED:
 *	An error occurred while processing the chunk data.
 * @CHUNK_ST_DIRTY:
 *	The chunk is in the dirty state. The chunk is marked dirty in case
 *	there was a write operation to the snapshot image.
 *	The flag is removed when the data of the chunk is stored in the
 *	difference storage.
 * @CHUNK_ST_BUFFER_READY:
 *	The data of the chunk is ready to be read from the RAM buffer.
 *	The flag is removed when a chunk is removed from the store queue
 *	and its buffer is released.
 * @CHUNK_ST_STORE_READY:
 *	The data of the chunk has been written to the difference storage.
 *	The flag cannot be removed.
 * @CHUNK_ST_LOADING:
 *	The data is being read from the original block device.
 *	The flag is replaced with the CHUNK_ST_BUFFER_READY flag.
 * @CHUNK_ST_STORING:
 *	The data is being saved to the difference storage.
 *	The flag is replaced with the CHUNK_ST_STORE_READY flag.
 *
 * Chunks life circle.
 * Copy-on-write when writing to original:
 *	0 -> LOADING -> BUFFER_READY -> BUFFER_READY | STORING ->
 *	BUFFER_READY | STORE_READY -> STORE_READY
 * Write to snapshot image:
 *	0 -> LOADING -> BUFFER_READY | DIRTY -> DIRTY | STORING ->
 *	BUFFER_READY | STORE_READY -> STORE_READY
 */

enum chunk_st {
	CHUNK_ST_FAILED = (1 << __CHUNK_ST_FAILED),
	CHUNK_ST_DIRTY = (1 << __CHUNK_ST_DIRTY),
	CHUNK_ST_BUFFER_READY = (1 << __CHUNK_ST_BUFFER_READY),
	CHUNK_ST_STORE_READY = (1 << __CHUNK_ST_STORE_READY),
	CHUNK_ST_LOADING = (1 << __CHUNK_ST_LOADING),
	CHUNK_ST_STORING = (1 << __CHUNK_ST_STORING),
};

/**
 * struct chunk - Minimum data storage unit.
 *
 * @link:
 *	The list header allows to create queue of chunks.
 * @diff_area:
 *	Pointer to the difference area - the storage of changes for a specific device.
 * @number:
 *	Sequential number of the chunk.
 * @sector_count:
 *	Number of sectors in the current chunk. This is especially true
 *	for the	last chunk.
 * @lock:
 *	Binary semaphore. Syncs access to the chunks fields: state,
 *	diff_buffer and diff_region.
 * @state:
 *	Defines the state of a chunk. May contain CHUNK_ST_* bits.
 * @diff_buffer:
 *	Pointer to &struct diff_buffer. Describes a buffer in the memory
 *	for storing the chunk data.
 * @diff_region:
 *	Pointer to &struct diff_region. Describes a copy of the chunk data
 *	on the difference storage.
 *
 * This structure describes the block of data that the module operates
 * with when executing the copy-on-write algorithm and when performing I/O
 * to snapshot images.
 *
 * If the data of the chunk has been changed or has just been read, then
 * the chunk gets into store queue.
 *
 * The semaphore is blocked for writing if there is no actual data in the
 * buffer, since a block of data is being read from the original device or
 * from a diff storage. If data is being read from or written to the
 * diff_buffer, the semaphore must be locked.
 */
struct chunk {
	struct list_head link;
	struct diff_area *diff_area;

	unsigned long number;
	sector_t sector_count;

	struct semaphore lock;

	atomic_t state;
	struct diff_buffer *diff_buffer;
	struct diff_region *diff_region;
};

static inline void chunk_state_set(struct chunk *chunk, int st)
{
	atomic_or(st, &chunk->state);
};

static inline void chunk_state_unset(struct chunk *chunk, int st)
{
	atomic_and(~st, &chunk->state);
};

static inline bool chunk_state_check(struct chunk *chunk, int st)
{
	return !!(atomic_read(&chunk->state) & st);
};

struct chunk *chunk_alloc(struct diff_area *diff_area, unsigned long number);
void chunk_free(struct chunk *chunk);

void chunk_diff_buffer_release(struct chunk *chunk);
void chunk_store_failed(struct chunk *chunk, int error);

void chunk_schedule_storing(struct chunk *chunk);
void chunk_copy_bio(struct chunk *chunk, struct bio *bio,
		    struct bvec_iter *iter);
void chunk_clone_bio(struct chunk *chunk, struct bio *bio);
void chunk_store(struct chunk *chunk);
int chunk_load_and_schedule_io(struct chunk *chunk, struct bio *orig_bio);
int chunk_load_and_postpone_io(struct chunk *chunk, struct bio **chunk_bio);
void chunk_load_and_postpone_io_finish(struct list_head *chunks,
                                struct bio *chunk_bio, struct bio *orig_bio);
void chunk_submit_bio(struct bio *bio);

int __init chunk_init(void);
void chunk_done(void);
#endif /* __BLKSNAP_CHUNK_H */
