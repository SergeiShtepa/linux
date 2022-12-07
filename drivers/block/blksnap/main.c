// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <uapi/linux/blksnap.h>
#include "version.h"
#include "params.h"
#include "ctrl.h"
#include "sysfs.h"
#include "snapimage.h"
#include "snapshot.h"
#include "tracker.h"
#include "diff_io.h"

static int __init blk_snap_init(void)
{
	int result;

	pr_info("Loading\n");
	pr_debug("Version: %s\n", VERSION_STR);
	pr_debug("tracking_block_minimum_shift: %d\n",
		 tracking_block_minimum_shift);
	pr_debug("tracking_block_maximum_count: %d\n",
		 tracking_block_maximum_count);
	pr_debug("chunk_minimum_shift: %d\n", chunk_minimum_shift);
	pr_debug("chunk_maximum_count: %d\n", chunk_maximum_count);
	pr_debug("chunk_maximum_in_cache: %d\n", chunk_maximum_in_cache);
	pr_debug("free_diff_buffer_pool_size: %d\n",
		 free_diff_buffer_pool_size);
	pr_debug("diff_storage_minimum: %d\n", diff_storage_minimum);

	result = diff_io_init();
	if (result)
		return result;

	result = snapimage_init();
	if (result)
		return result;

	result = tracker_init();
	if (result)
		return result;

	result = ctrl_init();
	if (result)
		return result;

	result = sysfs_initialize();
	return result;
}

static void __exit blk_snap_exit(void)
{
	pr_info("Unloading module\n");

	sysfs_finalize();
	ctrl_done();

	diff_io_done();
	snapshot_done();
	snapimage_done();
	tracker_done();

	pr_info("Module was unloaded\n");
}

module_init(blk_snap_init);
module_exit(blk_snap_exit);

/*
 * The power of 2 for minimum tracking block size.
 * If we make the tracking block size small, we will get detailed information
 * about the changes, but the size of the change tracker table will be too
 * large, which will lead to inefficient memory usage.
 */
int tracking_block_minimum_shift = 16;

/*
 * The maximum number of tracking blocks.
 * A table is created to store information about the status of all tracking
 * blocks in RAM. So, if the size of the tracking block is small, then the size
 * of the table turns out to be large and memory is consumed inefficiently.
 * As the size of the block device grows, the size of the tracking block
 * size should also grow. For this purpose, the limit of the maximum
 * number of block size is set.
 */
int tracking_block_maximum_count = 2097152;

/*
 * The power of 2 for minimum chunk size.
 * The size of the chunk depends on how much data will be copied to the
 * difference storage when at least one sector of the block device is changed.
 * If the size is small, then small I/O units will be generated, which will
 * reduce performance. Too large a chunk size will lead to inefficient use of
 * the difference storage.
 */
int chunk_minimum_shift = 18;

/*
 * The maximum number of chunks.
 * To store information about the state of all the chunks, a table is created
 * in RAM. So, if the size of the chunk is small, then the size of the table
 * turns out to be large and memory is consumed inefficiently.
 * As the size of the block device grows, the size of the chunk should also
 * grow. For this purpose, the maximum number of chunks is set.
 */
int chunk_maximum_count = 2097152;

/*
 * The maximum number of chunks in memory cache.
 * Since reading and writing to snapshots is performed in large chunks,
 * a cache is implemented to optimize reading small portions of data
 * from the snapshot image. As the number of chunks in the cache
 * increases, memory consumption also increases.
 * The minimum recommended value is four.
 */
int chunk_maximum_in_cache = 32;

/*
 * The size of the pool of preallocated difference buffers.
 * A buffer can be allocated for each chunk. After use, this buffer is not
 * released immediately, but is sent to the pool of free buffers.
 * However, if there are too many free buffers in the pool, then these free
 * buffers will be released immediately.
 */
int free_diff_buffer_pool_size = 128;

/*
 * The minimum allowable size of the difference storage in sectors.
 * The difference storage is a part of the disk space allocated for storing
 * snapshot data. If there is less free space in the storage than the minimum,
 * an event is generated about the lack of free space.
 */
int diff_storage_minimum = 2097152;

module_param_named(tracking_block_minimum_shift, tracking_block_minimum_shift,
		   int, 0644);
MODULE_PARM_DESC(tracking_block_minimum_shift,
		 "The power of 2 for minimum tracking block size");
module_param_named(tracking_block_maximum_count, tracking_block_maximum_count,
		   int, 0644);
MODULE_PARM_DESC(tracking_block_maximum_count,
		 "The maximum number of tracking blocks");
module_param_named(chunk_minimum_shift, chunk_minimum_shift, int, 0644);
MODULE_PARM_DESC(chunk_minimum_shift,
		 "The power of 2 for minimum chunk size");
module_param_named(chunk_maximum_count, chunk_maximum_count, int, 0644);
MODULE_PARM_DESC(chunk_maximum_count,
		 "The maximum number of chunks");
module_param_named(chunk_maximum_in_cache, chunk_maximum_in_cache, int, 0644);
MODULE_PARM_DESC(chunk_maximum_in_cache,
		 "The maximum number of chunks in memory cache");
module_param_named(free_diff_buffer_pool_size, free_diff_buffer_pool_size, int,
		   0644);
MODULE_PARM_DESC(free_diff_buffer_pool_size,
		 "The size of the pool of preallocated difference buffers");
module_param_named(diff_storage_minimum, diff_storage_minimum, int, 0644);
MODULE_PARM_DESC(diff_storage_minimum,
	"The minimum allowable size of the difference storage in sectors");

MODULE_DESCRIPTION("Block Device Snapshots Module");
MODULE_VERSION(VERSION_STR);
MODULE_AUTHOR("Veeam Software Group GmbH");
MODULE_LICENSE("GPL");
