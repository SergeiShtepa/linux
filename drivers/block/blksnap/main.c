// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <uapi/linux/blksnap.h>
#include "snapimage.h"
#include "snapshot.h"
#include "tracker.h"
#include "diff_io.h"

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

#define VERSION_STR "2.0.0.0"
static const struct blksnap_version version = {
	.major = 2,
	.minor = 0,
	.revision = 0,
	.build = 0,
};

static int ioctl_version(unsigned long arg)
{
	struct blksnap_version __user *user_version = (void *)arg;

	if (copy_to_user(user_version, &version, sizeof(version))) {
		pr_err("Unable to get version: invalid user buffer\n");
		return -ENODATA;
	}

	return 0;
}

static_assert(sizeof(uuid_t) == sizeof(struct blksnap_uuid),
	"Invalid size of struct blksnap_uuid.");

static int ioctl_snapshot_create(unsigned long arg)
{
	struct blksnap_uuid __user *user_id = (void *)arg;
	uuid_t kernel_id;
	int ret;

	ret = snapshot_create(&kernel_id);
	if (ret)
		return ret;

	if (copy_to_user(user_id->b, kernel_id.b, sizeof(uuid_t))) {
		pr_err("Unable to create snapshot: invalid user buffer\n");
		return -ENODATA;
	}

	return 0;
}

static int ioctl_snapshot_destroy(unsigned long arg)
{
	struct blksnap_uuid __user *user_id = (void *)arg;
	uuid_t kernel_id;

	if (copy_from_user(kernel_id.b, user_id->b, sizeof(uuid_t))) {
		pr_err("Unable to destroy snapshot: invalid user buffer\n");
		return -ENODATA;
	}

	return snapshot_destroy(&kernel_id);
}

static int ioctl_snapshot_append_storage(unsigned long arg)
{
	int ret;
	struct blksnap_snapshot_append_storage __user *uarg = (void *)arg;
	struct blksnap_snapshot_append_storage karg;
	char *bdev_path = NULL;

	pr_debug("Append difference storage\n");

	if (copy_from_user(&karg, uarg, sizeof(karg))) {
		pr_err("Unable to append difference storage: invalid user buffer\n");
		return -EINVAL;
	}

	bdev_path = strndup_user(karg.bdev_path, karg.bdev_path_size);
	if (IS_ERR(bdev_path))
		return PTR_ERR(bdev_path);

	ret = snapshot_append_storage((uuid_t *)karg.id.b, bdev_path,
				       karg.ranges, karg.count);
	kfree(bdev_path);
	return ret;
}

static int ioctl_snapshot_take(unsigned long arg)
{
	struct blksnap_uuid __user *user_id = (void *)arg;
	uuid_t kernel_id;

	if (copy_from_user(kernel_id.b, user_id->b, sizeof(uuid_t))) {
		pr_err("Unable to take snapshot: invalid user buffer\n");
		return -ENODATA;
	}

	return snapshot_take(&kernel_id);
}

static int ioctl_snapshot_wait_event(unsigned long arg)
{
	int ret = 0;
	struct blksnap_snapshot_event __user *uarg = (void *)arg;
	struct blksnap_snapshot_event *karg;
	struct event *ev;

	karg = kzalloc(sizeof(struct blksnap_snapshot_event), GFP_KERNEL);
	if (!karg)
		return -ENOMEM;

	/* Copy only snapshot ID */
	if (copy_from_user(karg->id.b, uarg->id.b, sizeof(uuid_t))) {
		pr_err("Unable to get snapshot event. Invalid user buffer\n");
		ret = -EINVAL;
		goto out;
	}

	ev = snapshot_wait_event((uuid_t *)karg->id.b, karg->timeout_ms);
	if (IS_ERR(ev)) {
		ret = PTR_ERR(ev);
		goto out;
	}

	pr_debug("Received event=%lld code=%d data_size=%d\n", ev->time,
		 ev->code, ev->data_size);
	karg->code = ev->code;
	karg->time_label = ev->time;

	if (ev->data_size > sizeof(karg->data)) {
		pr_err("Event size %d is too big\n", ev->data_size);
		ret = -ENOSPC;
		/* If we can't copy all the data, we copy only part of it. */
	}
	memcpy(karg->data, ev->data, ev->data_size);
	event_free(ev);

	if (copy_to_user(uarg, karg, sizeof(struct blksnap_snapshot_event))) {
		pr_err("Unable to get snapshot event. Invalid user buffer\n");
		ret = -EINVAL;
	}
out:
	kfree(karg);

	return ret;
}

static int (*const blksnap_ioctl_table[])(unsigned long arg) = {
	ioctl_version,
	ioctl_snapshot_create,
	ioctl_snapshot_destroy,
	ioctl_snapshot_append_storage,
	ioctl_snapshot_take,
	ioctl_snapshot_wait_event,
};

static_assert(
	sizeof(blksnap_ioctl_table) ==
	((blksnap_ioctl_snapshot_wait_event + 1) * sizeof(void *)),
	"The size of table blksnap_ioctl_table does not match the enum blksnap_ioctl.");

static long ctrl_unlocked_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	int nr = _IOC_NR(cmd);

	if (nr > (sizeof(blksnap_ioctl_table) / sizeof(void *)))
		return -ENOTTY;

	if (!blksnap_ioctl_table[nr])
		return -ENOTTY;

	return blksnap_ioctl_table[nr](arg);
}

static const struct file_operations blksnap_ctrl_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= ctrl_unlocked_ioctl,
};

static struct miscdevice blksnap_ctrl_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= BLKSNAP_CTL,
	.fops		= &blksnap_ctrl_fops,
};

static int __init blksnap_init(void)
{
	int ret;

	pr_debug("Loading\n");
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

	ret = diff_io_init();
	if (ret)
		goto fail_diff_io_init;

	ret = tracker_init();
	if (ret)
		goto fail_tracker_init;

	ret = misc_register(&blksnap_ctrl_misc);
	if (ret)
		goto fail_misc_register;

	return 0;

fail_misc_register:
	tracker_done();
fail_tracker_init:
	diff_io_done();
fail_diff_io_init:

	return ret;
}

static void __exit blksnap_exit(void)
{
	pr_debug("Unloading module\n");

	misc_deregister(&blksnap_ctrl_misc);

	diff_io_done();
	snapshot_done();
	tracker_done();

	pr_debug("Module was unloaded\n");
}

module_init(blksnap_init);
module_exit(blksnap_exit);

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
