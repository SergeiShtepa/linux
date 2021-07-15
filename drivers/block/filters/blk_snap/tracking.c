// SPDX-License-Identifier: GPL-2.0
#define BLK_SNAP_SECTION "-tracking"
#include "common.h"
#include "tracking.h"
#include "tracker.h"
#include "blk_util.h"
#include "defer_io.h"
#include "params.h"

#include <linux/blk-filter.h>

/* pointer to block layer filter */
//void *filter;

/*
 * tracking_submit_bio() - Intercept bio by block io layer filter
 */
#if 0
static void _tracking_submit_bio(struct bio *bio, void *filter_data)
{
	int res;
	bool bio_redirected = false;
	struct tracker *tracker = filter_data;

	if (!tracker)
		submit_bio_direct(bio);

	//intercepting
	if (atomic_read(&tracker->is_captured)) {
		//snapshot is captured, call bio redirect algorithm

		res = defer_io_redirect_bio(tracker->defer_io, bio, tracker);
		if (res == 0)
			bio_redirected = true;
	}

	if (!bio_redirected) {
		bool cbt_locked = false;

		if (tracker && bio_data_dir(bio) && bio_has_data(bio)) {
			//call CBT algorithm
			cbt_locked = tracker_cbt_bitmap_lock(tracker);
			if (cbt_locked) {
				sector_t sectStart = bio->bi_iter.bi_sector;
				sector_t sectCount = bio_sectors(bio);

				tracker_cbt_bitmap_set(tracker, sectStart, sectCount);
			}
		}
		if (cbt_locked)
			tracker_cbt_bitmap_unlock(tracker);

		submit_bio_direct(bio);
	}
}

static bool _tracking_part_add(dev_t devt, void **p_filter_data)
{
	int result;
	struct tracker *tracker = NULL;

	pr_info("new block device [%d:%d] in system\n", MAJOR(devt), MINOR(devt));

	result = tracker_find_by_dev_id(devt, &tracker);
	if (result != 0)
		return false; /*do not track this device*/

	if (_tracker_create(tracker, filter, false)) {
		pr_err("Failed to attach new device to tracker. errno=%d\n", result);
		return false; /*failed to attach new device to tracker*/
	}

	*p_filter_data = tracker;
	return true;
}

static void _tracking_part_del(void *private_data)
{
	struct tracker *tracker = private_data;

	if (!tracker)
		return;

	pr_info("delete block device [%d:%d] from system\n",
		MAJOR(tracker->original_dev_id), MINOR(tracker->original_dev_id));

	_tracker_remove(tracker, false);
}

struct blk_filter_ops filter_ops = {
	.filter_bio = _tracking_submit_bio,
	.part_add = _tracking_part_add,
	.part_del = _tracking_part_del };
#endif


int tracking_init(void)
{
	return 0;
}

void tracking_done(void)
{

}

static int tracking_submit_bio_cb(struct bio *bio, void *ctx)
{
	struct tracker *tracker = ctx;
	unsigned int curr_flags;
	struct bio_list bio_list_on_stack[2];
	struct bio *new_bio;

	if (bio_data_dir(bio) != WRITE)
		return FLT_ST_PASS;

	if ((bio->bi_end_io == tracker_cow_end_io))
		return FLT_ST_PASS;

	/*
	 * All memory allocations will be without IO to avoid blocking
	 * the process when allocating memory.
	 */
	curr_flags = memalloc_noio_save();
	/*
	 * If the snapshot is held, the tracker appends initiates the COW
	 * algorithm, adding read bio requests for the overwritten data.
	 * To avoid loading the stack with a recursive calling of submit_bio()
	 * function, current->bio_list is used.
	 */
	bio_list_init(&bio_list_on_stack[0]);
	current->bio_list = bio_list_on_stack;

	tracker_submit_bio_cb(tracker, bio);
	while ((new_bio = bio_list_pop(&bio_list_on_stack[0])))
		submit_bio_noacct(new_bio);

	current->bio_list = NULL;
	memalloc_noio_restore(curr_flags);

	return FLT_ST_PASS;
}

static void tracking_detach_cb(void *ctx)
{
	struct tracker *tracker = ctx;
	unsigned int curr_flags;

	/*
	 * In the process of releasing resources, memory is unlikely
	 * to be allocated, but who knows...
	 */
	curr_flags = memalloc_noio_save();
	tracker_put(tracker);
	memalloc_noio_restore(curr_flags);
}

static const struct filter_operations tracking_fops = {
	.submit_bio_cb = tracking_submit_bio_cb,
	.detach_cb = tracking_detach_cb
};

int tracking_add(dev_t dev_id, unsigned long long snapshot_id)
{
	int result;
	struct block_device *bdev;
	unsigned int curr_flags;
	struct tracker *tracker = NULL;

	pr_info("Adding device [%d:%d] under tracking\n", MAJOR(dev_id), MINOR(dev_id));
	bdev = blkdev_get_by_dev(dev_id, TRACKER_BDEV_MODE, NULL);
	if (IS_ERR(bdev)) {
		pr_err("Failed to lock device '%d:%d'\n",
			MAJOR(dev_id), MINOR(dev_id));
		return PTR_ERR(bdev);
	}
	bdev_filter_lock(bdev);
	curr_flags = memalloc_noio_save();

	tracker = bdev_filter_find_ctx(bdev, KBUILD_MODNAME);
	if (!IS_ERR(tracker)) {
		//pr_info("Device [%d:%d] is already tracked\n", MAJOR(dev_id), MINOR(dev_id));
		if (tracker_renew_needed(tracker, bdev)) {
			result = bdev_filter_del(bdev, KBUILD_MODNAME);
			tracker = NULL;
		} else {
			result = -EALREADY;
			goto out;
		}
	} else if (PTR_ERR(tracker) != -ENOENT) {
		pr_err("Unable to add device [%d:%d] under tracking\n",
			MAJOR(dev_id), MINOR(dev_id));
		result = PTR_ERR(tracker);
		goto out;
	}

	tracker = tracker_new(bdev, snapshot_id);
	if (!tracker) {
		pr_err("Failed to allocate tracker.\n");
		result = -ENOMEM;
		goto out;
	}

	result = bdev_filter_add(bdev, KBUILD_MODNAME, &tracking_fops, tracker);
	if (result) {
		tracker_put(tracker);
		goto out;
	}

out:
	memalloc_noio_restore(curr_flags);
	bdev_filter_unlock(bdev);
	blkdev_put(bdev, TRACKER_BDEV_MODE);
	return result;
}

int tracking_remove(dev_t dev_id)
{
	int result;
	struct tracker *tracker = NULL;

	pr_info("Removing device [%d:%d] from tracking\n", MAJOR(dev_id), MINOR(dev_id));

	bdev = blkdev_get_by_dev(dev_id, TRACKER_BDEV_MODE, NULL);
	if (IS_ERR(bdev)) {
		pr_err("Failed to lock device '%d:%d'\n",
			MAJOR(dev_id), MINOR(dev_id));
		return PTR_ERR(bdev);
	}
	bdev_filter_lock(bdev);

	result = bdev_filter_del(bdev, KBUILD_MODNAME);

	bdev_filter_unlock(bdev);
	blkdev_put(bdev, TRACKER_BDEV_MODE);
	return result;
}

int tracking_collect(int max_count, struct cbt_info_s *p_cbt_info, int *p_count)
{
	int res = tracker_enum_cbt_info(max_count, p_cbt_info, p_count);

	if (res == 0)
		pr_info("%d devices found under tracking\n", *p_count);
	else if (res == -ENODATA) {
		pr_info("There are no devices under tracking\n");
		*p_count = 0;
		res = 0;
	} else
		pr_err("Failed to collect devices under tracking. errno=%d", res);

	return res;
}

int tracking_read_cbt_bitmap(dev_t dev_id, unsigned int offset, size_t length,
			     void __user *user_buff)
{
	int result = 0;
	struct tracker *tracker = NULL;

	result = tracker_find_by_dev_id(dev_id, &tracker);
	if (result == 0) {
		if (atomic_read(&tracker->is_captured))
			result = cbt_map_read_to_user(tracker->cbt_map, user_buff, offset, length);
		else {
			pr_err("Unable to read CBT bitmap for device [%d:%d]: ", MAJOR(dev_id),
			       MINOR(dev_id));
			pr_err("device is not captured by snapshot\n");
			result = -EPERM;
		}
	} else if (-ENODATA == result) {
		pr_err("Unable to read CBT bitmap for device [%d:%d]: ", MAJOR(dev_id),
		       MINOR(dev_id));
		pr_err("device not found\n");
	} else
		pr_err("Failed to find devices under tracking. errno=%d", result);

	return result;
}
