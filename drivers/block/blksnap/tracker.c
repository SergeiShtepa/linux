// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-tracker: " fmt

#include <linux/slab.h>
#include <linux/blk-mq.h>
#include <linux/sched/mm.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "tracker.h"
#include "cbt_map.h"
#include "diff_area.h"
#include "snapimage.h"
#include "snapshot.h"

LIST_HEAD(tracker_list);
DEFINE_SPINLOCK(tracker_list_lock);

static inline void __tracker_free(struct tracker *tracker)
{
	if (!tracker)
		return;

	might_sleep();

	pr_debug("Free tracker for device [%u:%u]\n", MAJOR(tracker->dev_id),
		 MINOR(tracker->dev_id));

	if (tracker->diff_area)
		diff_area_free(tracker->diff_area);
	if (tracker->cbt_map)
		cbt_map_destroy(tracker->cbt_map);

	kfree(tracker);
}

void tracker_free(struct kref *kref)
{
	__tracker_free(container_of(kref, struct tracker, kref));
}

static inline struct tracker *__tracker_find(dev_t dev_id)
{
	struct tracker *tracker;

	if (!list_empty(&tracker_list))
		list_for_each_entry(tracker, &tracker_list, link)
			if (tracker->dev_id == dev_id)
				return tracker;

	return NULL;
}

static inline struct tracker *tracker_find(dev_t dev_id)
{
	struct tracker *tracker = NULL;

	spin_lock(&tracker_list_lock);
	tracker = __tracker_find(dev_id);
	if (!tracker->is_active)
		tracker = NULL;
	spin_unlock(&tracker_list_lock);

	return tracker;
}

static bool tracker_submit_bio(struct bio *bio)
{
	struct bio_list bio_list_on_stack[2] = { };
	struct bio *new_bio;
	int err;
	sector_t sector;
	sector_t count = bio_sectors(bio);
	unsigned int current_flag;
	bool is_nowait = !!(bio->bi_opf & REQ_NOWAIT);
	struct tracker *tracker = tracker_find(bio->bi_bdev->bd_dev);

	if (!tracker || !op_is_write(bio_op(bio)) || !count)
		return false;

	sector = bio->bi_iter.bi_sector;
	if (bio_flagged(bio, BIO_REMAPPED))
		sector -= bio->bi_bdev->bd_start_sect;

	current_flag = memalloc_noio_save();
	err = cbt_map_set(tracker->cbt_map, sector, count);
	memalloc_noio_restore(current_flag);

	if (err ||
	    !atomic_read(&tracker->snapshot_is_taken) ||
	    diff_area_is_corrupted(tracker->diff_area))
		return false;

	current_flag = memalloc_noio_save();
	bio_list_init(&bio_list_on_stack[0]);
	current->bio_list = bio_list_on_stack;

	err = diff_area_copy(tracker->diff_area, sector, count, is_nowait);

	current->bio_list = NULL;
	memalloc_noio_restore(current_flag);

	if (unlikely(err)) {
		if (err == -EAGAIN) {
			bio_wouldblock_error(bio);
			return true;
		}
		pr_err("Failed to copy data to diff storage with error %d\n", abs(err));
		return false;
	}

	while ((new_bio = bio_list_pop(&bio_list_on_stack[0]))) {
		/*
		 * The result from submitting a bio from the
		 * filter itself does not need to be processed,
		 * even if this function has a return code.
		 */
		bio_set_flag(new_bio, BIO_FILTERED);
		submit_bio_noacct(new_bio);
	}
	/*
	 * If a new bio was created during the handling, then new bios must
	 * be sent and returned to complete the processing of the original bio.
	 * Unfortunately, this has to be done for any bio, regardless of their
	 * flags and options.
	 * Otherwise, write I/O units may overtake read I/O units.
	 */
	err = diff_area_wait(tracker->diff_area, sector, count, is_nowait);
	if (unlikely(err)) {
		if (err == -EAGAIN) {
			bio_wouldblock_error(bio);
			return true;
		}
		pr_err("Failed to wait for available data in diff storage with error %d\n", abs(err));
	}
	return false;
}

static int tracker_attach(struct block_device *bdev, bool is_frozen)
{
	struct tracker *tracker = NULL;
	struct cbt_map *cbt_map;

	pr_debug("Creating tracker for device [%u:%u]\n", MAJOR(bdev->bd_dev),
		 MINOR(bdev->bd_dev));

	if (!is_frozen) {
		/*
		 * If the file system has not been frozen, we have to attach a
		 * filter. This means that when the filter was attached, the
		 * state of the file system was not consistent.
		 * If the file system cannot be frozen, it is possible that it
		 * is damaged and requires repair. For such a file system, we
		 * still need to create a snapshot and perform a backup for
		 * subsequent repair during recovery.
		 */
		pr_warn("The filter attach to the device [%u:%u] when it was unfrozen\n",
			MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
	}

	cbt_map = cbt_map_create(bdev);
	if (!cbt_map) {
		pr_err("Failed to create CBT map for device [%u:%u]\n",
		       MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
		return -ENOMEM;
	}

	tracker = kzalloc(sizeof(struct tracker), GFP_KERNEL);
	if (tracker == NULL) {
		cbt_map_destroy(cbt_map);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&tracker->link);
	tracker->dev_id = bdev->bd_dev;
	atomic_set(&tracker->snapshot_is_taken, false);
	tracker->cbt_map = cbt_map;
	tracker->diff_area = NULL;
	tracker->snapimage =  NULL;
	tracker->is_frozen = false;

	spin_lock(&tracker_list_lock);
	tracker->is_active = true;
	list_add_tail(&tracker->link, &tracker_list);
	spin_unlock(&tracker_list_lock);

	pr_debug("New tracker for device [%u:%u] was created\n",
		 MAJOR(tracker->dev_id), MINOR(tracker->dev_id));

	return 0;
}

static void tracker_release_fn(
	__attribute__ ((unused)) struct work_struct *work)
{
	struct tracker *tracker;

	do {
		tracker = NULL;

		spin_lock(&tracker_list_lock);
		if (!list_empty(&tracker_list)) {
			struct tracker *entry;

			list_for_each_entry(entry, &tracker_list, link) {
				if (!entry->is_active) {
					tracker = entry;
					list_del(&tracker->link);
					break;
				}
			}
		}
		spin_unlock(&tracker_list_lock);

		tracker_put(tracker);
	} while (tracker);
}
DECLARE_WORK(tracker_release_worker, tracker_release_fn);

static void tracker_detach(struct block_device *bdev, bool is_frozen)
{
	struct tracker *tracker;

	if (!is_frozen) {
		/*
		 * It is assumed that if the filter no longer wants to filter
		 * I/O units on a block device, then it does not matter at all
		 * what state the file system is in.
		 */
		pr_warn("The filter detach from the device [%u:%u] when it was unfrozen\n",
			MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
	}

	spin_lock(&tracker_list_lock);
	tracker = __tracker_find(bdev->bd_dev);
	if (tracker)
		tracker->is_active = false;
	spin_unlock(&tracker_list_lock);

	queue_work(system_wq, &tracker_release_worker);
}

static int ctl_cbtinfo(struct tracker *tracker, __u8 __user *buf, __u32 *plen)
{
	struct cbt_map *cbt_map = tracker->cbt_map;
	struct blksnap_cbtinfo arg;

	if (!cbt_map)
		return -ESRCH;

	if (*plen < sizeof(arg))
		return -EINVAL;

	arg.device_capacity = (__u64)(cbt_map->device_capacity << SECTOR_SHIFT);
	arg.block_size = (__u32)(1 << cbt_map->blk_size_shift);
	arg.block_count = (__u32)cbt_map->blk_count;
	export_uuid(arg.generation_id.b, &cbt_map->generation_id);
	arg.changes_number = (__u8)cbt_map->snap_number_previous;

	if (copy_to_user(buf, &arg, sizeof(arg)))
		return -ENODATA;

	*plen = sizeof(arg);
	return 0;
}

static int ctl_cbtmap(struct tracker *tracker, __u8 __user *buf, __u32 *plen)
{
	struct cbt_map *cbt_map = tracker->cbt_map;
	struct blksnap_cbtmap arg;
	size_t readed;

	if (!cbt_map)
		return -ESRCH;

	if (unlikely(cbt_map->is_corrupted)) {
		pr_err("CBT table was corrupted\n");
		return -EFAULT;
	}

	if (*plen < sizeof(arg))
		return -EINVAL;

	if (copy_from_user(&arg, buf, sizeof(arg)))
		return -ENODATA;

	readed = cbt_map_read_to_user(cbt_map, arg.buffer, arg.offset,
				      arg.length);
	*plen = sizeof(arg) + readed;

	return 0;
}
static int ctl_cbtdirty(struct tracker *tracker, __u8 __user *buf, __u32 *plen)
{
	struct cbt_map *cbt_map = tracker->cbt_map;
	struct blksnap_cbtdirty arg;

	if (!cbt_map)
		return -ESRCH;

	if (*plen < sizeof(arg))
		return -EINVAL;

	if (copy_from_user(&arg, buf, sizeof(arg)))
		return -ENODATA;

	*plen = 0;
	return cbt_map_mark_dirty_blocks(cbt_map, arg.dirty_sectors_array,
					 arg.count);
}
static int ctl_snapshotadd(struct tracker *tracker,
			   __u8 __user *buf, __u32 *plen)
{
	struct blksnap_snapshotadd arg;

	if (*plen < sizeof(arg))
		return -EINVAL;

	if (copy_from_user(&arg, buf, sizeof(arg)))
		return -ENODATA;

	*plen = 0;
	return  snapshot_add_device((uuid_t *)&arg.id, tracker);
}
static int ctl_snapshotinfo(struct tracker *tracker,
			    __u8 __user *buf, __u32 *plen)
{
	struct blksnap_snapshotinfo arg = {0};
	int ret = 0;

	if (*plen < sizeof(arg))
		return -EINVAL;

	if (copy_from_user(&arg, buf, sizeof(arg)))
		return -ENODATA;


	if (tracker->diff_area && diff_area_is_corrupted(tracker->diff_area))
		arg.error_code = tracker->diff_area->error_code;
	else
		arg.error_code = 0;

	if (tracker->snapimage)
		strncpy(arg.image, tracker->snapimage->disk->disk_name, IMAGE_DISK_NAME_LEN);

	*plen = sizeof(arg);
	return ret;
}

static int (*const ctl_table[])(struct tracker *tracker,
				__u8 __user *buf, __u32 *plen) = {
	ctl_cbtinfo,
	ctl_cbtmap,
	ctl_cbtdirty,
	ctl_snapshotadd,
	ctl_snapshotinfo,
};

static int tracker_ctl(struct block_device *bdev, const unsigned int cmd,
		       __u8 __user *buf, __u32 *plen)
{
	struct tracker *tracker;

	tracker = tracker_find(bdev->bd_dev);
	if (!tracker)
		return -ENOENT;

	if (cmd > (sizeof(ctl_table) / sizeof(ctl_table[0])))
		return -ENOTTY;

	return ctl_table[cmd](tracker, buf, plen);
}

static const struct blkfilter_operations tracker_fops = {
	.submit_bio = tracker_submit_bio,
	.attach = tracker_attach,
	.detach = tracker_detach,
	.ctl = tracker_ctl,
};

int tracker_take_snapshot(struct tracker *tracker)
{
	int ret = 0;
	bool cbt_reset_needed = false;
	struct block_device *orig_bdev = tracker->diff_area->orig_bdev;
	sector_t capacity;
	unsigned int current_flag;

	blk_mq_freeze_queue(orig_bdev->bd_queue);
	current_flag = memalloc_noio_save();

	if (tracker->cbt_map->is_corrupted) {
		cbt_reset_needed = true;
		pr_warn("Corrupted CBT table detected. CBT fault\n");
	}

	capacity = bdev_nr_sectors(orig_bdev);
	if (tracker->cbt_map->device_capacity != capacity) {
		cbt_reset_needed = true;
		pr_warn("Device resize detected. CBT fault\n");
	}

	if (cbt_reset_needed) {
		ret = cbt_map_reset(tracker->cbt_map, capacity);
		if (ret) {
			pr_err("Failed to create tracker. errno=%d\n",
			       abs(ret));
			return ret;
		}
	}

	cbt_map_switch(tracker->cbt_map);
	atomic_set(&tracker->snapshot_is_taken, true);

	memalloc_noio_restore(current_flag);
	blk_mq_unfreeze_queue(orig_bdev->bd_queue);

	return 0;
}

void tracker_release_snapshot(struct tracker *tracker)
{
	blk_mq_freeze_queue(tracker->diff_area->orig_bdev->bd_queue);

	pr_debug("Tracker for device [%u:%u] release snapshot\n",
		 MAJOR(tracker->dev_id), MINOR(tracker->dev_id));

	atomic_set(&tracker->snapshot_is_taken, false);

	blk_mq_unfreeze_queue(tracker->diff_area->orig_bdev->bd_queue);

	if (tracker->snapimage) {
		snapimage_free(tracker->snapimage);
		tracker->snapimage = NULL;
	}

	if (tracker->diff_area) {
		diff_area_free(tracker->diff_area);
		tracker->diff_area = NULL;
	}
}

int tracker_collect(unsigned int *pcount, struct blksnap_bdev __user *id_array)
{
	int ret = 0;
	int inx = 0;
	struct tracker *tr = NULL;
	struct blksnap_bdev *ids;

	pr_debug("Collect trackers\n");

	spin_lock(&tracker_list_lock);
	if (list_empty(&tracker_list)) {
		spin_unlock(&tracker_list_lock);
		*pcount = 0;
		return 0;
	}

	if (!id_array) {
		list_for_each_entry(tr, &tracker_list, link)
			inx++;
		spin_unlock(&tracker_list_lock);
		*pcount = inx;
		return 0;
	}
	spin_unlock(&tracker_list_lock);

	ids = kcalloc(*pcount, sizeof(struct blksnap_bdev), GFP_KERNEL);
	if (ids)
		return -ENOMEM;

	spin_lock(&tracker_list_lock);
	list_for_each_entry(tr, &tracker_list, link) {
		if (inx >= *pcount) {
			ret = -ENODATA;
			break;
		}
		ids[inx].major = MAJOR(tr->dev_id);
		ids[inx].minor = MINOR(tr->dev_id);
		inx++;
	}
	spin_unlock(&tracker_list_lock);

	if (!ret) {
		unsigned long sz = inx * sizeof(struct blksnap_bdev);

		if (copy_to_user(id_array, ids, sz)) {
			pr_err("Unable to collect trackers: failed to copy data to user buffer\n");
			ret = -EINVAL;
		}
	}
	kfree(tr);
	*pcount = inx;
	return ret;
}

int tracker_init(void)
{
	return blkfilter_register("blksnap", &tracker_fops);
}

void tracker_done(void)
{
	struct tracker *tracker;

	pr_debug("Cleanup trackers\n");
	do {
		spin_lock(&tracker_list_lock);
		tracker = list_first_entry_or_null(&tracker_list,
						  struct tracker, link);
		if (tracker) {
			tracker->is_active = false;
			list_del(&tracker->link);
		}
		spin_unlock(&tracker_list_lock);

		tracker_put(tracker);
	} while (tracker);

	blkfilter_unregister("blksnap");
}
