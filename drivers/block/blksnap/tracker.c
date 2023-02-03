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

void tracker_free(struct kref *kref)
{
	struct tracker *tracker = container_of(kref, struct tracker, kref);

	might_sleep();

	pr_debug("Free tracker for device [%u:%u]\n", MAJOR(tracker->dev_id),
		 MINOR(tracker->dev_id));

	if (tracker->diff_area)
		diff_area_free(tracker->diff_area);
	if (tracker->cbt_map)
		cbt_map_destroy(tracker->cbt_map);

	kfree(tracker);
}

static bool tracker_submit_bio(struct bio *bio)
{
	struct blkfilter *flt = bio->bi_bdev->bd_filter;
	struct tracker *tracker = container_of(flt, struct tracker, filter);
	struct bio_list bio_list_on_stack[2] = { };
	struct bio *new_bio;
	int err;
	sector_t sector;
	sector_t count = bio_sectors(bio);
	unsigned int current_flag;

	if (!op_is_write(bio_op(bio)) || !count)
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

	/*
	 * Writing to the diff area may split the bio or block, so don't try
	 * to handle nowait requests.  Just let the caller retry from a context
	 * where it can block.
	 */
	if (bio->bi_opf & REQ_NOWAIT) {
		bio->bi_status = BLK_STS_AGAIN;
		bio_endio(bio);
		return true;
	}

	current_flag = memalloc_noio_save();
	bio_list_init(&bio_list_on_stack[0]);
	current->bio_list = bio_list_on_stack;

	err = diff_area_copy(tracker->diff_area, sector, count);

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
	err = diff_area_wait(tracker->diff_area, sector, count);
	if (unlikely(err)) {
		if (err == -EAGAIN) {
			bio_wouldblock_error(bio);
			return true;
		}
		pr_err("Failed to wait for available data in diff storage with error %d\n", abs(err));
	}
	return false;
}

static struct blkfilter_account tracker_acc;

static struct blkfilter *tracker_attach(struct block_device *bdev)
{
	struct tracker *tracker = NULL;
	struct cbt_map *cbt_map;

	pr_debug("Creating tracker for device [%u:%u]\n",
		 MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));

	if (tracker_acc.owner)
		pr_debug("module_refcount=%d", module_refcount(tracker_acc.owner));

	cbt_map = cbt_map_create(bdev);
	if (!cbt_map) {
		pr_err("Failed to create CBT map for device [%u:%u]\n",
		       MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
		return ERR_PTR(-ENOMEM);
	}

	tracker = kzalloc(sizeof(struct tracker), GFP_KERNEL);
	if (tracker == NULL) {
		cbt_map_destroy(cbt_map);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&tracker->link);
	kref_init(&tracker->kref);
	tracker->dev_id = bdev->bd_dev;
	atomic_set(&tracker->snapshot_is_taken, false);
	tracker->cbt_map = cbt_map;
	tracker->diff_area = NULL;
	tracker->is_frozen = false;

	pr_debug("New tracker for device [%u:%u] was created\n",
		 MAJOR(tracker->dev_id), MINOR(tracker->dev_id));

	return &tracker->filter;
}

static void tracker_detach(struct blkfilter *flt)
{
	struct tracker *tracker = container_of(flt, struct tracker, filter);

	pr_debug("Detach tracker from device [%u:%u]\n",
		 MAJOR(tracker->dev_id), MINOR(tracker->dev_id));

	if (flt->acc->owner)
		pr_debug("module_refcount=%d", module_refcount(flt->acc->owner));

	tracker_put(tracker);
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

	if (copy_to_user(arg.buffer, cbt_map->read_map + arg.offset,
			 min_t(unsigned int, cbt_map->blk_count - arg.offset, arg.length)))
		return -EINVAL;

	*plen = 0;
	return 0;
}
static int ctl_cbtdirty(struct tracker *tracker, __u8 __user *buf, __u32 *plen)
{
	struct cbt_map *cbt_map = tracker->cbt_map;
	struct blksnap_cbtdirty arg;
	unsigned int inx;

	if (!cbt_map)
		return -ESRCH;

	if (*plen < sizeof(arg))
		return -EINVAL;

	if (copy_from_user(&arg, buf, sizeof(arg)))
		return -ENODATA;

	for (inx=0; inx < arg.count; inx++) {
		struct blksnap_sectors range;
		int ret;

		if (copy_from_user(&range, arg.dirty_sectors, sizeof(range)))
			return -ENODATA;

		ret = cbt_map_set_both(cbt_map, range.offset, range.count);
		if (ret)
			return ret;
	}
	*plen = 0;
	return 0;
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

	if (*plen < sizeof(arg))
		return -EINVAL;

	if (copy_from_user(&arg, buf, sizeof(arg)))
		return -ENODATA;


	if (tracker->diff_area && diff_area_is_corrupted(tracker->diff_area))
		arg.error_code = tracker->diff_area->error_code;
	else
		arg.error_code = 0;

	if (tracker->snap_disk)
		strncpy(arg.image, tracker->snap_disk->disk_name, IMAGE_DISK_NAME_LEN);

	if (copy_to_user(buf, &arg, sizeof(arg)))
		return -ENODATA;

	*plen = sizeof(arg);
	return 0;
}

static int (*const ctl_table[])(struct tracker *tracker,
				__u8 __user *buf, __u32 *plen) = {
	ctl_cbtinfo,
	ctl_cbtmap,
	ctl_cbtdirty,
	ctl_snapshotadd,
	ctl_snapshotinfo,
};

static int tracker_ctl(struct blkfilter *flt, const unsigned int cmd,
		       __u8 __user *buf, __u32 *plen)
{
	struct tracker *tracker = container_of(flt, struct tracker, filter);

	if (cmd > (sizeof(ctl_table) / sizeof(ctl_table[0])))
		return -ENOTTY;

	return ctl_table[cmd](tracker, buf, plen);
}

static const struct blkfilter_operations tracker_ops = {
	.attach		= tracker_attach,
	.detach		= tracker_detach,
	.ctl		= tracker_ctl,
	.submit_bio	= tracker_submit_bio,
};

static struct blkfilter_account tracker_acc = {
	.name		= "blksnap",
	.owner		= THIS_MODULE,
	.ops		= &tracker_ops,
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
	if (tracker->diff_area) {
		blk_mq_freeze_queue(tracker->diff_area->orig_bdev->bd_queue);

		pr_debug("Tracker for device [%u:%u] release snapshot\n",
			 MAJOR(tracker->dev_id), MINOR(tracker->dev_id));

		atomic_set(&tracker->snapshot_is_taken, false);

		blk_mq_unfreeze_queue(tracker->diff_area->orig_bdev->bd_queue);
	}
	snapimage_free(tracker);

	if (tracker->diff_area) {
		diff_area_free(tracker->diff_area);
		tracker->diff_area = NULL;
	}
}

int __init tracker_init(void)
{
	pr_debug("Register filter '%s'", tracker_acc.name);

	return blkfilter_register(&tracker_acc);
}

void tracker_done(void)
{
	pr_debug("Unregister filter '%s'", tracker_acc.name);

	if (tracker_acc.owner)
		pr_debug("module_refcount=%d", module_refcount(tracker_acc.owner));

	blkfilter_unregister(&tracker_acc);
}
