// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-snapimage: " fmt

#include <linux/slab.h>
#include <linux/cdrom.h>
#include <linux/blk-mq.h>
#include <uapi/linux/blksnap.h>
#include "snapimage.h"
#include "tracker.h"
#include "diff_area.h"
#include "chunk.h"
#include "cbt_map.h"

static inline void snapimage_process_bio(struct diff_area *diff_area,
					 struct bio *bio)
{

	struct diff_area_image_ctx io_ctx;
	struct bio_vec bvec;
	struct bvec_iter iter;
	sector_t pos = bio->bi_iter.bi_sector;

	diff_area_throttling_io(diff_area);
	diff_area_image_ctx_init(&io_ctx, diff_area, op_is_write(bio_op(bio)));
	bio_for_each_segment(bvec, bio, iter) {
		blk_status_t st;

		st = diff_area_image_io(&io_ctx, &bvec, &pos);
		if (unlikely(st != BLK_STS_OK))
			break;
	}
	diff_area_image_ctx_done(&io_ctx);
	bio_endio(bio);
}

static inline struct bio *get_bio_from_queue(struct snapimage *snapimage)
{
	struct bio *bio;

	spin_lock(&snapimage->queue_lock);
	bio = bio_list_pop(&snapimage->queue);
	spin_unlock(&snapimage->queue_lock);

	return bio;
}

static int snapimage_kthread_worker_fn(void *param)
{
	struct tracker *tracker = param;
	struct bio *bio;

	for (;;) {
		while ((bio = get_bio_from_queue(tracker->snapimage)))
			snapimage_process_bio(tracker->diff_area, bio);
		if (kthread_should_stop())
			break;
		schedule();
	}

	return 0;
}

static void snapimage_submit_bio(struct bio *bio)
{
	struct tracker *tracker = bio->bi_bdev->bd_disk->private_data;

	if (!diff_area_is_corrupted(tracker->diff_area)) {
		struct snapimage *snapimage = tracker->snapimage;

		spin_lock(&snapimage->queue_lock);
		bio_list_add(&snapimage->queue, bio);
		spin_unlock(&snapimage->queue_lock);

		wake_up_process(snapimage->worker);
	} else
		bio_io_error(bio);
}

static void snapimage_free_disk(struct gendisk *disk)
{
	struct tracker *tracker = disk->private_data;

	kfree(tracker->snapimage);
	tracker->snapimage = NULL;
}

const struct block_device_operations bd_ops = {
	.owner = THIS_MODULE,
	.submit_bio = snapimage_submit_bio,
	.free_disk = snapimage_free_disk,
};

void snapimage_free(struct snapimage *snapimage)
{
	pr_debug("Snapshot image disk %s delete\n", snapimage->disk->disk_name);
	del_gendisk(snapimage->disk);
	kthread_stop(snapimage->worker);
	put_disk(snapimage->disk);
}

int snapimage_create(struct tracker *tracker)
{
	int ret = 0;
	dev_t dev_id = tracker->dev_id;
	struct snapimage *snapimage = NULL;
	struct gendisk *disk;
	struct task_struct *task;

	snapimage = kzalloc(sizeof(struct snapimage), GFP_KERNEL);
	if (!snapimage)
		return -ENOMEM;

	snapimage->capacity = tracker->cbt_map->device_capacity;
	pr_info("Create snapshot image device for original device [%u:%u]\n",
		MAJOR(dev_id), MINOR(dev_id));

	spin_lock_init(&snapimage->queue_lock);
	bio_list_init(&snapimage->queue);

	task = kthread_create(snapimage_kthread_worker_fn, tracker,
			      "blksnap_%d_%d",
			      MAJOR(dev_id), MINOR(dev_id));
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		pr_err("Failed to start worker thread. errno=%d\n", abs(ret));
		goto fail_create_task;
	}

	snapimage->worker = task;
	set_user_nice(task, MAX_NICE);
	task->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;

	disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk) {
		pr_err("Failed to allocate disk\n");
		ret = -ENOMEM;
		goto fail_disk_alloc;
	}
	snapimage->disk = disk;

	blk_queue_max_hw_sectors(disk->queue, BLK_DEF_MAX_SECTORS);
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, disk->queue);

	disk->flags = 0;
	disk->flags |= GENHD_FL_NO_PART;
	disk->fops = &bd_ops;
	disk->private_data = tracker;
	tracker->snapimage = snapimage;

	set_capacity(disk, snapimage->capacity);
	pr_debug("Snapshot image device capacity %lld bytes\n",
		 (u64)(snapimage->capacity << SECTOR_SHIFT));


	ret = snprintf(disk->disk_name, DISK_NAME_LEN, "%s_%d:%d",
		       BLKSNAP_IMAGE_NAME, MAJOR(dev_id), MINOR(dev_id));
	if (ret < 0) {
		pr_err("Unable to set disk name for snapshot image device: invalid device id [%d:%d]\n",
		       MAJOR(dev_id), MINOR(dev_id));
		ret = -EINVAL;
		goto fail_cleanup_disk;
	}
	pr_debug("Snapshot image disk name [%s]\n", disk->disk_name);

	ret = add_disk(disk);
	if (ret) {
		pr_err("Failed to add disk [%s] for snapshot image device\n",
		       disk->disk_name);
		goto fail_cleanup_disk;
	}

	pr_debug("Image block device [%d:%d] has been created\n",
		disk->major, disk->first_minor);

	return 0;

fail_cleanup_disk:
	kthread_stop(snapimage->worker);
	put_disk(disk);
	return ret;

fail_disk_alloc:
	kthread_stop(snapimage->worker);
fail_create_task:
	kfree(snapimage);
	return ret;
}
