// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME "-snapimage: " fmt

#include <linux/slab.h>
#include <linux/cdrom.h>
#include <linux/blk-mq.h>
#include <uapi/linux/blksnap.h>
#include "snapimage.h"
#include "diff_area.h"
#include "chunk.h"
#include "cbt_map.h"

#define NR_SNAPIMAGE_DEVT	(1 << MINORBITS)

static unsigned int _major;
static DEFINE_IDA(snapimage_devt_ida);

static int snapimage_kthread_worker_fn(void *param);

static inline void snapimage_stop_worker(struct snapimage *snapimage)
{
	kthread_stop(snapimage->worker);
	put_task_struct(snapimage->worker);
}

static inline int snapimage_start_worker(struct snapimage *snapimage)
{
	struct task_struct *task;

	spin_lock_init(&snapimage->queue_lock);
	bio_list_init(&snapimage->queue);

	task = kthread_create(snapimage_kthread_worker_fn,
			      snapimage,
			      BLK_SNAP_IMAGE_NAME "%d",
			      MINOR(snapimage->image_dev_id));
	if (IS_ERR(task))
		return -ENOMEM;

	snapimage->worker = get_task_struct(task);
	set_user_nice(task, MAX_NICE);
	task->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
	wake_up_process(task);

	return 0;
}

static void snapimage_process_bio(struct snapimage *snapimage, struct bio *bio)
{

	struct diff_area_image_ctx io_ctx;
	struct bio_vec bvec;
	struct bvec_iter iter;
	sector_t pos = bio->bi_iter.bi_sector;

	diff_area_throttling_io(snapimage->diff_area);
	diff_area_image_ctx_init(&io_ctx, snapimage->diff_area,
				 op_is_write(bio_op(bio)));
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
	struct snapimage *snapimage = param;
	struct bio *bio;
	int ret = 0;

	while (!kthread_should_stop()) {
		bio = get_bio_from_queue(snapimage);
		if (!bio) {
			schedule_timeout_interruptible(HZ / 100);
			continue;
		}

		snapimage_process_bio(snapimage, bio);
	}

	while ((bio = get_bio_from_queue(snapimage)))
		snapimage_process_bio(snapimage, bio);

	return ret;
}

static void snapimage_submit_bio(struct bio *bio)
{
	struct snapimage *snapimage = bio->bi_bdev->bd_disk->private_data;
	gfp_t gfp = GFP_NOIO;

	if (bio->bi_opf & REQ_NOWAIT)
		gfp |= GFP_NOWAIT;
	if (snapimage->is_ready) {
		spin_lock(&snapimage->queue_lock);
		bio_list_add(&snapimage->queue, bio);
		spin_unlock(&snapimage->queue_lock);

		wake_up_process(snapimage->worker);
	} else
		bio_io_error(bio);
}

const struct block_device_operations bd_ops = {
	.owner = THIS_MODULE,
	.submit_bio = snapimage_submit_bio
};

void snapimage_free(struct snapimage *snapimage)
{
	pr_info("Snapshot image disk [%u:%u] delete\n",
		MAJOR(snapimage->image_dev_id), MINOR(snapimage->image_dev_id));

	blk_mq_freeze_queue(snapimage->disk->queue);
	snapimage->is_ready = false;
	blk_mq_unfreeze_queue(snapimage->disk->queue);

	snapimage_stop_worker(snapimage);

	del_gendisk(snapimage->disk);
	put_disk(snapimage->disk);

	diff_area_put(snapimage->diff_area);
	cbt_map_put(snapimage->cbt_map);

	ida_free(&snapimage_devt_ida, MINOR(snapimage->image_dev_id));
	kfree(snapimage);
}

struct snapimage *snapimage_create(struct diff_area *diff_area,
				   struct cbt_map *cbt_map)
{
	int ret = 0;
	int minor;
	struct snapimage *snapimage = NULL;
	struct gendisk *disk;

	snapimage = kzalloc(sizeof(struct snapimage), GFP_KERNEL);
	if (snapimage == NULL)
		return ERR_PTR(-ENOMEM);

	minor = ida_alloc_range(&snapimage_devt_ida, 0, NR_SNAPIMAGE_DEVT - 1,
				GFP_KERNEL);
	if (minor < 0) {
		ret = minor;
		pr_err("Failed to allocate minor for snapshot image device. errno=%d\n",
		       abs(ret));
		goto fail_free_image;
	}

	snapimage->is_ready = true;
	snapimage->capacity = cbt_map->device_capacity;
	snapimage->image_dev_id = MKDEV(_major, minor);
	pr_info("Create snapshot image device [%u:%u] for original device [%u:%u]\n",
		MAJOR(snapimage->image_dev_id),
		MINOR(snapimage->image_dev_id),
		MAJOR(diff_area->orig_bdev->bd_dev),
		MINOR(diff_area->orig_bdev->bd_dev));

	ret = snapimage_start_worker(snapimage);
	if (ret) {
		pr_err("Failed to start worker thread. errno=%d\n", abs(ret));
		goto fail_free_minor;
	}

	disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk) {
		pr_err("Failed to allocate disk\n");
		ret = -ENOMEM;
		goto fail_free_worker;
	}
	snapimage->disk = disk;

	blk_queue_max_hw_sectors(disk->queue, BLK_DEF_MAX_SECTORS);
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, disk->queue);

	if (snprintf(disk->disk_name, DISK_NAME_LEN, "%s%d",
		     BLK_SNAP_IMAGE_NAME, minor) < 0) {
		pr_err("Unable to set disk name for snapshot image device: invalid minor %u\n",
		       minor);
		ret = -EINVAL;
		goto fail_cleanup_disk;
	}
	pr_debug("Snapshot image disk name [%s]\n", disk->disk_name);

	disk->flags = 0;
#ifdef GENHD_FL_NO_PART_SCAN
	disk->flags |= GENHD_FL_NO_PART_SCAN;
#else
	disk->flags |= GENHD_FL_NO_PART;
#endif
	disk->major = _major;
	disk->first_minor = minor;
	disk->minors = 1; /* One disk has only one partition */

	disk->fops = &bd_ops;
	disk->private_data = snapimage;

	set_capacity(disk, snapimage->capacity);
	pr_debug("Snapshot image device capacity %lld bytes\n",
		 (u64)(snapimage->capacity << SECTOR_SHIFT));

	diff_area_get(diff_area);
	snapimage->diff_area = diff_area;
	cbt_map_get(cbt_map);
	snapimage->cbt_map = cbt_map;

	pr_debug("Add device [%d:%d]",
		MAJOR(snapimage->image_dev_id), MINOR(snapimage->image_dev_id));
	ret = add_disk(disk);
	if (ret) {
		pr_err("Failed to add disk [%s] for snapshot image device\n",
		       disk->disk_name);
		goto fail_cleanup_disk;
	}

	wake_up_process(snapimage->worker);

	return snapimage;

fail_cleanup_disk:
	put_disk(disk);
fail_free_worker:
	snapimage_stop_worker(snapimage);
fail_free_minor:
	ida_free(&snapimage_devt_ida, minor);
fail_free_image:
	kfree(snapimage);

	return ERR_PTR(ret);
}

int snapimage_init(void)
{
	int ret = 0;

	ret = register_blkdev(0, BLK_SNAP_IMAGE_NAME);
	if (ret < 0) {
		pr_err("Failed to register snapshot image block device\n");
		return ret;
	}

	_major = ret;
	pr_info("Snapshot image block device major %d was registered\n",
		_major);

	return 0;
}

void snapimage_done(void)
{
	unregister_blkdev(_major, BLK_SNAP_IMAGE_NAME);
	pr_info("Snapshot image block device [%d] was unregistered\n", _major);
}

int snapimage_major(void)
{
	return _major;
}
