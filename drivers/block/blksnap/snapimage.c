// SPDX-License-Identifier: GPL-2.0
/*
 * Present the snapshot image as a block device.
 */
#define pr_fmt(fmt) KBUILD_MODNAME "-snapimage: " fmt
#include <linux/slab.h>
#include <linux/cdrom.h>
#include <linux/blk-mq.h>
#include <linux/build_bug.h>
#include <uapi/linux/blksnap.h>
#include "snapimage.h"
#include "tracker.h"
#include "diff_area.h"
#include "chunk.h"
#include "cbt_map.h"

static void snapimage_submit_bio(struct bio *bio)
{
	struct tracker *tracker = bio->bi_bdev->bd_disk->private_data;
	struct diff_area *diff_area = tracker->diff_area;
	struct bio_list *old_bio_list;
	struct bio_list bio_list[2] = { };
	struct bio *new_bio;
	struct image_rw_ctx *ctx;

	WARN_ONCE(bio->bi_opf & REQ_NOWAIT, "Processing bio with the flag REQ_NOWAIT is not supported\n");
	if (unlikely(bio->bi_opf & REQ_NOWAIT)) {
		bio_io_error(bio);
		return;
	}

	if (diff_area_is_corrupted(diff_area)) {
		bio_io_error(bio);
		return;
	}

	ctx = kzalloc(sizeof(struct image_rw_ctx), GFP_NOIO);
	if (!ctx) {
		bio_io_error(bio);
		return;
	}

	kref_init(&ctx->kref);
	ctx->diff_area = tracker->diff_area;
	ctx->bio = bio;
	atomic_set(&ctx->error_cnt, 0);

	diff_area_throttling_io(ctx->diff_area);

	bio_list_init(&bio_list[0]);
	old_bio_list = current->bio_list;
	current->bio_list = bio_list;

	diff_area_preload(ctx);

	current->bio_list = NULL;
	while ((new_bio = bio_list_pop(&bio_list[0])))
		submit_bio_noacct(new_bio);
	current->bio_list = old_bio_list;

	kref_put(&ctx->kref, diff_area_rw_chunk);
}

const struct block_device_operations bd_ops = {
	.owner = THIS_MODULE,
	.submit_bio = snapimage_submit_bio,
};

void snapimage_free(struct tracker *tracker)
{
	struct gendisk *disk = tracker->snap_disk;

	if (!disk)
		return;

	pr_debug("Snapshot image disk %s delete\n", disk->disk_name);
	del_gendisk(disk);
	put_disk(disk);

	tracker->snap_disk = NULL;
}

int snapimage_create(struct tracker *tracker)
{
	int ret = 0;
	dev_t dev_id = tracker->dev_id;
	struct gendisk *disk;

	pr_info("Create snapshot image device for original device [%u:%u]\n",
		MAJOR(dev_id), MINOR(dev_id));

	disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk) {
		pr_err("Failed to allocate disk\n");
		return -ENOMEM;
	}

	disk->flags = GENHD_FL_NO_PART;
	disk->fops = &bd_ops;
	disk->private_data = tracker;
	set_capacity(disk, tracker->cbt_map->device_capacity);
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
	tracker->snap_disk = disk;

	pr_debug("Image block device [%d:%d] has been created\n",
		disk->major, disk->first_minor);

	return 0;

fail_cleanup_disk:
	put_disk(disk);
	return ret;
}
