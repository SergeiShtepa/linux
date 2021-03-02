// SPDX-License-Identifier: GPL-2.0
#include <linux/bio.h>
#include <linux/rwsem.h>
#include <linux/refcount.h>
#include <linux/device-mapper.h>
#include <linux/interval_tree_generic.h>

#include "dm-core.h"
#include "dm-interposer.h"

#define DM_MSG_PREFIX "interposer"

struct dm_interposer {
	struct bdev_interposer blk_ip;

	struct kref kref;
	struct rw_semaphore ip_devs_lock;
	struct rb_root_cached ip_devs_root; /* dm_interposed_dev tree, since there can be multiple
					     * interceptors for different ranges for a single
					     * block device. */
};

/*
 * Interval tree for device mapper
 */
#define START(node) ((node)->start)
#define LAST(node) ((node)->last)
INTERVAL_TREE_DEFINE(struct dm_rb_range, node, sector_t, _subtree_last,
		     START, LAST,, dm_rb);

static DEFINE_MUTEX(dm_interposer_attach_lock);

static void dm_submit_bio_interposer_fn(struct bio *bio)
{
	struct dm_interposer *ip;
	unsigned int noio_flag = 0;
	sector_t start;
	sector_t last;
	struct dm_rb_range *node;

	ip = container_of(bio->bi_bdev->bd_interposer, struct dm_interposer, blk_ip);
	start = bio->bi_iter.bi_sector;
	last = start + dm_sector_div_up(bio->bi_iter.bi_size, SECTOR_SIZE);

	noio_flag = memalloc_noio_save();
	down_read(&ip->ip_devs_lock);
	node = dm_rb_iter_first(&ip->ip_devs_root, start, last);
	while (node) {
		struct dm_interposed_dev *ip_dev =
			container_of(node, struct dm_interposed_dev, node);

		atomic64_inc(&ip_dev->ip_cnt);
		ip_dev->dm_interpose_bio(ip_dev, bio);

		node = dm_rb_iter_next(node, start, last);
	}
	up_read(&ip->ip_devs_lock);
	memalloc_noio_restore(noio_flag);
}

void dm_interposer_free(struct kref *kref)
{
	struct dm_interposer *ip = container_of(kref, struct dm_interposer, kref);

	bdev_interposer_detach(&ip->blk_ip, dm_submit_bio_interposer_fn);

	kfree(ip);
}

struct dm_interposer *dm_interposer_new(struct block_device *bdev)
{
	int ret = 0;
	struct dm_interposer *ip;

	ip = kzalloc(sizeof(struct dm_interposer), GFP_NOIO);
	if (!ip)
		return ERR_PTR(-ENOMEM);

	kref_init(&ip->kref);
	init_rwsem(&ip->ip_devs_lock);
	ip->ip_devs_root = RB_ROOT_CACHED;

	ret = bdev_interposer_attach(bdev, &ip->blk_ip, dm_submit_bio_interposer_fn);
	if (ret) {
		DMERR("Failed to attack bdev_interposer.");
		kref_put(&ip->kref, dm_interposer_free);
		return ERR_PTR(ret);
	}

	return ip;
}

static struct dm_interposer *dm_interposer_get(struct block_device *bdev)
{
	struct dm_interposer *ip;

	if (!bdev_has_interposer(bdev))
		return NULL;

	if (bdev->bd_interposer->ip_submit_bio != dm_submit_bio_interposer_fn) {
		DMERR("Block devices interposer slot already occupied.");
		return ERR_PTR(-EBUSY);
	}

	ip = container_of(bdev->bd_interposer, struct dm_interposer, blk_ip);

	kref_get(&ip->kref);
	return ip;
}

static inline void dm_disk_freeze(struct gendisk *disk)
{
	blk_mq_freeze_queue(disk->queue);
	blk_mq_quiesce_queue(disk->queue);
}

static inline void dm_disk_unfreeze(struct gendisk *disk)
{
	blk_mq_unquiesce_queue(disk->queue);
	blk_mq_unfreeze_queue(disk->queue);
}

/**
 * dm_interposer_dev_init - initialize interposed device
 * @ip_dev: interposed device
 * @bdev: block device for interposing
 * @ofs: offset from the beginning of the disk
 * @len: the length of the part of the disk to which requests will be interposed
 * @private: user purpose parameter
 * @interpose_fn: interposing callback
 *
 * Initialize structure dm_interposed_dev.
 * For interposing part of block device set ofs and len.
 * For interposing whole device set ofs=0 and len=0.
 */
void dm_interposer_dev_init(struct dm_interposed_dev *ip_dev,
			    sector_t ofs, sector_t len,
			    void *private, dm_interpose_bio_t interpose_fn)
{
	ip_dev->node.start = ofs;
	ip_dev->node.last = ofs + len - 1;
	ip_dev->dm_interpose_bio = interpose_fn;
	ip_dev->private = private;

	atomic64_set(&ip_dev->ip_cnt, 0);
}

/**
 * dm_interposer_dev_attach - attach interposed device to his disk
 * @bdev: block device
 * @ip_dev: interposed device
 *
 * Return error code.
 */
int dm_interposer_dev_attach(struct block_device *bdev, struct dm_interposed_dev *ip_dev)
{
	int ret = 0;
	struct dm_interposer *ip = NULL;
	unsigned int noio_flag = 0;

	if (!ip_dev)
		return -EINVAL;

	dm_disk_freeze(bdev->bd_disk);
	mutex_lock(&dm_interposer_attach_lock);
	noio_flag = memalloc_noio_save();

	ip = dm_interposer_get(bdev);
	if (ip == NULL)
		ip = dm_interposer_new(bdev);
	if (IS_ERR(ip)) {
		ret = PTR_ERR(ip);
		goto out;
	}

	/* Attach dm_interposed_dev to dm_interposer */
	down_write(&ip->ip_devs_lock);
	do {
		struct dm_rb_range *node;

		/* checking that ip_dev already exists for this region */
		node = dm_rb_iter_first(&ip->ip_devs_root, ip_dev->node.start, ip_dev->node.last);
		if (node) {
			DMERR("Disk part form [%llu] to [%llu] already have interposer.",
			      node->start, node->last);

			ret = -EBUSY;
			break;
		}

		/* insert ip_dev to ip tree */
		dm_rb_insert(&ip_dev->node, &ip->ip_devs_root);
		/* increment ip reference counter */
		kref_get(&ip->kref);
	} while (false);
	up_write(&ip->ip_devs_lock);

	kref_put(&ip->kref, dm_interposer_free);

out:
	memalloc_noio_restore(noio_flag);
	mutex_unlock(&dm_interposer_attach_lock);
	dm_disk_unfreeze(bdev->bd_disk);

	return ret;
}

/**
 * dm_interposer_detach_dev - detach interposed device from his disk
 * @bdev: block device
 * @ip_dev: interposed device
 *
 * Return error code.
 */
int dm_interposer_detach_dev(struct block_device *bdev, struct dm_interposed_dev *ip_dev)
{
	int ret = 0;
	struct dm_interposer *ip = NULL;
	unsigned int noio_flag = 0;

	if (!ip_dev)
		return -EINVAL;

	dm_disk_freeze(bdev->bd_disk);
	mutex_lock(&dm_interposer_attach_lock);
	noio_flag = memalloc_noio_save();

	ip = dm_interposer_get(bdev);
	if (IS_ERR(ip)) {
		ret = PTR_ERR(ip);
		DMERR("Interposer not found.");
		goto out;
	}
	if (unlikely(ip == NULL)) {
		ret = -ENXIO;
		DMERR("Interposer not found.");
		goto out;
	}

	down_write(&ip->ip_devs_lock);
	{
		dm_rb_remove(&ip_dev->node, &ip->ip_devs_root);
		/* the reference counter here cannot be zero */
		kref_put(&ip->kref, dm_interposer_free);
	}
	up_write(&ip->ip_devs_lock);

	/* detach and free interposer if it's not needed */
	kref_put(&ip->kref, dm_interposer_free);
out:
	memalloc_noio_restore(noio_flag);
	mutex_unlock(&dm_interposer_attach_lock);
	dm_disk_unfreeze(bdev->bd_disk);

	return ret;
}
