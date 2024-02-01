// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Veeam Software Group GmbH */
#include <linux/blk-filter.h>
#include <linux/blk-mq.h>
#include <linux/module.h>

#include "blk.h"

static LIST_HEAD(blkfilters);
static DEFINE_SPINLOCK(blkfilters_lock);

static inline struct blkfilter_operations *__blkfilter_find(const char *name)
{
	struct blkfilter_operations *ops;

	list_for_each_entry(ops, &blkfilters, link)
		if (strncmp(ops->name, name, BLKFILTER_NAME_LENGTH) == 0)
			return ops;

	return NULL;
}

static inline int is_disk_alive(struct gendisk *disk)
{
	int ret = 0;

	mutex_lock(&disk->open_mutex);
	if (!disk_live(disk))
		ret = -ENODEV;
	mutex_unlock(&disk->open_mutex);
	return ret;
}

int blkfilter_ioctl_attach(struct block_device *bdev,
		    struct blkfilter_name __user *argp)
{
	struct blkfilter_name name;
	struct blkfilter_operations *ops;
	struct blkfilter *flt;
	int ret = 0;

	if (copy_from_user(&name, argp, sizeof(name)))
		return -EFAULT;

	spin_lock(&blkfilters_lock);
	ops = __blkfilter_find(name.name);
	if (ops && !try_module_get(ops->owner))
		ops = NULL;
	spin_unlock(&blkfilters_lock);
	if (!ops)
		return -ENOENT;

	ret = is_disk_alive(bdev->bd_disk);
	if (ret)
		goto out_module_put;

	ret = bdev_freeze(bdev);
	if (ret)
		goto out_module_put;
	blk_mq_freeze_queue(bdev->bd_queue);

	spin_lock(&blkfilters_lock);
	if (bdev->bd_filter) {
		if (bdev->bd_filter->ops == ops)
			ret = -EALREADY;
		else
			ret = -EBUSY;
	}
	spin_unlock(&blkfilters_lock);
	if (ret)
		goto out_unfreeze;

	flt = ops->attach(bdev);
	if (IS_ERR(flt)) {
		ret = PTR_ERR(flt);
		goto out_unfreeze;
	}
	flt->ops = ops;

	spin_lock(&blkfilters_lock);
	if (bdev->bd_filter)
		if (bdev->bd_filter->ops == ops)
			ret = -EALREADY;
		else
			ret = -EBUSY;
	else
		bdev->bd_filter = flt;
	spin_unlock(&blkfilters_lock);

	if (ret)
		ops->detach(flt);

out_unfreeze:
	blk_mq_unfreeze_queue(bdev->bd_queue);
	bdev_thaw(bdev);
	if (ret)
out_module_put:
		module_put(ops->owner);
	return ret;
}

static inline void __blkfilter_detach(struct blkfilter *flt)
{
	if (flt) {
		const struct blkfilter_operations *ops = flt->ops;

		ops->detach(flt);
		module_put(ops->owner);
	}
}

void blkfilter_detach(struct block_device *bdev)
{
	struct blkfilter *flt;

	blk_mq_freeze_queue(bdev->bd_queue);

	spin_lock(&blkfilters_lock);
	if ((flt = bdev->bd_filter))
		bdev->bd_filter = NULL;
	spin_unlock(&blkfilters_lock);

	__blkfilter_detach(flt);

	blk_mq_unfreeze_queue(bdev->bd_queue);
}

int blkfilter_ioctl_detach(struct block_device *bdev,
		    struct blkfilter_name __user *argp)
{
	struct blkfilter_name name;
	struct blkfilter *flt = NULL;
	int ret = 0;

	if (copy_from_user(&name, argp, sizeof(name)))
		return -EFAULT;

	ret = is_disk_alive(bdev->bd_disk);
	if (ret)
		return ret;

	blk_mq_freeze_queue(bdev->bd_queue);

	spin_lock(&blkfilters_lock);
	if (bdev->bd_filter) {
		if (strncmp(bdev->bd_filter->ops->name,
			    name.name, BLKFILTER_NAME_LENGTH))
			ret = -EINVAL;
		else {
			flt = bdev->bd_filter;
			bdev->bd_filter = NULL;
		}
	} else
		ret = -ENOENT;
	spin_unlock(&blkfilters_lock);

	__blkfilter_detach(flt);
	blk_mq_unfreeze_queue(bdev->bd_queue);
	return ret;
}

int blkfilter_ioctl_ctl(struct block_device *bdev,
		    struct blkfilter_ctl __user *argp)
{
	struct blkfilter_ctl ctl;
	struct blkfilter *flt;
	int ret;

	if (copy_from_user(&ctl, argp, sizeof(ctl)))
		return -EFAULT;

	ret = is_disk_alive(bdev->bd_disk);
	if (ret)
		return ret;

	ret = blk_queue_enter(bdev_get_queue(bdev), 0);
	if (ret)
		return ret;

	spin_lock(&blkfilters_lock);
	flt = bdev->bd_filter;
	if (!flt || strncmp(flt->ops->name, ctl.name, BLKFILTER_NAME_LENGTH))
		ret = -ENOENT;
	else if (!flt->ops->ctl)
		ret = -ENOTTY;
	spin_unlock(&blkfilters_lock);

	if (!ret)
		ret = flt->ops->ctl(flt, ctl.cmd, u64_to_user_ptr(ctl.opt),
								&ctl.optlen);
	blk_queue_exit(bdev_get_queue(bdev));
	return ret;
}

ssize_t blkfilter_show(struct block_device *bdev, char *buf)
{
	int ret = 0;
	const char *name = NULL;

	ret = is_disk_alive(bdev->bd_disk);
	if (ret)
		goto out;

	blk_mq_freeze_queue(bdev->bd_queue);
	spin_lock(&blkfilters_lock);
	if (bdev->bd_filter)
		name = bdev->bd_filter->ops->name;
	spin_unlock(&blkfilters_lock);
	blk_mq_unfreeze_queue(bdev->bd_queue);

	if (name)
		return sprintf(buf, "%s\n", name);
out:
	return sprintf(buf, "\n");
}

/**
 * blkfilter_register() - Register block device filter operations.
 * @ops:	The operations to register.
 *
 * Return:
 *	0 if succeeded,
 *	-EBUSY if a block device filter with the same name is already
 *	registered.
 */
int blkfilter_register(struct blkfilter_operations *ops)
{
	struct blkfilter_operations *found;
	int ret = 0;

	spin_lock(&blkfilters_lock);
	found = __blkfilter_find(ops->name);
	if (found)
		ret = -EBUSY;
	else
		list_add_tail(&ops->link, &blkfilters);
	spin_unlock(&blkfilters_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(blkfilter_register);

/**
 * blkfilter_unregister() - Unregister block device filter operations.
 * @ops:	The operations to unregister.
 *
 * Recommended to detach the filter from all block devices before
 * unregistering block device filter operations.
 */
void blkfilter_unregister(struct blkfilter_operations *ops)
{
	spin_lock(&blkfilters_lock);
	list_del(&ops->link);
	spin_unlock(&blkfilters_lock);
}
EXPORT_SYMBOL_GPL(blkfilter_unregister);

/**
 * blkfilter_resubmit_bio() - Resubmit the bio after processing by the filter.
 * @bio:	The I/O unit.
 * @flt:	The block device filter.
 *
 * The filter can skip the processing of the I/O unit. This function allows
 * to return the I/O unit for processing again.
 */
void blkfilter_resubmit_bio(struct bio *bio, struct blkfilter *flt)
{
	struct blkfilter *prev = current->blk_filter;

	current->blk_filter = flt;
	submit_bio_noacct_nocheck_resubmit(bio);
	current->blk_filter = prev;
}
EXPORT_SYMBOL_GPL(blkfilter_resubmit_bio);
