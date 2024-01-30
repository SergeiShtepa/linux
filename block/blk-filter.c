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

static inline struct blkfilter_operations *blkfilter_find_get(const char *name)
{
	struct blkfilter_operations *ops;

	spin_lock(&blkfilters_lock);
	ops = __blkfilter_find(name);
	if (ops && !try_module_get(ops->owner))
		ops = NULL;
	spin_unlock(&blkfilters_lock);

	return ops;
}

static inline void blkfilter_put(const struct blkfilter_operations *ops)
{
	module_put(ops->owner);
}

int blkfilter_ioctl_attach(struct block_device *bdev,
		    struct blkfilter_name __user *argp)
{
	struct blkfilter_name name;
	struct blkfilter_operations *ops;
	struct blkfilter *flt;
	int ret;

	if (copy_from_user(&name, argp, sizeof(name)))
		return -EFAULT;

	ops = blkfilter_find_get(name.name);
	if (!ops)
		return -ENOENT;

	mutex_lock(&bdev->bd_disk->open_mutex);
	if (!disk_live(bdev->bd_disk)) {
		ret = -ENODEV;
		goto out_mutex_unlock;
	}
	ret = bdev_freeze(bdev);
	if (ret)
		goto out_mutex_unlock;
	blk_mq_freeze_queue(bdev->bd_queue);

	if (bdev->bd_filter) {
		if (bdev->bd_filter->ops == ops)
			ret = -EALREADY;
		else
			ret = -EBUSY;
		goto out_unfreeze;
	}

	flt = ops->attach(bdev);
	if (IS_ERR(flt)) {
		ret = PTR_ERR(flt);
		goto out_unfreeze;
	}

	flt->ops = ops;
	bdev->bd_filter = flt;

out_unfreeze:
	blk_mq_unfreeze_queue(bdev->bd_queue);
	bdev_thaw(bdev);
out_mutex_unlock:
	mutex_unlock(&bdev->bd_disk->open_mutex);
	if (ret)
		blkfilter_put(ops);
	return ret;
}

static void __blkfilter_detach(struct block_device *bdev)
{
	struct blkfilter *flt = bdev->bd_filter;
	const struct blkfilter_operations *ops = flt->ops;

	bdev->bd_filter = NULL;
	ops->detach(flt);
	blkfilter_put(ops);
}

void blkfilter_detach(struct block_device *bdev)
{
	blk_mq_freeze_queue(bdev->bd_queue);
	if (bdev->bd_filter)
		__blkfilter_detach(bdev);
	blk_mq_unfreeze_queue(bdev->bd_queue);
}

int blkfilter_ioctl_detach(struct block_device *bdev,
		    struct blkfilter_name __user *argp)
{
	struct blkfilter_name name;
	int ret = 0;

	if (copy_from_user(&name, argp, sizeof(name)))
		return -EFAULT;

	mutex_lock(&bdev->bd_disk->open_mutex);
	if (!disk_live(bdev->bd_disk)) {
		ret = -ENODEV;
		goto out_mutex_unlock;
	}
	blk_mq_freeze_queue(bdev->bd_queue);
	if (!bdev->bd_filter) {
		ret = -ENOENT;
		goto out_unfreeze;
	}
	if (strncmp(bdev->bd_filter->ops->name, name.name,
			BLKFILTER_NAME_LENGTH)) {
		ret = -EINVAL;
		goto out_unfreeze;
	}

	__blkfilter_detach(bdev);
out_unfreeze:
	blk_mq_unfreeze_queue(bdev->bd_queue);
out_mutex_unlock:
	mutex_unlock(&bdev->bd_disk->open_mutex);
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

	mutex_lock(&bdev->bd_disk->open_mutex);
	if (!disk_live(bdev->bd_disk)) {
		ret = -ENODEV;
		goto out_mutex_unlock;
	}
	ret = blk_queue_enter(bdev_get_queue(bdev), 0);
	if (ret)
		goto out_mutex_unlock;

	flt = bdev->bd_filter;
	if (!flt || strncmp(flt->ops->name, ctl.name, BLKFILTER_NAME_LENGTH)) {
		ret = -ENOENT;
		goto out_queue_exit;
	}

	if (!flt->ops->ctl) {
		ret = -ENOTTY;
		goto out_queue_exit;
	}

	ret = flt->ops->ctl(flt, ctl.cmd, u64_to_user_ptr(ctl.opt),
			    &ctl.optlen);
out_queue_exit:
	blk_queue_exit(bdev_get_queue(bdev));
out_mutex_unlock:
	mutex_unlock(&bdev->bd_disk->open_mutex);
	return ret;
}

ssize_t blkfilter_show(struct block_device *bdev, char *buf)
{
	ssize_t ret = 0;

	blk_mq_freeze_queue(bdev->bd_queue);
	if (bdev->bd_filter)
		ret = sprintf(buf, "%s\n", bdev->bd_filter->ops->name);
	else
		ret = sprintf(buf, "\n");
	blk_mq_unfreeze_queue(bdev->bd_queue);

	return ret;
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
