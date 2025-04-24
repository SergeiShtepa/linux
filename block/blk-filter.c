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

static inline bool is_disk_alive(struct gendisk *disk)
{
	bool ret;

	mutex_lock(&disk->open_mutex);
	ret = disk_live(disk);
	mutex_unlock(&disk->open_mutex);
	return ret;
}

void blkfilter_release(struct kref *kref)
{
	struct blkfilter *flt = container_of(kref, struct blkfilter, kref);

	kfree(flt);
}
EXPORT_SYMBOL_GPL(blkfilter_release);

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

	if (!is_disk_alive(bdev->bd_disk)) {
		ret = -ENODEV;
		goto out_module_put;
	}

	ret = bdev_freeze(bdev);
	if (ret)
		goto out_module_put;
	blk_mq_freeze_queue(bdev_get_queue(bdev));

	if (bdev->bd_filter) {
		ret = (bdev->bd_filter->ops == ops) ? -EALREADY : -EBUSY;
		goto out_unfreeze;
	}

	flt = ops->attach(bdev);
	if (IS_ERR(flt)) {
		ret = PTR_ERR(flt);
		goto out_unfreeze;
	}
	kref_init(&flt->kref);
	flt->ops = ops;

	if (bdev->bd_filter) {
		ret = (bdev->bd_filter->ops == ops) ? -EALREADY : -EBUSY;
		flt->ops->detach(flt);
		goto out_unfreeze;
	}

	bdev->bd_filter = flt;
	ops = NULL;

out_unfreeze:
	blk_mq_unfreeze_queue(bdev_get_queue(bdev));
	bdev_thaw(bdev);
out_module_put:
	if (ops)
		module_put(ops->owner);
	return ret;
}

void blkfilter_detach(struct block_device *bdev)
{
	struct blkfilter *flt = NULL;

	blk_mq_freeze_queue(bdev_get_queue(bdev));
	flt = bdev->bd_filter;
	if (flt) {
		if (blkfilter_get(flt))
			bdev->bd_filter = NULL;
		else
			flt = NULL;
	}
	if (flt && flt->ops->detach)
		flt->ops->detach(flt);
	blk_mq_unfreeze_queue(bdev_get_queue(bdev));
	blkfilter_put(flt);
}

int blkfilter_ioctl_detach(struct block_device *bdev,
		    struct blkfilter_name __user *argp)
{
	struct blkfilter_name name;
	struct blkfilter *flt = NULL;
	int ret = 0;

	if (copy_from_user(&name, argp, sizeof(name)))
		return -EFAULT;

	if (!is_disk_alive(bdev->bd_disk))
		return -ENODEV;

	blk_mq_freeze_queue(bdev_get_queue(bdev));

	flt = bdev->bd_filter;
	if (!flt) {
		ret = -ENOENT;
		goto out;
	}

	if (strncmp(flt->ops->name, name.name, BLKFILTER_NAME_LENGTH)) {
		ret = -EINVAL;
		goto out;
	}
	if (!blkfilter_get(flt)) {
		ret = -ENOENT;
		goto out;
	}

	bdev->bd_filter = NULL;
	flt->ops->detach(flt);
	blkfilter_put(flt);
out:
	blk_mq_unfreeze_queue(bdev_get_queue(bdev));
	return ret;
}

int blkfilter_ioctl_ctl(struct block_device *bdev,
		    struct blkfilter_ctl __user *argp)
{
	struct blkfilter_ctl ctl;
	struct blkfilter *flt;
	int ret = 0;

	if (copy_from_user(&ctl, argp, sizeof(ctl)))
		return -EFAULT;

	if (!is_disk_alive(bdev->bd_disk))
		return -ENODEV;

	ret = blk_queue_enter(bdev_get_queue(bdev), 0);
	if (ret)
		return ret;

	flt = bdev->bd_filter;
	if (!flt)
		ret = -ENOENT;
	else if (strncmp(flt->ops->name, ctl.name, BLKFILTER_NAME_LENGTH))
		ret = -EINVAL;
	else if (!blkfilter_get(flt))
		ret = -ENOENT;

	blk_queue_exit(bdev_get_queue(bdev));

	if (ret)
		return ret;

	if (flt->ops->ctl)
		ret = flt->ops->ctl(flt, ctl.cmd, u64_to_user_ptr(ctl.opt),
								&ctl.optlen);
	else
		ret = -ENOTTY;

	blkfilter_put(flt);
	return ret;
}

ssize_t blkfilter_show(struct block_device *bdev, char *buf)
{
	struct blkfilter *flt = NULL;

	if (!is_disk_alive(bdev->bd_disk))
		goto out;

	if (blk_queue_enter(bdev_get_queue(bdev), 0))
		goto out;

	if ((bdev->bd_filter) && blkfilter_get(bdev->bd_filter))
		flt = bdev->bd_filter;

	blk_queue_exit(bdev_get_queue(bdev));

	if (flt) {
		ssize_t ret;

		ret = sprintf(buf, "%s\n", flt->ops->name);
		blkfilter_put(flt);
		return ret;

	}
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
