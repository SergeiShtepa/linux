// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Veeam Software Group GmbH */
#include <linux/blk-filter.h>
#include <linux/blk-mq.h>
#include <linux/module.h>

static LIST_HEAD(blkfilters);
static DEFINE_SPINLOCK(blkfilters_lock);

static inline struct blkfilter_account *blkfilter_find_get(const char *name)
{
	struct blkfilter_account *acc, *found = NULL;

	spin_lock(&blkfilters_lock);
	list_for_each_entry(acc, &blkfilters, link) {
		if (strncmp(acc->name, name, BLKFILTER_NAME_LENGTH) == 0) {
			found = acc;
			break;
		}
	}
	if (found && !try_module_get(found->owner))
		found = NULL;
	spin_unlock(&blkfilters_lock);

	return found;
}

/**
 * blkfilter_attach() - Attach block device filter to block device.
 *
 * @bdev:
 *	The block device.
 * @name:
 *	The name of block device filter.
 *
 * The function is called during processing ioctl BLKFILTER with command
 * BLKFILTER_CMD_ATTACH. The filter with the specified name must be
 * registered in the system. The block device should not have filters attached.
 *
 * Context:
 *	May sleep, flush filesystem and freeze I/O queue.
 * Return:
 *	0 if succeeded,
 *	-ENOENT if filter with this name is not registered in the system,
 *	-EALREADY if filter with this name is already attached to the block
 *	device,
 *	-EBUSY if filter with a different name attached to the block device,
 *	otherwise, another negative error occurred as a result of the filters
 *	attach() callback.
 */
static int blkfilter_attach(struct block_device *bdev, const char *name)
{
	struct blkfilter_account *acc;
	struct blkfilter *flt;
	int ret;

	acc = blkfilter_find_get(name);
	if (!acc)
		return -ENOENT;

	ret = freeze_bdev(bdev);
	if (ret)
		goto out_put_module;
	blk_mq_freeze_queue(bdev->bd_queue);

	if (bdev->bd_filter) {
		if (bdev->bd_filter->acc == acc)
			ret = -EALREADY;
		else
			ret = -EBUSY;
		goto out_unfreeze;
	}

	flt = acc->ops->attach(bdev);
	if (IS_ERR(flt)) {
		ret = PTR_ERR(flt);
		goto out_unfreeze;
	}

	flt->acc = acc;
	bdev->bd_filter = flt;

out_unfreeze:
	blk_mq_unfreeze_queue(bdev->bd_queue);
	thaw_bdev(bdev);
out_put_module:
	if (ret)
		module_put(acc->owner);
	return ret;
}

/**
 * blkfilter_detach() - Detach block device filter from block device.
 *
 * @bdev:
 *	The block device.
 * @name:
 *	The name of block device filter.
 *
 * The function is called during processing ioctl BLKFILTER with command
 * BLKFILTER_CMD_DETACH. The name of the detached filter must match the
 * name of the attached block device filter.
 *
 * Context:
 *	May sleep and freeze I/O queue.
 * Return:
 *	0 if succeeded,
 *	-ENOENT if filter with this name is not registered in the system,
 *	-EINVAL if filter with this name is not attached to the block device,
 *	otherwise, another negative error occurred as a result of the filters
 *	detach() callback.
 */
int blkfilter_detach(struct block_device *bdev, const char *name)
{
	const struct blkfilter_account *acc;
	struct blkfilter *flt;
	int error = 0;

	pr_debug("Detach block device filter %s\n", name);
	blk_mq_freeze_queue(bdev->bd_queue);
	flt = bdev->bd_filter;
	if (!flt) {
		pr_debug("Block device filter is not attached\n");
		error = -ENOENT;
		goto out_unfreeze;
	}
	acc = flt->acc;
	if (name && strncmp(acc->name, name, BLKFILTER_NAME_LENGTH) != 0) {
		pr_debug("Block device filter not found\n");
		error = -EINVAL;
		goto out_unfreeze;
	}

	bdev->bd_filter = NULL;
	acc->ops->detach(flt);
	module_put(acc->owner);
out_unfreeze:
	blk_mq_unfreeze_queue(bdev->bd_queue);

	return error;
}

/**
 * blkfilter_control() - Send a control command to the filter.
 *
 * @bdev:
 *	The block device.
 * @name:
 *	The name of block device filter.
 * @cmd:
 *	Command code.
 * @buf:
 *	Buffer for command options and result data.
 * @plen:
 *	A pointer to the buffer size with command options. If the command
 *	returns a result, the variable will contain the size of the result.
 *
 * The function is called during processing ioctl BLKFILTER with command
 * BLKFILTER_CMD_CTL.
 *
 * Context:
 *	May sleep.
 * Return:
 *	0 if succeeded, negative errno otherwise.
 */
static int blkfilter_control(struct block_device *bdev, const char *name,
		const unsigned int cmd, __u8 __user *buf, __u32 *plen)
{
	struct blkfilter *flt;
	int ret;

	ret = blk_queue_enter(bdev_get_queue(bdev), 0);
	if (ret)
		return ret;

	flt = bdev->bd_filter;
	if (!flt || strncmp(flt->acc->name, name, BLKFILTER_NAME_LENGTH) != 0) {
		ret = -ENOENT;
		goto out_queue_exit;
	}

	if (flt->acc->ops->ctl)
		ret = flt->acc->ops->ctl(flt, cmd, buf, plen);
	else
		ret = -ENOTTY;

out_queue_exit:
	blk_queue_exit(bdev_get_queue(bdev));
	return ret;
}

int blkfilter_ioctl(struct block_device *bdev,
		    struct blkfilter_ctl __user *argp)
{
	struct blkfilter_ctl ctl;

	if (copy_from_user(&ctl, argp, sizeof(ctl)))
		return -EFAULT;

	switch (ctl.cmd) {
	case BLKFILTER_CMD_ATTACH:
		return blkfilter_attach(bdev, ctl.name);
	case BLKFILTER_CMD_DETACH:
		return blkfilter_detach(bdev, ctl.name);
	default:
		return blkfilter_control(bdev, ctl.name,
					 ctl.cmd - BLKFILTER_CMD_CTL,
					 ctl.opt, &ctl.optlen);
	}
}

/**
 * blkfilter_register() - Registration of a new block device filter in
 * 	the system.
 *
 * @new_acc:
 *	The new block device filter account - a pointer to a structure
 *	with a description of the filter that is being registered.
 *
 * A block device filter can be a loadable module. When the module is loaded,
 * it registers its account so that its callback functions are available to
 * the system. It is best to call this function from the init function.
 *
 * Return:
 * 	0 if succeeded,
 *	-EALREADY if this block device filter account is already registered,
 *	-EBUSY if a block device filter account with same name is already
 *	registered.
 */
int blkfilter_register(struct blkfilter_account *new_acc)
{
	struct blkfilter_account *acc;
	int ret = 0;

	spin_lock(&blkfilters_lock);
	list_for_each_entry(acc, &blkfilters, link) {
		if (new_acc == acc) {
			ret = -EALREADY;
			break;
		}
		if (strncmp(new_acc->name, acc->name,
			    BLKFILTER_NAME_LENGTH) == 0) {
			ret = -EBUSY;
			break;
		}
	}
	if (!ret)
		list_add_tail(&new_acc->link, &blkfilters);
	spin_unlock(&blkfilters_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(blkfilter_register);

/**
 * blkfilter_unregister() - Unregistration of a block device filter from
 * 	the system.
 *
 * @acc:
 *	The block device filter account - a pointer to a structure with
 *	a description of the filter.
 *
 * A block device filter can be a loadable module. When the module is unloaded,
 * it must unregister its account. It is best to call this function from
 * the exit function.
 *
 * Important: before unloading, it is necessary to detach the filter from all
 * block devices.
 *
 */
void blkfilter_unregister(struct blkfilter_account *acc)
{
	WARN(acc->owner && (module_refcount(acc->owner) != -1),
	     "The filter should be unregistered when the module is unloading");

	spin_lock(&blkfilters_lock);
	list_del(&acc->link);
	spin_unlock(&blkfilters_lock);
}
EXPORT_SYMBOL_GPL(blkfilter_unregister);
