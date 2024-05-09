/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023 Veeam Software Group GmbH */
#ifndef _LINUX_BLK_FILTER_H
#define _LINUX_BLK_FILTER_H

#include <uapi/linux/blk-filter.h>
#include <linux/bio.h>

struct blkfilter_operations;

/**
 * struct blkfilter - Block device filter.
 *
 * @kref:	The reference counter allows to control the lifetime of this
 * 		structure.
 * @ops:	Block device filter operations.
 *
 * For each filtered block device, the filter creates a data structure
 * associated with this device. The data in this structure is specific to the
 * filter, but it must contain a pointer to the block device filter account.
 */
struct blkfilter {
	struct kref kref;
	const struct blkfilter_operations *ops;
};

/**
 * struct blkfilter_operations - Block device filter operations.
 *
 * @link:	Entry in the global list of filter drivers
 *		(must not be accessed by the driver).
 * @owner:	Module implementing the filter driver.
 * @name:	Name of the filter driver.
 * @attach:	Attach the filter driver to the block device.
 * @detach:	Detach the filter driver from the block device.
 * @ctl:	Send a control command to the filter driver.
 * @submit_bio:	Handle bio submissions to the filter driver.
 */
struct blkfilter_operations {
	struct list_head link;
	struct module *owner;
	const char *name;
	struct blkfilter *(*attach)(struct block_device *bdev);
	void (*detach)(struct blkfilter *flt);
	int (*ctl)(struct blkfilter *flt, const unsigned int cmd,
		   __u8 __user *buf, __u32 *plen);
	bool (*submit_bio)(struct bio *bio);
};

int blkfilter_register(struct blkfilter_operations *ops);
void blkfilter_unregister(struct blkfilter_operations *ops);

/**
 * blkfilter_get() - Acquire the block device filters object.
 * The function guarantees that the object will be available, and the module
 * associated with this filter will not be unloaded, until the object is
 * released.
 * @flt:	The block device filter object.
 *
 * Returns true if the reference count was successfully incremented.
 */
static inline bool blkfilter_get(struct blkfilter *flt)
{
	if (!try_module_get(flt->ops->owner))
		return false;

	kref_get(&flt->kref);
	return true;
}

void blkfilter_release(struct kref *kref);

/**
 * blkfilter_put() - Releases the block device filters object.
 * @flt:	The block device filter object.
 */
static inline void blkfilter_put(struct blkfilter *flt)
{
	if (likely(flt)) {
		module_put(flt->ops->owner);
		kref_put(&flt->kref, blkfilter_release);
	}
}

/*
 * The internal function for the block layer.
 * Executes a call to the filter handler for the I/O unit.
 */
static inline bool blkfilter_bio(struct bio *bio)
{
	bool skip_bio = false;
	struct blkfilter *flt = bio->bi_bdev->bd_filter;

	if (flt && flt != current->blk_filter) {
		struct blkfilter *prev = current->blk_filter;

		current->blk_filter = flt;
		skip_bio = flt->ops->submit_bio(bio);
		current->blk_filter = prev;
	}

	return skip_bio;
};

void resubmit_filtered_bio(struct bio *bio);

#endif /* _UAPI_LINUX_BLK_FILTER_H */
