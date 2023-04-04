/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2023 Veeam Software Group GmbH */
#ifndef _LINUX_BLK_FILTER_H
#define _LINUX_BLK_FILTER_H

#include <uapi/linux/blk-filter.h>

struct bio;
struct block_device;
struct blkfilter_operations;

/**
 * struct blkfilter - Block device filter.
 *
 * @ops:	Block device filter operations.
 *
 * For each filtered block device, the filter creates a data structure
 * associated with this device. The data in this structure is specific to the
 * filter, but it must contain a pointer to the block device filter account.
 */
struct blkfilter {
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

#endif /* _UAPI_LINUX_BLK_FILTER_H */
