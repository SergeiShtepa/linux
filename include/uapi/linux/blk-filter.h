/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (C) 2023 Veeam Software Group GmbH */
#ifndef _UAPI_LINUX_BLK_FILTER_H
#define _UAPI_LINUX_BLK_FILTER_H

#include <linux/types.h>

#define BLKFILTER_NAME_LENGTH	32

/**
 * struct blkfilter_name - parameter for BLKFILTER_ATTACH and BLKFILTER_DETACH
 *      ioctl.
 *
 * @name:       Name of block device filter.
 */
struct blkfilter_name {
	__u8 name[BLKFILTER_NAME_LENGTH];
};

/**
 * struct blkfilter_ctl - parameter for BLKFILTER_CTL ioctl
 *
 * @name:	Name of block device filter.
 * @cmd:	The filter-specific operation code of the command.
 * @optlen:	Size of data at @opt.
 * @opt:	Userspace buffer with options.
 */
struct blkfilter_ctl {
	__u8 name[BLKFILTER_NAME_LENGTH];
	__u32 cmd;
	__u32 optlen;
	__u64 opt;
};

#endif /* _UAPI_LINUX_BLK_FILTER_H */
