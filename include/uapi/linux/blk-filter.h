/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (C) 2023 Veeam Software Group GmbH */
#ifndef _UAPI_LINUX_BLK_FILTER_H
#define _UAPI_LINUX_BLK_FILTER_H

#include <linux/types.h>

enum {
	BLKFILTER_CMD_ATTACH,
	BLKFILTER_CMD_DETACH,
	BLKFILTER_CMD_CTL,
};

#define BLKFILTER_NAME_LENGTH	32

/**
 * struct blkfilter_ctl - parameter for BLKFILTER ioctl
 *
 * @name:	Name of block device filter.
 * @cmd:	Command code opcode (BLKFILTER_CMD_*)
 * @optlen:	Size of data at @opt
 * @opt:	userspace buffer with options
 */
struct blkfilter_ctl {
	__u8 name[BLKFILTER_NAME_LENGTH];
	__u32 cmd;
	__u32 optlen;
	__u8 *opt;
};

#endif /* _UAPI_LINUX_BLK_FILTER_H */
