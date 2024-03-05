.. SPDX-License-Identifier: GPL-2.0

================================
Block Device Filtering Mechanism
================================

The block device filtering mechanism provides the ability to attach block
device filters. Block device filters allow performing additional processing
for I/O units.

Introduction
============

The idea of handling I/O units on block devices is not new. Back in the
2.6 kernel, there was an undocumented possibility of handling I/O units
by substituting the make_request_fn() function, which belonged to the
request_queue structure. But none of the in-tree kernel modules used this
feature, and it was eliminated in the 5.10 kernel.

The block device filtering mechanism returns the ability to handle I/O units.
It is possible to safely attach a filter to a block device "on the fly" without
changing the structure of the block device's stack.

It supports attaching one filter to one block device, because there is only
one filter implementation in the kernel yet.
See Documentation/block/blksnap.rst.

Design
======

The block device filtering mechanism provides registration and unregistration
for filter operations. The struct blkfilter_operations contains a pointer to
the callback functions for the filter. After registering the filter operations,
the filter can be managed using block device ioctls BLKFILTER_ATTACH,
BLKFILTER_DETACH and BLKFILTER_CTL.

When the filter is attached, the callback function is called for each I/O unit
for a block device, providing I/O unit filtering. Depending on the result of
filtering the I/O unit, it can either be passed for subsequent processing by
the block layer, or skipped.

The filter can be implemented as a loadable module. In this case, the filter
module cannot be unloaded while the filter is attached to at least one of the
block devices.

Interface description
=====================

The ioctl BLKFILTER_ATTACH allows user-space programs to attach a block device
filter to a block device. The ioctl BLKFILTER_DETACH allows user-space programs
to detach it. Both ioctls use &struct blkfilter_name. The ioctl BLKFILTER_CTL
allows user-space programs to send a filter-specific command. It use &struct
blkfilter_ctl.

.. kernel-doc:: include/uapi/linux/blk-filter.h

To register in the system, the filter uses the &struct blkfilter_operations,
which contains callback functions, unique filter name and module owner. When
attaching a filter to a block device, the filter creates a &struct blkfilter.
The pointer to the &struct blkfilter allows the filter to determine for which
block device the callback functions are being called.

.. kernel-doc:: include/linux/blk-filter.h

.. kernel-doc:: block/blk-filter.c
   :export:
