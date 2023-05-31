.. SPDX-License-Identifier: GPL-2.0

================================
Block Device Filtering Mechanism
================================

The block device filtering mechanism is an API that allows to attach block
device filters. Block device filters allow perform additional processing
for I/O units.

Introduction
============

The idea of handling I/O units on block devices is not new. Back in the
2.6 kernel, there was an undocumented possibility of handling I/O units
by substituting the make_request_fn() function, which belonged to the
request_queue structure. But none of the in-tree kernel modules used this
feature, and it was eliminated in the 5.10 kernel.

The block device filtering mechanism returns the ability to handle I/O units.
It is possible to safely attach filter to a block device "on the fly" without
changing the structure of block devices stack.

It supports attaching one filter to one block device, because there is only
one filter implementation in the kernel yet.
See Documentation/block/blksnap.rst.

Design
======

The block device filtering mechanism provides registration and unregistration
for filter operations. The struct blkfilter_operations contains a pointer to
the callback functions for the filter. After registering the filter operations,
filter can be managed using block device ioctl BLKFILTER_ATTACH,
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

The ioctl BLKFILTER_ATTACH and BLKFILTER_DETACH use structure blkfilter_name.
It allows to attach a filter to a block device or detach it.

The ioctl BLKFILTER_CTL use structure blkfilter_ctl. It allows to send a
filter-specific command.

.. kernel-doc:: include/uapi/linux/blk-filter.h

To register in the system, the filter creates its own account, which contains
callback functions, unique filter name and module owner. This filter account is
used by the registration functions.

.. kernel-doc:: include/linux/blk-filter.h

.. kernel-doc:: block/blk-filter.c
   :export:
