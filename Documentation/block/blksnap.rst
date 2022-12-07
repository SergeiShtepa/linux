.. SPDX-License-Identifier: GPL-2.0

========================================
Block Devices Snapshots Module (blksnap)
========================================

Introduction
============

At first glance, there is no novelty in the idea of creating snapshots for
block devices.  The Linux kernel already has mechanisms for creating snapshots.
Device Mapper includes dm-snap, which allows to create snapshots of block
devices.  BTRFS supports snapshots at the file system level.  However, both
of these options have flaws that do not allow to use them as a universal
tool for creating backups.

Device Mapper flaws:

- Block devices must have LVM markup.
  If no logical volumes were created during system installation, then dm-snap
  cannot be applied.
- To store snapshot differences of one logical volume, it is necessary to
  reserve a fixed range of sectors on a reserved empty logical volume.
  Firstly, it is required that the system has enough space unoccupied by the
  file system, which rarely occurs on real servers.  Secondly, as a rule,
  it is necessary to create snapshots for all logical volumes at once, which
  requires dividing this reserved space between several logical volumes.
  This space can be divided equally or proportionally to the size. But
  the load on different disks is usually uneven.  As a result, a snapshot
  overflow may occur for one of the block devices, while for others all
  the reserved space may remain free.  This complicates management of the
  difference storage and makes it almost impossible to create a coherent
  snapshot of multiple logical volumes.

BTRFS flaws:

- Snapshots create an immutable image of the file system, not a block
  device. Such a snapshot is only applicable for a file backup.
- When synchronizing the snapshot subvolume with the backup subvolume, reading
  the differences leads to random access to the block device, which leads
  to decrease in efficiency compared to direct copying of the block device.
- BTRFS allows to get an incremental backup [#btrfs_increment]_, but it is
  necessary to keep a snapshot of the previous backup cycle on the system,
  which leads to excessive consumption of disk space.  - If there is not enough
  free space on the file system while holding the snapshot, new data cannot
  be saved, which leads to a server malfunction.

Features of the blksnap module:

- Change tracker
- Snapshots at the block device level
- Dynamic allocation of space for storing differences
- Snapshot overflow resistance
- Coherent snapshot of multiple block devices


For a more detailed description of the features, see the Features section.

The listed set of features allows to achieve the key goals of the backup tool:

- Simplicity and versatility of use
- Reliability
- Minimal consumption of system resources during backup
- Minimal time required for recovery or replication of the entire system

Features
========

Change tracker
--------------

The change tracker allows to determine which blocks were changed during the
time between the last snapshot created and any of the previous snapshots.
Having a map of changes, it is enough to copy only the changed blocks, and
no need to reread the entire block device completely.  The change tracker
allows to implement the logic of both incremental and differential backups.
Incremental backup is critical for large file repositories whose size can be
hundreds of terabytes and whose full backup time can take more than a day.
On such servers, the use of backup tools without a change tracker becomes
practically impossible.

Snapshot at the block device level
----------------------------------

A snapshot at the block device level allows to simplify the backup algorithm
and reduce consumption of system resources.  It also allows to perform linear
reading of disk space directly, which allows to achieve maximum reading speed
with minimal use of processor time.  At the same time, the versatility of
creating snapshots for any block device is achieved, regardless of the file
system located on it.  The exceptions are BTRFS, ZFS and cluster file systems.

Dynamic allocation of storage space for differences
---------------------------------------------------

To store differences, the module does not require a pre-reserved block
device range.  A range of sectors can be allocated on any block device
immediately before creating a snapshot in individual files on the file
system.  In addition, the size of the difference storage can be increased
after the snapshot is created by adding new sector ranges on block devices.
Sector ranges can be allocated on any block devices of the system, including
those on which the snapshot was created.  A shared difference storage for
all images of snapshot block devices allows to optimize the use of disk space.

Snapshot overflow resistance
----------------------------

To create images of snapshots of block devices, the module stores blocks
of the original block device that have been changed since the snapshot
was taken.  To do this, the module handles write requests and reads blocks
that need to be overwritten.  This algorithm guarantees safety of the data
of the original block device in the event of an overflow of the snapshot,
and even in the case of unpredictable critical errors.  If a problem occurs
during backup, the difference storage is released, the snapshot is closed,
no backup is created, but the server continues to work.

Coherent snapshot of multiple block devices
-------------------------------------------

A snapshot is created simultaneously for all block devices for which a backup
is being created, ensuring their coherent state.


Algorithms
==========

Overview
--------

The blksnap module is a block-level filter. It handles all write I/O units.
The filter is attached to the block device when the snapshot is created
for the first time.  The change tracker marks all overwritten blocks.
Information about the history of changes on the block device is available
while holding the snapshot.  The module reads the blocks that need to be
overwritten and stores them in the difference storage.  When reading from
a snapshot image, reading is performed either from the original device or
from the difference storage.

Change tracker
--------------

A change tracker map is created for each block device.  One byte
of this map corresponds to one block.  The block size is set by the
``tracking_block_minimum_shift`` and ``tracking_block_maximum_count``
module parameters.  The ``tracking_block_minimum_shift`` parameter limits
the minimum block size for tracking, while ``tracking_block_maximum_count``
defines the maximum allowed number of blocks.  The size of the change tracker
block is determined depending on the size of the block device when adding
a tracking device, that is, when the snapshot is taken for the first time.
The block size must be a power of two.

The byte of the change map stores a number from 0 to 255.  This is the
snapshot number, since the creation of which there have been changes in
the block.  Each time a snapshot is created, the number of the current
snapshot is increased by one.  This number is written to the cell of the
change map when writing to the block.  Thus, knowing the number of one of
the previous snapshots and the number of the last snapshot, one can determine
from the change map which blocks have been changed.  When the number of the
current change reaches the maximum allowed value for the map of 255, at the
time when the next snapshot is created, the map of changes is reset to zero,
and the number of the current snapshot is assigned the value 1.  The change
tracker is reset, and a new UUID is generated — a unique identifier of the
snapshot generation.  The snapshot generation identifier allows to identify
that a change tracking reset has been performed.

The change map has two copies. One copy is active, it tracks the current
changes on the block device.  The second copy is available for reading
while the snapshot is being held, and contains the history up to the moment
the snapshot is taken.  Copies are synchronized at the moment of snapshot
creation.  After the snapshot is released, a second copy of the map is not
needed, but it is not released, so as not to allocate memory for it again
the next time the snapshot is created.

Copy on write
-------------

Data is copied in blocks, or rather in chunks.  The term "chunk" is used to
avoid confusion with change tracker blocks and I/O blocks.  In addition,
the "chunk" in the blksnap module means about the same as the "chunk" in
the dm-snap module.

The size of the chunk is determined by the ``chunk_minimum_shift`` and
``chunk_maximum_count`` module parameters.  The ``chunk_minimum_shift``
parameter limits the minimum size of the chunk, while ``chunk_maximum_count``
defines the maximum allowed number of chunks.  The size of the chunk is
determined depending on the size of the block device at the time of taking the
snapshot. The size of the chunk must be a power of two.  One chunk is described
by the ``struct chunk`` structure. An array of structures is created for each
block device.  The structure contains all the necessary information to copy
the chunks data from the original block device to the difference storage.
This information allows to describe the snapshot image. A semaphore is located
in the structure, which allows synchronization of threads accessing the chunk.

The block level has a feature. If a read I/O unit was sent, and a write I/O
unit was sent after it, then a write can be performed first, and only then
a read.  Therefore, the copy-on-write algorithm is executed synchronously.
If a write request is handled, the execution of this I/O unit will be
delayed until the overwritten chunks are copied to the difference storage.
But if, when handling a write I/O unit, it turns out that the recorded range
of sectors has already been copied to the difference storage, then the I/O
unit is simply passed.

This algorithm allows to efficiently perform backups of systems that run
Round Robin Database.  Such databases can be overwritten several times during
the system backup.  Of course, the value of a backup of the RRD monitoring
system data can be questioned. However, it is often a task to make a backup
of the entire enterprise infrastructure in order to restore or replicate it
entirely in case of problems.

There is also a flaw in the algorithm. When overwriting at least one sector,
an entire chunk is copied. Thus, a situation of rapid filling of the difference
storage when writing data to a block device in small portions in random order
is possible.  This situation is possible in case of strong fragmentation of
data on the file system.  But it must be borne in mind that with such data
fragmentation, performance of systems usually degrades greatly.  So, this
problem does not occur on real servers, although it can easily be created
by artificial tests.

Difference storage
------------------

The difference storage is a pool of disk space areas, and it is shared with
all block devices in the snapshot.  Therefore, there is no need to divide
the difference storage area between block devices, and the difference storage
itself can be located on different block devices.

There is no need to allocate a large disk space immediately before creating
a snapshot.  Even while the snapshot is being held, the difference storage
can be expanded.  It is enough to have free space on the file system.

Areas of disk space can be allocated on the file system using fallocate(),
and the file location can be requested using Fiemap Ioctl or Fibmap Ioctl.
Unfortunately, not all file systems support these mechanisms, but the most
common XFS, EXT4 and BTRFS file systems support it.  BTRFS requires additional
conversion of virtual offsets to physical ones.

While holding the snapshot, the user process can poll the status of the module.
When free space in the difference storage is reduced to a threshold value, the
module generates an event about it.  The user process can prepare a new area
and pass it to the module to expand the difference storage.  The threshold
value is determined as half of the value of the ``diff_storage_minimum``
module parameter.

If free space in the difference storage runs out, an event is generated about
the overflow of the snapshot.  Such a snapshot is considered corrupted, and
read I/O units to snapshot images will be terminated with an error code.
The difference storage stores outdated data required for snapshot images,
so when the snapshot is overflowed, the backup process is interrupted,
but the system maintains its operability without data loss.

How to use
==========

Depending on the needs and the selected license, you can choose different
options for managing the module:

- Using ioctl directly
- Using a static C++ library
- Using the blksnap console tool

Using ioctl
-----------

The module provides the ``include/uapi/blksnap.h`` header file.  It describes
all the available ioctl and structures for interacting with the module.
Each ioctl and structure is documented in detail.  The general algorithm
for calling control requests is approximately the following:

1. ``blk_snap_ioctl_snapshot_create`` initiates the snapshot
   creation process.
2. ``blk_snap_ioctl_snapshot_append_storage`` allows to add the first range of
   blocks to store changes.
3. ``blk_snap_ioctl_snapshot_take`` creates block devices of block device
   snapshot images.
4. ``blk_snap_ioctl_snapshot_collect`` and
   ``blk_snap_ioctl_snapshot_collect_images`` allow to match the original
   block devices and their corresponding snapshot images.
5. Snapshot images are being read from block devices whose numbers were received
   when calling ``blk_snap_ioctl_snapshot_collect_images``. Snapshot images also
   support the write operation. So, the file system on the snapshot image can be
   mounted before backup, which allows to perform the necessary preprocessing.
6. ``blk_snap_ioctl_tracker_collect`` and
   ``blk_snap_ioctl_tracker_read_cbt_map`` allow to get data of the change
   tracker. If a write operation was performed for the snapshot, then the change
   tracker takes this into account. Therefore, it is necessary to receive
   tracker data after write operations have been completed.
7. ``blk_snap_ioctl_snapshot_wait_event`` allows to track the status of
   snapshots and receive events about the requirement to expand the difference
   storage or about snapshot overflow.
8. The difference storage is expanded using
   ``blk_snap_ioctl_snapshot_append_storage``.
9. ``blk_snap_ioctl_snapshot_destroy`` releases the snapshot.
10. If, after creating a backup, postprocessing is performed that changes the
    backup blocks, it is necessary to mark such blocks as dirty in the change
    tracker table. ``blk_snap_ioctl_tracker_mark_dirty_blocks`` is used for
    this.
11. It is possible to disable the change tracker from any block device using
    ``blk_snap_ioctl_tracker_remove``.

Static C++ library
------------------

The [#userspace_libs]_ library was created primarily to simplify creation of
tests in C++, and it is also a good example of using the module interface.
When creating applications, direct use of control calls is preferable.
However, the library can be used in an application with a GPL-2+ license,
or a library with an LGPL-2+ license can be created, with which even a
proprietary application can be dynamically linked.

blksnap console tool
--------------------

The blksnap [#userspace_tools]_ console tool allows to control the module
from the command line.  The tool contains detailed built-in help.  To get
the list of commands, enter the ``blksnap --help`` command. The ``blksnap
<command name> --help`` command allows to get detailed information about the
parameters of each command call.  This option may be convenient when creating
proprietary software, as it allows not to compile with the open source code.
At the same time, the blksnap tool can be used for creating backup scripts.
For example, rsync can be called to synchronize files on the file system of
the mounted snapshot image and files in the archive on a file system that
supports compression.

Tests
-----

A set of tests was created for regression testing [#userspace_tests]_.
Tests with simple algorithms that use the ``blksnap`` console tool to
control the module are written in Bash.  More complex testing algorithms
are implemented in C++.  Documentation [#userspace_tests_doc]_ about them
can be found on the project repository.

References
==========

.. [#btrfs_increment] https://btrfs.wiki.kernel.org/index.php/Incremental_Backup

.. [#userspace_libs] https://github.com/veeam/blksnap/tree/master/lib/blksnap

.. [#userspace_tools] https://github.com/veeam/blksnap/tree/master/tools/blksnap

.. [#userspace_tests] https://github.com/veeam/blksnap/tree/master/tests

.. [#userspace_tests_doc] https://github.com/veeam/blksnap/tree/master/doc

Module interface description
============================

.. kernel-doc:: include/uapi/linux/blksnap.h
