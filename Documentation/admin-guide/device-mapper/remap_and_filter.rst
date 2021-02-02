=================
DM remap & filter
=================

Introduction
============

Usually LVM should be used for new devices.
The administrator have to create logical volumes for the system partition
when installing the operating system. For a running system with
partitioned disk space and mounted file systems, it is quite difficult to
reconfigure to logical volumes. As a result, all the features that Device
Mapper provides are not available for non-LVM systems.
This problem is partially solved by the dm remap functionality, which
uses the kernel's blk_interposer.

blk_interposer
==============

Blk_interposer extends the capabilities of the DM, as it allows to
intercept and redirect bio requests for block devices that are not
dm device. At the same time, blk_interposer allows to attach and detach
from devices "on the fly", without stopping the execution of user
programs.

Blk_interposer allows to do two tasks: remap and filter.
Remap allows to redirect all requests from one block device to another.
Filter allows to do additional processing of the request, but without
redirection. An intercepted request can get to the block device to which
it was addressed, without changes.

Remap
=====

Consider the functionality of the remap. This will allow to connect
any block device with a dm device "on the fly".
Suppose we have a file system mounted on the block device /dev/sda1::

  +-------------+
  | file system |
  +-------------+
        ||
        \/
  +-------------+
  | /dev/sda1   |
  +-------------+

Creating a new DM device that will be mapped on the same /dev/sda1::

  +-------------+  +-----------+
  | file system |  | dm-linear |
  +-------------+  +-----------+
           ||         ||
           \/         \/
         +---------------+
         |   /dev/sda1   |
         +---------------+

Redirecting all bio requests for the /dev/sda1 device to the new dm
device::

  +-------------+
  | file system |
  +-------------+
        ||
        \/
   +----------+    +-----------+
   |  remap   | => | dm-linear |
   +----------+    +-----------+
                         ||
                         \/
                   +-----------+
                   | /dev/sda1 |
                   +-----------+

To achieve this, you need to:

Create new dm device with option 'noexcl'. It's allow to open
underlying block-device without the FMODE_EXCL flag::

  echo "0 `blockdev --getsz $1` linear $DEV 0 noexcl" | dmsetup create dm-noexcl

Call remap command::

  dmsetup remap start dm-noexcl $1

Remap can be used to extend the functionality of dm-snap. This will allow
to take snapshots from any block devices, not just logical volumes.

Filter
======

Filter does not redirect the bio to another device. It does not create
a clone of the bio request. After receiving the request, the filter can
only add some processing, complete the bio request, or return the bio
for further processing.

Suppose we have a file system mounted on the block device /dev/sda1::

  +-------------+
  | file system |
  +-------------+
        ||
        \/
  +-------------+
  | /dev/sda1   |
  +-------------+

Creating a new dm device that will implement filter::

  +-------------+
  | file system |
  +-------------+
        ||
        \/
    +--------+    +----------+
    | filter | => | dm-delay |
    +--------+    +----------+
        ||
        \/
  +-------------+
  | /dev/sda1   |
  +-------------+

Using filter we can change the behavior of debugging tools:
 * dm-dust,
 * dm-delay,
 * dm-flakey,
 * dm-verity.

In the new version, they are will be able to change the behavior of any
existing block device, without creating a new one.
