===============================
Generic Block Device Capability
===============================

This file documents the sysfs file ``block/<disk>/capability``.

``capability`` is a bitfield, printed in hexadecimal, indicating which
capabilities a specific block device supports:

.. kernel-doc:: include/linux/blkdev.h
	:DOC: genhd capability flags
.. kernel-doc:: include/linux/blkdev.h
	:functions: disk_openers blk_alloc_disk bio_end_io_acct
