// SPDX-License-Identifier: GPL-2.0
#include "common.h"
#include "blk-snap-ctl.h"
#include "params.h"
#include "ctrl_fops.h"
#include "ctrl_pipe.h"
#include "ctrl_sysfs.h"
#include "snapimage.h"
#include "snapstore.h"
#include "snapstore_device.h"
#include "snapshot.h"
#include "tracker.h"
#include "tracking.h"
#include <linux/module.h>


int __init blk_snap_init(void)
{
	int result = 0;

	pr_info("Loading\n");

	params_check();

	result = ctrl_init();
	if (result != 0)
		return result;

	result = blk_redirect_bioset_create();
	if (result != 0)
		return result;

	result = blk_deferred_bioset_create();
	if (result != 0)
		return result;

	result = snapimage_init();
	if (result != 0)
		return result;

	result = ctrl_sysfs_init();
	if (result != 0)
		return result;

	result = tracking_init();
	if (result != 0)
		return result;

	return result;
}

void __exit blk_snap_exit(void)
{
	pr_info("Unloading module\n");

	ctrl_sysfs_done();

	snapshot_done();

	snapstore_device_done();
	snapstore_done();

	tracker_done();
	tracking_done();

	snapimage_done();

	blk_deferred_bioset_free();
	blk_deferred_done();

	blk_redirect_bioset_free();

	ctrl_done();
}

module_init(blk_snap_init);
module_exit(blk_snap_exit);

MODULE_DESCRIPTION("Block Device Snapshot kernel module");
MODULE_VERSION(MODULE_VERSION_STR);
MODULE_AUTHOR("Veeam Software Group GmbH");
MODULE_LICENSE("GPL");
