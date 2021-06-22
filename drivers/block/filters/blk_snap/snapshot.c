// SPDX-License-Identifier: GPL-2.0
#define BLK_SNAP_SECTION "-snapshot"
#include "common.h"
#include "snapshot.h"
#include "tracker.h"
#include "snapimage.h"
#include "tracking.h"

LIST_HEAD(snapshots);
DECLARE_RWSEM(snapshots_lock);


static int _snapshot_remove_device(dev_t dev_id)
{
	int result;
	struct tracker *tracker = NULL;

	result = tracker_find_by_dev_id(dev_id, &tracker);
	if (result != 0) {
		if (result == -ENODEV)
			pr_err("Cannot find device by device id=[%d:%d]\n", MAJOR(dev_id),
			       MINOR(dev_id));
		else
			pr_err("Failed to find device by device id=[%d:%d]\n", MAJOR(dev_id),
			       MINOR(dev_id));
		return 0;
	}

	if (result != 0)
		return result;

	tracker->snapshot_id = 0ull;

	pr_info("Device [%d:%d] successfully removed from snapshot\n", MAJOR(dev_id),
		MINOR(dev_id));
	return 0;
}

static void _snapshot_cleanup(struct snapshot *snapshot)
{
	int inx;

	for (inx = 0; inx < snapshot->dev_id_set_size; ++inx) {

		if (_snapshot_remove_device(snapshot->dev_id_set[inx]) != 0)
			pr_err("Failed to remove device [%d:%d] from snapshot\n",
			       MAJOR(snapshot->dev_id_set[inx]), MINOR(snapshot->dev_id_set[inx]));
	}

	if (snapshot->dev_id_set != NULL)
		kfree(snapshot->dev_id_set);
	kfree(snapshot);
}

static void _snapshot_destroy(struct snapshot *snapshot)
{
	size_t inx;

	for (inx = 0; inx < snapshot->dev_id_set_size; ++inx)
		snapimage_stop(snapshot->dev_id_set[inx]);

	pr_info("Release snapshot [0x%llx]\n", snapshot->id);

	tracker_release_snapshot(snapshot->dev_id_set, snapshot->dev_id_set_size);

	for (inx = 0; inx < snapshot->dev_id_set_size; ++inx)
		snapimage_destroy(snapshot->dev_id_set[inx]);

	_snapshot_cleanup(snapshot);
}


static int _snapshot_new(dev_t *p_dev, int count, struct snapshot **pp_snapshot)
{
	struct snapshot *p_snapshot = NULL;
	dev_t *snap_set = NULL;

	p_snapshot = kzalloc(sizeof(struct snapshot), GFP_KERNEL);
	if (p_snapshot == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&p_snapshot->link);

	p_snapshot->id = (unsigned long)(p_snapshot);

	snap_set = kcalloc(count, sizeof(dev_t), GFP_KERNEL);
	if (snap_set == NULL) {
		kfree(p_snapshot);

		pr_err("Unable to create snapshot: faile to allocate memory for snapshot map\n");
		return -ENOMEM;
	}
	memcpy(snap_set, p_dev, sizeof(dev_t) * count);

	p_snapshot->dev_id_set_size = count;
	p_snapshot->dev_id_set = snap_set;

	down_write(&snapshots_lock);
	list_add_tail(&snapshots, &p_snapshot->link);
	up_write(&snapshots_lock);

	*pp_snapshot = p_snapshot;

	return 0;
}

void snapshot_done(void)
{
	struct snapshot *snap;

	pr_info("Removing all snapshots\n");
	do {
		snap = NULL;
		down_write(&snapshots_lock);
		if (!list_empty(&snapshots)) {
			struct snapshot *snap = list_entry(snapshots.next, struct snapshot, link);

			list_del(&snap->link);
		}
		up_write(&snapshots_lock);

		if (snap)
			_snapshot_destroy(snap);

	} while (snap);
}

int snapshot_create(dev_t *dev_id_set, unsigned int dev_id_set_size,
		    unsigned long long *p_snapshot_id)
{
	struct snapshot *snapshot = NULL;
	int result = 0;
	unsigned int inx;

	pr_info("Create snapshot for devices:\n");
	for (inx = 0; inx < dev_id_set_size; ++inx)
		pr_info("\t%d:%d\n", MAJOR(dev_id_set[inx]), MINOR(dev_id_set[inx]));

	result = _snapshot_new(dev_id_set, dev_id_set_size, &snapshot);
	if (result != 0) {
		pr_err("Unable to create snapshot: failed to allocate snapshot structure\n");
		return result;
	}

	do {
		result = -ENODEV;
		for (inx = 0; inx < snapshot->dev_id_set_size; ++inx) {
			dev_t dev_id = snapshot->dev_id_set[inx];

			result = tracking_add(dev_id, snapshot->id);
			if (result == -EALREADY)
				result = 0;
			else if (result != 0) {
				pr_err("Unable to create snapshot\n");
				pr_err("Failed to add device [%d:%d] to snapshot tracking\n",
				       MAJOR(dev_id), MINOR(dev_id));
				break;
			}
		}
		if (result != 0)
			break;

		result = tracker_capture_snapshot(snapshot->dev_id_set, snapshot->dev_id_set_size);
		if (result != 0) {
			pr_err("Unable to create snapshot: failed to capture snapshot [0x%llx]\n",
			       snapshot->id);
			break;
		}

		result = snapimage_create_for(snapshot->dev_id_set, snapshot->dev_id_set_size);
		if (result != 0) {
			pr_err("Unable to create snapshot\n");
			pr_err("Failed to create snapshot image devices\n");

			tracker_release_snapshot(snapshot->dev_id_set, snapshot->dev_id_set_size);
			break;
		}

		*p_snapshot_id = snapshot->id;
		pr_info("Snapshot [0x%llx] was created\n", snapshot->id);
	} while (false);

	if (result != 0) {
		pr_info("Snapshot [0x%llx] cleanup\n", snapshot->id);

		down_write(&snapshots_lock);
		list_del(&snapshot->link);
		up_write(&snapshots_lock);

		_snapshot_cleanup(snapshot);
	}
	return result;
}

int snapshot_destroy(unsigned long long snapshot_id)
{
	struct snapshot *snapshot = NULL;

	pr_info("Destroy snapshot [0x%llx]\n", snapshot_id);

	down_read(&snapshots_lock);
	if (!list_empty(&snapshots)) {
		struct list_head *_head;

		list_for_each(_head, &snapshots) {
			struct snapshot *_snap = list_entry(_head, struct snapshot, link);

			if (_snap->id == snapshot_id) {
				snapshot = _snap;
				list_del(&snapshot->link);
				break;
			}
		}
	}
	up_read(&snapshots_lock);

	if (snapshot == NULL) {
		pr_err("Unable to destroy snapshot [0x%llx]: cannot find snapshot by id\n",
		       snapshot_id);
		return -ENODEV;
	}

	_snapshot_destroy(snapshot);
	return 0;
}
