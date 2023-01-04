/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BLKSNAP_TRACKER_H
#define __BLKSNAP_TRACKER_H

#include <linux/kref.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/blkdev.h>
#include <linux/fs.h>

struct cbt_map;
struct diff_area;
struct snapimage;

/**
 * struct tracker - Tracker for a block device.
 *
 * @link:
 *	List header. Tracker release cannot be performed in the release()
 *	filters callback function. Therefore, the trackers are queued for
 *	release in the worker thread.
 * @kref:
 *      The block device filter structure.
 * @dev_id:
 *	Original block device ID.
 * @snapshot_is_taken:
 *	Indicates that a snapshot was taken for the device whose I/O unit are
 *	handled by this tracker.
 * @cbt_map:
 *	Pointer to a change block tracker map.
 * @diff_area:
 *	Pointer to a difference area.
 * @snapimage:
 *
 * The goal of the tracker is to handle I/O unit. The tracker detectes
 * the range of sectors that will change and transmits them to the CBT map
 * and to the difference area.
 */
struct tracker {
	struct list_head link;
        struct kref kref;
	dev_t dev_id;

	atomic_t snapshot_is_taken;

	struct cbt_map *cbt_map;
	struct diff_area *diff_area;
        struct snapimage *snapimage;

        bool is_frozen;
        bool is_active;
};

int tracker_init(void);
void tracker_done(void);

void tracker_free(struct kref *kref);
static inline void tracker_put(struct tracker *tracker)
{
        if (likely(tracker))
                kref_put(&tracker->kref, tracker_free);
};
static inline void tracker_get(struct tracker *tracker)
{
        kref_get(&tracker->kref);
};
int tracker_take_snapshot(struct tracker *tracker);
void tracker_release_snapshot(struct tracker *tracker);

#endif /* __BLKSNAP_TRACKER_H */
