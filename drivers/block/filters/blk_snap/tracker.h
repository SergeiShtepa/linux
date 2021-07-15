/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include "cbt_map.h"
#include "defer_io.h"
#include "blk-snap-ctl.h"
#include "snapshot.h"
#include "snapstore_device.h"

#define TRACKER_BDEV_MODE (FMODE_READ | FMODE_WRITE)

struct tracker {
	struct kref refcount;
	dev_t original_dev_id;
	unsigned long long snapshot_id;
	atomic_t is_captured;
	struct cbt_map *cbt_map;
	struct snapstore_device *snapstore_device;
};

//void tracker_done(void);

int tracker_find_by_bio(struct bio *bio, struct tracker **ptracker);
int tracker_find_by_dev_id(dev_t dev_id, struct tracker **ptracker);

int tracker_enum_cbt_info(int max_count, struct cbt_info_s *p_cbt_info, int *p_count);

int tracker_capture_snapshot(dev_t *dev_id_set, int dev_id_set_size);
void tracker_release_snapshot(dev_t *dev_id_set, int dev_id_set_size);

struct tracker *tracker_new(struct block_device *bdev, unsigned long long snapshot_id);
void __tracker_free(struct kref *kref);
static inline void tracker_get(struct tracker *tracker)
{
	kref_get(&tracker->refcount);
};
static inline void tracker_put(struct tracker *tracker)
{
	kref_put(&tracker->refcount, __tracker_free);
};
bool tracker_renew_needed(struct tracker *tracker, struct block_device *bdev);

void tracker_submit_bio_cb(struct tracker *tracker, struct bio *bio);

//void _tracker_remove(struct tracker *tracker, bool detach_filter);
//void tracker_remove(struct tracker *tracker);
void tracker_remove_all(void);

void tracker_cbt_bitmap_set(struct tracker *tracker, sector_t sector, sector_t sector_cnt);

bool tracker_cbt_bitmap_lock(struct tracker *tracker);
void tracker_cbt_bitmap_unlock(struct tracker *tracker);
