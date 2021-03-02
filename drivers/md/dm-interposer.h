/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Device mapper's interposer.
 */

#include <linux/rbtree.h>

struct dm_rb_range {
	struct rb_node node;
	sector_t start;		/* start sector of rb node */
	sector_t last;		/* end sector of rb node */
	sector_t _subtree_last; /* highest sector in subtree of rb node */
};

typedef void (*dm_interpose_bio_t) (struct dm_interposed_dev *ip_dev, struct bio *bio);

struct dm_interposed_dev {
	struct dm_rb_range node;
	void *private;
	dm_interpose_bio_t dm_interpose_bio;

	atomic64_t ip_cnt; /* for debug purpose only */
};

/*
 * Initialize structure dm_interposed_dev.
 * For interposing part of block device set ofs and len.
 * For interposing whole device set ofs=0 and len=0.
 */
void dm_interposer_dev_init(struct dm_interposed_dev *ip_dev,
			    sector_t ofs, sector_t len,
			    void *private, dm_interpose_bio_t interpose_fn);
/*
 * Attach interposer to his disk.
 */
int dm_interposer_dev_attach(struct block_device *bdev, struct dm_interposed_dev *ip_dev);
/*
 * Detach interposer from his disk.
 */
int dm_interposer_detach_dev(struct block_device *bdev, struct dm_interposed_dev *ip_dev);
