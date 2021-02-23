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

typedef void (*dm_interpose_bio_t) (void *context, sector_t start_sect,  struct bio *bio);

struct dm_interposed_dev {
	struct gendisk *disk;
	struct dm_rb_range node;
	void *context;
	dm_interpose_bio_t dm_interpose_bio;

	atomic64_t ip_cnt; /* for debug purpose only */
};

/*
 * Just initialize structure dm_interposed_dev.
 */
void dm_interposer_dev_init(struct dm_interposed_dev *ip_dev,
			    struct gendisk *disk, sector_t ofs, sector_t len,
			    void *context, dm_interpose_bio_t interpose_fn);

/*
 * Attach interposer to his disk.
 */
int dm_interposer_dev_attach(struct dm_interposed_dev *ip_dev);
/*
 * Detach interposer from his disk.
 */
int dm_interposer_detach_dev(struct dm_interposed_dev *ip_dev);
