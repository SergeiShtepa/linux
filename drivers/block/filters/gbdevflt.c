// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/blkdev.h>

#define MODULE_NAME "gbdevflt"

dev_t bdev_id = MKDEV(7, 1);
bool is_attached = false;

#define my_filter_fn(a) (false)


static flt_st_t gfd_submit_bio_cb(struct bio *bio)
{
	if (likely(my_filter_fn(bio)))
		return FLT_ST_PASS;

	bio->bi_status = BLK_STS_NOTSUPP;
	bio_endio(bio);
	return FLT_ST_COMPLETE;
}

static void gfd_detach_cb(struct block_device *bdev)
{
	is_attached = false;
	pr_info("Detach Generic block device filter from device %s",
		bdev->bd_device.kobj.name);
}

const static struct filter_operations gfd_fops = {
	.submit_bio_cb = gfd_submit_bio_cb,
	.detach_cb = gfd_detach_cb
};

static int __init gfd_init(void)
{
	int ret;

	is_attached = true;
	ret = bdev_filter_add(bdev_id, MODULE_NAME, &gfd_fops);
	if (ret) {
		pr_err("Failed to attach Generic Block Device Filter to device [%d:%d]",
			MAJOR(bdev_id), MINOR(bdev_id));
		return ret;
	}

	return 0;
}

static void __exit gfd_exit(void)
{
	int ret;

	if (!is_attached)
		return;

	ret = bdev_filter_del(bdev_id, MODULE_NAME);
	if (ret)
		pr_err("Failed to detach Generic Block Device Filter from device [%d:%d]",
			MAJOR(bdev_id), MINOR(bdev_id));

}

module_init(gfd_init);
module_exit(gfd_exit);

MODULE_DESCRIPTION("Generic Block Device Filter Driver");
MODULE_AUTHOR("Oracle Corporation");
MODULE_LICENSE("GPL");
