// SPDX-License-Identifier: GPL-2.0
#define BLK_SNAP_SECTION "-snapstore"
#include "common.h"
#include "snapstore.h"
#include "snapstore_device.h"
#include "big_buffer.h"
#include "params.h"

LIST_HEAD(snapstores);
DECLARE_RWSEM(snapstores_lock);

bool _snapstore_check_halffill(struct snapstore *snapstore, sector_t *fill_status)
{
	struct blk_descr_pool *pool = NULL;

	if (snapstore->file)
		pool = &snapstore->file->pool;
#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
	else if (snapstore->multidev)
		pool = &snapstore->multidev->pool;
#endif
	else if (snapstore->mem)
		pool = &snapstore->mem->pool;

	if (pool)
		return blk_descr_pool_check_halffill(pool, snapstore->empty_limit, fill_status);

	return false;
}

void _snapstore_destroy(struct snapstore *snapstore)
{
	sector_t fill_status;

	pr_info("Destroy snapstore with id %pUB\n", &snapstore->id);

	_snapstore_check_halffill(snapstore, &fill_status);

	down_write(&snapstores_lock);
	list_del(&snapstore->link);
	up_write(&snapstores_lock);

	if (snapstore->mem != NULL)
		snapstore_mem_destroy(snapstore->mem);
	if (snapstore->multidev != NULL)
		snapstore_multidev_destroy(snapstore->multidev);
	if (snapstore->file != NULL)
		snapstore_file_destroy(snapstore->file);

	if (snapstore->ctrl_pipe) {
		struct ctrl_pipe *pipe;

		pipe = snapstore->ctrl_pipe;
		snapstore->ctrl_pipe = NULL;

		ctrl_pipe_request_terminate(pipe, fill_status);

		ctrl_pipe_put_resource(pipe);
	}

	kfree(snapstore);
}

static void _snapstore_destroy_cb(struct kref *kref)
{
	struct snapstore *snapstore = container_of(kref, struct snapstore, refcount);

	_snapstore_destroy(snapstore);
}

struct snapstore *snapstore_get(struct snapstore *snapstore)
{
	if (snapstore)
		kref_get(&snapstore->refcount);

	return snapstore;
}

void snapstore_put(struct snapstore *snapstore)
{
	if (snapstore)
		kref_put(&snapstore->refcount, _snapstore_destroy_cb);
}

void snapstore_done(void)
{
	bool is_empty;

	down_read(&snapstores_lock);
	is_empty = list_empty(&snapstores);
	up_read(&snapstores_lock);

	if (!is_empty)
		pr_err("Unable to perform snapstore cleanup: container is not empty\n");
}

int snapstore_create(uuid_t *id, dev_t snapstore_dev_id, dev_t *dev_id_set,
		     size_t dev_id_set_length)
{
	int res = 0;
	size_t dev_id_inx;
	struct snapstore *snapstore = NULL;

	if (dev_id_set_length == 0)
		return -EINVAL;

	snapstore = kzalloc(sizeof(struct snapstore), GFP_KERNEL);
	if (snapstore == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&snapstore->link);
	uuid_copy(&snapstore->id, id);

	pr_info("Create snapstore with id %pUB\n", &snapstore->id);

	snapstore->mem = NULL;
	snapstore->multidev = NULL;
	snapstore->file = NULL;

	snapstore->ctrl_pipe = NULL;
	snapstore->empty_limit = (sector_t)(64 * (1024 * 1024 / SECTOR_SIZE)); //by default value
	snapstore->halffilled = false;
	snapstore->overflowed = false;

	if (snapstore_dev_id == 0)
		pr_info("Memory snapstore create\n");

#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
	else if (snapstore_dev_id == 0xFFFFffff) {
		struct snapstore_multidev *multidev = NULL;

		res = snapstore_multidev_create(&multidev);
		if (res != 0) {
			kfree(snapstore);

			pr_err("Failed to create multidevice snapstore %pUB\n", id);
			return res;
		}
		snapstore->multidev = multidev;
	}
#endif
	else {
		struct snapstore_file *file = NULL;

		res = snapstore_file_create(snapstore_dev_id, &file);
		if (res != 0) {
			kfree(snapstore);

			pr_err("Failed to create snapstore file for snapstore %pUB\n", id);
			return res;
		}
		snapstore->file = file;
	}

	down_write(&snapstores_lock);
	list_add_tail(&snapstores, &snapstore->link);
	up_write(&snapstores_lock);

	kref_init(&snapstore->refcount);

	for (dev_id_inx = 0; dev_id_inx < dev_id_set_length; ++dev_id_inx) {
		res = snapstore_device_create(dev_id_set[dev_id_inx], snapstore);
		if (res != 0)
			break;
	}

	if (res != 0)
		snapstore_device_cleanup(id);

	snapstore_put(snapstore);
	return res;
}

#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
int snapstore_create_multidev(uuid_t *id, dev_t *dev_id_set, size_t dev_id_set_length)
{
	int res = 0;
	size_t dev_id_inx;
	struct snapstore *snapstore = NULL;
	struct snapstore_multidev *multidev = NULL;

	if (dev_id_set_length == 0)
		return -EINVAL;

	snapstore = kzalloc(sizeof(struct snapstore), GFP_KERNEL);
	if (snapstore == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&snapstore->link);

	uuid_copy(&snapstore->id, id);

	pr_info("Create snapstore with id %pUB\n", &snapstore->id);

	snapstore->mem = NULL;
	snapstore->file = NULL;
	snapstore->multidev = NULL;

	snapstore->ctrl_pipe = NULL;
	snapstore->empty_limit = (sector_t)(64 * (1024 * 1024 / SECTOR_SIZE)); //by default value
	snapstore->halffilled = false;
	snapstore->overflowed = false;

	res = snapstore_multidev_create(&multidev);
	if (res != 0) {
		kfree(snapstore);

		pr_err("Failed to create snapstore file for snapstore %pUB\n", id);
		return res;
	}
	snapstore->multidev = multidev;

	down_write(&snapstores_lock);
	list_add_tail(&snapstore->link, &snapstores);
	up_write(&snapstores_lock);

	kref_init(&snapstore->refcount);

	for (dev_id_inx = 0; dev_id_inx < dev_id_set_length; ++dev_id_inx) {
		res = snapstore_device_create(dev_id_set[dev_id_inx], snapstore);
		if (res != 0)
			break;
	}

	if (res != 0)
		snapstore_device_cleanup(id);

	snapstore_put(snapstore);
	return res;
}
#endif

int snapstore_cleanup(uuid_t *id, u64 *filled_bytes)
{
	int res;
	sector_t filled;

	res = snapstore_check_halffill(id, &filled);
	if (res == 0) {
		*filled_bytes = (u64)from_sectors(filled);

		pr_info("Snapstore fill size: %lld MiB\n", (*filled_bytes >> 20));
	} else {
		*filled_bytes = -1;
		pr_err("Failed to obtain snapstore data filled size\n");
	}

	return snapstore_device_cleanup(id);
}

struct snapstore *_snapstore_find(uuid_t *id)
{
	struct snapstore *result = NULL;

	down_read(&snapstores_lock);
	if (!list_empty(&snapstores)) {
		struct list_head *_head;

		list_for_each(_head, &snapstores) {
			struct snapstore *snapstore = list_entry(_head, struct snapstore, link);

			if (uuid_equal(&snapstore->id, id)) {
				result = snapstore;
				break;
			}
		}
	}
	up_read(&snapstores_lock);

	return result;
}

int snapstore_stretch_initiate(uuid_t *unique_id, struct ctrl_pipe *ctrl_pipe, sector_t empty_limit)
{
	struct snapstore *snapstore;

	snapstore = _snapstore_find(unique_id);
	if (snapstore == NULL) {
		pr_err("Unable to initiate stretch snapstore: ");
		pr_err("cannot find snapstore by uuid %pUB\n", unique_id);
		return -ENODATA;
	}

	snapstore->ctrl_pipe = ctrl_pipe_get_resource(ctrl_pipe);
	snapstore->empty_limit = empty_limit;

	return 0;
}

int snapstore_add_memory(uuid_t *id, unsigned long long sz)
{
	int res = 0;
	struct snapstore *snapstore = NULL;
	size_t available_blocks = (size_t)(sz >> (snapstore_block_shift() + SECTOR_SHIFT));
	size_t current_block = 0;

	pr_info("Adding %lld bytes to the snapstore\n", sz);

	snapstore = _snapstore_find(id);
	if (snapstore == NULL) {
		pr_err("Unable to add memory block to the snapstore: ");
		pr_err("cannot found snapstore by id %pUB\n", id);
		return -ENODATA;
	}

	if (snapstore->file != NULL) {
		pr_err("Unable to add memory block to the snapstore: ");
		pr_err("snapstore file is already created\n");
		return -EINVAL;
	}
#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
	if (snapstore->multidev != NULL) {
		pr_err("Unable to add memory block to the snapstore: ");
		pr_err("snapstore multidevice is already created\n");
		return -EINVAL;
	}
#endif
	if (snapstore->mem != NULL) {
		pr_err("Unable to add memory block to the snapstore: ");
		pr_err("snapstore memory buffer is already created\n");
		return -EINVAL;
	}

	snapstore->mem = snapstore_mem_create(available_blocks);
	for (current_block = 0; current_block < available_blocks; ++current_block) {
		void *buffer = snapstore_mem_get_block(snapstore->mem);

		if (buffer == NULL) {
			pr_err("Unable to add memory block to the snapstore: ");
			pr_err("not enough memory\n");
			res = -ENOMEM;
			break;
		}

		res = blk_descr_mem_pool_add(&snapstore->mem->pool, buffer);
		if (res != 0) {
			pr_err("Unable to add memory block to the snapstore: ");
			pr_err("failed to initialize new block\n");
			break;
		}
	}
	if (res != 0) {
		snapstore_mem_destroy(snapstore->mem);
		snapstore->mem = NULL;
	}

	return res;
}

int rangelist_add(struct list_head *rglist, struct blk_range *rg)
{
	struct blk_range_link *range_link;

	range_link = kzalloc(sizeof(struct blk_range_link), GFP_KERNEL);
	if (range_link == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&range_link->link);

	range_link->rg.ofs = rg->ofs;
	range_link->rg.cnt = rg->cnt;

	list_add_tail(&range_link->link, rglist);

	return 0;
}

int snapstore_add_file(uuid_t *id, struct big_buffer *ranges, size_t ranges_cnt)
{
	int res = 0;
	struct snapstore *snapstore = NULL;
	struct snapstore_device *snapstore_device = NULL;
	sector_t current_blk_size = 0;
	LIST_HEAD(blk_rangelist);
	size_t inx;

	pr_info("Snapstore add %ld ranges\n", ranges_cnt);

	if ((ranges_cnt == 0) || (ranges == NULL))
		return -EINVAL;

	snapstore = _snapstore_find(id);
	if (snapstore == NULL) {
		pr_err("Unable to add file to snapstore: ");
		pr_err("cannot find snapstore by id %pUB\n", id);
		return -ENODATA;
	}

	if (snapstore->file == NULL) {
		pr_err("Unable to add file to snapstore: ");
		pr_err("snapstore file was not initialized\n");
		return -EFAULT;
	}

	snapstore_device =
		snapstore_device_find_by_dev_id(snapstore->file->blk_dev_id); //for zeroed

	for (inx = 0; inx < ranges_cnt; ++inx) {
		size_t blocks_count = 0;
		sector_t range_offset = 0;

		struct blk_range range;
		struct ioctl_range_s *ioctl_range;

		ioctl_range = big_buffer_get_element(ranges, inx, sizeof(struct ioctl_range_s));
		if (ioctl_range == NULL) {
			pr_err("Invalid count of ranges\n");
			res = -ENODATA;
			break;
		}

		range.ofs = (sector_t)to_sectors(ioctl_range->left);
		range.cnt = (blkcnt_t)to_sectors(ioctl_range->right) - range.ofs;

		while (range_offset < range.cnt) {
			struct blk_range rg;

			rg.ofs = range.ofs + range_offset;
			rg.cnt = min_t(sector_t, (range.cnt - range_offset),
				       (snapstore_block_size() - current_blk_size));

			range_offset += rg.cnt;

			res = rangelist_add(&blk_rangelist, &rg);
			if (res != 0) {
				pr_err("Unable to add file to snapstore: ");
				pr_err("cannot add range to rangelist\n");
				break;
			}

			//zero sectors logic
			if (snapstore_device != NULL) {
				res = rangevector_add(&snapstore_device->zero_sectors, &rg);
				if (res != 0) {
					pr_err("Unable to add file to snapstore: ");
					pr_err("cannot add range to zero_sectors tree\n");
					break;
				}
			}

			current_blk_size += rg.cnt;

			if (current_blk_size == snapstore_block_size()) { //allocate  block
				res = blk_descr_file_pool_add(&snapstore->file->pool,
							      &blk_rangelist);
				if (res != 0) {
					pr_err("Unable to add file to snapstore: ");
					pr_err("cannot initialize new block\n");
					break;
				}

				snapstore->halffilled = false;

				current_blk_size = 0;
				INIT_LIST_HEAD(&blk_rangelist); //renew list
				++blocks_count;
			}
		}
		if (res != 0)
			break;
	}

	if ((res == 0) && (current_blk_size != 0))
		pr_warn("Snapstore portion was not ordered by Copy-on-Write block size\n");

	return res;
}

#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
static int rangelist_ex_add(struct list_head *list, struct blk_range *rg,
			    struct block_device *blk_dev)
{
	struct blk_range_link_ex *range_link =
		kzalloc(sizeof(struct blk_range_link_ex), GFP_KERNEL);
	if (range_link == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&range_link->link);

	range_link->rg.ofs = rg->ofs;
	range_link->rg.cnt = rg->cnt;
	range_link->blk_dev = blk_dev;

	list_add_tail(&range_link->link, list);

	return 0;
}

int snapstore_add_multidev(uuid_t *id, dev_t dev_id, struct big_buffer *ranges, size_t ranges_cnt)
{
	int res = 0;
	struct snapstore *snapstore = NULL;
	sector_t current_blk_size = 0;
	size_t inx;
	LIST_HEAD(blk_rangelist);

	pr_info("Snapstore add %ld ranges for device [%d:%d]\n", ranges_cnt, MAJOR(dev_id),
		MINOR(dev_id));

	if ((ranges_cnt == 0) || (ranges == NULL))
		return -EINVAL;

	snapstore = _snapstore_find(id);
	if (snapstore == NULL) {
		pr_err("Unable to add file to multidevice snapstore: ");
		pr_err("cannot find snapstore by id %pUB\n", id);
		return -ENODATA;
	}

	if (snapstore->multidev == NULL) {
		pr_err("Unable to add file to multidevice snapstore: ");
		pr_err("it was not initialized\n");
		return -EFAULT;
	}

	for (inx = 0; inx < ranges_cnt; ++inx) {
		size_t blocks_count = 0;
		sector_t range_offset = 0;
		struct blk_range range;
		struct ioctl_range_s *data;

		data = big_buffer_get_element(ranges, inx, sizeof(struct ioctl_range_s));
		if (data == NULL) {
			pr_err("Invalid count of ranges\n");
			res = -ENODATA;
			break;
		}

		range.ofs = (sector_t)to_sectors(data->left);
		range.cnt = (blkcnt_t)to_sectors(data->right) - range.ofs;

		while (range_offset < range.cnt) {
			struct blk_range rg;
			struct block_device *blk_dev = NULL;

			rg.ofs = range.ofs + range_offset;
			rg.cnt = min_t(sector_t,
				       range.cnt - range_offset,
				       snapstore_block_size() - current_blk_size);

			range_offset += rg.cnt;

			blk_dev = snapstore_multidev_get_device(snapstore->multidev, dev_id);
			if (blk_dev == NULL) {
				pr_err("Cannot find or open device [%d:%d] for multidevice snapstore\n",
				       MAJOR(dev_id), MINOR(dev_id));
				res = -ENODEV;
				break;
			}

			res = rangelist_ex_add(&blk_rangelist, &rg, blk_dev);
			if (res != 0) {
				pr_err("Unable to add file to multidevice snapstore: ");
				pr_err("failed to add range to rangelist\n");
				break;
			}

			/*
			 * zero sectors logic is not implemented for multidevice snapstore
			 */

			current_blk_size += rg.cnt;

			if (current_blk_size == snapstore_block_size()) { //allocate  block
				res = blk_descr_multidev_pool_add(&snapstore->multidev->pool,
								  &blk_rangelist);
				if (res != 0) {
					pr_err("Unable to add file to multidevice snapstore: ");
					pr_err("failed to initialize new block\n");
					break;
				}

				snapstore->halffilled = false;

				current_blk_size = 0;
				INIT_LIST_HEAD(&blk_rangelist);
				++blocks_count;
			}
		}
		if (res != 0)
			break;
	}

	if ((res == 0) && (current_blk_size != 0))
		pr_warn("Snapstore portion was not ordered by Copy-on-Write block size\n");

	return res;
}
#endif

void snapstore_order_border(struct blk_range *in, struct blk_range *out)
{
	struct blk_range unorder;

	unorder.ofs = in->ofs & snapstore_block_mask();
	out->ofs = in->ofs & ~snapstore_block_mask();
	out->cnt = in->cnt + unorder.ofs;

	unorder.cnt = out->cnt & snapstore_block_mask();
	if (unorder.cnt != 0)
		out->cnt += (snapstore_block_size() - unorder.cnt);
}

union blk_descr_unify snapstore_get_empty_block(struct snapstore *snapstore)
{
	union blk_descr_unify result = { NULL };

	if (snapstore->overflowed)
		return result;

	if (snapstore->file != NULL)
		result = blk_descr_file_pool_take(&snapstore->file->pool);
	else if (snapstore->multidev != NULL)
		result = blk_descr_multidev_pool_take(&snapstore->multidev->pool);
	else if (snapstore->mem != NULL)
		result = blk_descr_mem_pool_take(&snapstore->mem->pool);

	if (result.ptr == NULL) {
		if (snapstore->ctrl_pipe) {
			sector_t fill_status;

			_snapstore_check_halffill(snapstore, &fill_status);
			ctrl_pipe_request_overflow(snapstore->ctrl_pipe, -EINVAL,
						   (u64)from_sectors(fill_status));
		}
		snapstore->overflowed = true;
	}

	return result;
}

int snapstore_check_halffill(uuid_t *unique_id, sector_t *fill_status)
{
	struct snapstore *snapstore;

	snapstore = _snapstore_find(unique_id);
	if (snapstore == NULL) {
		pr_err("Cannot find snapstore by uuid %pUB\n", unique_id);
		return -ENODATA;
	}

	_snapstore_check_halffill(snapstore, fill_status);

	return 0;
}

int snapstore_request_store(struct snapstore *snapstore, struct blk_deferred_request *dio_copy_req)
{
	int res = 0;

	if (snapstore->ctrl_pipe) {
		if (!snapstore->halffilled) {
			sector_t fill_status = 0;

			if (_snapstore_check_halffill(snapstore, &fill_status)) {
				snapstore->halffilled = true;
				ctrl_pipe_request_halffill(snapstore->ctrl_pipe,
							   (u64)from_sectors(fill_status));
			}
		}
	}

	if (snapstore->file)
		res = blk_deferred_request_store_file(snapstore->file->blk_dev, dio_copy_req);
#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
	else if (snapstore->multidev)
		res = blk_deferred_request_store_multidev(dio_copy_req);
#endif
	else if (snapstore->mem)
		res = blk_deferred_request_store_mem(dio_copy_req);
	else
		res = -EINVAL;

	return res;
}

static int _snapstore_redirect_read_file(struct blk_redirect_bio *rq_redir,
					 struct block_device *snapstore_blk_dev,
					 struct blk_descr_file *file,
					 sector_t block_ofs,
					 sector_t rq_ofs, sector_t rq_count)
{
	int res = 0;
	sector_t current_ofs = 0;
	struct list_head *_list_head;

	if (unlikely(list_empty(&file->rangelist))) {
		pr_err("Invalid file block descriptor");
		return -EINVAL;
	}

	list_for_each(_list_head, &file->rangelist) {
		struct blk_range_link *range_link;

		range_link = list_entry(_list_head, struct blk_range_link, link);
		if (current_ofs >= rq_count)
			break;

		if (range_link->rg.cnt > block_ofs) {
			sector_t pos = range_link->rg.ofs + block_ofs;
			sector_t len = min_t(sector_t,
					     range_link->rg.cnt - block_ofs,
					     rq_count - current_ofs);

			res = blk_dev_redirect_part(rq_redir, READ, snapstore_blk_dev, pos,
						    rq_ofs + current_ofs, len);
			if (res != 0) {
				pr_err("Failed to read from snapstore file. Sector #%lld\n",
				       pos);
				break;
			}

			current_ofs += len;
			block_ofs = 0;
		} else
			block_ofs -= range_link->rg.cnt;
	}

	if (res != 0)
		pr_err("Failed to read from file snapstore\n");
	return res;
}

#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
static int _snapstore_redirect_read_multidev(struct blk_redirect_bio *rq_redir,
					      struct blk_descr_multidev *multidev,
					      sector_t block_ofs,
					      sector_t rq_ofs, sector_t rq_count)
{
	int res = 0;
	sector_t current_ofs = 0;
	struct list_head *_list_head;

	if (unlikely(list_empty(&multidev->rangelist))) {
		pr_err("Invalid multidev block descriptor");
		return -EINVAL;
	}

	list_for_each(_list_head, &multidev->rangelist) {
		struct blk_range_link_ex *range_link =
			list_entry(_list_head, struct blk_range_link_ex, link);

		if (current_ofs >= rq_count)
			break;

		if (range_link->rg.cnt > block_ofs) {
			sector_t pos = range_link->rg.ofs + block_ofs;
			sector_t len = min_t(sector_t,
					     range_link->rg.cnt - block_ofs,
					     rq_count - current_ofs);

			res = blk_dev_redirect_part(rq_redir, READ, range_link->blk_dev, pos,
						    rq_ofs + current_ofs, len);

			if (res != 0) {
				pr_err("Failed to read from snapstore file. Sector #%lld\n", pos);
				break;
			}

			current_ofs += len;
			block_ofs = 0;
		} else
			block_ofs -= range_link->rg.cnt;
	}

	if (res != 0)
		pr_err("Failed to read from multidev snapstore\n");
	return res;
}
#endif

int snapstore_redirect_read(struct blk_redirect_bio *rq_redir, struct snapstore *snapstore,
			    union blk_descr_unify blk_descr, sector_t target_pos, sector_t rq_ofs,
			    sector_t rq_count)
{
	int res = 0;
	sector_t block_ofs = target_pos & snapstore_block_mask();

	if (snapstore->file)
		res = _snapstore_redirect_read_file(rq_redir, snapstore->file->blk_dev,
						    blk_descr.file, block_ofs, rq_ofs, rq_count);
#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
	else if (snapstore->multidev)
		res = _snapstore_redirect_read_multidev(rq_redir, blk_descr.multidev, block_ofs,
							rq_ofs, rq_count);
#endif
	else if (snapstore->mem) {
		res = blk_dev_redirect_memcpy_part(
			rq_redir, READ, blk_descr.mem->buff + (size_t)from_sectors(block_ofs),
			rq_ofs, rq_count);

		if (res != 0)
			pr_err("Failed to read from snapstore memory\n");
	} else
		res = -EINVAL;

	if (res != 0)
		pr_err("Failed to read from snapstore. Offset %lld sector\n", target_pos);
	return res;
}

static int _snapstore_redirect_write_file(struct blk_redirect_bio *rq_redir,
					  struct block_device *snapstore_blk_dev,
					  struct blk_descr_file *file,
					  sector_t block_ofs,
					  sector_t rq_ofs, sector_t rq_count)
{
	int res = 0;
	sector_t current_ofs = 0;
	struct list_head *_list_head;

	if (unlikely(list_empty(&file->rangelist))) {
		pr_err("Invalid file block descriptor");
		return -EINVAL;
	}

	list_for_each(_list_head, &file->rangelist) {
		struct blk_range_link *range_link;

		range_link = list_entry(_list_head, struct blk_range_link, link);
		if (current_ofs >= rq_count)
			break;

		if (range_link->rg.cnt > block_ofs) {
			sector_t pos = range_link->rg.ofs + block_ofs;
			sector_t len = min_t(sector_t,
					     range_link->rg.cnt - block_ofs,
					     rq_count - current_ofs);

			res = blk_dev_redirect_part(rq_redir, WRITE, snapstore_blk_dev, pos,
						    rq_ofs + current_ofs, len);

			if (res != 0) {
				pr_err("Failed to write to snapstore file. Sector #%lld\n",
				       pos);
				break;
			}

			current_ofs += len;
			block_ofs = 0;
		} else
			block_ofs -= range_link->rg.cnt;
	}
	if (res != 0)
		pr_err("Failed to write to file snapstore\n");
	return res;
}

#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
static int _snapstore_redirect_write_multidev(struct blk_redirect_bio *rq_redir,
					      struct blk_descr_multidev *multidev,
					      sector_t block_ofs,
					      sector_t rq_ofs, sector_t rq_count)
{
	int res = 0;
	sector_t current_ofs = 0;
	struct list_head *_list_head;

	if (unlikely(list_empty(&multidev->rangelist))) {
		pr_err("Invalid multidev block descriptor");
		return -EINVAL;
	}

	list_for_each(_list_head, &multidev->rangelist) {
		struct blk_range_link_ex *range_link;

		range_link = list_entry(_list_head, struct blk_range_link_ex, link);
		if (current_ofs >= rq_count)
			break;

		if (range_link->rg.cnt > block_ofs) {
			sector_t pos = range_link->rg.ofs + block_ofs;
			sector_t len = min_t(sector_t,
					     range_link->rg.cnt - block_ofs,
					     rq_count - current_ofs);

			res = blk_dev_redirect_part(rq_redir, WRITE, range_link->blk_dev, pos,
						    rq_ofs + current_ofs, len);

			if (res != 0) {
				pr_err("Failed to write to snapstore file. Sector #%lld\n",
				       pos);
				break;
			}

			current_ofs += len;
			block_ofs = 0;
		} else
			block_ofs -= range_link->rg.cnt;
	}

	if (res != 0)
		pr_err("Failed to write to multidevice snapstore\n");
	return res;
}
#endif

int snapstore_redirect_write(struct blk_redirect_bio *rq_redir, struct snapstore *snapstore,
			     union blk_descr_unify blk_descr, sector_t target_pos, sector_t rq_ofs,
			     sector_t rq_count)
{
	int res = 0;
	sector_t block_ofs = target_pos & snapstore_block_mask();

	if (snapstore->file)
		res = _snapstore_redirect_write_file(rq_redir, snapstore->file->blk_dev,
						     blk_descr.file, block_ofs, rq_ofs, rq_count);

#ifdef CONFIG_BLK_SNAP_SNAPSTORE_MULTIDEV
	else if (snapstore->multidev)
		res = _snapstore_redirect_write_multidev(rq_redir, blk_descr.multidev,
							 block_ofs, rq_ofs, rq_count);
#endif
	else if (snapstore->mem) {
		res = blk_dev_redirect_memcpy_part(
			rq_redir, WRITE, blk_descr.mem->buff + (size_t)from_sectors(block_ofs),
			rq_ofs, rq_count);

		if (res != 0)
			pr_err("Failed to write to memory snapstore\n");
	} else {
		pr_err("Unable to write to snapstore: invalid type of snapstore device\n");
		res = -EINVAL;
	}

	if (res != 0)
		pr_err("Failed to write to snapstore. Offset %lld sector\n", target_pos);
	return res;
}
