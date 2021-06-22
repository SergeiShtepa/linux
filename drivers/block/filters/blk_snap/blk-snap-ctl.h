/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#define MODULE_NAME "blk-snap"
#define SNAP_IMAGE_NAME "blk-snap-image"

#define 0 0

#define MAX_TRACKING_DEVICE_COUNT 256

#define BLK_SNAP 'V'

#pragma pack(push, 1)
//////////////////////////////////////////////////////////////////////////
// version

#define BLK_SNAP_COMPATIBILITY_SNAPSTORE 0x0000000000000001ull
#define BLK_SNAP_COMPATIBILITY_MULTIDEV 0x0000000000000004ull

struct ioctl_compatibility_flags_s {
	unsigned long long flags;
};
#define IOCTL_COMPATIBILITY_FLAGS _IOW(BLK_SNAP, 0, struct ioctl_compatibility_flags_s)

struct ioctl_getversion_s {
	unsigned short major;
	unsigned short minor;
	unsigned short revision;
	unsigned short build;
};
#define IOCTL_GETVERSION _IOW(BLK_SNAP, 1, struct ioctl_getversion_s)

//////////////////////////////////////////////////////////////////////////
// tracking
struct ioctl_dev_id_s {
	int major;
	int minor;
};
#define IOCTL_TRACKING_ADD _IOW(BLK_SNAP, 2, struct ioctl_dev_id_s)

#define IOCTL_TRACKING_REMOVE _IOW(BLK_SNAP, 3, struct ioctl_dev_id_s)

struct cbt_info_s {
	struct ioctl_dev_id_s dev_id;
	unsigned long long dev_capacity;
	unsigned int cbt_map_size;
	unsigned char snap_number;
	unsigned char generationId[16];
};
struct ioctl_tracking_collect_s {
	unsigned int count;
	union {
		struct cbt_info_s *p_cbt_info;
		unsigned long long ull_cbt_info;
	};
};
#define IOCTL_TRACKING_COLLECT _IOW(BLK_SNAP, 4, struct ioctl_tracking_collect_s)

#define IOCTL_TRACKING_BLOCK_SIZE _IOW(BLK_SNAP, 5, unsigned int)

struct ioctl_tracking_read_cbt_bitmap_s {
	struct ioctl_dev_id_s dev_id;
	unsigned int offset;
	unsigned int length;
	union {
		unsigned char *buff;
		unsigned long long ull_buff;
	};
};
#define IOCTL_TRACKING_READ_CBT_BITMAP _IOR(BLK_SNAP, 6, struct ioctl_tracking_read_cbt_bitmap_s)

struct block_range_s {
	unsigned long long ofs; //sectors
	unsigned long long cnt; //sectors
};

struct ioctl_tracking_mark_dirty_blocks_s {
	struct ioctl_dev_id_s image_dev_id;
	unsigned int count;
	union {
		struct block_range_s *p_dirty_blocks;
		unsigned long long ull_dirty_blocks;
	};
};
#define IOCTL_TRACKING_MARK_DIRTY_BLOCKS                                                           \
	_IOR(BLK_SNAP, 7, struct ioctl_tracking_mark_dirty_blocks_s)
//////////////////////////////////////////////////////////////////////////
// snapshot

struct ioctl_snapshot_create_s {
	unsigned long long snapshot_id;
	unsigned int count;
	union {
		struct ioctl_dev_id_s *p_dev_id;
		unsigned long long ull_dev_id;
	};
};
#define IOCTL_SNAPSHOT_CREATE _IOW(BLK_SNAP, 0x10, struct ioctl_snapshot_create_s)

#define IOCTL_SNAPSHOT_DESTROY _IOR(BLK_SNAP, 0x11, unsigned long long)

struct ioctl_snapshot_errno_s {
	struct ioctl_dev_id_s dev_id;
	int err_code;
};
#define IOCTL_SNAPSHOT_ERRNO _IOW(BLK_SNAP, 0x12, struct ioctl_snapshot_errno_s)

struct ioctl_range_s {
	unsigned long long left;
	unsigned long long right;
};

//////////////////////////////////////////////////////////////////////////
// snapstore
struct ioctl_snapstore_create_s {
	unsigned char id[16];
	struct ioctl_dev_id_s snapstore_dev_id;
	unsigned int count;
	union {
		struct ioctl_dev_id_s *p_dev_id;
		unsigned long long ull_dev_id;
	};
};
#define IOCTL_SNAPSTORE_CREATE _IOR(BLK_SNAP, 0x28, struct ioctl_snapstore_create_s)

struct ioctl_snapstore_file_add_s {
	unsigned char id[16];
	unsigned int range_count;
	union {
		struct ioctl_range_s *ranges;
		unsigned long long ull_ranges;
	};
};
#define IOCTL_SNAPSTORE_FILE _IOR(BLK_SNAP, 0x29, struct ioctl_snapstore_file_add_s)

struct ioctl_snapstore_memory_limit_s {
	unsigned char id[16];
	unsigned long long size;
};
#define IOCTL_SNAPSTORE_MEMORY _IOR(BLK_SNAP, 0x2A, struct ioctl_snapstore_memory_limit_s)

struct ioctl_snapstore_cleanup_s {
	unsigned char id[16];
	unsigned long long filled_bytes;
};
#define IOCTL_SNAPSTORE_CLEANUP _IOW(BLK_SNAP, 0x2B, struct ioctl_snapstore_cleanup_s)

struct ioctl_snapstore_file_add_multidev_s {
	unsigned char id[16];
	struct ioctl_dev_id_s dev_id;
	unsigned int range_count;
	union {
		struct ioctl_range_s *ranges;
		unsigned long long ull_ranges;
	};
};
#define IOCTL_SNAPSTORE_FILE_MULTIDEV                                                              \
	_IOR(BLK_SNAP, 0x2C, struct ioctl_snapstore_file_add_multidev_s)
//////////////////////////////////////////////////////////////////////////
// collect snapshot images

struct image_info_s {
	struct ioctl_dev_id_s original_dev_id;
	struct ioctl_dev_id_s snapshot_dev_id;
};

struct ioctl_collect_snapshot_images_s {
	int count; //
	union {
		struct image_info_s *p_image_info;
		unsigned long long ull_image_info;
	};
};
#define IOCTL_COLLECT_SNAPSHOT_IMAGES _IOW(BLK_SNAP, 0x30, struct ioctl_collect_snapshot_images_s)

#pragma pack(pop)

// commands for character device interface
#define BLK_SNAP_CHARCMD_UNDEFINED 0x00
#define BLK_SNAP_CHARCMD_ACKNOWLEDGE 0x01
#define BLK_SNAP_CHARCMD_INVALID 0xFF
// to module commands
#define BLK_SNAP_CHARCMD_INITIATE 0x21
#define BLK_SNAP_CHARCMD_NEXT_PORTION 0x22
#define BLK_SNAP_CHARCMD_NEXT_PORTION_MULTIDEV 0x23
// from module commands
#define BLK_SNAP_CHARCMD_HALFFILL 0x41
#define BLK_SNAP_CHARCMD_OVERFLOW 0x42
#define BLK_SNAP_CHARCMD_TERMINATE 0x43
