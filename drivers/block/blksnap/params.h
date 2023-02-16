/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BLKSNAP_PARAMS_H
#define __BLKSNAP_PARAMS_H

int get_tracking_block_minimum_shift(void);
int get_tracking_block_maximum_count(void);
int get_chunk_minimum_shift(void);
int get_chunk_maximum_count(void);
int get_chunk_maximum_in_cache(void);
int get_free_diff_buffer_pool_size(void);
int get_diff_storage_minimum(void);

#endif /* __BLKSNAP_PARAMS_H */
