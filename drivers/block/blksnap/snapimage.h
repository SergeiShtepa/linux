/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BLKSNAP_SNAPIMAGE_H
#define __BLKSNAP_SNAPIMAGE_H

struct tracker;

void snapimage_free(struct tracker *tracker);
int snapimage_create(struct tracker *tracker);
#endif /* __BLKSNAP_SNAPIMAGE_H */
