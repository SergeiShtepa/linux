# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2023 Veeam Software Group GmbH

# EXTRA_CFLAGS += "-D DEBUG"

blksnap-y := 		\
	cbt_map.o	\
	chunk.o		\
	diff_area.o	\
	diff_buffer.o	\
	diff_storage.o	\
	event_queue.o	\
	main.o		\
	snapimage.o	\
	snapshot.o	\
	tracker.o

obj-$(CONFIG_BLKSNAP)	 += blksnap.o
