// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */
#ifndef __TEST_FILE_OPEN_COMMON_H
#define __TEST_FILE_OPEN_COMMON_H

struct test_file_open_config {
	int mnt_id;
	int dev_major;
	int dev_minor;
	int inode;
};

#endif
