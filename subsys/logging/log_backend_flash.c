/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <logging/log_backend.h>
#include "log_backend_std.h"
#include <assert.h>
#include <fs/fs.h>
#include <fs/littlefs.h>

#define MAX_PATH_LEN 255
#define MAX_FLASH_WRITE_SIZE 256
#define LOG_FILENAME_LEN (sizeof(CONFIG_LOG_FLASH_FILENAME) - 1)

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(storage);
static struct fs_mount_t lfs_storage_mnt = {
	.type = FS_LITTLEFS,
	.fs_data = &storage,
	.storage_dev = (void *)FLASH_AREA_ID(storage),
	.mnt_point = "/lfs",
};

static const char *log_filename = CONFIG_LOG_FLASH_FILENAME;
static char fname[MAX_PATH_LEN];
static struct fs_file_t file;
static struct fs_statvfs stat;

/* In case of no log file or current file is near overflow
 * create new log file.
 */
static int allocate_new_file(struct fs_file_t *file);

#if defined(CONFIG_OVERWRITE_OLD_LOG_FILES)
static int delete_oldest_logs(void);
#endif

static int write_log_to_file(uint8_t *data, size_t length, void *ctx)
{
	int rc;
	struct fs_file_t *f = (struct fs_file_t*)ctx;

	assert(ctx);
	int size = fs_tell(f);
	/* Check if new data overwrites max file size.
	 * If so, create new log file.
	 */
	if ((size + length) > (stat.f_frsize * CONFIG_LOG_FLASH_FILE_SIZE)) {
		int ret = allocate_new_file(f);
		if (ret) {
			return length;
		}
	}
	rc = fs_write(f, data, length);
	if (rc == LFS_ERR_NOSPC) {
#if defined(CONFIG_OVERWRITE_OLD_LOG_FILES)
		delete_oldest_logs();
		return 0;
#else
		return length;
#endif
	}
	if (rc < 0){
		return 0;
	}
	fs_sync(f);
	return length;
}

static uint8_t __aligned(4) buf[MAX_FLASH_WRITE_SIZE];

LOG_OUTPUT_DEFINE(log_output, write_log_to_file, buf, MAX_FLASH_WRITE_SIZE);

static void put(const struct log_backend *const backend,
		struct log_msg *msg)
{
	uint32_t flag = IS_ENABLED(CONFIG_LOG_BACKEND_FLASH_SYST_ENABLE) ?
			LOG_OUTPUT_FLAG_FORMAT_SYST : 0;

	log_backend_std_put(&log_output, flag, msg);
}

static void log_backend_flash_init(void)
{
	int rc;
	struct fs_mount_t *mp = &lfs_storage_mnt;
	int file_num = 0;

	rc = fs_mount(mp);
	if (rc < 0) {
		return;
	}

	/* Search for the last used log number.*/
	struct fs_dir_t dir = { 0 };

	rc = fs_opendir(&dir, mp->mnt_point);

	while (rc >= 0) {
		struct fs_dirent ent = { 0 };

		rc = fs_readdir(&dir, &ent);
		if (rc < 0) {
			break;
		}
		if (ent.name[0] == 0) {
			break;
		}
		if (strstr(ent.name, log_filename) != NULL) {
			file_num = atoi(ent.name + LOG_FILENAME_LEN) + 1;
		}
	}
	(void)fs_closedir(&dir);

#if defined(CONFIG_OVERWRITE_OLD_LOG_FILES)
	/* Check if some space should be freed. */
	fs_statvfs(mp->mnt_point, &stat);
	if (stat.f_bfree <= CONFIG_LOG_FLASH_FILE_SIZE) {
		delete_oldest_logs();
	}
#endif
	/* Open new file.*/
	snprintf(fname, sizeof(fname), "%s/%s%04d",
		 mp->mnt_point, log_filename, file_num);
	rc = fs_open(&file, fname);
	if (rc < 0) {
		return;
	}
	log_output_ctx_set(&log_output, (void*)&file);
}

static void panic(struct log_backend const *const backend)
{
	/* In case of panic flush the buffer and deinitialize backend.
	 * It is better to keep current data than log new and risk of failure.
	 */
	log_backend_deactivate(backend);
}

static void dropped(const struct log_backend *const backend, uint32_t cnt)
{
	ARG_UNUSED(backend);

	log_backend_std_dropped(&log_output, cnt);
}

static int allocate_new_file(struct fs_file_t *file)
{
	int rc;
	
	if (file == NULL) {
		return -EINVAL;
	}
	fs_close(file);
	fs_statvfs(lfs_storage_mnt.mnt_point, &stat);

	if (stat.f_bfree <= CONFIG_LOG_FLASH_FILE_SIZE) {
#if defined(CONFIG_OVERWRITE_OLD_LOG_FILES)
		delete_oldest_logs();
#else
		return -ENOSPC;
#endif
	}
	char *name = strstr(fname, log_filename);
	if (name != NULL) {
		int file_num = atoi(name + LOG_FILENAME_LEN) + 1;
		snprintf(fname, sizeof(fname), "%s/%s%04d",
			 lfs_storage_mnt.mnt_point, log_filename, file_num);
	}
	rc = fs_open(file, fname);
	if (rc < 0) {
		return rc;
	}
	log_output_ctx_set(&log_output, (void*)file);
	return rc;
}

#if defined(CONFIG_OVERWRITE_OLD_LOG_FILES)
static int delete_oldest_logs(void)
{
	struct fs_dir_t dir = { 0 };
	int rc;

	rc = fs_opendir(&dir, lfs_storage_mnt.mnt_point);
	while (stat.f_bfree <= CONFIG_LOG_FLASH_FILE_SIZE) {
		struct fs_dirent ent = { 0 };

		rc = fs_readdir(&dir, &ent);
		if (rc < 0) {
			break;
		}
		if (strstr(ent.name, log_filename) != NULL) {
			char del_file_path[MAX_FILE_NAME];
			sprintf(del_file_path, "%s/%s",
				lfs_storage_mnt.mnt_point,
				ent.name);
			rc = fs_unlink(del_file_path);
			if (rc < 0) {
				break;
			}
		}
		fs_statvfs(lfs_storage_mnt.mnt_point, &stat);
	}
	fs_closedir(&dir);
	return rc;
}
#endif

const struct log_backend_api log_backend_flash_api = {
	.put = put,
	.put_sync_string = NULL,
	.put_sync_hexdump = NULL,
	.panic = panic,
	.init = log_backend_flash_init,
	.dropped = dropped,
};

LOG_BACKEND_DEFINE(log_backend_flash, log_backend_flash_api, true);
