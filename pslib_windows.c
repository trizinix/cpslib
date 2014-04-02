#include <stdio.h>
#include <stdbool.h>
#include <winsock2.h>

#include "pslib.h"
#include "common.h"

static char *get_drive_type(int type) {
	switch (type) {
	case DRIVE_FIXED:
		return "fixed";
	case DRIVE_CDROM:
		return "cdrom";
	case DRIVE_REMOVABLE:
		return "removable";
	case DRIVE_UNKNOWN:
		return "unknown";
	case DRIVE_NO_ROOT_DIR:
		return "unmounted";
	case DRIVE_REMOTE:
		return "remote";
	case DRIVE_RAMDISK:
		return "ramdisk";
	default:
		return "?";
	}
}

/* Public functions */
int disk_usage(char path[], DiskUsage *ret) {
	bool retval;
	__int64 a, f, t;
	
	retval = GetDiskFreeSpaceEx(path, (PULARGE_INTEGER)&a, (PULARGE_INTEGER)&t, (PULARGE_INTEGER)&f);
	check(ret != 0, "GetDiskFreeSpaceEx returned 0");

	ret->free = f;
	ret->total = t;
	ret->used = t - f;
	ret->percent = percentage(t - f, t);

	return 0;
error:
	return -1;
}

DiskPartitionInfo *disk_partitions(bool all) {
	int num_bytes;
	char drive_strings[255];	
	int nparts = 5;
	DiskPartition *partitions = calloc(nparts, sizeof(DiskPartition));
	DiskPartitionInfo *ret = calloc(1, sizeof(DiskPartitionInfo));
	DiskPartition *d = partitions;
	check_mem(partitions);
	check_mem(ret);

	ret->nitems = 0;
	ret->partitions = partitions;

	num_bytes = GetLogicalDriveStrings(254, drive_strings);
	check(num_bytes > 0, "GetLogicalDriveStrings failed");

	char opts[20];
	LPTSTR fs_type[MAX_PATH + 1] = { 0 };

	int type;
	char *drive_letter = drive_strings;
	while (*drive_letter != 0) {
		opts[0] = 0;
		fs_type[0] = 0;

		type = GetDriveType(drive_letter);

		// consider only hard drives and cd-roms
		if (all == 0) {
			if ((type == DRIVE_UNKNOWN) ||
				(type == DRIVE_NO_ROOT_DIR) ||
				(type == DRIVE_REMOTE) ||
				(type == DRIVE_RAMDISK)) {
				goto next;
			}

			// Skip floppy(avoid slowdown)
			if ((type == DRIVE_REMOVABLE) && (strcmp(drive_letter, "A:\\") == 0)) {
				goto next;
			}
		}

		DWORD pflags;
		int ret2 = GetVolumeInformation(drive_letter, NULL, _ARRAYSIZE(drive_letter),
			NULL, NULL, &pflags, fs_type, _ARRAYSIZE(fs_type));
		if (ret2 == 0) {
			// Floppy or empty CDRom, ERROR is 21(device not ready),
			//  the fstype is ''
			SetLastError(0);
		}

		if (pflags & FILE_READ_ONLY_VOLUME) {
			strcat_s(opts, 20, "ro");			
		}
		else {
			strcat_s(opts, 20, "rw");
		}
		if (pflags & FILE_VOLUME_IS_COMPRESSED) {
			strcat_s(opts, 20, ",compressed");			
		}

		if (strlen(opts) > 0) {
			strcat_s(opts, 20, ",");
		}
		strcat_s(opts, 20, get_drive_type(type));

		d->device = strdup(drive_letter);
		d->mountpoint = strdup(drive_letter);
		d->fstype = strdup(fs_type);
		d->opts = strdup(opts);

		ret->nitems++;
		d++;

		if (ret->nitems == nparts) {
			nparts *= 2;
			partitions = realloc(partitions, sizeof(DiskPartition)* nparts);
			check_mem(partitions);
			ret->partitions = partitions;
			d = ret->partitions + ret->nitems;
		}
		
	next:
		drive_letter = strchr(drive_letter, 0) + 1;
	}
	return ret;
error:
	free_disk_partition_info(ret);
	return NULL;
}