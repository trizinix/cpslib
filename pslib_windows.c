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

// TBD Find a more elegant/reliable solution
// http://stackoverflow.com/questions/327718/how-to-list-physical-disks
DiskIOCounterInfo *disk_io_counters() {
	DISK_PERFORMANCE disk_perf;
	DWORD dwSize;

	int nparts = 5;
	DiskIOCounters *counters = calloc(nparts, sizeof(DiskIOCounters));
	DiskIOCounterInfo *ret = calloc(1, sizeof(DiskIOCounterInfo));
	DiskIOCounters *ci = counters;
	check_mem(counters);
	check_mem(ret);

	ret->nitems = 0;
	ret->iocounters = counters;

	HANDLE hDevice = NULL;
	char szDevice[MAX_PATH];
	char szDeviceDisplay[MAX_PATH];
	int devNum;

	for (devNum = 0;; devNum++) {
		sprintf(szDevice, "\\\\.\\PhysicalDrive%d", devNum);
		hDevice = CreateFile(szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);

		if (hDevice == INVALID_HANDLE_VALUE) {
			// TBD: Make something smart
			// what happens if we get an invalid handle on the first disk?
			// we might end up with an empty dict incorrectly in some cases
			break;
		}

		if (DeviceIoControl(hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
			&disk_perf, sizeof(DISK_PERFORMANCE),
			&dwSize, NULL))
		{
			sprintf(szDeviceDisplay, "PhysicalDrive%d", devNum);
			ci->name = strdup(szDeviceDisplay);
			ci->reads = disk_perf.ReadCount;
			ci->writes = disk_perf.WriteCount;
			printf("%ld - %ld  sizeof: %d - %d\n\n", ci->reads, ci->writes, disk_perf.ReadCount, disk_perf.WriteCount);
			ci->readbytes = disk_perf.BytesRead.QuadPart;
			ci->writebytes = disk_perf.BytesWritten.QuadPart;
			ci->readtime = (disk_perf.ReadTime.QuadPart * 10) / 1000;
			ci->writetime = (disk_perf.WriteTime.QuadPart * 10) / 1000;
		}
		else {
			// TBD: we might get here with ERROR_INSUFFICIENT_BUFFER
		}

		ret->nitems++;
		ci++;

		if (ret->nitems == nparts) {
			nparts *= 2;
			counters = realloc(counters, sizeof(DiskIOCounters)*nparts);
			check_mem(counters);
			ret->iocounters = counters;
			ci = ret->iocounters + ret->nitems;
		}

		CloseHandle(hDevice); // TBD: We might not close when goto error
	}
	return ret;

error:
	return NULL;
}