#include <stdio.h>
#include <stdbool.h>
#include <winsock2.h>

#include "pslib.h"
#include "common.h"

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

DiskPartitionInfo *disk_partitions() {


}