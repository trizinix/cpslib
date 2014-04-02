#include "pslib.h"
#include <stdlib.h>

void
free_disk_partition_info(DiskPartitionInfo *di)
{
	DiskPartition *d = di->partitions;
	while (di->nitems--) {
		free(d->device);
		free(d->mountpoint);
		free(d->fstype);
		free(d->opts);
		d++;
	}
	free(di->partitions);
	free(di);
}