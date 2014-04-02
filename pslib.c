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

void
free_disk_iocounter_info(DiskIOCounterInfo *di)
{
	DiskIOCounters *d = di->iocounters;
	while (di->nitems--) {
		free(d->name);
		d++;
	}
	free(di->iocounters);
	free(di);
}