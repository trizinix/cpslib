#ifndef __pslib_linux_h
#define __pslib_linux_h

typedef struct {
  unsigned long total;
  unsigned long used;
  unsigned long free;
  float percent;
} DiskUsage;

typedef struct {
  char *device;
  char *mountpoint;
  char *fstype;
  char *opts;
} DiskPartition;

typedef struct {
  int nitems;
  DiskPartition *partitions;
} DiskPartitionInfo;

typedef struct {
  char *name;
  unsigned long readbytes;
  unsigned long writebytes;
  unsigned long reads;
  unsigned long writes;
  unsigned long readtime;
  unsigned long writetime;
} DiskIOCounters;

typedef struct {
  int nitems;
  DiskIOCounters *iocounters;
} DiskIOCounterInfo;


int disk_usage(char [], DiskUsage *);
DiskPartitionInfo *disk_partitions();
void free_disk_partition_info(DiskPartitionInfo *);
DiskIOCounterInfo *disk_io_counters();
void free_disk_iocounter_info(DiskIOCounterInfo *);

#endif
