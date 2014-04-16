#ifndef __pslib_linux_h
#define __pslib_linux_h

#include <stdbool.h>

enum proc_status {
  STATUS_UNKNOWN,
  STATUS_RUNNING,
  STATUS_SLEEPING,
  STATUS_DISK_SLEEP,
  STATUS_STOPPED,
  STATUS_TRACING_STOP,
  STATUS_ZOMBIE,
  STATUS_DEAD,
  STATUS_WAKE_KILL,
  STATUS_WAKING,
  STATUS_IDLE,
  STATUS_LOCKED,
  STATUS_WAITING
};

enum ioprio_class {
  IOPRIO_CLASS_NONE,
  IOPRIO_CLASS_RT,
  IOPRIO_CLASS_BE,
  IOPRIO_CLASS_IDLE
};

/* Same values than RLIMIT_* in resource.h 
   TBD: write converting function, some platforms could overrite
   the values here */
enum cpslib_rlimit {
  CPSLIB_RLIMIT_CPU = 0,
  CPSLIB_RLIMIT_FSIZE = 1,
  CPSLIB_RLIMIT_DATA = 2,
  CPSLIB_RLIMIT_STACK = 3,
  CPSLIB_RLIMIT_CORE = 4,
  CPSLIB_RLIMIT_RSS = 5,
  CPSLIB_RLIMIT_NPROC = 6,
  CPSLIB_RLIMIT_NOFILE = 7,
  CPSLIB_RLIMIT_MEMLOCK = 8,
  CPSLIB_RLIMIT_AS = 9,
  CPSLIB_RLIMIT_LOCKS = 10,
  CPSLIB_RLIMIT_SIGPENDING = 11,
  CPSLIB_RLIMIT_MSGQUEUE = 12,
  CPSLIB_RLIMIT_NICE = 13,
  CPSLIB_RLIMIT_RTPRIO = 14,
  CPSLIB_RLIMIT_RTTIME = 15,
  CPSLIB_RLIMIT_INFINITY = (~0UL)
};

enum con_status {
  ESTABLISHED,
  SYN_SENT,
  SYN_RECV,
  FIN_WAIT1,
  FIN_WAIT2,
  TIME_WAIT,
  CLOSE,
  CLOSE_WAIT,
  LAST_ACK,
  LISTEN,
  CLOSING,
  NONE,
  DELETE_TCB,
  IDLE,
  BOUND
};

enum proc_priority {
  ABOVE_NORMAL_PRIORITY_CLASS,
  BELOW_NORMAL_PRIORITY_CLASS,
  HIGH_PRIORITY_CLASS,
  IDLE_PRIORITY_CLASS,
  NORMAL_PRIORITY_CLASS,
  REALTIME_PRIORITY_CLASS
};


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
} DiskPartition; /* TBD: Pluralise */

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

typedef struct {
  char * name;
  unsigned long bytes_sent;
  unsigned long bytes_recv;
  unsigned long packets_sent;
  unsigned long packets_recv;
  unsigned long errin;
  unsigned long errout;
  unsigned long dropin;
  unsigned long dropout;
} NetIOCounters;

typedef struct {
  int nitems;
  NetIOCounters *iocounters;
} NetIOCounterInfo;

typedef struct {
  char *username;
  char *tty;
  char *hostname;
  float tstamp;
} Users;

typedef struct {
  int nitems;
  Users *users;
} UsersInfo;

typedef struct {
  unsigned long total;
  unsigned long available;
  float percent;
  unsigned long used;
  unsigned long free;
  unsigned long active;
  unsigned long inactive;
  unsigned long buffers;
  unsigned long cached;
} VmemInfo;

typedef struct {
  unsigned long total;
  unsigned long used;
  unsigned long free;
  float percent;
  unsigned long sin;
  unsigned long sout;
} SwapMem;

typedef struct {
  double user;
  double system;
  double idle;
  double nice;
  double iowait;
  double irq;
  double softirq;
  double steal;
  double guest;
  double guest_nice;
} CpuTimes;

typedef struct {
  unsigned int pid;
  unsigned int ppid;
  char *name;
  char *exe;
  char *cmdline;
  unsigned long create_time;
  unsigned int uid;
  unsigned int euid;
  unsigned int suid;
  unsigned int gid;
  unsigned int egid;
  unsigned int sgid;
  char *username;
  char *terminal;
  // char *cwd
  //unsigned int nice;
  // ioprio_class ionice;

} Process;

//*Process process_get_parent();
//proc_status process_get_status();
//rlimit process_get_rlimit();
//int process_io_counters();
//int process_num_ctx_switches();
//int process_num_fds();
//int num_handles();
//int num_threads();


int disk_usage(char [], DiskUsage *);

DiskPartitionInfo *disk_partitions();
DiskPartitionInfo *disk_partitions_phys();
//DiskPartitionInfo *disk_partitions_physical(); ?
void free_disk_partition_info(DiskPartitionInfo *);

DiskIOCounterInfo *disk_io_counters();
void free_disk_iocounter_info(DiskIOCounterInfo *);
//DiskIOCounterInfo *disk_io_counters_per_disk(); ?

NetIOCounterInfo *net_io_counters();
//NetIOCounterInfo *net_io_counters_per_nic(); ?
void free_net_iocounter_info(NetIOCounterInfo *);

UsersInfo *get_users();
void free_users_info(UsersInfo *);

long int get_boot_time();

int virtual_memory(VmemInfo *);
int swap_memory(SwapMem *);

int cpu_times(CpuTimes *);
int cpu_times_per_cpu(CpuTimes **);

int cpu_times_percent(CpuTimes *);
int cpu_times_percent_per_cpu(CpuTimes **);

double cpu_percent();
int cpu_percent_per_cpu(double **);

int cpu_count(bool);

Process *get_process(unsigned int);
void free_process(Process *);

#endif
// disk_io_counters_per_disk
// net_io_counters_per_nic
// net_connections

