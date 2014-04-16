#ifndef __pslib_process_h
#define __pslib_process_h

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>

typedef struct Proc Proc;

/* Taken from include/net/tcp_states.h in the linux kernel */
enum tcp_states {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,
    TCP_NONE
};

typedef struct {
  unsigned int uid;
  unsigned int euid;
  unsigned int suid;
} Proc_UserIDs;

typedef struct {
  unsigned int gid;
  unsigned int egid;
  unsigned int sgid;
} Proc_GroupIDs;

typedef struct {
  unsigned long int read_count;
  unsigned long int write_count;
  unsigned long int read_bytes;
  unsigned long int write_bytes;
} Proc_IOCounters;

typedef struct {
  double user;
  double system;
} Proc_CPUTimes;

typedef struct {
  unsigned long int rss;
  unsigned long int vms;
} Proc_MemoryInfo;

typedef struct {
  unsigned long int rss;
  unsigned long int vms;
  unsigned long int shared;
  unsigned long int text;
  unsigned long int lib;
  unsigned long int data;
  unsigned long int dirty;
} Proc_MemoryInfoExt;

typedef struct {
  char *path;
  unsigned long int rss;
  unsigned long int size;
  unsigned long int pss;
  unsigned long int shared_clean;
  unsigned long int shared_dirty;
  unsigned long int private_clean;
  unsigned long int private_dirty;
  unsigned long int referenced;
  unsigned long int anonymous;
  unsigned long int swap;  
} Proc_MemoryMap;

typedef struct {
  int nitems;
  Proc_MemoryMap *memorymaps;
} Proc_MemoryMapInfo;

typedef struct {
  unsigned long int voluntary;
  unsigned long int involuntary;
} Proc_NumCTXSwitches;

typedef struct {
  unsigned long int id;
  double user_time;
  double system_time;
} Proc_Thread;

typedef struct {
  int nitems;
  Proc_Thread *threads;
} Proc_ThreadInfo;

typedef struct {
  int nitems;
  int *cpus;
} Proc_CPUAffinity;

typedef struct {
  enum ioprio_class ioclass;
  unsigned int value;
} Proc_IONice;

typedef struct {
  char *path;
  int fd;
} Proc_OpenFile;

typedef struct {
  int nitems;
  Proc_OpenFile *files;
} Proc_OpenFileInfo;

enum connection_filter {
  CON_INET,
  CON_INET4,
  CON_INET6,
  CON_TCP,
  CON_TCP4,
  CON_TCP6,
  CON_UDP,
  CON_UDP4,
  CON_UDP6,
  CON_UNIX,
  CON_ALL
};

enum connection_family {
  PS_AF_UNIX,
  PS_AF_INET,
  PS_AF_INET6
};

enum connection_type {
  PS_SOCK_NONE,
  PS_SOCK_STREAM,
  PS_SOCK_DGRAM,
  PS_SOCK_RAW,
  PS_SOCK_RDM,
  PS_SOCK_SEQPACKET
};

struct Proc_Addr {
  char *addr;
  int port;
};

typedef struct {
  int fd;
  enum connection_family family;
  enum connection_type type;
  struct Proc_Addr laddr;
  struct Proc_Addr raddr;
  enum tcp_states status;
} Proc_Connection;

typedef struct {
  int nitems;
  Proc_Connection *connections;
} Proc_ConnectionsInfo;

typedef struct {
  long int soft;
  long int hard;
} Proc_RlimitVal;

typedef struct {
  int nitems;
  Proc *processes;
} ProcInfo;


Proc* process_new(pid_t pid);
pid_t proces_pid(Proc *process);
pid_t process_ppid(Proc *process);
Proc* process_parent(Proc *process);
char* process_username(Proc *process);
Proc_UserIDs* process_uids(Proc *process);
Proc_GroupIDs* process_gids(Proc *p);
Proc_RlimitVal* process_rlimit(Proc *process, enum cpslib_rlimit resource); 
int process_set_rlimit(Proc *process, enum cpslib_rlimit resource, Proc_RlimitVal *value);
int process_num_fds(Proc *process);
ProcInfo* process_children(Proc *process);
// process_children
// process_wait (delete wait_for)
bool process_is_running(Proc *process);
int process_free(Proc *process);
char* process_name(Proc *process);
char* process_exe(Proc *process);
char* process_cmdline(Proc *process);
char* process_terminal(Proc *process);
Proc_IOCounters* process_io_counters(Proc *process);
Proc_CPUTimes* process_cpu_times(Proc *process);
double process_memory_percent(Proc *process);
double process_cpu_percent(Proc *process);
int process_wait(Proc *process, double timeout, bool *is_child);
double process_create_time(Proc *process);
Proc_MemoryInfo* process_memory_info(Proc *process);
Proc_MemoryInfoExt* process_memory_info_ex(Proc *process);
Proc_MemoryMapInfo* process_memory_maps(Proc *process);
char* process_cwd(Proc *process);
Proc_NumCTXSwitches *process_num_ctx_switches(Proc *process);
int process_num_threads(Proc *process);
Proc_ThreadInfo *process_threads(Proc *process);
int process_nice(Proc *process, int *nice_value);
int process_set_nice(Proc *process, int new_nice_value);
Proc_CPUAffinity* process_cpu_affinity(Proc *process);
int process_set_cpu_affinity(Proc *process, Proc_CPUAffinity *affinity);
Proc_IONice* process_ionice(Proc *process);
int process_set_ionice(Proc *process, Proc_IONice *value);
enum proc_status process_status(Proc *process);
Proc_OpenFileInfo *process_open_files(Proc *process);
Proc_ConnectionsInfo *process_connections(Proc* process, enum connection_filter filter);
#endif
