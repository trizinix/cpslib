#ifndef __pslib_process_h
#define __pslib_process_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

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

typedef struct Proc Proc;
int process_new(Proc *process, int pid);
int process_free(Proc *process);
int process_name(Proc *process, char *name);
int process_exe(Proc *process, char *exe);
int process_cmdline(Proc *process, char *cmdline);
int process_terminal(Proc *process, char *terminal);
int process_io_counters(Proc *process, Proc_IOCounters *counters);
int process_cpu_times(Proc *process,  Proc_CPUTimes *cpu_times);
int process_wait(Proc *process, double timeout, bool *is_child);
int process_create_time(Proc *process, double *create_time);
int process_memory_info(Proc *process, Proc_MemoryInfo *meminf);
int process_memory_info_ex(Proc *process, Proc_MemoryInfoExt *meminfo_ext);
Proc_MemoryMapInfo *process_memory_maps(Proc *process);
char *process_cwd(Proc *process);
Proc_NumCTXSwitches *process_num_ctx_switches(Proc *process);
int process_num_threads(Proc *process);
Proc_ThreadInfo *process_threads(Proc *process);
int process_nice(Proc *process, int *nice_value);
int process_set_nice(Proc *process, int new_nice_value);
#endif
