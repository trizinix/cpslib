#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pslib.h"
#include "process.h"
#include "common.h"
// TBD: Check return values

void test_proc_name(Proc *process) {
  char *name = process_name(process);
  printf("Process name: %s\n", name);
  free(name);
}

void test_proc_exe(Proc *process) {
  char *exe = process_exe(process);
  printf("Process executable(absolute path): %s\n", exe);
  free(exe);
}

void test_proc_cmdline(Proc *process) {
  char *cmdline = process_cmdline(process);
  printf("Process cmdline: %s\n", cmdline);
  free(cmdline);
}

void test_proc_terminal(Proc *process) {
  char *term = process_terminal(process);
  printf("Process terminal: %s\n", term);
  free(term);
}

void test_proc_iocounters(Proc *process) {
  Proc_IOCounters *counter = process_io_counters(process);
  printf("\n Process IOCounter:\n");
  printf("Read/Write count: %lu/%lu\n", counter->read_count, counter->write_count);
  printf("Read/Write bytes: %lu/%lu\n", counter->read_bytes, counter->write_bytes);
  free(counter);
}

void test_proc_cputimes(Proc *process) {
  Proc_CPUTimes *times = process_cpu_times(process);
  printf("\n Process CPUTimes:\n");
  printf("User: %f, System: %f\n", times->user, times->system);
  free(times);
}

void test_proc_create_time(Proc *process) {
  double time = process_create_time(process);
  printf("\n Process create time: %f\n", time);
}

void test_proc_memory_info(Proc *process) {
  Proc_MemoryInfo *mem = process_memory_info(process);
  printf("\n Memory Info:\n");
  printf("RSS: %lu, VMS: %lu\n", mem->rss, mem->vms);
  free(mem);
}

void test_proc_memory_info_ex(Proc *process) {
  Proc_MemoryInfoExt *mem = process_memory_info_ex(process);
  printf("\n Memory Info Extended:\n");
  printf("rss: %lu\n", mem->rss);
  printf("vms: %lu\n", mem->vms);
  printf("shared: %lu\n", mem->shared);
  printf("text: %lu\n", mem->text);
  printf("lib: %lu\n", mem->lib);
  printf("data: %lu\n", mem->data);
  printf("dirty: %lu\n", mem->dirty);
  printf("\n\n");
}

/* TBD: Swap output doesn't match expeceted result */
void test_proc_memory_map(Proc *process) {
  Proc_MemoryMapInfo *map_info = process_memory_maps(process);
  int i;
  printf("\n Memory Maps(%d)[showing only 5]:\n", map_info->nitems);
  for(i=0;i<min(5, map_info->nitems);i++) {
    Proc_MemoryMap *cur = map_info->memorymaps+i;
    printf("Map(%s):\n", cur->path);
    printf("rss: %lu\n", cur->rss);
    printf("size: %lu\n", cur->size);
    printf("pss: %lu\n", cur->pss);
    printf("shared_clean: %lu\n", cur->shared_clean);
    printf("shared_dirty: %lu\n", cur->shared_dirty);
    printf("private_clean: %lu\n", cur->private_clean);
    printf("private_dirty: %lu\n", cur->private_dirty);
    printf("referenced: %lu\n", cur->referenced);
    printf("anonymous: %lu\n", cur->anonymous);
    printf("swap: %lu\n\n", cur->swap);
  }
}

void test_proc_cwd(Proc *process) {
  char *cwd = process_cwd(process);
  printf("\ncwd: %s\n", cwd);
  free(cwd);
}

void test_proc_num_ctx_switches(Proc *process) {
  Proc_NumCTXSwitches *switches = process_num_ctx_switches(process);
  printf("\n NumCTXSwitches:\n");
  printf("Voluntary: %lu\n", switches->voluntary);
  printf("Involuntary: %lu\n", switches->involuntary);
  free(switches);
}

void test_proc_num_threads(Proc *process) {
  int threads= process_num_threads(process);
  printf("\n Number of Threads: %d\n", threads);
}

void test_proc_threads(Proc *process) {
  Proc_ThreadInfo *threads = process_threads(process);
  int i;

  printf("\n Threads(%d):\n", threads->nitems);
  for(i = 0;i < threads->nitems; i++) {
    Proc_Thread *cur = threads->threads + i;
    printf("Id=%lu ", cur->id);
    printf("(user_time=%f, system_time=%f)\n",cur->user_time, cur->system_time);
  }
  free(threads);
}

void test_proc_nice(Proc *process) {
  int prio, prio2;
  process_nice(process, &prio);
  printf("\n process priority:\n");
  printf("before: %d\n", prio);
  process_set_nice(process, 4);
  printf("set nice to 4\n");
  process_nice(process, &prio2);
  printf("after: %d\n", prio2);
  process_set_nice(process, prio);
}

void test_proc_affinity(Proc *process) {
  Proc_CPUAffinity *aff2 = NULL, *aff = NULL;
  int i;

  aff = process_cpu_affinity(process);

  printf("\n CPU Affinity(before): ");
  for(i=0;i<aff->nitems;i++) {
    printf("%d ", aff->cpus[i]);
  }
  printf("\n");

  // Set to [0]
  int c = 0;
  Proc_CPUAffinity a;
  a.nitems = 1;
  a.cpus = &c;
  process_set_cpu_affinity(process, &a);

  // After
  aff2 = process_cpu_affinity(process);
  printf("\n CPU Affinity(after): ");
  for(i=0;i<aff2->nitems;i++) {
    printf("%d ", aff2->cpus[i]);
  }
  printf("\n");

  // Restore 
  process_set_cpu_affinity(process, aff);

  free(aff);
  free(aff2);
}

static char* print_ioprio_class(enum ioprio_class c) {
  switch(c) {
  case IOPRIO_CLASS_NONE:
    return strdup("None");
  case IOPRIO_CLASS_RT:
    return strdup("Realtime");
  case IOPRIO_CLASS_BE:
    return strdup("Best effort");
  case IOPRIO_CLASS_IDLE:
    return strdup("Idle");
  }
  return NULL;
}

void test_proc_ionice(Proc *process) {
  Proc_IONice *ionice = process_ionice(process);
  char *desc = print_ioprio_class(ionice->ioclass);
  printf("\n IONice:\n");
  printf("Class: %s, value: %u\n", desc, ionice->value);

/*  ionice->ioclass = IOPRIO_CLASS_BE;
  ionice->value = 3;
  process_set_ionice(process, ionice);*/

  free(desc);
  free(ionice);
}

static char* print_status_class(enum proc_status s) {
  switch(s) {
  case STATUS_UNKNOWN:
    return strdup("Unknown");
  case STATUS_RUNNING:
    return strdup("Running");
  case STATUS_SLEEPING:
    return strdup("Sleeping");
  case STATUS_DISK_SLEEP:
    return strdup("Sleep");
  case STATUS_STOPPED:
    return strdup("Stopped");
  case STATUS_TRACING_STOP:
    return strdup("Tracing stop");
  case STATUS_ZOMBIE:
    return strdup("Zombie");
  case STATUS_DEAD:
    return strdup("Dead");
  case STATUS_WAKE_KILL:
    return strdup("Wake kill");
  case STATUS_WAKING:
    return strdup("Waking");
  case STATUS_IDLE:
    return strdup("Idle");
  case STATUS_LOCKED:
    return strdup("Locked");
  case STATUS_WAITING:
    return strdup("Waiting");
  }
  return NULL;
}

void test_proc_status(Proc *process) {
  enum proc_status s = process_status(process);
  char *status = print_status_class(s);
  printf("Process status: %s\n", status);
  free(status);
}

void test_open_files(Proc *process) {
  Proc_OpenFileInfo *files = process_open_files(process);
  Proc_OpenFile *cur;
  int i;

  printf("\n OpenFiles:\n");
  for(i=0;i < files->nitems;i++) {
    cur = files->files+i;
    printf("Openfile(fd=%d): %s\n", cur->fd, cur->path);
  }
}

int main(int argc, char **argv) {
  pid_t pid;

  if(argc > 2) {
    printf("Usage: proc_driver [pid]\n");
  }
  if(argc == 2) {
    pid = (pid_t)strtol(argv[1], NULL, 10);
  } else {
    pid = getpid();
  }

  struct stat sts;
  char procfile[50];
  sprintf(procfile, "/proc/%d/status", pid);
  if (stat(procfile, &sts) == -1 && errno == ENOENT) {
    fprintf(stderr, "Process with pid '%ld' doesn't exist\nAborting\n", (long)pid);
    exit(1);
  }
  
  Proc *process = process_new(pid);

//  test_proc_name(process);
//  test_proc_exe(process);
//  test_proc_cmdline(process);
//  test_proc_terminal(process);
//  test_proc_iocounters(process);
//  test_proc_cputimes(process);
//  test_proc_create_time(process);
//  test_proc_memory_info(process);
//  test_proc_memory_info_ex(process);
//  test_proc_memory_map(process);
//  test_proc_cwd(process);  
//  test_proc_num_ctx_switches(process);
//  test_proc_num_threads(process);
//  test_proc_threads(process);
//  test_proc_nice(process);
//  test_proc_affinity(process);
//  test_proc_ionice(process);
//  test_proc_status(process);
  test_open_files(process);

  process_free(process);
  
//  while ( getchar() != '\n');
  return 0;
}
