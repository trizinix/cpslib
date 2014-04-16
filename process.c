#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <linux/unistd.h>
#include <limits.h>
#include <mntent.h>
#include <pwd.h>
#include <sched.h>
#include <search.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>


#include "pslib.h"
#include "process.h"
#include "common.h"
#include "deps/hash/hash.h"

struct Proc {
  pid_t pid;
  bool gone;
  Proc_CPUTimes *last_proc_cpu_times;
  double last_sys_cpu_times;
};
/*
static inline int popcount(unsigned int x)
{
  int a = 0;
  int b = (int)x
  for (; b > 0; b &= b -1) a++;
  return a;
  }*/

/* Renduntant function */
static long get_clock_ticks() {
  static long ret;
  if(ret == 0) {
    ret = sysconf(_SC_CLK_TCK);
  }
  return ret;
}

static long get_page_size() {
  static long ret;
  if(ret == 0) {
    ret = sysconf(_SC_PAGE_SIZE);
  }
  return ret;
}

/* Private functions */

static double boot_time()
{
  static double btime;
  if(btime > 0) return btime;

  FILE *fp = fopen("/proc/stat", "r");
  char *line = (char *)calloc(200, sizeof(char));
  char *tmp = NULL;
  int ret = -1;
  check(fp, "Couldn't open /proc/stat");
  check_mem(line);

  while (fgets(line, 150, fp)) {
    if (strncmp(line, "btime", 5) == 0) {
      strtok(line, " ");
      tmp = strtok(NULL, "\n");
      ret = strtoul(tmp, NULL, 10);
      break;
    }
  }
  check(ret != -1, "Couldn't find 'btime' line in /proc/stat");
  fclose(fp);
  free(line);

  btime = ret;
  return ret;

error:
  if (fp) fclose(fp);
  if (line) free(line);
  return -1;
}


/* Public functions */

Proc* process_new(pid_t pid) {
  Proc *p = malloc(sizeof(Proc));
  check_mem(p);
  p->pid = pid;
  p->last_proc_cpu_times = NULL;
  p->last_sys_cpu_times = -1.0;
  return p;
error:
  return NULL;
}

int process_free(Proc* p) {
  free(p);
  return 0;
}

pid_t process_pid(Proc *p) {
  return p->pid;
}

pid_t process_ppid(Proc *p) {
  FILE *fp = NULL;
  pid_t ppid = -1;
  char *tmp;
  char procfile[50];

  sprintf(procfile,"/proc/%d/status", p->pid);
  fp = fopen(procfile,"r");
  check(fp, "Couldn't open process status file");
  tmp = grep_awk(fp, "PPid", 1, ":");
  ppid = (tmp ? (int)strtoul(tmp, NULL, 10) : -1);

  check(ppid != -1, "Couldnt' find Ppid in process status file");
  fclose(fp);
  free(tmp);

  return ppid;
 error:
  if (fp) fclose(fp);
  return -1;
}

Proc* process_parent(Proc *p) {
  pid_t ppid = process_ppid(p);
  Proc *ret = process_new(ppid);
  return ret;
}


static unsigned int *
get_ids(unsigned int pid, const char *field)
/* field parameter is used to determine which line to parse (Uid or Gid) */
{
  FILE *fp = NULL;
  char *tmp;
  char procfile[50];
  char line[400];
  unsigned int* retval = NULL;

  sprintf(procfile,"/proc/%d/status", pid);
  fp = fopen(procfile,"r");
  check(fp, "Couldn't open process status file");
  while (fgets(line, 399, fp) != NULL) {
    if (strncmp(line, field, 4) == 0) {
      retval = (unsigned int *)calloc(3, sizeof(unsigned int));
      check_mem(retval);
      tmp = strtok(line, "\t");
      tmp = strtok(NULL, "\t");
      retval[0] = strtoul(tmp, NULL, 10); /* Real UID */
      tmp = strtok(NULL, "\t");
      retval[1] = strtoul(tmp, NULL, 10); /* Effective UID */
      tmp = strtok(NULL, "\t");
      retval[2] = strtoul(tmp, NULL, 10); /* Saved UID */
      break;
    }
  }

  check(retval != NULL, "Couldnt' find Uid in process status file");
  fclose(fp);

  return retval;
 error:
  if (fp) fclose(fp);
  return NULL;
}

Proc_UserIDs *process_uids(Proc *p) {
  Proc_UserIDs *ret;
  unsigned int *uids = NULL;

  uids = get_ids(p->pid, "Uid:");
  check(uids != NULL, "Couldn't get uids");

  ret = calloc(1, sizeof(Proc_UserIDs));
  ret->uid = uids[0];
  ret->euid = uids[1];
  ret->suid = uids[2];

  free(uids);
  return ret;
error:
  if(uids) free(uids);
  return NULL;
}

Proc_GroupIDs *process_gids(Proc *p) {
  Proc_GroupIDs *ret;
  unsigned int *gids = NULL;

  gids = get_ids(p->pid, "Gid:");
  check(gids != NULL, "Couldn't get gids");

  ret = calloc(1, sizeof(Proc_GroupIDs));
  ret->gid = gids[0];
  ret->egid = gids[1];
  ret->sgid = gids[2];

  free(gids);
  return ret;
error:
  if(gids) free(gids);
  return NULL;
}

char* process_username(Proc *p) {
  struct passwd *pwd = NULL;
  char *username = NULL;
  unsigned int uid;
  Proc_UserIDs *uids;

  uids = process_uids(p);
  check(uids != NULL, "Couldn't get uids");
  uid = uids->uid;
  pwd = getpwuid(uid);
  check(pwd, "Couldn't access passwd database for entry %d", uid);
  username = strdup(pwd->pw_name);
  check(username, "Couldn't allocate memory for name");

  free(uids);
  return username;
 error:
  if(uids) free(uids);
  return NULL;
}

Proc_RlimitVal* process_rlimit(Proc *p, enum cpslib_rlimit res) {
  struct rlimit limits;
  int r;
  Proc_RlimitVal *ret = NULL;

  r = prlimit(p->pid, (int)res, NULL, &limits);
  check(r != -1, "Couldn get rlimit");

  ret = calloc(1, sizeof(Proc_RlimitVal));
  check_mem(ret);

  ret->soft = limits.rlim_cur;
  ret->hard = limits.rlim_max;

  return ret;
error:
  if(ret) free(ret);
  return NULL;
}

int process_set_rlimit(Proc *p, enum cpslib_rlimit res, Proc_RlimitVal *val) {
  struct rlimit new, old;
  int ret;

  new.rlim_cur = val->soft;
  new.rlim_max = val->hard;
  ret = prlimit(p->pid, (int)res, &new, &old);
  check(ret != -1, "Couldn't set rlimit");

  return 0;
error:
  return -1;
}

int process_num_fds(Proc *p) {
  int count;
  DIR* d;
  struct dirent *dir;
  char procfile[50];

  sprintf(procfile, "/proc/%d/fd", p->pid);
  d = opendir(procfile);
  check(d != NULL, "Couldn't open process fd directory");

  count = 0;
  while ((dir = readdir(d)) != NULL) {
    count++;
  }

  closedir(d);
  return count;

error:
  if(d) closedir(d);
  return -1;
}

char* process_name(Proc* p) {
  FILE *fp = NULL;
  char *tmp, *ret = NULL;
  char procfile[50];
  char line[350];

  sprintf(procfile,"/proc/%d/stat", p->pid);
  fp = fopen(procfile,"r");
  check(fp, "Couldn't open process stat file");
  fgets(line, 300, fp);
  fclose(fp);

  tmp = strtok(line, " ");
  tmp = strtok(NULL, " "); /* Name field */
  tmp = squeeze(tmp, "()");

  ret = strdup(tmp);
  return ret;
  return 0;
 error:
  if (fp) fclose(fp);
  return NULL;
}

char *process_exe(Proc* p) {
  FILE *fp = NULL;
  char *tmp = NULL;
  char procfile[50];
  ssize_t r;
  unsigned int bufsize = 1024;
  struct stat buf;

  sprintf(procfile,"/proc/%d/exe", p->pid);
  tmp = calloc(bufsize, sizeof(char));
  check_mem(tmp);
  r = readlink(procfile, tmp, bufsize - 1);
  if (r == -1 && errno == ENOENT) {
    if (lstat(procfile, &buf) == 0) {
      debug("Probably a system process. No executable");
      strcpy(tmp, "");
      return tmp;
    } else {
      sentinel("No such process");
    }
  }
  check(r != -1, "Couldn't expand symbolic link");
  while(r == bufsize -1 ) {
    /* Buffer filled. Might be incomplete. Increase size and try again. */
    bufsize *= 2;
    tmp = realloc(tmp, bufsize);
    r = readlink(procfile, tmp, bufsize - 1);
    check(r != -1, "Couldn't expand symbolic link");
  }
  tmp[r] = '\0';
  return tmp;

 error:
  if (fp) fclose(fp);
  if (tmp) free(tmp);
  return NULL;
}


char* process_cmdline(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t size = 0;
  int r;

  sprintf(procfile,"/proc/%d/cmdline", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process cmdline file");
  r = getline(&contents, &size, fp); /*size argument unused since *contents is NULL */
  check(r != -1, "Couldn't read command line from /proc");
  fclose(fp);
  return contents;

 error:
  if (fp) fclose(fp);
  if (contents) free(contents);
  return NULL;
}

char* get_from_terminal_map(unsigned int tty_nr) {
  DIR *d = NULL;
  struct dirent *dir;
  struct stat s;
  int r = 0;
  char tmp[100];
  char *ret = NULL;

  d = opendir("/dev");
  check(d, "Couldn't open dir /dev");

  while((dir = readdir(d)) != NULL) {
    if(strncmp(dir->d_name, "tty", 3) == 0) {
      strncpy(tmp, "/dev/", 10);
      strncat(tmp, dir->d_name, 80);

      r = stat(tmp, &s);
      if(r == -1) continue;

      if(s.st_rdev == tty_nr) {
	ret = strdup(tmp);
	break;
      }
    }
  }

  closedir(d);
  d = opendir("/dev/pts");
  check(d, "Couldn't open dir /dev/pts");

  while((dir = readdir(d)) != NULL) {
    if(strncmp(dir->d_name, ".", 1) == 0) continue;
    strncpy(tmp, "/dev/pts/", 10);
    strncat(tmp, dir->d_name, 80);
    r = stat(tmp, &s);
    if(r == -1) continue;

    if(s.st_rdev == tty_nr && ret == NULL) {
      ret = strdup(tmp);
      break;
    }
  }
  closedir(d);

  return ret;
error:
  if(d) closedir(d);
  if(ret) free(ret);
  return NULL;
}

char* process_terminal(Proc *p) {
  FILE *fp = NULL;
  int i, r;
  size_t size = 0;
  char procfile[50];
  char *line = NULL, *tmp = NULL;
  char *ret = NULL;
  unsigned int tty_nr;

  sprintf(procfile,"/proc/%d/stat", p->pid);
  fp = fopen(procfile, "rb");
  check(fp, "Couldn't open process stat file");

  r = getline(&line, &size, fp);
  check(r > 0, "Couldn't read from process stat file");

  tmp = strtok(line, " ");
  for(i = 0;i < 6;i++) { /* Skip 6 values and get the 7th*/
    tmp = strtok(NULL, " ");
  }
  tty_nr = strtoul(tmp, NULL, 10);

  ret = get_from_terminal_map(tty_nr);
  if(ret == NULL) ret = strdup("");

  return ret;

 error:
  if (fp) fclose(fp);
  if (tmp) free(tmp);
  if (ret) free(ret);
  return NULL;
}

/* TBD: make sure we actually read the properties and didn't just
   return 0 because it was set to 0 in calloc */
Proc_IOCounters* process_io_counters(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;
  Proc_IOCounters *ret = NULL;

  ret = calloc(1, sizeof(Proc_IOCounters));
  check_mem(ret);

  sprintf(procfile, "/proc/%d/io", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process io file");

  ret->read_count = ret->write_count = ULONG_MAX;
  while((r = getline(&contents, &n, fp)) > 0) {
    if(strncmp(contents, "syscr", 5) == 0) {
      ret->read_count = strtoul(contents+7, NULL, 10);
    }
    else if(strncmp(contents, "syscw", 5) == 0) {
      ret->write_count = strtoul(contents+7, NULL, 10);
    }
    else if(strncmp(contents, "read_bytes", 10) == 0) {
      ret->read_bytes = strtoul(contents+12, NULL, 10);
    }
    else if(strncmp(contents, "write_bytes", 11) == 0) {
      ret->write_bytes = strtoul(contents+13, NULL, 10);
    }
    free(contents);
    contents = NULL;
    n = 0;
  }
  fclose(fp);

  return ret;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return NULL;
}

Proc_CPUTimes* process_cpu_times(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r, i = 0;
  unsigned long ticks;
  Proc_CPUTimes *ret = NULL;

  ret = calloc(1, sizeof(Proc_CPUTimes));
  sprintf(procfile, "/proc/%d/stat", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process io file");
  r = getline(&contents, &n, fp);
  check(r > 0, "Couldn't read from process stat file");

  char *pos = contents;
  while(*pos != ')') pos++;
  pos += 2; /* Skip pid (exe) */

  pos = strtok(pos, " ");
  while(pos != NULL && i < 11) {
    i++;
    pos = strtok(NULL, " ");
  } /* Skip 11 values */

  ticks = get_clock_ticks();
  ret->user = (double)strtoul(pos, &pos, 10) / ticks;
  ret->system = (double)strtoul(pos+1, NULL, 10) / ticks;

  free(contents);
  fclose(fp);
  return ret;

error:
  if(contents) free(contents);
  if(fp) free(fp);
  if(ret) free(ret);
  return NULL;
}
/* Return 0.0 the first time it is called */
double process_cpu_percent(Proc *p) {
  int num_cpus = cpu_count(true);
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  double timer = tp.tv_sec + 10e-9*tp.tv_nsec;
  timer *= num_cpus;

  double st1 = p->last_sys_cpu_times;
  Proc_CPUTimes *pt1 = p->last_proc_cpu_times;

  double st2 = timer;
  Proc_CPUTimes *pt2 = process_cpu_times(p);

  if(st1 < 0 || pt1 == NULL) {
    p->last_sys_cpu_times = st2;
    p->last_proc_cpu_times = pt2;
    return 0.0;
  }

  double delta_proc = (pt2->user - pt1->user) + (pt2->system - pt1->system);
  double delta_time = st2 - st1;
  double overall_percent;
  if(delta_time <= 0)
    overall_percent = 0.0;
  else
    overall_percent = ((delta_proc/delta_time) * 100) * num_cpus;

  return overall_percent;
}

/* t1 > t2 => 1, t1 == t2 => 0, t1 < t2 => -1 */
static int cmp_timespec(struct timespec *t1, struct timespec *t2) {
  if(t1->tv_sec == t2->tv_sec) {
    if(t1->tv_nsec == t2->tv_nsec) return 0;
    return (t1->tv_nsec > t2->tv_nsec ? 1 : -1);
  }
  return (t1->tv_sec > t2->tv_sec ? 1 : -1);
}

/* checks timeout and waits delay  */
static int check_timeout(struct timespec *delay, struct timespec *stop_at) {
  if(stop_at != NULL) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now); /* TBD: check reutrn value */
    if(cmp_timespec(&now,stop_at) >= 0) {
      errno = ETIMEDOUT;
      return -1;
    }
  }
  nanosleep(delay, NULL);
  // chango delay to min(delay*2, 0.04sec)
  delay->tv_sec *= 2;
  delay->tv_sec *= 2;
  if(delay->tv_sec + delay->tv_nsec*1e-9 > 0.04) {
    delay->tv_sec = 0;
    delay->tv_nsec = 4*1e7;
  }
  return 0;
}

static bool pid_exists(pid_t pid) {
  int ret;
  if(pid < 0)
    return false;

  // send signal 0(does nothing) to determine if the process exists.
  ret = kill(pid, 0);
  if(ret < 0) {
    return (errno == EPERM);
  }
  return true;
}

// Untested
static int proc_wait_pid(pid_t pid, struct timespec *timeout, bool* child) {
  struct timespec delay;
  struct timespec stop_at;
  if(timeout != NULL) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now); /* TBD: check reutrn value */
    stop_at.tv_sec = now.tv_sec + timeout->tv_sec;
    stop_at.tv_nsec = now.tv_nsec + timeout->tv_nsec;
  }

  delay.tv_sec = 0;
  delay.tv_nsec = 1e5; // 0.0001 sec

  while(true) {
    int status;
    pid_t retpid = waitpid(pid, &status, WNOHANG);
    if(retpid == -1) {
      if(errno == EINTR) {
	if(check_timeout(&delay, &stop_at) < 0) {
	  return -1;
	}
	continue;
      }
      else if(errno == ECHILD) {
	/* This has two meanings:
	 * - pid is not a child of this process
	 *   we keep polling until it's gone
	 * - pid never existed in the first place
	 * In both case we will return None(? what in C) */
	*child = false;
	while(true) {
	  if(pid_exists(pid)) {
	    if(check_timeout(&delay, &stop_at) < 0) {
	      return -1;
	    }
	  }
	  else
	    return 0;
	}
      }
      else {
	return -1;
      }
      // endif retpid == -1
    } else {
      if(retpid == 0) {
	// pid is still running
	if(check_timeout(&delay, &stop_at) < 0) {
	  return -1;
	}
	continue;
      }
      // process exited due to a signal; return the integer of that signal
      if(WIFSIGNALED(status) == true) {
	return WTERMSIG(status);
      }
      else if(WIFEXITED(status) == true) {
	return WEXITSTATUS(status);
      }
      else {
	// should never happen
	return -1;
      }
    }
  }

  return 0;
}

// Untested
int process_wait(Proc *p, double t, bool *is_child) {
  struct timespec timeout;
  int ret;

  timeout.tv_sec = (int)t;
  timeout.tv_nsec = (int)(1e9*(t - timeout.tv_sec));
  *is_child = true;
  ret = proc_wait_pid(p->pid, &timeout, is_child);
  return ret;
}


double process_create_time(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r, i = 0;
  double ret;

  sprintf(procfile,"/proc/%d/stat", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process stat file");
  r = getline(&contents, &n, fp);
  check(r > 0, "Couldn't parse process stat file");

  char *pos = contents;
  while(*pos != ')') pos++;
  pos += 2; /* Skip pid (exe) */

  pos = strtok(pos, " ");
  while(pos != NULL && i < 19) {
    i++;
    pos = strtok(NULL, " ");
  } /* Skip 19 values */

  double ticks = get_clock_ticks();
  double proc_time = (double)strtol(pos, NULL, 10);
  ret = (proc_time / ticks) + boot_time();

  fclose(fp);
  free(contents);
  return ret;

 error:
  if (fp) fclose(fp);
  if (contents) free(contents);
  return 0.0;
}

static unsigned long total_memory() {
 static unsigned long total_phys_memory = 0;

  if(total_phys_memory != 0) {
    return total_phys_memory;
  }

  VmemInfo mem;
  int ret = virtual_memory(&mem);
  check(ret != -1, "Couldn't get total system memory");
  total_phys_memory = mem.total;

  return total_phys_memory;

error:
  return -1;
}

double process_memory_percent(Proc *p) {
  Proc_MemoryInfo *mem = process_memory_info(p);
  unsigned long rss = mem->rss;
  unsigned long total = total_memory();

  free(mem);
  if(total == 0)
    return 0.0;
  return (double)rss/total;
}

static bool is_digit(const char *str) {
  while(*str != '\0') {
    if(!isdigit(*str)) return false;
  }
  return true;
}

static int get_pids(int** pids) {
  DIR *d = NULL;
  struct dirent *dir = NULL;
  int *ret = NULL;
  d = opendir("/proc");
  check(d, "Couldn't open /proc");

  ret = calloc(1, sizeof(int));
  int i = 0;

  while ((dir = readdir(d)) != NULL) {
    if(!is_digit(dir->d_name))
      continue;

    ret[i] = (int)strtol(dir->d_name, NULL, 10);
    i++;
    ret = realloc(ret, (i+1)*sizeof(int));
  }
  closedir(d);

  *pids = ret;

error:
  if(d) closedir(d);
  if(ret) free(ret);
  return -1;
}

/* TBD error checking */
ProcInfo* process_children(Proc *p) {
  static hash_t *pmap = NULL;
  if(pmap == NULL)
    pmap = hash_new();

  char tmp[50];
  ProcInfo *ret = calloc(1, sizeof(ProcInfo));

  // fill a
  int* pids;
  int num_pids = get_pids(&pids);
  int i;
  hash_t *a = hash_new();
  for(i = 0;i < num_pids;i++) {
    sprintf(tmp, "%d", pids[i]);
    hash_set(a, tmp, (void*)true);
  }

  // fill b
  hash_t *b = hash_new();
  hash_each_key(pmap, {
      hash_set(b, (char *)key, (void*)true);
    });

  // fill new_pids and gone_pids
  hash_t *new_pids = hash_new();


  // new_pids = all in a but not in b
  hash_each_key(a, {
      if(!hash_has(b, (char *)key)) {
      hash_set(new_pids, (char *)key, (void*)true);
    }
  });

  // gone_pids = all in b but not in a
  hash_each_key(b, {
    if(!hash_has(a, (char *)key)) {
      // TBD free process
      hash_del(pmap, (char *)key);
    }
  });

  // Processes already in pmap
  int j = 0;
  Proc* proc;
  hash_each_val(pmap, {
      proc = (Proc *)val;
      if(!process_is_running(proc)) {
	ret->processes = process_new(proc->pid);
	// TBD: Free
      } else 
	ret->processes[j] = *proc;
      j++;
      ret->processes = realloc(ret->processes, (j+1)*sizeof(Proc *));
    });

  // New processes
  Proc *new_proc;
  hash_each_key(new_pids, {
      new_proc = process_new((int)strtol(key, NULL, 10));
      ret->processes[j] = *new_proc;
      free(proc);

      j++;
      ret->processes = realloc(ret->processes, (j+1)*sizeof(Proc *));
    });

  return ret;
}

int process_send_signal(Proc *p, int sig) {
  int ret = kill(p->pid, sig);
  if(ret == -1) {
    if(errno == ESRCH) {
      p->gone = true;
    }
  }

  return ret;
}

int process_suspend(Proc *p) {
  return process_send_signal(p, SIGSTOP);
}

int process_resume(Proc *p) {
  return process_send_signal(p, SIGCONT);
}

int process_terminate(Proc *p) {
  return process_send_signal(p, SIGTERM);
}

int process_kill(Proc *p) {
  return process_send_signal(p, SIGKILL);
}

bool process_is_running(Proc *p) {
  /* TBD: Implement */
  return true;
}

Proc_MemoryInfo* process_memory_info(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;
  Proc_MemoryInfo *ret = calloc(1, sizeof(Proc_MemoryInfo));

  sprintf(procfile, "/proc/%d/statm", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process statm file");
  r = getline(&contents, &n, fp);
  check(r > 0, "Couldn't parse process statm file");

  char *pos = contents;
  ret->vms = strtoul(pos, &pos, 10) * get_page_size();
  ret->rss = strtoul(pos, NULL, 10) * get_page_size();

  free(contents);
  fclose(fp);
  return ret;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return NULL;
}

Proc_MemoryInfoExt* process_memory_info_ex(Proc *p) {
    FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;
  Proc_MemoryInfoExt *ret = NULL;

  sprintf(procfile, "/proc/%d/statm", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process statm file");
  r = getline(&contents, &n, fp);
  check(r > 0, "Couldn't parse process statm file");

  ret = calloc(1, sizeof(Proc_MemoryInfoExt));
  char *pos = contents;
  ret->vms = strtoul(pos, &pos, 10) * get_page_size();
  ret->rss = strtoul(pos, &pos, 10) * get_page_size();
  ret->shared = strtoul(pos, &pos, 10) * get_page_size();
  ret->text = strtoul(pos, &pos, 10) * get_page_size();
  ret->lib = strtoul(pos, &pos, 10) * get_page_size();
  ret->data = strtoul(pos, &pos, 10) * get_page_size();
  ret->dirty = strtoul(pos, NULL, 10) * get_page_size();

  free(contents);
  fclose(fp);
  return ret;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return NULL;
}

struct _smaps_header {
  char *addr;
  char *perms;
  char *offset;
  char *dev;
  char *inode;
  char *path;
};
void _free_smaps_header(struct _smaps_header *s) {
  free(s->addr);
  free(s->perms);
  free(s->offset);
  free(s->dev);
  free(s->inode);
  free(s->path);
}

static int parse_smaps_header(char *line, struct _smaps_header *header) {
  char *pos = line;

  pos = strtok(pos, " ");
  check(pos != NULL, "");
  header->addr = strdup(pos);

  pos = strtok(NULL, " ");
  check(pos != NULL, "");
  header->perms = strdup(pos);

  pos = strtok(NULL, " ");
  check(pos != NULL, "");
  header->offset = strdup(pos);

  pos = strtok(NULL, " ");
  check(pos != NULL, "");
  header->dev = strdup(pos);

  pos = strtok(NULL, " ");
  check(pos != NULL, "");
  header->inode = strdup(pos);

  pos = strtok(NULL, " \n");
  if(!pos) {
    header->path = strdup("[anon]");
  } else {
    header->path = strdup(pos);
  }
  return 0;

error:
  return -1;
}

// Don't change index of elements
const char* __mmap_base_fields[] = {
  "path", "rss", "size", "pss", "shared_clean", "shared_dirty",
  "private_clean", "private_dirty", "referenced", "anonymous", "swap"
};

static int parse_smaps_body_line(char *line, unsigned long int* ret) {
  char *pos = line;
  size_t i;
  pos = strtok(pos, " ");
  check(pos != NULL, "");

  for(i = 0;i < NELEMS(__mmap_base_fields);i++) {
    if(strncasecmp(pos, __mmap_base_fields[i], strlen(__mmap_base_fields[i])) == 0) {
      pos = strtok(NULL, " ");
      *ret = strtoul(pos, NULL, 10);
      return (int)i;
    }
  }

error:
  return -1;
}

/* TBD: Make sure errno is set apropriatly */
/* TBD: Align header detection with psutil */
Proc_MemoryMapInfo* process_memory_maps(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;
  struct _smaps_header header;
  Proc_MemoryMap *current;
  Proc_MemoryMapInfo *ret = calloc(1, sizeof(Proc_MemoryMapInfo));
  ret->memorymaps = calloc(1, sizeof(Proc_MemoryMap));
  current = ret->memorymaps;

  sprintf(procfile, "/proc/%d/smaps", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process smap file");

  r = getline(&contents, &n, fp);
  check(r != -1, "Couldn't read from process smap file");
  parse_smaps_header(contents, &header);
  free(contents);
  contents = NULL;
  n = 0;

  while((r = getline(&contents, &n, fp)) > 0) {
    if(isdigit(contents[0])) {
      current->path = strdup(header.path);
      ret->nitems++;
      ret->memorymaps = realloc(ret->memorymaps, ret->nitems*sizeof(Proc_MemoryMap));
      current = ret->memorymaps + (ret->nitems-1);
      _free_smaps_header(&header);

      parse_smaps_header(contents, &header);
    } else {
      int idx;
      unsigned long int val;
      idx = parse_smaps_body_line(contents, &val);

      switch(idx) {
      case 1:
	current->rss = val;
	break;
      case 2:
	current->size = val;
	break;
      case 3:
	current->pss = val;
	break;
      case 4:
	current->shared_clean = val;
	break;
      case 5:
	current->private_clean = val;
	break;
      case 6:
	current->private_dirty = val;
	break;
      case 7:
	current->referenced = val;
	break;
      case 8:
	current->anonymous = val;
	break;
      case 9:
	current->swap = val;
	break;
	//default:
	//check(false, "Internal Error, should never happen");
      }
    }

    free(contents);
    contents = NULL;
    n = 0;
  }
  fclose(fp);
  return ret;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return NULL;
}

char *process_cwd(Proc *p) {
  FILE *fp = NULL;
  char *tmp = NULL;
  char procfile[50];
  ssize_t r;
  unsigned int bufsize = 1024;

  sprintf(procfile,"/proc/%d/cwd", p->pid);
  tmp = calloc(bufsize, sizeof(char));
  check_mem(tmp);
  r = readlink(procfile, tmp, bufsize - 1);
  check(r != -1, "Couldn't expand symbolic link");
  while(r == bufsize -1 ) {
    /* Buffer filled. Might be incomplete. Increase size and try again. */
    bufsize *= 2;
    tmp = realloc(tmp, bufsize);
    r = readlink(procfile, tmp, bufsize - 1);
    check(r != -1, "Couldn't expand symbolic link");
  }
  tmp[r] = '\0';
  return tmp;
 error:
  if (fp) fclose(fp);
  if (tmp) free(tmp);
  return NULL;
}

Proc_NumCTXSwitches *process_num_ctx_switches(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *line = NULL;
  int r;
  size_t n = 0;
  Proc_NumCTXSwitches *ret = calloc(1, sizeof(Proc_NumCTXSwitches));

  sprintf(procfile,"/proc/%d/status", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process status file");

  while((r = getline(&line, &n, fp)) > 0) {
    if(strncmp(line, "voluntary_ctxt_switches", 23) == 0) {
      ret->voluntary = strtoul(line+24, NULL, 10);
    }
    else if(strncmp(line, "nonvoluntary_ctxt_switches", 26) == 0) {
      ret->involuntary = strtoul(line+27, NULL, 10);
    }

    free(line);
    line = NULL;
    n = 0;
  }
  return ret;

 error:
  if (fp) fclose(fp);
  if (line) free(line);
  return NULL;
}

int process_num_threads(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *line = NULL;
  int r, ret = -1;
  size_t n = 0;

  sprintf(procfile,"/proc/%d/status", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process status file");

  while((r = getline(&line, &n, fp)) > 0) {
    if(strncmp(line, "Threads:", 8) == 0) {
      ret  = strtoul(line+8, NULL, 10);
    }

    free(line);
    line = NULL;
    n = 0;
  }
  return ret;

 error:
  if (fp) fclose(fp);
  if (line) free(line);
  return -1;
}

static int comp(const void *a,const void *b)
{
  const unsigned long int *na = (const unsigned long *)a;
  const unsigned long int *nb = (const unsigned long *)b;
  if (*na==*nb)
    return 0;
  else
    if (*na < *nb)
        return -1;
     else
      return 1;
}

Proc_ThreadInfo *process_threads(Proc *p) {
  FILE *fp = NULL;
  DIR *d = NULL;
  char *contents = NULL;
  char procfile[50];
  struct dirent *dir;
  unsigned long int *thread_ids = NULL;
  Proc_ThreadInfo *ret;
  Proc_Thread *cur_thread;
  int num_threads, threads_missed, i, j;
  unsigned long int ticks;

  thread_ids = calloc(1, sizeof(unsigned long int));
  ret = calloc(1, sizeof(Proc_ThreadInfo));

  sprintf(procfile,"/proc/%d/task", p->pid);
  d = opendir(procfile);
  check(d, "Couldn't list threads");

  i = 0;
  while ((dir = readdir(d)) != NULL) {
    thread_ids = realloc(thread_ids, (i+1)*sizeof(unsigned long int));
    check_mem(thread_ids);
    thread_ids[i] = strtoul(dir->d_name, NULL, 10);
    if(thread_ids[i] == 0 || thread_ids[i] == ULONG_MAX) {
      continue; // .,.. directories
    }
    i++;
  }

  num_threads = i;
  closedir(d); d=NULL;

  //sort dirs
  qsort(thread_ids, num_threads, sizeof(unsigned long int), comp);


  ret->threads = calloc(num_threads, sizeof(Proc_Thread));
  cur_thread = ret->threads;
  threads_missed = 0;

  for(i = 0;i < num_threads;i++) {
    size_t n = 0;
    int r;

    sprintf(procfile, "/proc/%d/task/%lu/stat", p->pid, thread_ids[i]);

    fp = fopen(procfile, "r");
    if(fp == NULL && errno == ENOENT) {
      threads_missed++;
      continue;
    } else {
      check(fp, "Couldn't open thread stat file");
    }
    r = getline(&contents, &n, fp);
    check(r > 0, "Couldn't parse process stat file");

    char *pos = contents;
    while(*pos != ')') pos++;
    pos += 2; /* Skip pid (exe) */

    pos = strtok(pos, " ");
    j = 0;
    while(pos != NULL && j < 11) {
      j++;
      pos = strtok(NULL, " ");
    } /* Skip 11 values */

    ticks = get_clock_ticks();
    cur_thread->id = thread_ids[i-threads_missed];
    cur_thread->user_time = (double)strtoul(pos, &pos, 10) / ticks;
    cur_thread->system_time = (double)strtoul(pos+1, NULL, 10) / ticks;

    cur_thread++;

    free(contents); contents = NULL;
    fclose(fp); fp = NULL;
  }
  free(thread_ids);

  ret->nitems = num_threads - threads_missed;
  ret->threads = realloc(ret->threads, ret->nitems*sizeof(Proc_Thread));

  return ret;
error:
  if(d) closedir(d);
  if(thread_ids) free(thread_ids);
  if(contents) free(contents);
  if(fp) fclose(fp);
  return NULL;
}

int process_nice(Proc *p, int *ret) {
    int priority;
    errno = 0;

    priority = getpriority(PRIO_PROCESS, p->pid);
    if (errno != 0) {
      return -1;
    }
    *ret = priority;
    return 0;
}

int process_set_nice(Proc *p, int prio) {
    int retval;
    retval = setpriority(PRIO_PROCESS, p->pid, prio);
    if (retval == -1) {
      return -1;
    }
    return 0;
}

Proc_CPUAffinity* process_cpu_affinity(Proc *p) {
  cpu_set_t mask;
  Proc_CPUAffinity *ret;
  int i, j = 0;

  if(sched_getaffinity(p->pid, sizeof(mask), &mask) == -1) {
    return NULL;
  }

  ret = calloc(1, sizeof(Proc_CPUAffinity));
  check_mem(ret);

  ret->cpus = calloc(ret->nitems, sizeof(int));
  check_mem(ret->cpus);

  ret->nitems = CPU_COUNT_S(sizeof(mask), &mask);

  for(i = 0;i < CPU_SETSIZE;i++) {
    if(CPU_ISSET(i, &mask)) {
      ret->cpus[j] = i;
      j++;
    }
  }

  return ret;

error:
  if(ret->cpus) free(ret->cpus);
  if(ret) free(ret);
  return NULL;
}

int process_set_cpu_affinity(Proc *p, Proc_CPUAffinity *aff) {
  cpu_set_t mask;
  int i;
  CPU_ZERO(&mask);

  // Convert int list to bitmask
  for(i = 0;i < aff->nitems; i++) {
    CPU_SET(aff->cpus[i], &mask);
  }

  if(sched_setaffinity(p->pid, sizeof(mask), &mask) == -1) {
    // TBD: Look which cpu in mask didn't exist
    return -1;
  }
  return 0;
}

// TBD: Introduce defines when ionice is not available(linux < 2.6.x)
// TBD: make these function more readable
Proc_IONice* process_ionice(Proc *p) {
  int ioprio;
  Proc_IONice *ret = calloc(1, sizeof(Proc_IONice));
  check_mem(ret);

  ioprio = syscall(__NR_ioprio_get, 1, p->pid);
  ret->ioclass = (enum ioprio_class)(ioprio >> 13);
  ret->value = ioprio & ((1UL << 13)-1);
  return ret;

error:
  return NULL;
}

int process_set_ionice(Proc *p, Proc_IONice *n) {
  int ioprio, retval;
  int ioclass;

  if(n->ioclass == IOPRIO_CLASS_NONE || n->ioclass == IOPRIO_CLASS_IDLE) {
    if(n->value != 0)
      return -1; // can't set value with class_none/idle
  }
  if(n->value > 8) {
    return -1; // value out of range
  }

  ioclass = (int)(n->ioclass);
  ioprio = (ioclass << 13) | n->value;
  retval = syscall(__NR_ioprio_set, 1, p->pid, ioprio);
  if(retval == -1) {
    return -1;
  }
  return 0;
}

enum proc_status process_status(Proc *p) {
  FILE *fp = NULL;
  char procfile[50];
  char *line = NULL;
  int r;
  size_t n = 0;
  char *pos;
  enum proc_status status = STATUS_UNKNOWN;

  sprintf(procfile,"/proc/%d/status", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process status file");

  while((r = getline(&line, &n, fp)) > 0) {
    if(strncmp(line, "State:", 6) == 0) {
      pos = line;
      while(isspace(*pos)) pos++;
      switch(*pos) {
      case 'R':
	status = STATUS_RUNNING;
	break;
      case 'S':
	status = STATUS_SLEEPING;
	break;
      case 'D':
	status = STATUS_DISK_SLEEP;
	break;
      case 'T':
	status = STATUS_STOPPED;
	break;
      case 't':
	status = STATUS_TRACING_STOP;
	break;
      case 'Z':
	status = STATUS_ZOMBIE;
	break;
      case 'X':
      case 'x':
	status = STATUS_DEAD;
	break;
      case 'K':
	status = STATUS_WAKE_KILL;
	break;
      case 'W':
	status = STATUS_WAKING;
	break;
      }
    }

    free(line);
    line = NULL;
    n = 0;
  }
  free(line);
  return status;

 error:
  if (fp) fclose(fp);
  if (line) free(line);
  return STATUS_UNKNOWN;
}


static int get_open_fds(Proc *p, int **fds) {
  DIR *d = NULL;
  struct dirent *dir;
  char procfile[50];
  int i = 0;
  int *ret;

  sprintf(procfile,"/proc/%d/fd", p->pid);
  d = opendir(procfile);
  check(d, "Couldn't list fd for process");

  ret = calloc(1, sizeof(int));
  check_mem(ret);

  while((dir = readdir(d)) != NULL) {
    if(dir->d_name[0] == '.') continue;
    ret[i] = (int)strtol(dir->d_name, NULL, 10);

    ret = realloc(ret, (i+2)*sizeof(int));
    check_mem(ret);
    i++;
  }
  *fds = ret;
  return i;
error:
  return -1;
}

static bool islink(const char* path) {
  struct stat s;
  int r;

  r = lstat(path, &s);
  check(r != -1, "Couldn't determine if symlink");

  if(S_ISLNK(s.st_mode)) {
    return true;
  }
  return false;

error:
  return false;
}

static char* follow_symlink(const char* path) {
  int bufsize = 1024;
  int r;
  char *tmp;
  tmp = calloc(bufsize, sizeof(char));
  check_mem(tmp);

  r = readlink(path, tmp, bufsize-1);
  while(r == bufsize-1) {
    /* Buffer filled. Might be incomplete. Increase size and try again. */
    bufsize *= 2;
    tmp = realloc(tmp, bufsize);
    r = readlink(path, tmp, bufsize - 1);
    if(r == -1) {
      goto error; // Maybe the file just disappeard on us, keep errno
    }

  }
  tmp[r] = '\0';
  return tmp;

error:
  if(tmp) free(tmp);
  return NULL;
}

// 1=true, 0=false, -1=error
static int isfile_strict(const char* path) {
  struct stat s;
  int r;

  r = stat(path, &s);
  if(r == -1) {
    if(errno == EPERM || errno == EACCES)
      return -1;
    return false;
  }

  return S_ISREG(s.st_mode);
}

Proc_OpenFileInfo *process_open_files(Proc *p) {
  int *fds = NULL;
  int num_fd = get_open_fds(p, &fds);
  int i = 0, j = 0;
  char *link = NULL;
  Proc_OpenFileInfo *ret = calloc(1, sizeof(Proc_OpenFileInfo));
  ret->files = calloc(1, sizeof(Proc_OpenFile));

  for(i = 0;i < num_fd;i++) {
    int fd = fds[i];
    char procfile[50];

    sprintf(procfile,"/proc/%d/fd/%d", p->pid, fd);
    if(islink(procfile)) {
      link = follow_symlink(procfile);
      if(link == NULL) {
	check(errno == ENOENT, "Couldn't expand symbolic link");
	continue;
      }

      if(link[0] == '/' && isfile_strict(procfile)) {
	ret->files[j].path = link;
	ret->files[j].fd = fd;
	j++;
	ret->files = realloc(ret->files, (j+1)*sizeof(Proc_OpenFile));
      } else {
	free(link);
      }
    }
  }
  ret->nitems = j;
  return ret;

error:
  if(link) free(link);
  return NULL;
}

static enum tcp_states strtotcpstate(char *status) {
  if(strncmp(status, "01", 2) == 0) {
    return TCP_ESTABLISHED;
  }
  else if(strncmp(status, "02", 2) == 0) {
    return TCP_SYN_SENT;
  }
  else if(strncmp(status, "03", 2) == 0) {
    return TCP_SYN_RECV;
  }
  else if(strncmp(status, "04", 2) == 0) {
    return TCP_FIN_WAIT1;
  }
  else if(strncmp(status, "05", 2) == 0) {
    return TCP_FIN_WAIT2;
  }
  else if(strncmp(status, "06", 2) == 0) {
    return TCP_TIME_WAIT;
  }
  else if(strncmp(status, "07", 2) == 0) {
    return TCP_CLOSE;
  }
  else if(strncmp(status, "08", 2) == 0) {
    return TCP_CLOSE_WAIT;
  }
  else if(strncmp(status, "09", 2) == 0) {
    return TCP_LAST_ACK;
  }
  else if(strncmp(status, "0A", 2) == 0) {
    return TCP_LISTEN;
  }
  else if(strncmp(status, "0B", 2) == 0) {
    return TCP_CLOSING;
  }
  else {
    return TCP_NONE;
  }
}

typedef struct {
  pid_t pid;
  int fd;
} Inode;

typedef struct {
  int nitems;
  int* keys;
  Inode* values;
} InodeInfo;

static InodeInfo* proc_inodes(Proc *p) {
  int *fds = NULL;
  int num_fds, i;
  char procfile[50];
  int j = 0;
  Inode *cur_node;
  InodeInfo* ret = calloc(1, sizeof(InodeInfo));
  ret->keys = calloc(1, sizeof(int));
  ret->values = calloc(1, sizeof(Inode));


  num_fds = get_open_fds(p, &fds);
  check(num_fds, "Couldn't get open fd's");

  for(i = 0;i < num_fds;i++) {
    sprintf(procfile,"/proc/%d/fd/%d", p->pid, fds[i]);
    char *inode = follow_symlink(procfile);
    if(strncmp(inode, "socket:[", 8)) {
      cur_node = calloc(1, sizeof(Inode));
      cur_node->pid = p->pid;
      cur_node->fd = fds[i];
      ret->keys[j] = (int)strtoul(inode+8, NULL, 10);
      ret->values[j] = *cur_node;

      j++;
      ret->keys = realloc(ret->keys, (j+1)*sizeof(int));
      ret->values = realloc(ret->values, (j+1)*sizeof(Inode));
    }
    free(inode);
  }
  ret->nitems = j;
  free(fds);
  return ret;

error:
  if(fds) free(fds);
  return NULL;
}

bool path_exists(const char* path) {
  struct stat st;
  if(stat(path, &st) == 0)
    return true;
  return false;
}

static void inplace_reverse(char* str) {
  if(!str) return;
  char * end = str + strlen(str) - 1;
  while (str < end)
    {
      do { *str ^= *end; *end ^= *str; *str ^= *end; } while (0);
      str++;
      end--;
    }
}

static char* b16decode(char *str) {
  size_t i, n = strlen(str);
  char *ret = calloc(strlen(str)/2, sizeof(char));
  check_mem(ret);

  if(n % 2 != 0) sentinel("b16decode needs an even length string");
  for(i=0;i<n;i+=2) {
    if(!isxdigit(str[i]) || !isxdigit(str[i+1])) {
      sentinel("String contains non base16 digit");
    }

    ret[i/2] = 16*(str[i] >= 'A' ? str[i]-'A' : str[i]-'0');
    ret[i/2] += (str[i+1] >= 'A' ? str[i+1]-'A' : str[i+1]-'0');
  }
  return ret;

error:
    if(ret) free(ret);
    return NULL;
}

/*
Converts "ip:port" as in /pro/net/\* into a human readable form:

"0500000A:0016" -> ("10.0.0.5", 22)
"0000000000000000FFFF00000100007F:9E49" -> ("::ffff:127.0.0.1", 40521)

The portion with the IP address is 4bytes in little or big endian.
The port is represented as 2byte hex number.

Reference:
http://linuxdevcenter.com/pub/a/linux/2000/11/16/LinuxAdmin.html
*/
static struct Proc_Addr * decode_address(char *addr, enum connection_family family) {
  char *c_ip = NULL, *c_port = NULL;
  char *ip = NULL, *tmp = NULL;
  const char *r;
  int port;
  struct Proc_Addr *ret = calloc(1, sizeof(struct Proc_Addr));

  c_ip = strtok(addr, ":");
  c_port = strtok(NULL, ":");

  port = (int)strtol(c_port, NULL, 16);
  check(port > 0, "Couldn't parse port");

  if(family == PS_AF_INET) {
#if BYTE_ORDER == LITTLE_ENDIAN
    inplace_reverse(c_ip);
#else //BYTE_ORDER == BIG_ENDIAN
#endif
    tmp = b16decode(c_ip);
    ip = calloc(INET_ADDRSTRLEN+2, sizeof(char));
    r = inet_ntop(AF_INET, tmp, ip, INET_ADDRSTRLEN+1);
    check(r, "Couldn't convert ip to string");
  } else { // IPv6
    sentinel("Not implemented");
  }

  ret->addr = ip;
  ret->port = port;
  return ret;
error:
  return NULL;
}

Proc_ConnectionsInfo* process_inet(
  char *file,
  enum connection_family family,
  enum connection_type type,
  InodeInfo *inode_info)
{
  FILE *fp = NULL;
  int i, r;
  size_t size = 0;
  char *line = NULL;
  Proc_ConnectionsInfo *ret = calloc(1, sizeof(Proc_ConnectionsInfo));
  Proc_Connection *cur_connection;
  ret->connections = calloc(1, sizeof(Proc_Connection));
  cur_connection = ret->connections;

  if(file[strlen(file)-1] == '6' && !path_exists(file)) {
    /* IPv6 not supported */
    return NULL;
  }
  fp = fopen(file, "r");
  check(fp, "Couldn't open net file");

  r = getline(&line, &size, fp);
  free(line); line = NULL; size = 0;

  while((r = getline(&line, &size, fp)) > 0) {
    char *pos = strtok(line, " ");
    pos = strtok(NULL, " "); // skip first value

    struct Proc_Addr *laddr = decode_address(pos, family);
    pos = strtok(NULL, " ");

    struct Proc_Addr *raddr = decode_address(pos, family);
    pos = strtok(NULL, " ");

    char *status = strdup(pos);
    for(i=0;i<6;i++)
      pos = strtok(NULL, " ");

    int inode = strtoul(pos, NULL, 10);

    Inode *n = NULL;
    for(i = 0;i < inode_info->nitems; i++) {
      if(inode_info->keys[i] == inode) {
	if(n != NULL) {
	  /* We assume inet socks are unique and error out if
	     there ar multiple references to the same inode */
	}
	n = inode_info->values + i;
      }
    }
    cur_connection->fd = (n == NULL) ? -1 : n->fd;
    cur_connection->type = type;
    cur_connection->family = family;
    cur_connection->laddr = *laddr;
    cur_connection->raddr = *raddr;

    if(type == PS_SOCK_STREAM) {
      cur_connection->status = strtotcpstate(status);
    } else {
      cur_connection->status = TCP_NONE;
    }

  }
error:
  return NULL;
}

Proc_ConnectionsInfo *process_connections(Proc* process, enum connection_filter filter) {

  int i;
  Proc_ConnectionsInfo *ret = calloc(1, sizeof(Proc_ConnectionsInfo));

  InodeInfo *inodes = proc_inodes(process);

  bool has_tcp4 = false, has_tcp6 = false;
  bool has_udp4 = false, has_udp6 = false;
  bool has_unix = false;

  switch(filter) {
  case CON_ALL:
    has_tcp4 = has_tcp6 = has_udp4 = has_udp6 = has_unix = true;
    break;
  case CON_TCP:
    has_tcp4 = has_tcp6 = true;
    break;
  case CON_TCP4:
    has_tcp4 = true;
    break;
  case CON_TCP6:
    has_tcp6 = true;
    break;
  case CON_UDP:
    has_udp4 = has_udp6 = true;
    break;
  case CON_UDP4:
    has_udp4 = true;
    break;
  case CON_UDP6:
    has_udp6 = true;
    break;
  case CON_UNIX:
    has_unix = true;
    break;
  case CON_INET:
    has_tcp4 = has_tcp6 = has_udp4 = has_udp6 = true;
    break;
  case CON_INET4:
    has_tcp4 = has_udp4 = true;
    break;
  case CON_INET6:
    has_tcp6 = has_udp6 = true;
    break;
  default:
    sentinel("Should never happen");
  }

  bool kind_in_round[5] = {has_tcp4, has_tcp6, has_udp4, has_udp6, has_unix };
  enum connection_family fam[5] = {PS_AF_INET, PS_AF_INET6, PS_AF_INET, PS_AF_INET6, PS_AF_UNIX};
  enum connection_type typ[5] = {PS_SOCK_STREAM, PS_SOCK_STREAM, PS_SOCK_DGRAM,
				 PS_SOCK_DGRAM, PS_SOCK_NONE};
  char* name[5] = {"tcp", "tcp6", "udp", "udp6", "unix"};

  for(i = 0;i < 5; i++) {
    char procfile[50];
    if(!kind_in_round[i]) continue;

    sprintf(procfile, "/proc/net/%s", name[i]);
    if(fam[i] == PS_AF_INET || fam[i] == PS_AF_INET6) {
      ret = process_inet(&procfile[0], fam[i], typ[i], inodes);
    } else {
      // process_unix
    }
  }



  free(inodes);

  return ret;
error:
  if(inodes) free(inodes);

  return NULL;
}
