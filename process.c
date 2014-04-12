#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <mntent.h>
#include <pwd.h>
#include <search.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#include "pslib.h"
#include "process.h"
#include "common.h"


struct Proc {
  pid_t pid;
};

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

int process_new(Proc* p, int pid) {
  p = malloc(sizeof(Proc));
  check_mem(p);
  p->pid = pid;
  return 0;
error:
  return -1;
}

int process_free(Proc* p) {
  free(p);
  return 0;
}

int process_name(Proc* p, char *ret) {
  FILE *fp = NULL;
  char *tmp;
  char procfile[50];
  char line[350];

  sprintf(procfile,"/proc/%d/stat", p->pid);
  fp = fopen(procfile,"r");
  check(fp, "Couldn't open process status file");
  fgets(line, 300, fp);
  fclose(fp);

  tmp = strtok(line, " ");
  tmp = strtok(NULL, " "); /* Name field */
  tmp = squeeze(tmp, "()");

  ret = strdup(tmp);
  return 0;
 error:
  if (fp) fclose(fp);
  return -1;
}

int process_exe(Proc* p, char* ret) {
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
      ret = tmp;
      return 0;
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
  ret = tmp;
  return 0;

 error:
  if (fp) fclose(fp);
  if (tmp) free(tmp);
  return -1;
}


int process_cmdline(Proc *p, char *ret) {
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
  ret = contents;
  return 0;

 error:
  if (fp) fclose(fp);
  if (contents) free(contents);
  return -1;
}

int process_terminal(Proc *p, char *ret) {
  FILE *fp = NULL;
  char *tmp = NULL;
  char procfile[50];
  ssize_t r;
  unsigned int bufsize = 1024;

  sprintf(procfile,"/proc/%d/fd/0", p->pid);
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
  ret = tmp;
 error:
  if (fp) fclose(fp);
  if (tmp) free(tmp);
  return -1;
}

int process_io_counters(Proc *p, Proc_IOCounters *ret) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;

  ret = calloc(1, sizeof(Proc_IOCounters));
  sprintf(procfile, "/proc/%d/io", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process io file");

  while((r = getline(&contents, &n, fp)) > 0) {
    if(strncmp(contents, "rchar", 5) == 0) {
      ret->read_count = strtoul(contents+7, NULL, 10);
    }
    else if(strncmp(contents, "wchar", 5) == 0) {
      ret->write_count = strtoul(contents+7, NULL, 10);
    }
    else if(strncmp(contents, "read_bytes", 10) == 0) {
      ret->read_bytes = strtoul(contents+12, NULL, 10);
    }
    else if(strncmp(contents, "write_bytes", 11) == 0) {
      ret->write_bytes = strtoul(contents+13l, NULL, 10);
    }
    free(contents);
    contents = NULL;
    n = 0;
  }
  fclose(fp);
  return 0;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return -1;
}

int process_cpu_times(Proc *p,  Proc_CPUTimes *ret) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r, i = 0;
  unsigned long ticks;

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
  ret->system = (double)strtoul(pos, NULL, 10) / ticks;

  free(contents);
  fclose(fp);
  return 0;
error:
  if(contents) free(contents);
  if(fp) free(fp);
  return -1;
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

int process_wait(Proc *p, double t, bool *is_child) {
  struct timespec timeout;
  int ret;

  timeout.tv_sec = (int)t;
  timeout.tv_nsec = (int)(1e9*(t - timeout.tv_sec));
  *is_child = true;
  ret = proc_wait_pid(p->pid, &timeout, is_child);
  return ret;
}


int process_create_time(Proc *p, double *ret) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r, i = 0;

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
  *ret = (proc_time / ticks) + boot_time();

  fclose(fp);
  free(contents);
  return -1;

 error:
  if (fp) fclose(fp);
  if (contents) free(contents);
  return -1;
}

int process_memory_info(Proc *p, Proc_MemoryInfo *ret) {
  FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;

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
  return 0;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return -1;
}

int process_memory_info_ex(Proc *p, Proc_MemoryInfoExt *ret) {
    FILE *fp = NULL;
  char procfile[50];
  char *contents = NULL;
  size_t n = 0;
  int r;

  sprintf(procfile, "/proc/%d/statm", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process statm file");
  r = getline(&contents, &n, fp);
  check(r > 0, "Couldn't parse process statm file");

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
  return 0;

error:
  if(fp) fclose(fp);
  if(contents) free(contents);
  return -1;
}

struct _smaps_header {
  char *addr;
  char *offset;
  char *dev;
  char *inode;
  char *path;
};
void _free_smaps_header(struct _smaps_header *s) {
  free(s->addr);
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

  pos = strtok(pos, " ");
  check(pos != NULL, "");
  header->offset = strdup(pos);

  pos = strtok(pos, " ");
  check(pos != NULL, "");
  header->dev = strdup(pos);

  pos = strtok(pos, " ");
  check(pos != NULL, "");
  header->inode = strdup(pos);

  pos = strtok(pos, " ");
  if(!pos) {
    header->path = strdup("[anon]");
  } else {
    header->path = strdup(pos);
  }
  return 0;

error:
  free(header);
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
    if(strncmp(pos, __mmap_base_fields[i], strlen(__mmap_base_fields[i])) == 0) {
      pos = strtok(NULL, " ");
      *ret = strtoul(pos, NULL, 10);
      return (int)i;
    }
  }

error:
  return -1;
}

/* TBD: Make sure errno is set apropriatly */
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

  sprintf(procfile, "/proc/%d/io", p->pid);
  fp = fopen(procfile, "r");
  check(fp, "Couldn't open process smap file");

  while((r = getline(&contents, &n, fp)) > 0) {
    if(isdigit(contents[0])) {
      current->path = strdup(header.path);
      ret->memorymaps = realloc(ret->memorymaps, ++(ret->nitems));
      current++;
      _free_smaps_header(&header);

      parse_smaps_header(contents, &header);
    } else {
      int idx;
      unsigned long int val;
      idx = parse_smaps_body_line(contents, &val);
      check(idx >= 0 && idx < (int)NELEMS(__mmap_base_fields), "Couldn't parse smap file");
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
      default:
	check(false, "Internal Error, should never happen");
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
  int num_threads, threads_missed, i;
  unsigned long int ticks;

  thread_ids = calloc(1, sizeof(unsigned long int));
  ret = calloc(1, sizeof(Proc_ThreadInfo));

  sprintf(procfile,"/proc/%d/status", p->pid);
  d = opendir(procfile);
  check(d, "Couldn't list threads");

  i = 0;
  while ((dir = readdir(d)) != NULL) {
    thread_ids = realloc(thread_ids, (i+1)*sizeof(int));
    check_mem(thread_ids);
    *(thread_ids+i) = strtoul(dir->d_name, NULL, 10);
    i++;
  }
  num_threads = i;
  closedir(d); d=NULL;

  //sort dirs
  qsort(thread_ids, i, sizeof(int), comp);

  ret->threads = calloc(num_threads, sizeof(Proc_Thread));
  cur_thread = ret->threads;
  threads_missed = 0;

  for(i = 0;i < num_threads;i++) {
    size_t n = 0;
    int r;

    sprintf(procfile, "/proc/%d/task/%lu/stat", p->pid, *(thread_ids+i));

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
    while(pos != NULL && i < 11) {
      i++;
      pos = strtok(NULL, " ");
    } /* Skip 11 values */

    ticks = get_clock_ticks();
    cur_thread->id = thread_ids[i-threads_missed];
    cur_thread->user_time = (double)strtoul(pos, &pos, 10) / ticks;
    cur_thread->system_time = (double)strtoul(pos, NULL, 10) / ticks;

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


