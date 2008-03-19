/*
 *	A Simple Sandbox for MO-Eval
 *
 *	(c) 2001--2008 Martin Mares <mj@ucw.cz>
 */

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#define NONRET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

static int filter_syscalls;		/* 0=off, 1=liberal, 2=totalitarian */
static int timeout;			/* milliseconds */
static int wall_timeout;
static int pass_environ;
static int file_access;
static int verbose;
static int memory_limit;
static char *redir_stdin, *redir_stdout, *redir_stderr;
static char *set_cwd;

static pid_t box_pid;
static int is_ptraced;
static volatile int timer_tick;
static struct timeval start_time;
static int ticks_per_sec;
static int exec_seen;
static int partial_line;

#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ > 0
/* glibc 2.1 or newer -> has lseek64 */
#define long_seek(f,o,w) lseek64(f,o,w)
#else
/* Touching clandestine places in glibc */
extern loff_t llseek(int fd, loff_t pos, int whence);
#define long_seek(f,o,w) llseek(f,o,w)
#endif

static void NONRET
box_exit(void)
{
  if (box_pid > 0)
    {
      if (is_ptraced)
	ptrace(PTRACE_KILL, box_pid);
      kill(-box_pid, SIGKILL);
      kill(box_pid, SIGKILL);
    }
  exit(1);
}

static void
flush_line(void)
{
  if (partial_line)
    fputc('\n', stderr);
  partial_line = 0;
}

static void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  flush_line();
  vfprintf(stderr, msg, args);
  fputc('\n', stderr);
  box_exit();
}

static void __attribute__((format(printf,1,2)))
msg(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  if (verbose)
    {
      int len = strlen(msg);
      if (len > 0)
        partial_line = (msg[len-1] != '\n');
      vfprintf(stderr, msg, args);
      fflush(stderr);
    }
  va_end(args);
}

static void *
xmalloc(size_t size)
{
  void *p = malloc(size);
  if (!p)
    die("Out of memory");
  return p;
}

/*** Syscall rules ***/

static const char * const syscall_names[] = {
#include "syscall-table.h"
};
#define NUM_SYSCALLS ARRAY_SIZE(syscall_names)
#define NUM_ACTIONS (NUM_SYSCALLS+64)

enum action {
  A_DEFAULT,		// Use the default action
  A_NO,			// Always forbid
  A_YES,		// Always permit
  A_FILENAME,		// Permit if arg1 is a known filename
  A_LIBERAL = 128,	// Valid only in liberal mode
};

static unsigned char syscall_action[NUM_ACTIONS] = {
#define S(x) [__NR_##x]

    // Syscalls permitted for specific file names
    S(open) = A_FILENAME,
    S(creat) = A_FILENAME,
    S(unlink) = A_FILENAME,
    S(oldstat) = A_FILENAME,
    S(access) = A_FILENAME,			
    S(oldlstat) = A_FILENAME,			
    S(truncate) = A_FILENAME,
    S(stat) = A_FILENAME,
    S(lstat) = A_FILENAME,
    S(truncate64) = A_FILENAME,
    S(stat64) = A_FILENAME,
    S(lstat64) = A_FILENAME,
    S(readlink) = A_FILENAME,

    // Syscalls permitted always
    S(exit) = A_YES,
    S(read) = A_YES,
    S(write) = A_YES,
    S(close) = A_YES,
    S(lseek) = A_YES,
    S(getpid) = A_YES,
    S(getuid) = A_YES,
    S(oldfstat) = A_YES,
    S(dup) = A_YES,
    S(brk) = A_YES,
    S(getgid) = A_YES,
    S(geteuid) = A_YES,
    S(getegid) = A_YES,
    S(dup2) = A_YES,
    S(ftruncate) = A_YES,
    S(fstat) = A_YES,
    S(personality) = A_YES,
    S(_llseek) = A_YES,
    S(readv) = A_YES,
    S(writev) = A_YES,
    S(getresuid) = A_YES,
#ifdef __NR_pread64
    S(pread64) = A_YES,
    S(pwrite64) = A_YES,
#else
    S(pread) = A_YES,
    S(pwrite) = A_YES,
#endif
    S(ftruncate64) = A_YES,
    S(fstat64) = A_YES,
    S(fcntl) = A_YES,
    S(fcntl64) = A_YES,
    S(mmap) = A_YES,
    S(munmap) = A_YES,
    S(ioctl) = A_YES,
    S(uname) = A_YES,
    S(gettid) = A_YES,
    S(set_thread_area) = A_YES,
    S(get_thread_area) = A_YES,
    S(exit_group) = A_YES,

    // Syscalls permitted only in liberal mode
    S(time) = A_YES | A_LIBERAL,
    S(alarm) = A_YES | A_LIBERAL,
    S(pause) = A_YES | A_LIBERAL,
    S(signal) = A_YES | A_LIBERAL,
    S(fchmod) = A_YES | A_LIBERAL,
    S(sigaction) = A_YES | A_LIBERAL,
    S(sgetmask) = A_YES | A_LIBERAL,
    S(ssetmask) = A_YES | A_LIBERAL,
    S(sigsuspend) = A_YES | A_LIBERAL,
    S(sigpending) = A_YES | A_LIBERAL,
    S(getrlimit) = A_YES | A_LIBERAL,
    S(getrusage) = A_YES | A_LIBERAL,
    S(ugetrlimit) = A_YES | A_LIBERAL,
    S(gettimeofday) = A_YES | A_LIBERAL,
    S(select) = A_YES | A_LIBERAL,
    S(readdir) = A_YES | A_LIBERAL,
    S(setitimer) = A_YES | A_LIBERAL,
    S(getitimer) = A_YES | A_LIBERAL,
    S(sigreturn) = A_YES | A_LIBERAL,
    S(mprotect) = A_YES | A_LIBERAL,
    S(sigprocmask) = A_YES | A_LIBERAL,
    S(getdents) = A_YES | A_LIBERAL,
    S(getdents64) = A_YES | A_LIBERAL,
    S(_newselect) = A_YES | A_LIBERAL,
    S(fdatasync) = A_YES | A_LIBERAL,
    S(mremap) = A_YES | A_LIBERAL,
    S(poll) = A_YES | A_LIBERAL,
    S(getcwd) = A_YES | A_LIBERAL,
    S(nanosleep) = A_YES | A_LIBERAL,
    S(rt_sigreturn) = A_YES | A_LIBERAL,
    S(rt_sigaction) = A_YES | A_LIBERAL,
    S(rt_sigprocmask) = A_YES | A_LIBERAL,
    S(rt_sigpending) = A_YES | A_LIBERAL,
    S(rt_sigtimedwait) = A_YES | A_LIBERAL,
    S(rt_sigqueueinfo) = A_YES | A_LIBERAL,
    S(rt_sigsuspend) = A_YES | A_LIBERAL,
    S(mmap2) = A_YES | A_LIBERAL,
    S(_sysctl) = A_YES | A_LIBERAL,
#undef S
};

static const char *
syscall_name(unsigned int id, char *buf)
{
  if (id < NUM_SYSCALLS && syscall_names[id])
    return syscall_names[id];
  else
    {
      sprintf(buf, "#%d", id);
      return buf;
    }
}

static int
syscall_by_name(char *name)
{
  for (unsigned int i=0; i<NUM_SYSCALLS; i++)
    if (syscall_names[i] && !strcmp(syscall_names[i], name))
      return i;
  if (name[0] == '#')
    name++;
  if (!*name)
    return -1;
  char *ep;
  unsigned long l = strtoul(name, &ep, 0);
  if (*ep)
    return -1;
  if (l >= NUM_ACTIONS)
    return NUM_ACTIONS;
  return l;
}

static int
set_syscall_action(char *a)
{
  char *sep = strchr(a, '=');
  enum action act = A_YES;
  if (sep)
    {
      *sep++ = 0;
      if (!strcmp(sep, "yes"))
	act = A_YES;
      else if (!strcmp(sep, "no"))
	act = A_NO;
      else if (!strcmp(sep, "file"))
	act = A_FILENAME;
      else
	return 0;
    }

  int sys = syscall_by_name(a);
  if (sys < 0)
    die("Unknown syscall `%s'", a);
  if (sys >= NUM_ACTIONS)
    die("Syscall `%s' out of range", a);
  syscall_action[sys] = act;
  return 1;
}

/*** Path rules ***/

struct path_rule {
  char *path;
  enum action action;
  struct path_rule *next;
};

static struct path_rule default_path_rules[] = {
  { "/etc/", A_YES },
  { "/lib/", A_YES },
  { "/usr/lib/", A_YES },
  { "/opt/lib/", A_YES },
  { "/usr/share/zoneinfo/", A_YES },
  { "/usr/share/locale/", A_YES },
  { "/dev/null", A_YES },
  { "/dev/zero", A_YES },
  { "/proc/meminfo", A_YES },
  { "/proc/self/stat", A_YES },
  { "/proc/self/exe", A_YES },			// Needed by FPC 2.0.x runtime
};

static struct path_rule *user_path_rules;
static struct path_rule **last_path_rule = &user_path_rules;

static int
set_path_action(char *a)
{
  char *sep = strchr(a, '=');
  enum action act = A_YES;
  if (sep)
    {
      *sep++ = 0;
      if (!strcmp(sep, "yes"))
	act = A_YES;
      else if (!strcmp(sep, "no"))
	act = A_NO;
      else
	return 0;
    }

  struct path_rule *r = xmalloc(sizeof(*r) + strlen(a) + 1);
  r->path = (char *)(r+1);
  strcpy(r->path, a);
  r->action = act;
  r->next = NULL;
  *last_path_rule = r;
  last_path_rule = &r->next;
  return 1;
}

static enum action
match_path_rule(struct path_rule *r, char *path)
{
  char *rr = r->path;
  while (*rr)
    if (*rr++ != *path++)
      {
	if (rr[-1] == '/' && !path[-1])
	  break;
	return A_DEFAULT;
      }
  if (rr > r->path && rr[-1] != '/' && *path)
    return A_DEFAULT;
  return r->action;
}

/*** Environment rules ***/

struct env_rule {
  char *var;			// Variable to match
  char *val;			// ""=clear, NULL=inherit
  int var_len;
  struct env_rule *next;
};

static struct env_rule *first_env_rule;
static struct env_rule **last_env_rule = &first_env_rule;

static struct env_rule default_env_rules[] = {
  { "LIBC_FATAL_STDERR_", "1" }
};

static int
set_env_action(char *a0)
{
  struct env_rule *r = xmalloc(sizeof(*r) + strlen(a0) + 1);
  char *a = (char *)(r+1);
  strcpy(a, a0);

  char *sep = strchr(a, '=');
  if (sep == a)
    return 0;
  r->var = a;
  if (sep)
    {
      *sep++ = 0;
      r->val = sep;
    }
  else
    r->val = NULL;
  *last_env_rule = r;
  last_env_rule = &r->next;
  r->next = NULL;
  return 1;
}

static int
match_env_var(char *env_entry, struct env_rule *r)
{
  if (strncmp(env_entry, r->var, r->var_len))
    return 0;
  return (env_entry[r->var_len] == '=');
}

static void
apply_env_rule(char **env, int *env_sizep, struct env_rule *r)
{
  // First remove the variable if already set
  int pos = 0;
  while (pos < *env_sizep && !match_env_var(env[pos], r))
    pos++;
  if (pos < *env_sizep)
    {
      (*env_sizep)--;
      env[pos] = env[*env_sizep];
      env[*env_sizep] = NULL;
    }

  // What is the new value?
  char *new;
  if (r->val)
    {
      if (!r->val[0])
	return;
      new = xmalloc(r->var_len + 1 + strlen(r->val) + 1);
      sprintf(new, "%s=%s", r->var, r->val);
    }
  else
    {
      pos = 0;
      while (environ[pos] && !match_env_var(environ[pos], r))
	pos++;
      if (!(new = environ[pos]))
	return;
    }

  // Add it at the end of the array
  env[(*env_sizep)++] = new;
  env[*env_sizep] = NULL;
}

static char **
setup_environment(void)
{
  // Link built-in rules with user rules
  for (int i=ARRAY_SIZE(default_env_rules)-1; i >= 0; i--)
    {
      default_env_rules[i].next = first_env_rule;
      first_env_rule = &default_env_rules[i];
    }

  // Scan the original environment
  char **orig_env = environ;
  int orig_size = 0;
  while (orig_env[orig_size])
    orig_size++;

  // For each rule, reserve one more slot and calculate length
  int num_rules = 0;
  for (struct env_rule *r = first_env_rule; r; r=r->next)
    {
      num_rules++;
      r->var_len = strlen(r->var);
    }

  // Create a new environment
  char **env = xmalloc((orig_size + num_rules + 1) * sizeof(char *));
  int size;
  if (pass_environ)
    {
      memcpy(env, environ, orig_size * sizeof(char *));
      size = orig_size;
    }
  else
    size = 0;
  env[size] = NULL;

  // Apply the rules one by one
  for (struct env_rule *r = first_env_rule; r; r=r->next)
    apply_env_rule(env, &size, r);

  // Return the new env and pass some gossip
  if (verbose > 1)
    {
      fprintf(stderr, "Passing environment:\n");
      for (int i=0; env[i]; i++)
	fprintf(stderr, "\t%s\n", env[i]);
    }
  return env;
}

/*** Syscall checks ***/

static void
valid_filename(unsigned long addr)
{
  char namebuf[4096], *p, *end;
  static int mem_fd;

  if (!file_access)
    die("File access forbidden");
  if (file_access >= 9)
    return;

  if (!mem_fd)
    {
      sprintf(namebuf, "/proc/%d/mem", (int) box_pid);
      mem_fd = open(namebuf, O_RDONLY);
      if (mem_fd < 0)
	die("open(%s): %m", namebuf);
    }
  p = end = namebuf;
  do
    {
      if (p >= end)
	{
	  int remains = PAGE_SIZE - (addr & (PAGE_SIZE-1));
	  int l = namebuf + sizeof(namebuf) - end;
	  if (l > remains)
	    l = remains;
	  if (!l)
	    die("Access to file with name too long");
	  if (long_seek(mem_fd, addr, SEEK_SET) < 0)
	    die("long_seek(mem): %m");
	  remains = read(mem_fd, end, l);
	  if (remains < 0)
	    die("read(mem): %m");
	  if (!remains)
	    die("Access to file with name out of memory");
	  end += l;
	  addr += l;
	}
    }
  while (*p++);

  msg("[%s] ", namebuf);
  if (file_access >= 3)
    return;

  // Everything in current directory is permitted
  if (!strchr(namebuf, '/') && strcmp(namebuf, ".."))
    return;

  // ".." anywhere in the path is forbidden
  enum action act = A_DEFAULT;
  if (strstr(namebuf, ".."))
    act = A_NO;

  // Scan user rules
  for (struct path_rule *r = user_path_rules; r && !act; r=r->next)
    act = match_path_rule(r, namebuf);

  // Scan built-in rules
  if (file_access >= 2)
    for (int i=0; i<ARRAY_SIZE(default_path_rules) && !act; i++)
      act = match_path_rule(&default_path_rules[i], namebuf);

  if (act != A_YES)
    die("Forbidden access to file `%s'", namebuf);
}

static int
valid_syscall(struct user *u)
{
  unsigned int sys = u->regs.orig_eax;
  enum action act = (sys < NUM_ACTIONS) ? syscall_action[sys] : A_DEFAULT;

  if (act & A_LIBERAL)
    {
      if (filter_syscalls == 1)
        act &= ~A_LIBERAL;
      else
        act = A_DEFAULT;
    }
  switch (act)
    {
    case A_YES:
      return 1;
    case A_NO:
      return 0;
    case A_FILENAME:
      valid_filename(u->regs.ebx);
      return 1;
    default: ;
    }

  switch (sys)
    {
    case __NR_kill:
      if (u->regs.ebx == box_pid)
	die("Committed suicide by signal %d", (int)u->regs.ecx);
      return 0;
    case __NR_tgkill:
      if (u->regs.ebx == box_pid && u->regs.ecx == box_pid)
	die("Committed suicide by signal %d", (int)u->regs.edx);
      return 0;
    default:
      return 0;
    }
}

static void
signal_alarm(int unused UNUSED)
{
  /* Time limit checks are synchronous, so we only schedule them there. */
  timer_tick = 1;
  alarm(1);
}

static void
signal_int(int unused UNUSED)
{
  /* Interrupts are fatal, so no synchronization requirements. */
  die("Interrupted");
}

static void
check_timeout(void)
{
  if (wall_timeout)
    {
      struct timeval now, wall;
      int wall_ms;
      gettimeofday(&now, NULL);
      timersub(&now, &start_time, &wall);
      wall_ms = wall.tv_sec*1000 + wall.tv_usec/1000;
      if (wall_ms > wall_timeout)
        die("Time limit exceeded (wall clock)");
      if (verbose > 1)
        fprintf(stderr, "[wall time check: %d msec]\n", wall_ms);
    }
  if (timeout)
    {
      char buf[4096], *x;
      int c, utime, stime, ms;
      static int proc_status_fd;
      if (!proc_status_fd)
	{
	  sprintf(buf, "/proc/%d/stat", (int) box_pid);
	  proc_status_fd = open(buf, O_RDONLY);
	  if (proc_status_fd < 0)
	    die("open(%s): %m", buf);
	}
      lseek(proc_status_fd, 0, SEEK_SET);
      if ((c = read(proc_status_fd, buf, sizeof(buf)-1)) < 0)
	die("read on /proc/$pid/stat: %m");
      if (c >= (int) sizeof(buf) - 1)
	die("/proc/$pid/stat too long");
      buf[c] = 0;
      x = buf;
      while (*x && *x != ' ')
	x++;
      while (*x == ' ')
	x++;
      if (*x++ != '(')
	die("proc syntax error 1");
      while (*x && (*x != ')' || x[1] != ' '))
	x++;
      while (*x == ')' || *x == ' ')
	x++;
      if (sscanf(x, "%*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %d %d", &utime, &stime) != 2)
	die("proc syntax error 2");
      ms = (utime + stime) * 1000 / ticks_per_sec;
      if (verbose > 1)
	fprintf(stderr, "[time check: %d msec]\n", ms);
      if (ms > timeout)
	die("Time limit exceeded");
    }
}

static void
boxkeeper(void)
{
  int syscall_count = 0;
  struct sigaction sa;

  is_ptraced = 1;
  bzero(&sa, sizeof(sa));
  sa.sa_handler = signal_int;
  sigaction(SIGINT, &sa, NULL);
  gettimeofday(&start_time, NULL);
  ticks_per_sec = sysconf(_SC_CLK_TCK);
  if (ticks_per_sec <= 0)
    die("Invalid ticks_per_sec!");
  if (timeout || wall_timeout)
    {
      sa.sa_handler = signal_alarm;
      sigaction(SIGALRM, &sa, NULL);
      alarm(1);
    }
  for(;;)
    {
      struct rusage rus;
      int stat;
      pid_t p;
      if (timer_tick)
	{
	  check_timeout();
	  timer_tick = 0;
	}
      p = wait4(box_pid, &stat, WUNTRACED, &rus);
      if (p < 0)
	{
	  if (errno == EINTR)
	    continue;
	  die("wait4: %m");
	}
      if (p != box_pid)
	die("wait4: unknown pid %d exited!", p);
      if (WIFEXITED(stat))
	{
	  struct timeval total, now, wall;
	  int total_ms, wall_ms;
	  box_pid = 0;
	  if (WEXITSTATUS(stat))
	    die("Exited with error status %d", WEXITSTATUS(stat));
	  timeradd(&rus.ru_utime, &rus.ru_stime, &total);
	  total_ms = total.tv_sec*1000 + total.tv_usec/1000;
	  gettimeofday(&now, NULL);
	  timersub(&now, &start_time, &wall);
	  wall_ms = wall.tv_sec*1000 + wall.tv_usec/1000;
	  if (timeout && total_ms > timeout)
	    die("Time limit exceeded");
	  if (wall_timeout && wall_ms > wall_timeout)
	    die("Time limit exceeded (wall clock)");
	  flush_line();
	  fprintf(stderr, "OK (%d.%03d sec real, %d.%03d sec wall, %d syscalls)\n",
	      (int) total.tv_sec, (int) total.tv_usec/1000,
	      (int) wall.tv_sec, (int) wall.tv_usec/1000,
	      syscall_count);
	  exit(0);
	}
      if (WIFSIGNALED(stat))
	{
	  box_pid = 0;
	  die("Caught fatal signal %d%s", WTERMSIG(stat), (syscall_count ? "" : " during startup"));
	}
      if (WIFSTOPPED(stat))
	{
	  int sig = WSTOPSIG(stat);
	  if (sig == SIGTRAP)
	    {
	      struct user u;
	      static int stop_count = -1;
	      if (ptrace(PTRACE_GETREGS, box_pid, NULL, &u) < 0)
		die("ptrace(PTRACE_GETREGS): %m");
	      stop_count++;
	      if (!stop_count)			/* Traceme request */
		msg(">> Traceme request caught\n");
	      else if (stop_count & 1)		/* Syscall entry */
		{
		  char namebuf[32];
		  msg(">> Syscall %-12s (%08lx,%08lx,%08lx) ", syscall_name(u.regs.orig_eax, namebuf), u.regs.ebx, u.regs.ecx, u.regs.edx);
		  if (!exec_seen)
		    {
		      msg("[master] ");
		      if (u.regs.orig_eax == __NR_execve)
			exec_seen = 1;
		    }
		  else if (valid_syscall(&u))
		    syscall_count++;
		  else
		    {
		      /*
		       * Unfortunately, PTRACE_KILL kills _after_ the syscall completes,
		       * so we have to change it to something harmless (e.g., an undefined
		       * syscall) and make the program continue.
		       */
		      unsigned int sys = u.regs.orig_eax;
		      u.regs.orig_eax = 0xffffffff;
		      if (ptrace(PTRACE_SETREGS, box_pid, NULL, &u) < 0)
			die("ptrace(PTRACE_SETREGS): %m");
		      die("Forbidden syscall %s", syscall_name(sys, namebuf));
		    }
		}
	      else					/* Syscall return */
		msg("= %ld\n", u.regs.eax);
	      ptrace(PTRACE_SYSCALL, box_pid, 0, 0);
	    }
	  else if (sig != SIGSTOP && sig != SIGXCPU && sig != SIGXFSZ)
	    {
	      msg(">> Signal %d\n", sig);
	      ptrace(PTRACE_SYSCALL, box_pid, 0, sig);
	    }
	  else
	    die("Received signal %d", sig);
	}
      else
	die("wait4: unknown status %x, giving up!", stat);
    }
}

static void
box_inside(int argc, char **argv)
{
  struct rlimit rl;
  char *args[argc+1];

  memcpy(args, argv, argc * sizeof(char *));
  args[argc] = NULL;
  if (set_cwd && chdir(set_cwd))
    die("chdir: %m");
  if (redir_stdin)
    {
      close(0);
      if (open(redir_stdin, O_RDONLY) != 0)
	die("open(\"%s\"): %m", redir_stdin);
    }
  if (redir_stdout)
    {
      close(1);
      if (open(redir_stdout, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 1)
	die("open(\"%s\"): %m", redir_stdout);
    }
  if (redir_stderr)
    {
      close(2);
      if (open(redir_stderr, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 2)
	die("open(\"%s\"): %m", redir_stderr);
    }
  else
    dup2(1, 2);
  setpgrp();
  if (memory_limit)
    {
      rl.rlim_cur = rl.rlim_max = memory_limit * 1024;
      if (setrlimit(RLIMIT_AS, &rl) < 0)
	die("setrlimit: %m");
    }
  rl.rlim_cur = rl.rlim_max = 64;
  if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
    die("setrlimit: %m");
  if (filter_syscalls)
    {
      if (ptrace(PTRACE_TRACEME) < 0)
	die("ptrace(PTRACE_TRACEME): %m");
      /* Trick: Make sure that we are stopped until the boxkeeper wakes up. */
      signal(SIGCHLD, SIG_IGN);
      raise(SIGCHLD);
    }
  execve(args[0], args, setup_environment());
  die("execve(\"%s\"): %m", args[0]);
}

static void
usage(void)
{
  fprintf(stderr, "Invalid arguments!\n");
  printf("\
Usage: box [<options>] -- <command> <arguments>\n\
\n\
Options:\n\
-a <level>\tSet file access level (0=none, 1=cwd, 2=/etc,/lib,..., 3=whole fs, 9=no checks; needs -f)\n\
-c <dir>\tChange directory to <dir> first\n\
-e\t\tInherit full environment of the parent process\n\
-E <var>\tInherit the environment variable <var> from the parent process\n\
-E <var>=<val>\tSet the environment variable <var> to <val>; unset it if <var> is empty\n\
-f\t\tFilter system calls (-ff=very restricted)\n\
-i <file>\tRedirect stdin from <file>\n\
-m <size>\tLimit address space to <size> KB\n\
-o <file>\tRedirect stdout to <file>\n\
-p <path>\tPermit access to the specified path (or subtree if it ends with a `/')\n\
-p <path>=<act>\tDefine action for the specified path (<act>=yes/no)\n\
-r <file>\tRedirect stderr to <file>\n\
-s <sys>\tPermit the specified syscall (be careful)\n\
-s <sys>=<act>\tDefine action for the specified syscall (<act>=yes/no/file)\n\
-t <time>\tSet run time limit (seconds, fractions allowed)\n\
-T\t\tAllow syscalls for measuring run time\n\
-v\t\tBe verbose (use multiple times for even more verbosity)\n\
-w <time>\tSet wall clock time limit (seconds, fractions allowed)\n\
");
  exit(1);
}

int
main(int argc, char **argv)
{
  int c;
  uid_t uid;

  while ((c = getopt(argc, argv, "a:c:eE:fi:m:o:p:r:s:t:Tvw:")) >= 0)
    switch (c)
      {
      case 'a':
	file_access = atol(optarg);
	break;
      case 'c':
	set_cwd = optarg;
	break;
      case 'e':
	pass_environ = 1;
	break;
      case 'E':
	if (!set_env_action(optarg))
	  usage();
	break;
      case 'f':
	filter_syscalls++;
	break;
      case 'i':
	redir_stdin = optarg;
	break;
      case 'm':
	memory_limit = atol(optarg);
	break;
      case 'o':
	redir_stdout = optarg;
	break;
      case 'p':
	if (!set_path_action(optarg))
	  usage();
	break;
      case 'r':
	redir_stderr = optarg;
	break;
      case 's':
	if (!set_syscall_action(optarg))
	  usage();
	break;
      case 't':
	timeout = 1000*atof(optarg);
	break;
      case 'T':
	syscall_action[__NR_times] = A_YES;
	break;
      case 'v':
	verbose++;
	break;
      case 'w':
        wall_timeout = 1000*atof(optarg);
	break;
      default:
	usage();
      }
  if (optind >= argc)
    usage();

  uid = geteuid();
  if (setreuid(uid, uid) < 0)
    die("setreuid: %m");
  box_pid = fork();
  if (box_pid < 0)
    die("fork: %m");
  if (!box_pid)
    box_inside(argc-optind, argv+optind);
  else
    boxkeeper();
  die("Internal error: fell over edge of the world");
}
