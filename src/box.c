/*
 *	A Simple Testing Sandbox
 *
 *	(c) 2001--2004 Martin Mares <mj@ucw.cz>
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

static int filter_syscalls;		/* 0=off, 1=liberal, 2=totalitarian */
static int timeout;
static int pass_environ;
static int use_wall_clock;
static int file_access;
static int verbose;
static int memory_limit;
static int allow_times;
static char *redir_stdin, *redir_stdout;
static char *set_cwd;

static pid_t box_pid;
static int is_ptraced;
static volatile int timer_tick;
static time_t start_time;
static int ticks_per_sec;

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

static void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  fputc('\n', stderr);
  box_exit();
}

static void __attribute__((format(printf,1,2)))
log(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  if (verbose)
    {
      vfprintf(stderr, msg, args);
      fflush(stderr);
    }
  va_end(args);
}

static void
valid_filename(unsigned long addr)
{
  char namebuf[4096], *p, *end;
  static int mem_fd;

  if (!file_access)
    die("File access forbidden.");
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
	    die("Access to file with name too long.");
	  if (long_seek(mem_fd, addr, SEEK_SET) < 0)
	    die("long_seek(mem): %m");
	  remains = read(mem_fd, end, l);
	  if (remains < 0)
	    die("read(mem): %m");
	  if (!remains)
	    die("Access to file with name out of memory.");
	  end += l;
	  addr += l;
	}
    }
  while (*p++);

  log("[%s] ", namebuf);
  if (file_access >= 3)
    return;
  if (!strchr(namebuf, '/') && strcmp(namebuf, ".."))
    return;
  if (file_access >= 2)
    {
      if ((!strncmp(namebuf, "/etc/", 5) ||
	   !strncmp(namebuf, "/lib/", 5) ||
	   !strncmp(namebuf, "/usr/lib/", 9))
	  && !strstr(namebuf, ".."))
	return;
      if (!strcmp(namebuf, "/dev/null") ||
	  !strcmp(namebuf, "/dev/zero") ||
	  !strcmp(namebuf, "/proc/meminfo") ||
	  !strcmp(namebuf, "/proc/self/stat") ||
	  !strncmp(namebuf, "/usr/share/zoneinfo/", 20))
	return;
    }
  die("Forbidden access to file `%s'.", namebuf);
}

static int
valid_syscall(struct user *u)
{
  switch (u->regs.orig_eax)
    {
    case SYS_execve:
      {
	static int exec_counter;
	return !exec_counter++;
      }
    case SYS_open:
    case SYS_creat:
    case SYS_unlink:
    case SYS_oldstat:
    case SYS_access:			
    case SYS_oldlstat:			
    case SYS_truncate:
    case SYS_stat:
    case SYS_lstat:
    case SYS_truncate64:
    case SYS_stat64:
    case SYS_lstat64:
      valid_filename(u->regs.ebx);
      return 1;
    case SYS_exit:
    case SYS_read:
    case SYS_write:
    case SYS_close:
    case SYS_lseek:
    case SYS_getpid:
    case SYS_getuid:
    case SYS_oldfstat:
    case SYS_dup:
    case SYS_brk:
    case SYS_getgid:
    case SYS_geteuid:
    case SYS_getegid:
    case SYS_dup2:
    case SYS_ftruncate:
    case SYS_fstat:
    case SYS_personality:
    case SYS__llseek:
    case SYS_readv:
    case SYS_writev:
    case SYS_getresuid:
    case SYS_pread:
    case SYS_pwrite:
    case SYS_ftruncate64:
    case SYS_fstat64:
    case SYS_fcntl:
    case SYS_fcntl64:
    case SYS_mmap:
    case SYS_munmap:
    case SYS_ioctl:
    case SYS_uname:
    case 252:
      return 1;
    case SYS_time:
    case SYS_alarm:
    case SYS_pause:
    case SYS_signal:
    case SYS_fchmod:
    case SYS_sigaction:
    case SYS_sgetmask:
    case SYS_ssetmask:
    case SYS_sigsuspend:
    case SYS_sigpending:
    case SYS_getrlimit:
    case SYS_getrusage:
    case SYS_gettimeofday:
    case SYS_select:
    case SYS_readdir:
    case SYS_setitimer:
    case SYS_getitimer:
    case SYS_sigreturn:
    case SYS_mprotect:
    case SYS_sigprocmask:
    case SYS_getdents:
    case SYS_getdents64:
    case SYS__newselect:
    case SYS_fdatasync:
    case SYS_mremap:
    case SYS_poll:
    case SYS_getcwd:
    case SYS_nanosleep:
    case SYS_rt_sigreturn:
    case SYS_rt_sigaction:
    case SYS_rt_sigprocmask:
    case SYS_rt_sigpending:
    case SYS_rt_sigtimedwait:
    case SYS_rt_sigqueueinfo:
    case SYS_rt_sigsuspend:
    case SYS_mmap2:
    case SYS__sysctl:
      return (filter_syscalls == 1);
    case SYS_times:
      return allow_times;
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
  die("Interrupted.");
}

static void
check_timeout(void)
{
  int sec;

  if (use_wall_clock)
    sec = time(NULL) - start_time;
  else
    {
      char buf[4096], *x;
      int c, utime, stime;
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
      sec = (utime + stime)/ticks_per_sec;
    }
  if (verbose > 1)
    fprintf(stderr, "[timecheck: %d seconds]\n", sec);
  if (sec > timeout)
    die("Time limit exceeded.");
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
  start_time = time(NULL);
  ticks_per_sec = sysconf(_SC_CLK_TCK);
  if (ticks_per_sec <= 0)
    die("Invalid ticks_per_sec!");
  if (timeout)
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
	  struct timeval total;
	  int wall;
	  box_pid = 0;
	  if (WEXITSTATUS(stat))
	    die("Exited with error status %d.", WEXITSTATUS(stat));
	  timeradd(&rus.ru_utime, &rus.ru_stime, &total);
	  wall = time(NULL) - start_time;
	  if ((use_wall_clock ? wall : total.tv_sec) > timeout)
	    die("Time limit exceeded (after exit).");
	  fprintf(stderr, "OK (%d sec real, %d sec wall, %d syscalls)\n", (int) total.tv_sec, wall, syscall_count);
	  exit(0);
	}
      if (WIFSIGNALED(stat))
	{
	  box_pid = 0;
	  die("Caught fatal signal %d.", WTERMSIG(stat));
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
		log(">> Traceme request caught\n");
	      else if (stop_count & 1)		/* Syscall entry */
		{
		  log(">> Syscall %3ld (%08lx,%08lx,%08lx) ", u.regs.orig_eax, u.regs.ebx, u.regs.ecx, u.regs.edx);
		  syscall_count++;
		  if (!valid_syscall(&u))
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
		      die("Forbidden syscall %d.", sys);
		    }
		}
	      else					/* Syscall return */
		log("= %ld\n", u.regs.eax);
	      ptrace(PTRACE_SYSCALL, box_pid, 0, 0);
	    }
	  else if (sig != SIGSTOP && sig != SIGXCPU && sig != SIGXFSZ)
	    {
	      log(">> Signal %d\n", sig);
	      ptrace(PTRACE_SYSCALL, box_pid, 0, sig);
	    }
	  else
	    die("Received signal %d.", sig);
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
  char *env[1] = { NULL };

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
  if (filter_syscalls && ptrace(PTRACE_TRACEME) < 0)
    die("ptrace(PTRACE_TRACEME): %m");
  execve(args[0], args, (pass_environ ? environ : env));
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
-e\t\tPass full environment of parent process\n\
-f\t\tFilter system calls (-ff=very restricted)\n\
-i <file>\tRedirect stdin from <file>\n\
-m <size>\tLimit address space to <size> KB\n\
-o <file>\tRedirect stdout to <file>\n\
-t <time>\tStop after <time> seconds\n\
-T\t\tAllow syscalls for measuring run time\n\
-v\t\tBe verbose\n\
-w\t\tMeasure wall clock time instead of run time\n\
");
  exit(1);
}

int
main(int argc, char **argv)
{
  int c;
  uid_t uid;

  while ((c = getopt(argc, argv, "a:c:efi:m:o:t:Tvw")) >= 0)
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
      case 't':
	timeout = atol(optarg);
	break;
      case 'T':
	allow_times++;
	break;
      case 'v':
	verbose++;
	break;
      case 'w':
	use_wall_clock = 1;
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
