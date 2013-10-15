typedef struct puretrace_opts puretrace_opts;
typedef struct puretrace_syscall_info puretrace_syscall_info;

#ifndef LIBPURETRACE_H
#define LIBPURETRACE_H
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include "purelibc.h"
#include <dlfcn.h>
#include <sys/poll.h>
#include <termios.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h> 
#include <getopt.h>
#include <signal.h>
#include "syscall_info.h"

extern char *program_invocation_name;

struct puretrace_opts {
  int help;
  int interactive;
  int disable_output;
  int log;
};

struct puretrace_syscall_info {
  char name[64];
  int number;
  struct syscall_args {
    char name[64];
    char type[64];
    char value[64];
  } args[6];
};

#endif
