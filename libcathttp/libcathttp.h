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
#include <curl/curl.h>
extern char *program_invocation_name;
