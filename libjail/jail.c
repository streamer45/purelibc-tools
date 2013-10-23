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


int main (int argc, char *argv[]) {
  int cid;
  int status;
  char *cwd;
  char *args[2] = {"bash",NULL};
  char *env;

  cwd = get_current_dir_name();

  if (!cwd) {
    return 1;
  }

  asprintf(&env,"%s/libpurelibc.so:%s/libjail.so",cwd,cwd);

  if (setenv("LD_PRELOAD",env,1) < 0) {
    fprintf(stderr,"%s",strerror(errno));
    free(cwd);
    free(env);
    return 1;
  }

  setenv("JAIL",cwd,1);
  
  cid = fork();

  if (!cid) {
    execvp("bash",args);
    return 0;
  } else {
    wait(&status);
  }

  printf("All over now.\n");

  /* Cleaning Up */
  free(cwd);
  free(env);
  unsetenv("LD_PRELOAD");

  return 0;
}
