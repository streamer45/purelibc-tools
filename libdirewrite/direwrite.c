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

static void print_usage() {
  printf("syntax: \ndirewrite source dest.\nsource is the path to the source directory while dest is the path to the destination directory.\n");
  return;
}

int main (int argc, char *argv[]) {
  int cid;
  int status;
  char *env;
  char *cwd;
  char *args[2] = {"bash",NULL};
  char *sourcepath;
  char *destpath;

  /* Fork and Exec */

  if (argc != 3) {
    print_usage();
    return 0;
  }

  sourcepath = realpath(argv[1],NULL);
  destpath = realpath(argv[2],NULL);

  if (!sourcepath || !destpath) {
    fprintf(stderr,"Error reading dir paths\n");
    return 1;
  }

  printf("Source: %s, Dest: %s\n",sourcepath,destpath);

  cwd = get_current_dir_name();

  if (!cwd) {
    return 1;
  }

  asprintf(&env,"%s/libpurelibc.so:%s/libdirewrite.so",cwd,cwd);

  if (setenv("LD_PRELOAD",env,1) < 0) {
    fprintf(stderr,"setenv failed: %s\n",strerror(errno));;
    free(cwd);
    free(env);
    return 1;
  }

  setenv("LDRW_SOURCE",sourcepath,1);
  setenv("LDRW_DEST",destpath,1);

  cid = fork();

  if (!cid) {
    execvp("bash",args);
    return 0;
  } else {
    wait(&status);
  }

  printf("All over now.\n");

  /* Cleaning Up */
  free(sourcepath);
  free(destpath);
  free(cwd);
  free(env);
  unsetenv("LD_PRELOAD");

  return 0;
}
