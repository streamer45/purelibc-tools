#include "libpuretrace.h"

static void print_usage() {
  printf("Usage: puretrace [-hid] command [args]\n");
  return;
}

static void print_help () {
  printf("puretrace, simple syscall tracing tool based on purelibc\n");
  print_usage();
  printf("Options:\n");
  printf("-h Shows this help\n");
  printf("-i Enable interactive mode\n");
  printf("-d Disable standard output of the process traced\n");
  printf("-o Output to puretrace.log\n");
  return;
}

int main (int argc, char *argv[]) {

  int fd;
  int opt;
  pid_t cid;
  int i;
  int status;
  int oc;
  int num_opts;
  puretrace_opts opts;
  puretrace_opts *shared_opts;
  char *argv_backup[argc+1];

  /* Init tracer options */

  status = 0;
  num_opts = 0;
  opterr = 0;    

  for (i=0;i<argc;i++) {
    argv_backup[i] = argv[i];
  }

  argv_backup[argc] = NULL;  

  memset(&opts,0,sizeof(puretrace_opts));

  while ((oc = getopt(argc,argv_backup,"hido")) != -1) {
    switch (oc) {
      case 'h': print_help(); num_opts++; return 0;
      case 'i': opts.interactive = 1; num_opts++; break;
      case 'd': opts.disable_output = 1; num_opts++; break;
      case 'o': opts.log = 1; num_opts++; break;
      default:  break;
    }
  }

  if (argc <= 1) {
    print_usage();
    return 0;
  }

  /* Shared Memory Operations */

  fd = shm_open("/puretrace_opts", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

  if (fd == -1) {
    fprintf(stderr,"shm_open failed: %s\n",strerror(errno));
    return 1;
  }

  if (ftruncate(fd, sizeof(puretrace_opts)) == -1) {
    fprintf(stderr,"ftruncate failed: %s\n",strerror(errno));
    return 1;
  }

  shared_opts = mmap(NULL, sizeof(puretrace_opts),
       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (shared_opts == MAP_FAILED) {
    fprintf(stderr,"mmap failed: %s\n",strerror(errno));
    return 1;
  }

  if (!memset(shared_opts,0,sizeof(puretrace_opts))) {
    fprintf(stderr,"memset failed: %s\n",strerror(errno));
    return 1;
  }

  memcpy(shared_opts,&opts,sizeof(puretrace_opts));

  if (setenv("LD_PRELOAD","/home/streamer45/c/vsd/libpurelibc.so:/home/streamer45/c/vsd/libpuretrace.so",1) < 0) {
    fprintf(stderr,"setenv failed: %s\n",strerror(errno));
    return 1;
  }

  /* Fork and Exec */

  cid = fork();

  if (!cid) {
    execvp(argv[1+num_opts],&argv[1+num_opts]);
    return 0;
  } else {
    wait(&status);
  }

  printf("No more syscalls to trace, process returned.\n");
  shm_unlink("/puretrace_opts");

  /* Cleaning Up */
  unsetenv("LD_PRELOAD");

  return 0;
}
