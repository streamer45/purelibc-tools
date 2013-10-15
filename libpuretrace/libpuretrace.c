#include "libpuretrace.h"

static sfun _native_syscall;
static syscall_counter;
static puretrace_opts gopts;

static long int puretrace(long int sysno, ...) {
  va_list ap;
  long int a1,a2,a3,a4,a5,a6;
  va_start (ap, sysno);
  a1=va_arg(ap,long int);
  a2=va_arg(ap,long int);
  a3=va_arg(ap,long int);
  a4=va_arg(ap,long int);
  a5=va_arg(ap,long int);
  a6=va_arg(ap,long int);
  va_end(ap);

  char buf[1];
  int res;
  puretrace_syscall_info sysc_info;

  syscall_counter++;

  memset(&sysc_info,0,sizeof(puretrace_syscall_info));
  sysc_info = syscall_get_info(sysno,a1,a2,a3,a4,a5,a6);

  if (!sysc_info.name[0]) {
    _pure_debug_printf("Could not get syscall n %d info, unknown syscall traced\n",sysc_info.number);
  } else {
    _pure_debug_printf("[%d]\n",syscall_counter);
    syscall_print_info(&sysc_info);    
  }

  if (gopts.interactive) {

    struct termios old_tio, new_tio;
    struct pollfd fds[1];

    tcgetattr(STDIN_FILENO,&old_tio);
    new_tio=old_tio;
    new_tio.c_lflag &=(~ICANON & ~ECHO);
    tcsetattr(STDIN_FILENO,TCSANOW,&new_tio);

    fds[0].fd = fileno(stdin);
    fds[0].events = POLLIN; 

    for (;;) {
      res = _native_syscall(__NR_poll,fds,1,100);
      if (res > 0) {
        if (fds[0].revents & POLLIN) {
          _native_syscall(__NR_read,fileno(stdin),buf,1);
          if (buf[0] == 'n') 
            break;
          if (buf[0] == 'i')
            syscall_print_detailed_info(&sysc_info);
        }
      }
    }

    tcsetattr(STDIN_FILENO,TCSANOW,&old_tio);
  }

  /* disable stdout output */
  if (gopts.disable_output) {
    if (sysno == __NR_write) {
      if (fileno(stdout) == a1) {
        return 0;
      }
    }
  }

  return _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
}

void __attribute((constructor)) init_test (void) {

  int fd;
  puretrace_opts *opts;

  printf("puretrace library loaded.\n");

  fd = shm_open("/puretrace_opts", O_RDONLY, S_IRUSR | S_IWUSR);

  if (fd == -1) {
    fprintf(stderr,"shm_open failed: %s\n",strerror(errno));
    return;
  }

  opts = mmap(NULL, sizeof(puretrace_opts),
       PROT_READ, MAP_SHARED, fd, 0);

  if (opts == MAP_FAILED) {
    fprintf(stderr,"mmap failed: %s\n",strerror(errno));
    return;
  }

  memcpy(&gopts,opts,sizeof(puretrace_opts));

  if (gopts.interactive) {
    printf("Interactive option activated!\n");
    _pure_debug_printf("Press 'n' key to trace the next syscall. Press 'i' for detailed info , if available.\n");
  }

  if (gopts.disable_output) {
    printf("Standard ouput disabled option activated!\n");
  }

  _native_syscall=_pure_start(puretrace,NULL,PUREFLAG_STDALL);

  return;

}

void __attribute((destructor)) exit_test (void) {
  _pure_debug_printf("Unloading lib, done tracing.\n");
  shm_unlink("/puretrace_opts");
  return;
}
