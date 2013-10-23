#include "libjail.h"

static sfun _native_syscall;

static long int syscall_handler(long int sysno, ...) {

  long int res;
  char *cwd;

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

  cwd = getenv("JAIL");

  if (cwd) {
    switch (sysno) {
      case __NR_chdir: {
        char *rpath;
        rpath = realpath((char *)a1,NULL);
        if (rpath) {
          if (strstr(rpath,cwd)) {
            _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
          } else {
            errno = EACCES;
            return -1;
          }
          free(rpath);
        }
        break;
      }
      default: break;
    }
  }

  return _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
}

void __attribute((constructor)) init_test (void) {
  _native_syscall=_pure_start(syscall_handler,NULL,PUREFLAG_STDALL);
  return;
}

