#include "libdirewrite.h"

static sfun _native_syscall;

static long int syscall_handler(long int sysno, ...) {

  long int res;
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


  if ( (sysno == __NR_open) || (sysno == __NR_stat) || (sysno == __NR_lstat) || (sysno == __NR_getxattr) || (sysno == __NR_chdir) || (sysno == __NR_statfs) || (sysno == __NR_access) || (sysno == __NR_inotify_add_watch) || (sysno == __NR_faccessat) || (sysno == __NR_newfstatat) || (sysno == __NR_unlinkat)) {
    char *source;
    char *dest;
    char *path;
    char *str;
    char *newpath;
    char *path_arg;
    
    source = getenv("LDRW_SOURCE");
    dest = getenv("LDRW_DEST");

    if ((sysno == __NR_inotify_add_watch) || (sysno == __NR_faccessat) || (sysno == __NR_newfstatat) || (sysno == __NR_unlinkat)) {
      path_arg = (char *)a2;
    } else {
      path_arg = (char *)a1;
    }

    if (source && dest) {
      
      path = realpath(path_arg,NULL);

      if (source[strlen(source)-1] == '/') {
        source[strlen(source)-1] = '\0';
      }

      if (dest[strlen(dest)-1] == '/') {
        dest[strlen(dest)-1] = '\0';
      }
      
      if (!path) {
        if (path_arg[0] != '/') {
          asprintf(&path,"%s/%s",source,path_arg);
        }
      }

      if (path) {
        str = strstr(path,source);
        if (str) {
          asprintf(&newpath,"%s%s",dest,&path[strlen(source)]);
          //_pure_debug_printf("newpath is %s\n",newpath);

          if ((sysno == __NR_inotify_add_watch) || (sysno == __NR_faccessat) || (sysno == __NR_newfstatat) || (sysno == __NR_unlinkat)) {
            res = _native_syscall(sysno,a1,newpath,a3,a4,a5,a6);
          } else {
            res = _native_syscall(sysno,newpath,a2,a3,a4,a5,a6);            
          }

          free(path);
          free(newpath);
          return res;
        }
      } 
    }

  }

  return _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
}

void __attribute((constructor)) init_test (void) {
  _native_syscall=_pure_start(syscall_handler,NULL,PUREFLAG_STDALL);
  return;
}

