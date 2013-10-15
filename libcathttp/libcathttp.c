#include "libcathttp.h"

static sfun _native_syscall;

static size_t http_data_handler(void *buffer, size_t size, size_t nmemb, void *userp) {

  _native_syscall(__NR_write,fileno(stdout),buffer,size*nmemb,NULL,NULL,NULL);

  return size*nmemb;
}

static long int syscall_handler(long int sysno, ...) {

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

  CURL *curl;
  CURLcode res;
 
  int dummy_fd = 88;

  static char url[256];
  static int is_url;

  if (sysno == __NR_open) {
    char *path;
    path = (char *)a1;
    if (!strncmp(path,"http://",7) || !strncmp(path,"https://",8)) {
      is_url = 1;
      strncpy(url,path,256);
      return dummy_fd;
    }
  }

  if (sysno == __NR_fstat) {
    if (a1 == dummy_fd) {
      /* needed to avoid errors on output redirection*/
      return _native_syscall(sysno,fileno(stderr),a2,a3,a4,a5,a6);;
    }
  }

  if (sysno == __NR_close) {
    if (a1 == dummy_fd) {
      return 0;
    }
  }

  if (sysno == __NR_read) {
    if (is_url) {
      if (a1 == dummy_fd) {

          curl = curl_easy_init();

          if (curl) {

            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_data_handler);

            /* Perform the request, res will get the return code */ 
            res = curl_easy_perform(curl);

            /* Check for errors */ 
            if(res != CURLE_OK) {
              fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
              return 0;
            }

            /* always cleanup */ 
            curl_easy_cleanup(curl);

            return 0;
          }
        } 
      }
  }

  return _native_syscall(sysno,a1,a2,a3,a4,a5,a6);
}

void __attribute((constructor)) init_test (void) {

  if (!strncmp(program_invocation_name,"cat",3)) {
    _native_syscall=_pure_start(syscall_handler,NULL,PUREFLAG_STDALL);
  }

  return;
}

void __attribute((destructor)) exit_test (void) {
  //_pure_debug_printf("Unloading libcathttp.\n");
  return;
}
