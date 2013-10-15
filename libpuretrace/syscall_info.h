#ifndef SYSCALL_INFO_H
#define SYSCALL_INFO_H
#include "libpuretrace.h"

puretrace_syscall_info syscall_get_info (long int sysno, long int a1, long int a2, long int a3, long int a4, long int a5, long int a6);
void syscall_print_info(puretrace_syscall_info *info);
void syscall_print_detailed_info(puretrace_syscall_info *info);

#endif
