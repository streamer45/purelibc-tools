#include "syscall_info.h"

static void read_write_get_info(puretrace_syscall_info *info, const char *read_write, long int a1, long int a2, long int a3) {

  char str[64];
  int i;
  int len;

  strcpy(info->name,read_write); 

  strcpy(info->args[0].name,"fd");
  strcpy(info->args[0].type,"int");
  sprintf(str,"%d",a1);
  strcpy(info->args[0].value,str);

  strcpy(info->args[1].name,"buf");
  strcpy(info->args[1].type,"const void *");
  sprintf(str,"%d --> \"",a2);
  len = strlen(str);
  snprintf(&str[len],64-len-1,"%s",(char *)a2);
  str[62] = '"';
  strcpy(info->args[1].value,str);

  strcpy(info->args[2].name,"count");
  strcpy(info->args[2].type,"size_t");
  sprintf(str,"%d",a3);
  strcpy(info->args[2].value,str);

  return;
}

static void open_get_info(puretrace_syscall_info *info, long int a1, long int a2, long int a3) {

  char str[16];

  strcpy(info->name,"open"); 

  strcpy(info->args[0].name,"pathname");
  strcpy(info->args[0].type,"char *");
  strcpy(info->args[0].value,(char *)a1);

  strcpy(info->args[1].name,"flags");
  strcpy(info->args[1].type,"int");
  sprintf(str,"%d",a2);
  strcpy(info->args[1].value,str);

  if (a3) {
    strcpy(info->args[2].name,"mode");
    strcpy(info->args[2].type,"mode_t");
    sprintf(str,"%d",a3);
    strcpy(info->args[2].value,str);
  }

  return;
}

static void close_get_info(puretrace_syscall_info *info, long int a1) {

  char str[16];

  strcpy(info->name,"close");
  strcpy(info->args[0].name,"fd");
  strcpy(info->args[0].type,"int");
  sprintf(str,"%d",a1);
  strcpy(info->args[0].value,str);

  return;
}

puretrace_syscall_info syscall_get_info (long int sysno, long int a1, long int a2, long int a3, long int a4, long int a5, long int a6) {

  puretrace_syscall_info info;
  memset(&info,0,sizeof(puretrace_syscall_info));

  info.number = sysno;

  switch (sysno) {
    /* x86_64 syscalls */
    case __NR_read: read_write_get_info(&info,"read",a1,a2,a3); break;
    case __NR_write: read_write_get_info(&info,"write",a1,a2,a3); break;
    case __NR_open: open_get_info(&info,a1,a2,a3); break;
    case __NR_close: close_get_info(&info,a1); break;
    case __NR_stat: strcpy(info.name,"stat"); break;
    case __NR_fstat: strcpy(info.name,"fstat"); break;
    case __NR_lstat: strcpy(info.name,"lstat"); break;
    case __NR_poll: strcpy(info.name,"poll"); break;
    case __NR_lseek: strcpy(info.name,"lseek"); break;
    case __NR_mmap: strcpy(info.name,"mmap"); break;
    case __NR_mprotect: strcpy(info.name,"mprotect"); break;
    case __NR_munmap: strcpy(info.name,"munmap"); break;
    case __NR_brk: strcpy(info.name,"brk"); break;
    case __NR_rt_sigaction: strcpy(info.name,"rt_sigaction"); break;
    case __NR_rt_sigprocmask: strcpy(info.name,"rt_sigprocmask"); break;
    case __NR_rt_sigreturn: strcpy(info.name,"rt_sigreturn"); break;
    case __NR_ioctl: strcpy(info.name,"ioctl"); break;
    case __NR_pread64: strcpy(info.name,"pread64"); break;
    case __NR_pwrite64: strcpy(info.name,"pwrite64"); break;
    case __NR_readv: strcpy(info.name,"readv"); break;
    case __NR_writev: strcpy(info.name,"writev"); break;
    case __NR_access: strcpy(info.name,"access"); break;
    case __NR_pipe: strcpy(info.name,"pipe"); break;
    case __NR_select: strcpy(info.name,"select"); break;
    case __NR_sched_yield: strcpy(info.name,"sched_yield"); break;
    case __NR_mremap: strcpy(info.name,"mremap"); break;
    case __NR_msync: strcpy(info.name,"msync"); break;
    case __NR_mincore: strcpy(info.name,"mincore"); break;
    case __NR_madvise: strcpy(info.name,"madvise"); break;
    case __NR_shmget: strcpy(info.name,"shmget"); break;
    case __NR_shmat: strcpy(info.name,"shmat"); break;
    case __NR_shmctl: strcpy(info.name,"shmctl"); break;
    case __NR_dup: strcpy(info.name,"dup"); break;
    case __NR_dup2: strcpy(info.name,"dup2"); break;
    case __NR_pause: strcpy(info.name,"pause"); break;
    case __NR_nanosleep: strcpy(info.name,"nanosleep"); break;
    case __NR_getitimer: strcpy(info.name,"getitimer"); break;
    case __NR_alarm: strcpy(info.name,"alarm"); break;
    case __NR_setitimer: strcpy(info.name,"setitimer"); break;
    case __NR_getpid: strcpy(info.name,"getpid"); break;
    case __NR_sendfile: strcpy(info.name,"sendfile"); break;
    case __NR_socket: strcpy(info.name,"socket"); break;
    case __NR_connect: strcpy(info.name,"connect"); break;
    case __NR_accept: strcpy(info.name,"accept"); break;
    case __NR_sendto: strcpy(info.name,"sendto"); break;
    case __NR_recvfrom: strcpy(info.name,"recvfrom"); break;
    case __NR_sendmsg: strcpy(info.name,"sendmsg"); break;
    case __NR_recvmsg: strcpy(info.name,"recvmsg"); break;
    case __NR_shutdown: strcpy(info.name,"shutdown"); break;
    case __NR_bind: strcpy(info.name,"bind"); break;
    case __NR_listen: strcpy(info.name,"listen"); break;
    case __NR_getsockname: strcpy(info.name,"getsockname"); break;
    case __NR_getpeername: strcpy(info.name,"getpeername"); break;
    case __NR_socketpair: strcpy(info.name,"socketpair"); break;
    case __NR_setsockopt: strcpy(info.name,"setsockopt"); break;
    case __NR_getsockopt: strcpy(info.name,"getsockopt"); break;
    case __NR_clone: strcpy(info.name,"clone"); break;
    case __NR_fork: strcpy(info.name,"fork"); break;
    case __NR_vfork: strcpy(info.name,"vfork"); break;
    case __NR_execve: strcpy(info.name,"execve"); break;
    case __NR_exit: strcpy(info.name,"exit"); break;
    case __NR_wait4: strcpy(info.name,"wait4"); break;
    case __NR_kill: strcpy(info.name,"kill"); break;
    case __NR_uname: strcpy(info.name,"uname"); break;
    case __NR_semget: strcpy(info.name,"semget"); break;
    case __NR_semop: strcpy(info.name,"semop"); break;
    case __NR_semctl: strcpy(info.name,"semctl"); break;
    case __NR_shmdt: strcpy(info.name,"shmdt"); break;
    case __NR_msgget: strcpy(info.name,"msgget"); break;
    case __NR_msgsnd: strcpy(info.name,"msgsnd"); break;
    case __NR_msgrcv: strcpy(info.name,"msgrcv"); break;
    case __NR_msgctl: strcpy(info.name,"msgctl"); break;
    case __NR_fcntl: strcpy(info.name,"fcntl"); break;
    case __NR_flock: strcpy(info.name,"flock"); break;
    case __NR_fsync: strcpy(info.name,"fsync"); break;
    case __NR_fdatasync: strcpy(info.name,"fdatasync"); break;
    case __NR_truncate: strcpy(info.name,"truncate"); break;
    case __NR_ftruncate: strcpy(info.name,"ftruncate"); break;
    case __NR_getdents: strcpy(info.name,"getdents"); break;
    case __NR_getcwd: strcpy(info.name,"getcwd"); break;
    case __NR_chdir: strcpy(info.name,"chdir"); break;
    case __NR_fchdir: strcpy(info.name,"fchdir"); break;
    case __NR_rename: strcpy(info.name,"rename"); break;
    case __NR_mkdir: strcpy(info.name,"mkdir"); break;
    case __NR_rmdir: strcpy(info.name,"rmdir"); break;
    case __NR_creat: strcpy(info.name,"creat"); break;
    case __NR_link: strcpy(info.name,"link"); break;
    case __NR_unlink: strcpy(info.name,"unlink"); break;
    case __NR_symlink: strcpy(info.name,"symlink"); break;
    case __NR_readlink: strcpy(info.name,"readlink"); break;
    case __NR_chmod: strcpy(info.name,"chmod"); break;
    case __NR_fchmod: strcpy(info.name,"fchmod"); break;
    case __NR_chown: strcpy(info.name,"chown"); break;
    case __NR_fchown: strcpy(info.name,"fchown"); break;
    case __NR_lchown: strcpy(info.name,"lchown"); break;
    case __NR_umask: strcpy(info.name,"umask"); break;
    case __NR_gettimeofday: strcpy(info.name,"gettimeofday"); break;
    case __NR_getrlimit: strcpy(info.name,"getrlimit"); break;
    case __NR_getrusage: strcpy(info.name,"getrusage"); break;
    case __NR_sysinfo: strcpy(info.name,"sysinfo"); break;
    case __NR_times: strcpy(info.name,"times"); break;
    case __NR_ptrace: strcpy(info.name,"ptrace"); break;
    case __NR_getuid: strcpy(info.name,"getuid"); break;
    case __NR_syslog: strcpy(info.name,"syslog"); break;
    case __NR_getgid: strcpy(info.name,"getgid"); break;
    case __NR_setuid: strcpy(info.name,"setuid"); break;
    case __NR_setgid: strcpy(info.name,"setgid"); break;
    case __NR_geteuid: strcpy(info.name,"geteuid"); break;
    case __NR_getegid: strcpy(info.name,"getegid"); break;
    case __NR_setpgid: strcpy(info.name,"setpgid"); break;
    case __NR_getppid: strcpy(info.name,"getppid"); break;
    case __NR_getpgrp: strcpy(info.name,"getpgrp"); break;
    case __NR_setsid: strcpy(info.name,"setsid"); break;
    case __NR_setreuid: strcpy(info.name,"setreuid"); break;
    case __NR_setregid: strcpy(info.name,"setregid"); break;
    case __NR_getgroups: strcpy(info.name,"getgroups"); break;
    case __NR_setgroups: strcpy(info.name,"setgroups"); break;
    case __NR_setresuid: strcpy(info.name,"setresuid"); break;
    case __NR_getresuid: strcpy(info.name,"getresuid"); break;
    case __NR_setresgid: strcpy(info.name,"setresgid"); break;
    case __NR_getresgid: strcpy(info.name,"getresgid"); break;
    case __NR_getpgid: strcpy(info.name,"getpgid"); break;
    case __NR_setfsuid: strcpy(info.name,"setfsuid"); break;
    case __NR_setfsgid: strcpy(info.name,"setfsgid"); break;
    case __NR_getsid: strcpy(info.name,"getsid"); break;
    case __NR_capget: strcpy(info.name,"capget"); break;
    case __NR_capset: strcpy(info.name,"capset"); break;
    case __NR_rt_sigpending: strcpy(info.name,"rt_sigpending"); break;
    case __NR_rt_sigtimedwait: strcpy(info.name,"rt_sigtimedwait"); break;
    case __NR_rt_sigqueueinfo: strcpy(info.name,"rt_sigqueueinfo"); break;
    case __NR_rt_sigsuspend: strcpy(info.name,"rt_sigsuspend"); break;
    case __NR_sigaltstack: strcpy(info.name,"sigaltstack"); break;
    case __NR_utime: strcpy(info.name,"utime"); break;
    case __NR_mknod: strcpy(info.name,"mknod"); break;
    case __NR_uselib: strcpy(info.name,"uselib"); break;
    case __NR_personality: strcpy(info.name,"personality"); break;
    case __NR_ustat: strcpy(info.name,"ustat"); break;
    case __NR_statfs: strcpy(info.name,"statfs"); break;
    case __NR_fstatfs: strcpy(info.name,"fstatfs"); break;
    case __NR_sysfs: strcpy(info.name,"sysfs"); break;
    case __NR_getpriority: strcpy(info.name,"getpriority"); break;
    case __NR_setpriority: strcpy(info.name,"setpriority"); break;
    case __NR_sched_setparam: strcpy(info.name,"sched_setparam"); break;
    case __NR_sched_getparam: strcpy(info.name,"sched_getparam"); break;
    case __NR_sched_setscheduler: strcpy(info.name,"sched_setscheduler"); break;
    case __NR_sched_getscheduler: strcpy(info.name,"sched_getscheduler"); break;
    case __NR_sched_get_priority_max: strcpy(info.name,"sched_get_priority_max"); break;
    case __NR_sched_get_priority_min: strcpy(info.name,"sched_get_priority_min"); break;
    case __NR_sched_rr_get_interval: strcpy(info.name,"sched_rr_get_interval"); break;
    case __NR_mlock: strcpy(info.name,"mlock"); break;
    case __NR_munlock: strcpy(info.name,"munlock"); break;
    case __NR_mlockall: strcpy(info.name,"mlockall"); break;
    case __NR_munlockall: strcpy(info.name,"munlockall"); break;
    case __NR_vhangup: strcpy(info.name,"vhangup"); break;
    case __NR_modify_ldt: strcpy(info.name,"modify_ldt"); break;
    case __NR_pivot_root: strcpy(info.name,"pivot_root"); break;
    case __NR__sysctl: strcpy(info.name,"_sysctl"); break;
    case __NR_prctl: strcpy(info.name,"prctl"); break;
    case __NR_arch_prctl: strcpy(info.name,"arch_prctl"); break;
    case __NR_adjtimex: strcpy(info.name,"adjtimex"); break;
    case __NR_setrlimit: strcpy(info.name,"setrlimit"); break;
    case __NR_chroot: strcpy(info.name,"chroot"); break;
    case __NR_sync: strcpy(info.name,"sync"); break;
    case __NR_acct: strcpy(info.name,"acct"); break;
    case __NR_settimeofday: strcpy(info.name,"settimeofday"); break;
    case __NR_mount: strcpy(info.name,"mount"); break;
    case __NR_umount2: strcpy(info.name,"umount2"); break;
    case __NR_swapon: strcpy(info.name,"swapon"); break;
    case __NR_swapoff: strcpy(info.name,"swapoff"); break;
    case __NR_reboot: strcpy(info.name,"reboot"); break;
    case __NR_sethostname: strcpy(info.name,"sethostname"); break;
    case __NR_setdomainname: strcpy(info.name,"setdomainname"); break;
    case __NR_iopl: strcpy(info.name,"iopl"); break;
    case __NR_ioperm: strcpy(info.name,"ioperm"); break;
    case __NR_create_module: strcpy(info.name,"create_module"); break;
    case __NR_init_module: strcpy(info.name,"init_module"); break;
    case __NR_delete_module: strcpy(info.name,"delete_module"); break;
    case __NR_get_kernel_syms: strcpy(info.name,"get_kernel_syms"); break;
    case __NR_query_module: strcpy(info.name,"query_module"); break;
    case __NR_quotactl: strcpy(info.name,"quotactl"); break;
    case __NR_nfsservctl: strcpy(info.name,"nfsservctl"); break;
    case __NR_getpmsg: strcpy(info.name,"getpmsg"); break;
    case __NR_putpmsg: strcpy(info.name,"putpmsg"); break;
    case __NR_afs_syscall: strcpy(info.name,"afs_syscall"); break;
    case __NR_tuxcall: strcpy(info.name,"tuxcall"); break;
    case __NR_security: strcpy(info.name,"security"); break;
    case __NR_gettid: strcpy(info.name,"gettid"); break;
    case __NR_readahead: strcpy(info.name,"readahead"); break;
    case __NR_setxattr: strcpy(info.name,"setxattr"); break;
    case __NR_lsetxattr: strcpy(info.name,"lsetxattr"); break;
    case __NR_fsetxattr: strcpy(info.name,"fsetxattr"); break;
    case __NR_getxattr: strcpy(info.name,"getxattr"); break;
    case __NR_lgetxattr: strcpy(info.name,"lgetxattr"); break;
    case __NR_fgetxattr: strcpy(info.name,"fgetxattr"); break;
    case __NR_listxattr: strcpy(info.name,"listxattr"); break;
    case __NR_llistxattr: strcpy(info.name,"llistxattr"); break;
    case __NR_flistxattr: strcpy(info.name,"flistxattr"); break;
    case __NR_removexattr: strcpy(info.name,"removexattr"); break;
    case __NR_lremovexattr: strcpy(info.name,"lremovexattr"); break;
    case __NR_fremovexattr: strcpy(info.name,"fremovexattr"); break;
    case __NR_tkill: strcpy(info.name,"tkill"); break;
    case __NR_time: strcpy(info.name,"time"); break;
    case __NR_futex: strcpy(info.name,"futex"); break;
    case __NR_sched_setaffinity: strcpy(info.name,"sched_setaffinity"); break;
    case __NR_sched_getaffinity: strcpy(info.name,"sched_getaffinity"); break;
    case __NR_set_thread_area: strcpy(info.name,"set_thread_area"); break;
    case __NR_io_setup: strcpy(info.name,"io_setup"); break;
    case __NR_io_destroy: strcpy(info.name,"io_destroy"); break;
    case __NR_io_getevents: strcpy(info.name,"io_getevents"); break;
    case __NR_io_submit: strcpy(info.name,"io_submit"); break;
    case __NR_io_cancel: strcpy(info.name,"io_cancel"); break;
    case __NR_get_thread_area: strcpy(info.name,"get_thread_area"); break;
    case __NR_lookup_dcookie: strcpy(info.name,"lookup_dcookie"); break;
    case __NR_epoll_create: strcpy(info.name,"epoll_create"); break;
    case __NR_epoll_ctl_old: strcpy(info.name,"epoll_ctl_old"); break;
    case __NR_epoll_wait_old: strcpy(info.name,"epoll_wait_old"); break;
    case __NR_remap_file_pages: strcpy(info.name,"remap_file_pages"); break;
    case __NR_getdents64: strcpy(info.name,"getdents64"); break;
    case __NR_set_tid_address: strcpy(info.name,"set_tid_address"); break;
    case __NR_restart_syscall: strcpy(info.name,"restart_syscall"); break;
    case __NR_semtimedop: strcpy(info.name,"semtimedop"); break;
    case __NR_fadvise64: strcpy(info.name,"fadvise64"); break;
    case __NR_timer_create: strcpy(info.name,"timer_create"); break;
    case __NR_timer_settime: strcpy(info.name,"timer_settime"); break;
    case __NR_timer_gettime: strcpy(info.name,"timer_gettime"); break;
    case __NR_timer_getoverrun: strcpy(info.name,"timer_getoverrun"); break;
    case __NR_timer_delete: strcpy(info.name,"timer_delete"); break;
    case __NR_clock_settime: strcpy(info.name,"clock_settime"); break;
    case __NR_clock_gettime: strcpy(info.name,"clock_gettime"); break;
    case __NR_clock_getres: strcpy(info.name,"clock_getres"); break;
    case __NR_clock_nanosleep: strcpy(info.name,"clock_nanosleep"); break;
    case __NR_exit_group: strcpy(info.name,"exit_group"); break;
    case __NR_epoll_wait: strcpy(info.name,"epoll_wait"); break;
    case __NR_epoll_ctl: strcpy(info.name,"epoll_ctl"); break;
    case __NR_tgkill: strcpy(info.name,"tgkill"); break;
    case __NR_utimes: strcpy(info.name,"utimes"); break;
    case __NR_vserver: strcpy(info.name,"vserver"); break;
    case __NR_mbind: strcpy(info.name,"mbind"); break;
    case __NR_set_mempolicy: strcpy(info.name,"set_mempolicy"); break;
    case __NR_get_mempolicy: strcpy(info.name,"get_mempolicy"); break;
    case __NR_mq_open: strcpy(info.name,"mq_open"); break;
    case __NR_mq_unlink: strcpy(info.name,"mq_unlink"); break;
    case __NR_mq_timedsend: strcpy(info.name,"mq_timedsend"); break;
    case __NR_mq_timedreceive: strcpy(info.name,"mq_timedreceive"); break;
    case __NR_mq_notify: strcpy(info.name,"mq_notify"); break;
    case __NR_mq_getsetattr: strcpy(info.name,"mq_getsetattr"); break;
    case __NR_kexec_load: strcpy(info.name,"kexec_load"); break;
    case __NR_waitid: strcpy(info.name,"waitid"); break;
    case __NR_add_key: strcpy(info.name,"add_key"); break;
    case __NR_request_key: strcpy(info.name,"request_key"); break;
    case __NR_keyctl: strcpy(info.name,"keyctl"); break;
    case __NR_ioprio_set: strcpy(info.name,"ioprio_set"); break;
    case __NR_ioprio_get: strcpy(info.name,"ioprio_get"); break;
    case __NR_inotify_init: strcpy(info.name,"inotify_init"); break;
    case __NR_inotify_add_watch: strcpy(info.name,"inotify_add_watch"); break;
    case __NR_inotify_rm_watch: strcpy(info.name,"inotify_rm_watch"); break;
    case __NR_migrate_pages: strcpy(info.name,"migrate_pages"); break;
    case __NR_openat: strcpy(info.name,"openat"); break;
    case __NR_mkdirat: strcpy(info.name,"mkdirat"); break;
    case __NR_mknodat: strcpy(info.name,"mknodat"); break;
    case __NR_fchownat: strcpy(info.name,"fchownat"); break;
    case __NR_futimesat: strcpy(info.name,"futimesat"); break;
    case __NR_newfstatat: strcpy(info.name,"newfstatat"); break;
    case __NR_unlinkat: strcpy(info.name,"unlinkat"); break;
    case __NR_renameat: strcpy(info.name,"renameat"); break;
    case __NR_linkat: strcpy(info.name,"linkat"); break;
    case __NR_symlinkat: strcpy(info.name,"symlinkat"); break;
    case __NR_readlinkat: strcpy(info.name,"readlinkat"); break;
    case __NR_fchmodat: strcpy(info.name,"fchmodat"); break;
    case __NR_faccessat: strcpy(info.name,"faccessat"); break;
    case __NR_pselect6: strcpy(info.name,"pselect6"); break;
    case __NR_ppoll: strcpy(info.name,"ppoll"); break;
    case __NR_unshare: strcpy(info.name,"unshare"); break;
    case __NR_set_robust_list: strcpy(info.name,"set_robust_list"); break;
    case __NR_get_robust_list: strcpy(info.name,"get_robust_list"); break;
    case __NR_splice: strcpy(info.name,"splice"); break;
    case __NR_tee: strcpy(info.name,"tee"); break;
    case __NR_sync_file_range: strcpy(info.name,"sync_file_range"); break;
    case __NR_vmsplice: strcpy(info.name,"vmsplice"); break;
    case __NR_move_pages: strcpy(info.name,"move_pages"); break;
    case __NR_utimensat: strcpy(info.name,"utimensat"); break;
    case __NR_epoll_pwait: strcpy(info.name,"epoll_pwait"); break;
    case __NR_signalfd: strcpy(info.name,"signalfd"); break;
    case __NR_timerfd_create: strcpy(info.name,"timerfd_create"); break;
    case __NR_eventfd: strcpy(info.name,"eventfd"); break;
    case __NR_fallocate: strcpy(info.name,"fallocate"); break;
    case __NR_timerfd_settime: strcpy(info.name,"timerfd_settime"); break;
    case __NR_timerfd_gettime: strcpy(info.name,"timerfd_gettime"); break;
    case __NR_accept4: strcpy(info.name,"accept4"); break;
    case __NR_signalfd4: strcpy(info.name,"signalfd4"); break;
    case __NR_eventfd2: strcpy(info.name,"eventfd2"); break;
    case __NR_epoll_create1: strcpy(info.name,"epoll_create1"); break;
    case __NR_dup3: strcpy(info.name,"dup3"); break;
    case __NR_pipe2: strcpy(info.name,"pipe2"); break;
    case __NR_inotify_init1: strcpy(info.name,"inotify_init1"); break;
    case __NR_preadv: strcpy(info.name,"preadv"); break;
    case __NR_pwritev: strcpy(info.name,"pwritev"); break;
    case __NR_rt_tgsigqueueinfo: strcpy(info.name,"rt_tgsigqueueinfo"); break;
    case __NR_perf_event_open: strcpy(info.name,"perf_event_open"); break;
    case __NR_recvmmsg: strcpy(info.name,"recvmmsg"); break;
    case __NR_fanotify_init: strcpy(info.name,"fanotify_init"); break;
    case __NR_fanotify_mark: strcpy(info.name,"fanotify_mark"); break;
    case __NR_prlimit64: strcpy(info.name,"prlimit64"); break;
    case __NR_name_to_handle_at: strcpy(info.name,"name_to_handle_at"); break;
    case __NR_open_by_handle_at: strcpy(info.name,"open_by_handle_at"); break;
    case __NR_clock_adjtime: strcpy(info.name,"clock_adjtime"); break;
    case __NR_syncfs: strcpy(info.name,"syncfs"); break;
    case __NR_sendmmsg: strcpy(info.name,"sendmmsg"); break;
    case __NR_setns: strcpy(info.name,"setns"); break;
    case __NR_getcpu: strcpy(info.name,"getcpu"); break;
    case __NR_process_vm_readv: strcpy(info.name,"process_vm_readv"); break;
    case __NR_process_vm_writev: strcpy(info.name,"process_vm_writev"); break;
    case __NR_kcmp: strcpy(info.name,"kcmp"); break;
    case __NR_finit_module: strcpy(info.name,"finit_module"); break;
    default: break;
  }

  return info;
}

void syscall_print_info(puretrace_syscall_info *info) {

  if (!info->name[0]) {
    return;
  }

  _pure_debug_printf("SYSCALL %d --> %s\n",info->number,info->name);

  return;
}

void syscall_print_detailed_info(puretrace_syscall_info *info) {

  if (!info->name[0]) {
    return;
  }

  int i;
  int printed;

  printed = 0;

  for (i=0;i<6;i++) {
    if (info->args[i].name[0]) {
      printed = 1;
      _pure_debug_printf("\n  arg[%d]\n",i);
      if (info->args[i].type[0]) {
        _pure_debug_printf("    %s %s = ",info->args[i].type,info->args[i].name);
        if (info->args[i].value[0]) {
          _pure_debug_printf("%s\n",info->args[i].value);
        } else {
          _pure_debug_printf("\n");
        }
      }
    }
  }  

  if (printed) {
    _pure_debug_printf("\n");
  }

  return;
}
