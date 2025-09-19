#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void system_exit(int status);
void exit_close(int fd);
#endif /* userprog/syscall.h */
