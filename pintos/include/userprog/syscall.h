#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/interrupt.h"

struct file;


void syscall_init (void);
void system_exit (int status);
void fdref_inc(struct file *fp);
void fdref_dec(struct file *fp);

#endif /* userprog/syscall.h */
