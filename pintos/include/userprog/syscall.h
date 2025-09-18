#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/interrupt.h"

void syscall_init (void);
void system_exit (int status);

#endif /* userprog/syscall.h */
