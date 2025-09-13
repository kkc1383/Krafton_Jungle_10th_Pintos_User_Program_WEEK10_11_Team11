#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

struct child_process {
    tid_t tid;
    int exit_status;
    bool is_exited;
    bool is_waited;
    struct semaphore wait_sema;
    struct list_elem elem;
};

struct initd_aux {
    char *file_name;
    struct child_process *cp;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

#endif /* userprog/process.h */
