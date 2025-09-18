#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct passing_arguments {
    char *full_args;
    char *file_name;
    struct child_process *cp;
};

struct fork_aux {
    struct intr_frame if_;
    struct thread *parent;
    struct child_process *cp;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct child_process *find_child_process(struct thread *parent, tid_t tid);

#endif /* userprog/process.h */
