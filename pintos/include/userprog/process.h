#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

/* 인지 전달 구조체 관련 */
#define ARGS_LEN_MAX 2048
#define FILE_NAME_LEN_MAX 14

struct passing_arguments {
    char full_args[ARGS_LEN_MAX];
    char file_name[FILE_NAME_LEN_MAX + 1];
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
