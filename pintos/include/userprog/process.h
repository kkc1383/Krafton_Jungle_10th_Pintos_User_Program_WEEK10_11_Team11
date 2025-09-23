#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"

/* 인지 전달 구조체 관련 */
#define ARGS_LEN_MAX 2048
#define FILE_NAME_LEN_MAX 14

struct passing_arguments {
  char full_args[ARGS_LEN_MAX];
  char file_name[FILE_NAME_LEN_MAX + 1];
  struct thread *parent;
};

struct fork_aux {
  struct intr_frame if_;
  struct thread *parent;
  // struct semaphore *fork_sema;
  // bool fork_success;
  struct child_process *cp;
};

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
static bool argument_passing(const char *args, struct intr_frame *if_);
struct child_process *find_child_process(struct thread *parent, tid_t tid);
struct thread *find_child_thread(tid_t child_tid);
struct child_process *child_process_create(tid_t tid);

#endif /* userprog/process.h */
