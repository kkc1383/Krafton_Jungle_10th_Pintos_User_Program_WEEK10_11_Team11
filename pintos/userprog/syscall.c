#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void validate_ptr(const void *uaddr);
void validate_str(const char *str);
void validate_buffer_size(void *buffer, unsigned size);
struct file *fd_to_file(int fd);

void sys_exit(int status);
int sys_fork(const char *thread_name, struct intr_frame *f);
int sys_exec(const char *cmd_line);
int sys_wait(int pid);

bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

#define ARG_1(f_) ((f_)->R.rdi)
#define ARG_2(f_) ((f_)->R.rsi)
#define ARG_3(f_) ((f_)->R.rdx)
#define ARG_4(f_) ((f_)->R.r10)
#define ARG_5(f_) ((f_)->R.r8)
#define ARG_6(f_) ((f_)->R.r9)

static struct lock filesys_lock;

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  lock_init(&filesys_lock);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  // printf("system call!\n");
  switch (f->R.rax) {
    case SYS_HALT:
      sys_halt();
    case SYS_EXIT:
      sys_exit(ARG_1(f));
      break;
    case SYS_FORK:
      const char *name = ARG_1(f);
      f->R.rax = sys_fork(name, f);
      break;
    case SYS_EXEC:
      f->R.rax = sys_exec(ARG_1(f));
      break;
    case SYS_WAIT:
      f->R.rax = sys_wait(ARG_1(f));
      break;
    case SYS_CREATE:
      f->R.rax = sys_create(ARG_1(f), ARG_2(f));
      break;
    case SYS_REMOVE:
      f->R.rax = sys_remove(ARG_1(f));
      break;
    case SYS_OPEN:
      f->R.rax = sys_open(ARG_1(f));
      break;
    case SYS_FILESIZE:
      f->R.rax = sys_filesize(ARG_1(f));
      break;
    case SYS_READ:
      f->R.rax = sys_read(ARG_1(f), ARG_2(f), ARG_3(f));
      break;
    case SYS_WRITE:
      f->R.rax = sys_write(ARG_1(f), ARG_2(f), ARG_3(f));
      break;
    case SYS_SEEK:
      sys_seek(ARG_1(f), ARG_2(f));
      break;
    case SYS_TELL:
      f->R.rax = sys_tell(ARG_1(f));
      break;
    case SYS_CLOSE:
      sys_close(ARG_1(f));
      break;
    case SYS_DUP2:
      sys_dup2();
      break;
    case SYS_MOUNT:
      sys_mount();
      break;
    case SYS_UMOUNT:
      sys_unmount();
      break;
    default:
      break;
  }
}

/* 유효 주소검사 */
void validate_ptr(const void *uaddr) {
  if (uaddr == NULL || !is_user_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL) {
    sys_exit(-1);
  }
}
/* 문자열 검사 */
void validate_str(const char *str) {
  for (const char *p = str;; p++) {
    validate_ptr(p);
    if (*p == '\0') {
      break;
    }
  }
}

/* buffer + size 가 유효한지 검사 */
void validate_buffer_size(void *buffer, unsigned size) {
  for (unsigned i = 0; i < size; i++) {
    // t->pml4
    if (!is_user_vaddr(buffer + i) || pml4_get_page(thread_current()->pml4, buffer + i) == NULL) {
      sys_exit(-1);
    }
  }
}
/* fd -> file 유틸함수 */
struct file *fd_to_file(int fd) {
  struct thread *t = thread_current();
  if (fd < 0 || fd > t->next_fd) {
    return NULL;
  }
  return t->fd_table[fd];
}

void sys_halt() { power_off(); }
void sys_exit(int status) {
  struct thread *t = thread_current();
  if (t->self_cp != NULL) {
    t->self_cp->exit_status = status;
  }

  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

/* 프로세스 시스템콜 */
int sys_fork(const char *thread_name, struct intr_frame *f) {
  validate_str(thread_name);
  return process_fork(thread_name, f);
}
int sys_exec(const char *cmd_line) {
  validate_str(cmd_line);
  char *kern_cmd_line = palloc_get_page(0);
  memcpy(kern_cmd_line, cmd_line, strlen(cmd_line) + 1);

  int len = strlen(kern_cmd_line) + 1;
  struct passing_arguments *pargs = palloc_get_page(0);
  pargs->cp = palloc_get_page(0);

  memcpy(pargs->full_args, kern_cmd_line, len);
  memcpy(pargs->file_name, kern_cmd_line, FILE_NAME_LEN_MAX + 1);
  char *space = strchr(pargs->file_name, ' ');
  if (space) {
    *space = '\0';
  }
  // exec() 호출자는 항상 자식프로세스
  pargs->cp = thread_current()->self_cp;

  int res = process_exec(pargs);
  if (res < 0) {
    palloc_free_page(kern_cmd_line);
    sys_exit(res);
  }
  free(kern_cmd_line);
  NOT_REACHED();  // 성공하면 현재 프로세스 주소 공간이 교체되므로 여기 안 옴
}
int sys_wait(int pid) { return process_wait(pid); }

/* 파일IO 시스템콜 */
bool sys_create(const char *file, unsigned initial_size) {
  validate_str(file);
  bool res = 0;
  lock_acquire(&filesys_lock);
  res = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return res;
}
bool sys_remove(const char *file) {
  validate_str(file);
  bool res = 0;
  lock_acquire(&filesys_lock);
  res = filesys_remove(file);
  lock_release(&filesys_lock);
  return res;
}
int sys_open(const char *file) {
  validate_str(file);
  int fd = 0;
  struct thread *t = thread_current();
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  fd = t->next_fd++;
  if (fd < FD_MAX) {
  t->fd_table[fd] = f;
  }
  lock_release(&filesys_lock);
  return fd;
}
int sys_filesize(int fd) {
  struct thread *t = thread_current();
  struct file *f = fd_to_file(fd);
  if (fd > t->next_fd || fd < 0) {
    sys_exit(-1);
  }
  if (f == NULL) {
    sys_exit(-1);
  }
  off_t length;
  lock_acquire(&filesys_lock);
  length = file_length(f);
  lock_release(&filesys_lock);
  return length;
}
int sys_read(int fd, void *buffer, unsigned size) {
  off_t bytes_read;
  struct thread *t = thread_current();
  struct file *f = fd_to_file(fd);
  if (fd > t->next_fd || fd < 0) {
    sys_exit(-1);
  }
  if (f == NULL) {
    sys_exit(-1);
  }
  validate_ptr(buffer);
  validate_buffer_size(buffer, size);
  lock_acquire(&filesys_lock);
  bytes_read = file_read(f, buffer, size);
  lock_release(&filesys_lock);

  return bytes_read;
}
int sys_write(int fd, const void *buffer, unsigned size) {
  off_t bytes_read;
  struct thread *t = thread_current();
  struct file *f = fd_to_file(fd);
  if (fd > t->next_fd || fd < 0) {
    sys_exit(-1);
  }
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  if (f == NULL) {
    sys_exit(-1);
  }
  validate_ptr(buffer);
  validate_buffer_size(buffer, size);

  lock_acquire(&filesys_lock);
  bytes_read = file_write(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes_read;
}
void sys_seek(int fd, unsigned position) {
  struct thread *t = thread_current();
  struct file *f = fd_to_file(fd);
  if (fd > t->next_fd || fd < 0) {
    sys_exit(-1);
  }
  if (f == NULL) {
    sys_exit(-1);
  }
  lock_acquire(&filesys_lock);
  file_seek(f, position);
  lock_release(&filesys_lock);
}
unsigned sys_tell(int fd) {
  off_t position = -1;
  struct thread *t = thread_current();
  struct file *f = fd_to_file(fd);
  if (fd > t->next_fd || fd < 0) {
    sys_exit(-1);
  }
  if (f == NULL) {
    sys_exit(-1);
  }
  lock_acquire(&filesys_lock);
  position = file_tell(f);
  lock_release(&filesys_lock);
  return position;
}
void sys_close(int fd) {
  struct thread *t = thread_current();
  struct file *f = fd_to_file(fd);
  if (fd > t->next_fd || fd < 0) {
    sys_exit(-1);
  }
  if (f == NULL) {
    sys_exit(-1);
  }
  lock_acquire(&filesys_lock);
  file_close(f);
  t->fd_table[fd] = NULL;
  lock_release(&filesys_lock);
}
void sys_dup2() {}
void sys_mount() {}
void sys_unmount() {}
