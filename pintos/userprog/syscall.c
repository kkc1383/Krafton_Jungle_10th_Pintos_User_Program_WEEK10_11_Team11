#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* system call */
static void system_halt(void);
static void system_exit(int status);
static pid_t system_fork(const char *thread_name, struct intr_frame *f);
static int system_exec(const char *cmdd_line);
static int system_wait(pid_t pid);
static bool system_create(const char *file, unsigned initial_size);
static bool system_remove(const char *file);
static int system_open(const char *file);
static int system_filesize(int fd);
static int system_read(int fd, void *buffer, unsigned size);
static int system_write(int fd, const void *buffer, unsigned size);
static void system_seek(int fd, unsigned position);
static unsigned system_tell(int fd);
static void system_close(int fd);

static void validate_user_string(const char *str);
static int allocate_fd(void);

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
struct lock filesys_lock;           /* to access filesys function */
struct lock fd_lock;                /* to allocate file descriptor number  */

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  lock_init(&filesys_lock);
  lock_init(&fd_lock);
  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
// rdi, rsi, rdx, r10, r8, r9
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  switch (f->R.rax) {
    case SYS_HALT:
      system_halt();
      break;
    case SYS_EXIT:
      system_exit(f->R.rdi);
      break;
    case SYS_FORK:
      f->R.rax = system_fork(f->R.rdi, f);
      break;
    case SYS_EXEC:
      f->R.rax = system_exec(f->R.rdi);
      break;
    case SYS_WAIT:
      f->R.rax = system_wait(f->R.rdi);
      break;
    case SYS_CREATE:
      f->R.rax = system_create(f->R.rdi, f->R.rsi);
      break;
    case SYS_REMOVE:
      f->R.rax = system_remove(f->R.rdi);
      break;
    case SYS_OPEN:
      f->R.rax = system_open(f->R.rdi);
      break;
    case SYS_FILESIZE:
      f->R.rax = system_filesize(f->R.rdi);
      break;
    case SYS_READ:
      f->R.rax = system_read(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_WRITE:
      f->R.rax = system_write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_SEEK:
      system_seek(f->R.rdi, f->R.rsi);
      break;
    case SYS_TELL:
      f->R.rax = system_tell(f->R.rdi);
      break;
    case SYS_CLOSE:
      system_close(f->R.rdi);
      break;
    default:
      printf("unknown! %d\n", f->R.rax);
      thread_exit();
      break;
  }
}

static void system_halt(void) { power_off(); }
void system_exit(int status) {
  /* child_list에 종료되었음을 기록, status, has_exited 등 */
  // 여기에 한 이유는 status가 process_exit()까지 못간다. 인자로 넘기려니 고칠게 너무많음.
  struct thread *curr = thread_current();
  struct thread *parent = thread_get_by_tid(curr->parent_tid);
  if (!parent) return;
  lock_acquire(&parent->children_lock);  // child_list 순회하기 때문에
  // tid로 child_info list에서 본인 노드 찾기
  struct list_elem *e;
  for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
    struct child_info *child = list_entry(e, struct child_info, child_elem);
    if (child->child_tid == curr->tid) {  // 본인노드 찾아서 semaup 하기
      child->exit_status = status;        // status 설정
      child->has_exited = true;
      sema_up(&child->wait_sema);
      break;
    }
  }
  lock_release(&parent->children_lock);  // child_list 순회하기 때문에

  // printf("%s: exit(%d), pid : %d\n", thread_current()->name, status, curr->tid);
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}
static pid_t system_fork(const char *thread_name, struct intr_frame *f) {
  return process_fork(thread_name, f);
}
static int system_exec(const char *cmdd_line) {
  validate_user_string(cmdd_line);
  int result = process_exec(cmdd_line);
  system_exit(result);
  // never reached!!
  return result;
}
static int system_wait(pid_t pid) {
  // printf("wait : pid is %d\n", pid);
  return process_wait(pid);
}
static bool system_create(const char *file, unsigned initial_size) {
  // 대신에 락이 걸려야함
  validate_user_string(file);  // file이 널 문자인지, 혹은 페이지 테이블에 없는 주소인지
  lock_acquire(&filesys_lock);                       // 동시접근을 막기 위해
  bool result = filesys_create(file, initial_size);  // 파일 생성
  lock_release(&filesys_lock);
  return result;  // 파일 생성이 성공적이면 true, 아니면 false
}
static bool system_remove(const char *file) {
  bool result;
  validate_user_string(file);
  lock_acquire(&filesys_lock);
  result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;
}
static int system_open(const char *file) {
  validate_user_string(file);  // file 이 널문자인지, 혹은 페이지 테이블에 없는 주소인지
  lock_acquire(&filesys_lock);                  // 동시접근을 막기 위해
  struct file *open_file = filesys_open(file);  // 파일 열기
  lock_release(&filesys_lock);
  if (open_file) {                // 파일을 제대로 열었다면
    int open_fd = allocate_fd();  // 파일 디스크립터 번호 할당
    struct thread *curr = thread_current();
    curr->fd_table[open_fd] = open_file;  // 해당 쓰레드의 파일 디스크립터 테이블 채우기
    return open_fd;                       // 파일 디스크립터 번호 반환
  } else
    return -1;  // 제대로 못열었으면 -1 반환
}
static int system_filesize(int fd) {
  if (fd < 0 || fd > 64) system_exit(-1);  // fd 범위를 벗어난경우 return
  int file_size;
  struct thread *curr = thread_current();
  struct file *open_file = curr->fd_table[fd];
  if (!open_file) return -1;
  lock_acquire(&filesys_lock);
  file_size = file_length(open_file);
  lock_release(&filesys_lock);
  return file_size;
}
static int system_read(int fd, void *buffer, unsigned size) {
  if (fd < 0 || fd > 64) system_exit(-1);  // fd 범위를 벗어난경우 return
  int read_bytes;
  validate_user_string(buffer);
  if (fd == 0) {  //표준 입력일 경우
    read_bytes = input_getc();
  } else {
    struct thread *curr = thread_current();
    struct file *read_file = curr->fd_table[fd];
    if (!read_file) return -1;
    lock_acquire(&filesys_lock);
    read_bytes = (int)file_read(read_file, buffer, size);
    lock_release(&filesys_lock);
  }
  return read_bytes;
}
static int system_write(int fd, const void *buffer, unsigned size) {
  if (fd < 0 || fd > 64) system_exit(-1);  // fd 범위를 벗어난경우 return
  int write_bytes;
  validate_user_string(buffer);
  if (fd == 1) {  // 표준 출력일 경우
    putbuf(buffer, size);
    return size;
  } else {
    struct thread *curr = thread_current();
    struct file *write_file = curr->fd_table[fd];
    if (!write_file) return -1;
    lock_acquire(&filesys_lock);
    write_bytes = (int)file_write(write_file, buffer, size);
    lock_release(&filesys_lock);
    return write_bytes;
  }
}
static void system_seek(int fd, unsigned position) {
  if (fd < 0 || fd > 64) system_exit(-1);  // fd 범위를 벗어난경우 return
  struct thread *curr = thread_current();
  struct file *seek_file = curr->fd_table[fd];
  if (!seek_file) return -1;
  lock_acquire(&filesys_lock);
  file_seek(seek_file, (off_t)position);
  lock_release(&filesys_lock);
}
static unsigned system_tell(int fd) {
  if (fd < 0 || fd > 64) system_exit(-1);  // fd 범위를 벗어난경우 return
  struct thread *curr = thread_current();
  struct file *tell_file = curr->fd_table[fd];
  unsigned tell_bytes;
  if (!tell_file) return -1;
  lock_acquire(&filesys_lock);
  tell_bytes = file_tell(tell_file);
  lock_release(&filesys_lock);
  return tell_bytes;
}
static void system_close(int fd) {
  if (fd < 0 || fd > 64) system_exit(-1);  // fd 범위를 벗어난경우 return
  struct thread *curr = thread_current();
  struct file *close_file = curr->fd_table[fd];
  if (!close_file) return;

  lock_acquire(&filesys_lock);  // 동시접근을 막기 위해
  file_close(close_file);       // file 닫아주기
  lock_release(&filesys_lock);
  curr->fd_table[fd] = NULL;  // fd_table에서 빼주기
}

static void validate_user_string(const char *str) {
  if (str == NULL || !is_user_vaddr(str)) system_exit(-1);
  if (pml4_get_page(thread_current()->pml4, str) == NULL) {
    system_exit(-1);
  }
}
/* Returns a tid to use for a new thread. */
static int allocate_fd(void) {
  static int next_fd = 2;
  int tid;

  lock_acquire(&fd_lock);
  tid = next_fd++;
  lock_release(&fd_lock);

  return tid;
}