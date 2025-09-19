#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* system call */
static void system_halt(void);
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
static int system_dup2(int oldfd, int newfd);

static void validate_user_string(const char *str);
static int allocate_fd(void);
static int expend_fd_table(struct thread *curr, size_t size);
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
// struct lock fd_lock;                /* to allocate file descriptor number  */

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  lock_init(&filesys_lock);
  // lock_init(&fd_lock);
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
    case SYS_DUP2:
      f->R.rax = system_dup2(f->R.rdi, f->R.rsi);
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
static int system_wait(pid_t pid) { return process_wait(pid); }
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
  if (!open_file) return -1;  // file 생성 실패 시 종료

  struct thread *curr = thread_current();

  //빈 공간 찾기
  int new_fd = -1;
  for (int i = 2; i < curr->fd_size; i++) {
    if (!curr->fd_table[i]) {
      new_fd = i;
      break;
    }
  }

  while (new_fd == -1 &&
         curr->fd_max + 1 >= curr->fd_size) {  // fd_table이 부족할 경우(혹시 몰라 while로 가둠)
    if (expend_fd_table(curr, 1) < 0) {  // 확장에 실패했다면 file 닫고 -1 리턴
      lock_acquire(&filesys_lock);
      file_close(open_file);
      lock_release(&filesys_lock);
      return -1;
    }
    new_fd = curr->fd_max + 1;  // 확장했으니 그 다음걸로 fd 설정
  }
  //공간이 충분하다면
  // file_info 만들기
  struct file_info *new_file_info = (struct file_info *)malloc(sizeof(struct file_info));
  if (!new_file_info) return -1;  // 메모리 할당 실패시 -1리턴
  new_file_info->dup_count = 1;
  list_init(&new_file_info->dup_list);
  new_file_info->duplicated_file = NULL;
  new_file_info->file = open_file;
  new_file_info->is_duplicated = false;

  if (curr->fd_max < new_fd) curr->fd_max = new_fd;  // fd_max 갱신

  curr->fd_table[new_fd] = new_file_info;  // 해당 쓰레드의 파일 디스크립터 테이블 채우기
  // printf("open file name : %s fd : %d\n", file, curr->fd_max);
  if (!strcmp(curr->name, file))
    file_deny_write(open_file);  // 본인 자신을 열려고 하면 deny_write설정
  return new_fd;                 // 파일 디스크립터 번호 반환
}
static int system_filesize(int fd) {
  int file_size;
  struct thread *curr = thread_current();
  if (fd < 0 || fd > curr->fd_max) system_exit(-1);  // fd 범위를 벗어난경우 return
  if (!curr->fd_table[fd] || curr->fd_table[fd] == get_std_in() ||
      curr->fd_table[fd] == get_std_out())
    return -1;
  lock_acquire(&filesys_lock);
  file_size = file_length(curr->fd_table[fd]->file);
  lock_release(&filesys_lock);
  return file_size;
}
static int system_read(int fd, void *buffer, unsigned size) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd > curr->fd_max) system_exit(-1);  // fd 범위를 벗어난경우 return
  int read_bytes;
  validate_user_string(buffer);
  if (curr->fd_table[fd] == get_std_out())  // 표준 입력일 경우 리턴
    return -1;
  if (curr->fd_table[fd] == get_std_in()) {  //표준 입력일 경우
    read_bytes = input_getc();
  } else {
    struct file_info *read_file_info = curr->fd_table[fd];
    if (!read_file_info) return -1;
    lock_acquire(&filesys_lock);
    read_bytes = (int)file_read(read_file_info->file, buffer, size);
    lock_release(&filesys_lock);
  }
  return read_bytes;
}
static int system_write(int fd, const void *buffer, unsigned size) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd > curr->fd_max) system_exit(-1);  // fd 범위를 벗어난경우 return
  int write_bytes;
  validate_user_string(buffer);  // buffer가 커널 영역이거나 NULL일경우 시스템 종료
  if (curr->fd_table[fd] == get_std_in())  // 표준 입력일 경우 리턴
    return -1;
  if (curr->fd_table[fd] == get_std_out()) {  // 표준 출력일 경우
    putbuf(buffer, size);
    return size;
  } else {
    struct file_info *write_file_info = curr->fd_table[fd];
    /* Exception Handle */
    if (!write_file_info) return -1;
    if (write_file_info->file->deny_write) return 0;

    lock_acquire(&filesys_lock);
    write_bytes = (int)file_write(write_file_info->file, buffer, size);
    lock_release(&filesys_lock);
    return write_bytes;
  }
}
static void system_seek(int fd, unsigned position) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd > curr->fd_max) system_exit(-1);  // fd 범위를 벗어난경우 return
  if (!curr->fd_table[fd] || curr->fd_table[fd] == get_std_in() ||
      curr->fd_table[fd] == get_std_out())
    return -1;
  lock_acquire(&filesys_lock);
  file_seek(curr->fd_table[fd]->file, (off_t)position);
  lock_release(&filesys_lock);
}
static unsigned system_tell(int fd) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd > curr->fd_max) system_exit(-1);  // fd 범위를 벗어난경우 return
  unsigned tell_bytes;
  if (!curr->fd_table[fd] || curr->fd_table[fd] == get_std_in() ||
      curr->fd_table[fd] == get_std_out())
    return -1;
  lock_acquire(&filesys_lock);
  tell_bytes = file_tell(curr->fd_table[fd]->file);
  lock_release(&filesys_lock);
  return tell_bytes;
}
static void system_close(int fd) {
  struct thread *curr = thread_current();
  if (fd < 0 || fd > curr->fd_max) system_exit(-1);  // fd 범위를 벗어난경우 return
  if (!curr->fd_table[fd]) return;                   // NULL 일 경우 리턴
  if (curr->fd_table[fd] != get_std_in() &&
      curr->fd_table[fd] != get_std_out()) {  //표준 입출력일 경우 그냥 NULL로만 바꿔줌
    if (curr->fd_table[fd]->dup_count >= 2) {  // dup2 관계일경우에
      // dup_list에서 제거
      for (struct list_elem *e = list_begin(&curr->fd_table[fd]->dup_list);
           e != list_end(&curr->fd_table[fd]->dup_list); e = list_next(e)) {
        struct dup_elem *dup = list_entry(e, struct dup_elem, elem);
        if (dup->fd == fd) {
          list_remove(&dup->elem);
          free(dup);
          break;
        }
      }
      curr->fd_table[fd]->dup_count--;  // dup_count 바꾸기
    } else {
      lock_acquire(&filesys_lock);           // 동시접근을 막기 위해
      file_close(curr->fd_table[fd]->file);  // file 닫아주기
      lock_release(&filesys_lock);

      free(curr->fd_table[fd]);  // file_info 메모리할당 해제
    }
  }
  curr->fd_table[fd] = NULL;  // fd_table에서 빼주기
}
static int system_dup2(int oldfd, int newfd) {
  struct thread *curr = thread_current();
  // oldfd가 유효한 파일 디스크립터가 아니라면 -1 반환 후 종료
  if (oldfd < 0 || curr->fd_table[oldfd] == NULL || newfd < 0) return -1;
  // oldfd와 newfd가 같으면 그냥 newfd 반환 후 종료
  if (oldfd == newfd) return newfd;

  // newfd가 열려있는 fd라면 fd닫기
  if (curr->fd_table[newfd] != NULL && newfd <= curr->fd_max) {
    system_close(newfd);  // 표준 입출력도 ok
  }

  /* 본격적인 dup2 동작 */

  // newfd가 현재 fd_table에 없는 숫자일 경우 확장
  if (newfd >= curr->fd_size) {
    if (expend_fd_table(curr, newfd - curr->fd_size + 1) < 0) return -1;
  }
  // 표준 입출력일 경우
  if (curr->fd_table[oldfd] == get_std_in() || curr->fd_table[oldfd] == get_std_out()) {
    curr->fd_table[newfd] = curr->fd_table[oldfd];
  } else {  //일반 파일일 경우
    struct file_info *dup_file_info = curr->fd_table[oldfd];
    curr->fd_table[newfd] = dup_file_info;
    dup_file_info->dup_count++;
    /* dup_list에 추가 */
    struct dup_elem *new_dup_elem = (struct dup_elem *)malloc(sizeof(struct dup_elem));
    if (!new_dup_elem) return -1;
    new_dup_elem->fd = newfd;
    list_push_back(&dup_file_info->dup_list, &new_dup_elem->elem);
  }
  if (newfd > curr->fd_max) curr->fd_max = newfd;
  return newfd;
}

static void validate_user_string(const char *str) {
  if (str == NULL || !is_user_vaddr(str)) system_exit(-1);
  if (pml4_get_page(thread_current()->pml4, str) == NULL) {
    system_exit(-1);
  }
}
static int expend_fd_table(struct thread *curr, size_t size) {  //넣고싶은 값 넣는 것으로 바꿈
  size = (size > MAX_FILES) ? size : MAX_FILES;
  // fd MAX_FILES개 만큼만 확장
  curr->fd_table = (struct file_info **)realloc(
      curr->fd_table, sizeof(struct file_info *) * (curr->fd_size + size));
  if (curr->fd_table == NULL) return -1;  //재할당에 실패했을 경우
  memset(curr->fd_table + curr->fd_size, 0, size * (sizeof(struct file_info *)));
  curr->fd_size += size;
  return 0;  // 성공적일 경우 0반환
}
static struct list *list_return(struct list *t) { return t; }
static struct file *file_return(struct file *f) { return f; }

void exit_close(int fd) {
  struct thread *curr = thread_current();
  if (!list_empty(&curr->fd_table[fd]->dup_list)) {  // dup2 관계일경우에
    // dup_list에서 제거
    for (struct list_elem *e = list_begin(&curr->fd_table[fd]->dup_list);
         e != list_end(&curr->fd_table[fd]->dup_list); e = list_next(e)) {
      struct dup_elem *dup = list_entry(e, struct dup_elem, elem);
      if (dup->fd == fd) {
        list_remove(&dup->elem);
        free(dup);
        break;
      }
    }
    curr->fd_table[fd]->dup_count--;  // dup_count 바꾸기
  } else {
    lock_acquire(&filesys_lock);           // 동시접근을 막기 위해
    file_close(curr->fd_table[fd]->file);  // file 닫아주기
    lock_release(&filesys_lock);

    free(curr->fd_table[fd]);  // file_info 메모리할당 해제
  }
  curr->fd_table[fd] = NULL;  // fd_table에서 빼주기
}