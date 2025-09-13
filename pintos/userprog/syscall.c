#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void system_halt(void);
static void system_exit(int status);
static pid_t system_fork(const char *thread_name);
static int system_exec(const char *cmdd_line);
static int system_wait(pid_t pid);
static bool system_create(const char *file, unsigned initial_size);
static bool system_remove(const char *file);
static int system_open(const char *file);
static int system_filesize(int fd);
static int system_read(int fd, void *buffer, unsigned size);
static void system_write(int fd, const void *buffer, unsigned size);
static void system_seek(int fd, unsigned position);
static unsigned system_tell(int fd);
static void system_close(int fd);

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

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

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
      system_fork(f->R.rdi);
      break;
    case SYS_EXEC:
      system_exec(f->R.rdi);
      break;
    case SYS_WAIT:
      system_wait(f->R.rdi);
      break;
    case SYS_CREATE:
      system_create(f->R.rdi, f->R.rsi);
      break;
    case SYS_REMOVE:
      system_remove(f->R.rdi);
      break;
    case SYS_OPEN:
      system_open(f->R.rdi);
      break;
    case SYS_FILESIZE:
      system_filesize(f->R.rdi);
      break;
    case SYS_READ:
      system_read(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_WRITE:
      system_write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_SEEK:
      system_seek(f->R.rdi, f->R.rsi);
      break;
    case SYS_TELL:
      system_tell(f->R.rdi);
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
static void system_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}
static pid_t system_fork(const char *thread_name) { ; }
static int system_exec(const char *cmdd_line) { ; }
static int system_wait(pid_t pid) { ; }
static bool system_create(const char *file, unsigned initial_size) { ; }
static bool system_remove(const char *file) { ; }
static int system_open(const char *file) { ; }
static int system_filesize(int fd) { ; }
static int system_read(int fd, void *buffer, unsigned size) { ; }
static void system_write(int fd, const void *buffer, unsigned size) {
  //일단 무조건 표춘출력이라는 가정 하, 나중에 file system때는 다를듯
  putbuf(buffer, size);
}
static void system_seek(int fd, unsigned position) { ; }
static unsigned system_tell(int fd) { ; }
static void system_close(int fd) { ; }
