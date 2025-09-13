#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void system_write(int fd, const void *buffer, unsigned size);
static void system_exit(int status);
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
  // printf("system call!");
  switch (f->R.rax) {
    case SYS_WRITE:
      // printf(" write! \n");
      system_write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_EXIT:
      // printf(" exit! \n");
      system_exit(f->R.rdi);
      break;
    default:
      // printf("unknown! %d\n", f->R.rax);
      thread_exit();
      break;
  }
}
static void system_write(int fd, const void *buffer, unsigned size) {
  //일단 무조건 표춘출력이라는 가정 하, 나중에 file system때는 다를듯
  putbuf(buffer, size);
}

static void system_exit(int status) {
  // status를 어떻게 써야할지 모르겠다.
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}