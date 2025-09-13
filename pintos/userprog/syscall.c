#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/init.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

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
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  // printf("system call!\n");
  switch (f->R.rax) {
    case SYS_HALT:
      sys_halt();
    case SYS_EXIT:
      sys_exit(f->R.rdi);
      break;
    case SYS_FORK:
      sys_fork();
      break;
    case SYS_EXEC:
      sys_exec();
      break;
    case SYS_WAIT:
      sys_wait();
      break;
    case SYS_CREATE:
      sys_create();
      break;
    case SYS_REMOVE:
      sys_remove();
      break;
    case SYS_OPEN:
      sys_open();
      break;
    case SYS_FILESIZE:
      sys_filesize();
      break;
    case SYS_READ:
      sys_read();
      break;
    case SYS_WRITE:
      f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_SEEK:
      sys_seek();
      break;
    case SYS_TELL:
      sys_tell();
      break;
    case SYS_CLOSE:
      sys_close();
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

void sys_halt() { power_off(); }
void sys_exit(int status) {
  struct thread *t = thread_current();

  int len = strlen(t->name) + 1;
  char *file_name = malloc(len);
  memcpy(file_name, t->name, len);
  char *space = strchr(file_name, ' ');
  if (space) {
    *space = '\0';
  }
  printf("%s: exit(%d)\n", file_name, status);
  free(file_name);
  thread_exit();
}
void sys_fork() {}
void sys_exec() {}
void sys_wait() {}
void sys_create() {}
void sys_remove() {}
void sys_open() {}
void sys_filesize() {}
void sys_read() {}
int sys_write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}
void sys_seek() {}
void sys_tell() {}
void sys_close() {}
void sys_dup2() {}
void sys_mount() {}
void sys_unmount() {}
