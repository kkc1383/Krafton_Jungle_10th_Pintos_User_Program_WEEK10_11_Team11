#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"

#ifdef VM
#include "vm/vm.h"
#endif

// static struct lock filesys_lock;

static void process_cleanup(void);
static bool load(const void *pargs, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *current = thread_current(); }

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
  tid_t tid;
  /* 인자전달 구조체 메모리 할당 */
  int len = strlen(file_name) + 1;
  struct passing_arguments *pargs = palloc_get_page(0);
  if (pargs == NULL) {
    return -1;
  }
  memcpy(pargs->full_args, file_name, len);
  memcpy(pargs->file_name, file_name, FILE_NAME_LEN_MAX + 1);
  char *space = strchr(pargs->file_name, ' ');
  if (space) {
    *space = '\0';
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(pargs->file_name, PRI_DEFAULT, initd, pargs);
  if (tid == TID_ERROR) {
    palloc_free_page(pargs);
    return TID_ERROR;
  }
  /* 자식 프로세스 구조체 */
  struct child_process *cp = child_process_create(tid);
  if (cp == NULL) {
    return -1;
  }

  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *aux) {
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif
  process_init();
  // 사용자 프로그램 실행 실패 시 해당 프로그램 exit()
  // if (process_exec(aux) < 0) PANIC("Fail to launch initd\n");
  if (process_exec(aux) < 0) {
    sys_exit(-1);
  }
  NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
  struct thread *parent = thread_current();
  struct semaphore fork_sema;
  sema_init(&fork_sema, 0);

  /* __do_fork 전달 구조체 */
  struct fork_aux faux;
  faux.parent = parent;
  faux.if_ = *if_;
  faux.fork_sema = &fork_sema;
  faux.fork_success = false;

  // struct child_process *cp = malloc(sizeof(struct child_process));
  // if (cp == NULL) {
  //   return TID_ERROR;
  // }

  // cp->exit_status = 0;
  // sema_init(&cp->exit_sema, 0);
  // list_push_back(&thread_current()->children, &cp->elem);
  // faux.cp = cp;

  printf("[PROCESS_FORK] 쓰레드 = %s\n", parent->name);

  tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, &faux);
  if (tid == TID_ERROR) {
    // free(cp);
    printf("스레드 생성 실패\n");
    return TID_ERROR;
  }

  /* 자식 프로세스 구조체 */
  struct child_process *cp = child_process_create(tid);
  // printf("cp구조체 생성\n");
  if (cp == NULL) {
    return -1;
  }

  /* 동기화 처리 - 자식 load 하는 동안 부모는 블락 */
  sema_down(&fork_sema);

  if (faux.fork_success) {
    /* fork 성공 */
    return tid;
  } else {
    /* fork 실패 */
    free(cp);
    return TID_ERROR;
  }
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
  struct thread *current = thread_current();
  struct thread *parent = (struct thread *)aux;
  void *parent_page;
  void *newpage;
  bool writable;

  /* 1. TODO: If the parent_page is kernel page, then return immediately. */
  if (is_kernel_vaddr(va)) {
    return true;
  }
  /* 2. Resolve VA from the parent's page map level 4. */
  parent_page = pml4_get_page(parent->pml4, va);
  if (parent_page == NULL) {
    return false;
  }

  /* 3. TODO: Allocate new PAL_USER page for the child and set result to
   *    TODO: NEWPAGE. */
  newpage = palloc_get_page(PAL_USER);  // PAL_USER - 사용자 페이지
  if (newpage == NULL) {
    return false;
  }
  /* 4. TODO: Duplicate parent's page to the new page and
   *    TODO: check whether parent's page is writable or not (set WRITABLE
   *    TODO: according to the result). */
  memcpy(newpage, parent_page, PGSIZE);
  writable = is_writable(pte);

  /* 5. Add new page to child's page table at address VA with WRITABLE
   *    permission. */
  if (!pml4_set_page(current->pml4, va, newpage, writable)) {
    /* 6. TODO: if fail to insert page, do error handling. */
    palloc_free_page(newpage);
    return false;
  }
  return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void *aux) {
  /* fork_aux */
  struct fork_aux *faux = aux;
  struct thread *parent = faux->parent;
  struct thread *current = thread_current();

  /* 1.문맥 복사 */
  memcpy(&current->tf, &faux->if_, sizeof(struct intr_frame));
  current->tf.R.rax = 0;  //자식 반환값은 0

  /* 2. 페이지 테이블 복사 */
  current->pml4 = pml4_create();
  if (current->pml4 == NULL) {
    printf("pml_create 실패\n");
    goto error;
  }
  process_activate(current);
#ifdef VM
  supplemental_page_table_init(&current->spt);
  if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
  if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) {
    printf("duplicate_pte 실패\n");
    goto error;
  }
#endif

  /* TODO: Your code goes here.
   * TODO: Hint) To duplicate the file object, use `file_duplicate`
   * TODO:       in include/filesys/file.h. Note that parent should not return
   * TODO:       from the fork() until this function successfully duplicates
   * TODO:       the resources of parent.*/

  /* 3. 파일 디스크립터 복사 */
  current->max_fd = parent->max_fd;
  for (int fd = START_FD; fd < FD_MAX; fd++) {
    if (parent->fd_table[fd] != NULL) {
      struct file *f = file_duplicate(parent->fd_table[fd]);
      if (f != NULL) {
        current->fd_table[fd] = f;
      } else {
        printf("파일복사 실패\n");
        goto error;
      }
    }
  }
  // hex_dump((uintptr_t)&current->tf, &current->tf, sizeof(struct intr_frame), true);
  // printf("[SEMA-UP] 쓰레드 = %s 성공 = %d\n", current->name, cp->load_success);
  faux->fork_success = true;
  sema_up(faux->fork_sema);
  /* 동기화 처리 및 문맥전환 */
  do_iret(&current->tf);

error:
  /* fork 실패 시 자원해제 */
  // /* fd 테이블 닫기 */
  // for (int fd = START_FD; fd < FD_MAX; fd++) {
  //   if (current->fd_table[fd] != NULL) {
  //     file_close(current->fd_table[fd]);
  //     current->fd_table[fd] = NULL;
  //   }
  // }
  // if (current->pml4 != NULL) {
  //   pml4_destroy(current->pml4);  // 지금까지 매핑된 페이지 전부 해제
  //   current->pml4 = NULL;
  // }
  sema_up(faux->fork_sema);
  // printf("[SEMA-UP] 쓰레드 = %s 실패 = %d\n", current->name, cp->load_success);
  // palloc_free_page(cp);
  // printf("[do_fork]parent children list size = %d\n", list_size(&parent->children));
  // list_remove(&cp->elem);
  // sys_exit(-1);
  thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *pargs) {
  bool success;
  /* We cannot use the intr_frame in the thread structure.
   * This is because when current thread rescheduled,
   * it stores the execution information to the member. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS;

  struct passing_arguments *pa = pargs;
  struct thread *curr = thread_current();

  /* We first kill the current context */
  process_cleanup();

  /* And then load the binary */
  success = load(pargs, &_if);

  /* If load failed, quit. */
  if (!success) {
    palloc_free_page(pa);
    return -1;
  }

  /* 인자전달 구조체 free */
  palloc_free_page(pa);
  /* Start switched process. */
  do_iret(&_if);
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid UNUSED) {
  /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
   * XXX:       to add infinite loop here before
   * XXX:       implementing the process_wait. */
  struct child_process *cp = find_child_process(thread_current(), child_tid);
  if (cp == NULL) {
    return -1;
  }
  sema_down(&cp->exit_sema);

  int status = cp->exit_status;
  // printf("[WAIT] %s waited %d, got %d\n", thread_current()->name, child_tid, status);
  // printf("[WAIT3]child list size = %d\n", list_size(&thread_current()->children));
  list_remove(&cp->elem);
  free(cp);
  // printf("[FREE-WAIT] cp @ %p by parent %d for child %d\n", cp, thread_current()->tid, child_tid); // 추가
  return status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
  /* TODO: Your code goes here.
   * TODO: Implement process termination message (see
   * TODO: project2/process_termination.html).
   * TODO: We recommend you to implement process resource cleanup here. */
  struct thread *curr = thread_current();

  /* 자식이 종료되었으면 부모 스레드 실행재개 */
  // printf("[EXIT] %s waited \n", thread_current()->name);
  sema_up(&curr->self_cp->exit_sema);

  /* 실행중인 ELF 파일에 대한 쓰기권한 복귀 */
  if (curr->running_file != NULL) {
    file_allow_write(curr->running_file);
    file_close(curr->running_file);
    curr->running_file = NULL;
  }

  /* fd 테이블 닫기 */
  for (int fd = START_FD; fd < FD_MAX; fd++) {
    if (curr->fd_table[fd] != NULL) {
      file_close(curr->fd_table[fd]);
    }
  }
  if (curr->fd_table != NULL) {
    palloc_free_page(curr->fd_table);
    curr->fd_table = NULL;
  }

  /* 페이지 테이블 비우기 */
  if (curr->pml4 != NULL) {
    process_cleanup();
  }
}

/* Free the current process's resources. */
static void process_cleanup(void) {
  struct thread *curr = thread_current();

#ifdef VM
  supplemental_page_table_kill(&curr->spt);
#endif

  uint64_t *pml4;
  /* Destroy the current process's page directory and switch back
   * to the kernel-only page directory. */
  pml4 = curr->pml4;
  if (pml4 != NULL) {
    /* Correct ordering here is crucial.  We must set
     * cur->pagedir to NULL before switching page directories,
     * so that a timer interrupt can't switch back to the
     * process page directory.  We must activate the base page
     * directory before destroying the process's page
     * directory, or our active page directory will be one
     * that's been freed (and cleared). */
    curr->pml4 = NULL;
    pml4_activate(NULL);
    pml4_destroy(pml4);
  }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
  /* Activate thread's page tables. */
  pml4_activate(next->pml4);

  /* Set thread's kernel stack for use in processing interrupts. */
  tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ELF64_PHDR {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const void *pargs, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  struct passing_arguments *pa = (struct passing_arguments *)pargs;

  /* Allocate and activate page directory. */
  t->pml4 = pml4_create();
  if (t->pml4 == NULL) goto done;
  process_activate(thread_current());

  /* Open executable file. */
  file = filesys_open(pa->file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", pa->file_name);
    goto done;
  }
  /* 쓰기방지 및 핸들 저장 */
  file_deny_write(file);
  t->running_file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) ||
      ehdr.e_type != 2 || ehdr.e_machine != 0x3E  // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", pa->file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint64_t file_page = phdr.p_offset & ~PGMASK;
          uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint64_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
             * Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
             * Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes, writable)) goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(if_)) goto done;

  /* TODO: Your code goes here.
   * TODO: Implement argument passing (see project2/argument_passing.html). */
  if (!argument_passing(pa->full_args, if_)) goto done;

  /* Start address. */
  if_->rip = ehdr.e_entry;
  // hex_dump(if_->rsp, (void *)if_->rsp, USER_STACK - if_->rsp, true);
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  if (!success) {
    file_close(file);
  }
  return success;
}

/* userprog 추가함수 */

/* 인자 전달 */
static bool argument_passing(const char *args, struct intr_frame *if_) {
  char *token, *save_ptr;
  int argc = 0;
  char *argv[32];
  int args_len = strlen(args) + 1;
  char *arguments = palloc_get_page(0);
  if (arguments == NULL) {
    return false;
  }
  memcpy(arguments, args, args_len);

  for (token = strtok_r(arguments, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
    argv[argc++] = token;
  }

  //유저스택
  uintptr_t rsp = USER_STACK;
  char *arg_addr[32];  // 스택에 저장된 문자열 시작 주소
  for (int i = argc - 1; i >= 0; i--) {
    int len = strlen(argv[i]) + 1;
    rsp -= len;
    memcpy((void *)rsp, argv[i], len);
    arg_addr[i] = (char *)rsp;
  }

  // 8바이트 정렬
  rsp &= ~0x7;

  // 배열 마지막 칸
  rsp -= 8;
  memset((void *)rsp, 0, 8);

  for (int i = argc - 1; i >= 0; i--) {
    rsp -= 8;
    memcpy((void *)rsp, &arg_addr[i], 8);
  }
  char **argv_start = (char **)rsp;

  rsp -= 8;
  memset((void *)rsp, 0, 8);

  //레지스터 채우기
  if_->R.rdi = argc;
  if_->R.rsi = (uint64_t)argv_start;

  // rsp 16바이트 정렬 맞추기
  if (rsp % 16 != 0) {
    rsp -= 8;
    memset((void *)rsp, 0, 8);
  }
  //유저스택 최상단을 가르키는 포인터: RSP
  if_->rsp = rsp;

  // hex_dump(if_->rsp, (void *)if_->rsp, USER_STACK - if_->rsp, true);
  palloc_free_page(arguments);
  arguments = NULL;
  return true;
}

/* 자식 프로세스 초기화 및 메모리 할당 */
struct child_process *child_process_create(tid_t tid) {
  struct child_process *cp = malloc(sizeof(struct child_process));
  if (cp == NULL) {
    return NULL;
  }
  cp->tid = tid;
  cp->exit_status = 0;
  sema_init(&cp->exit_sema, 0);
  // sema_init(&cp->load_sema, 0);
  struct thread *ct = find_child_thread(tid);
  if (ct == NULL) {
    free(cp);
    return NULL;
  }
  ct->self_cp = cp;
  list_push_back(&thread_current()->children, &cp->elem);
  return cp;
}

/* 자식 프로세스 찾기 */
struct child_process *find_child_process(struct thread *parent, tid_t child_tid) {
  struct list_elem *e;
  for (e = list_begin(&parent->children); e != list_end(&parent->children); e = list_next(e)) {
    struct child_process *cp = list_entry(e, struct child_process, elem);
    if (cp->tid == child_tid) {
      return cp;
    }
  }
  return NULL;
}

/* 스레드 찾기 */
struct thread *find_child_thread(tid_t child_tid) {
  struct list_elem *e;
  for (e = list_begin(get_all_list()); e != list_end(get_all_list()); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, all_elem);
    // printf("모든 스레드 정보 name = %s\n", t->name);
    if (t->tid == child_tid) {
      return t;
    }
  }
  return NULL;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (uint64_t)file_length(file)) return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0) return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE) return false;

  /* It's okay. */
  return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      printf("fail\n");
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
    if (success)
      if_->rsp = USER_STACK;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
   * address, then map our page there. */
  return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
  /* TODO: Load the segment from the file */
  /* TODO: This called when the first page fault occurs on address VA. */
  /* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO: Set up aux to pass information to the lazy_load_segment. */
    void *aux = NULL;
    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, aux)) return false;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
  bool success = false;
  void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  /* TODO: Map the stack on stack_bottom and claim the page immediately.
   * TODO: If success, set the rsp accordingly.
   * TODO: You should mark the page is stack. */
  /* TODO: Your code goes here */

  return success;
}
#endif /* VM */
