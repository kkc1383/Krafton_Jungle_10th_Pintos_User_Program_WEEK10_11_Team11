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

struct fork_aux {
  struct thread *parent;
  struct intr_frame *parent_if;
  struct semaphore fork_sema;
};

static void process_cleanup(void);
static bool load(const char **argv, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(struct fork_aux *);

/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *curr = thread_current(); }

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
  char *fn_copy;
  char *fn;
  tid_t tid;

  /* Make a copy of FILE_NAME.
   * Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;
  fn = palloc_get_page(0);  //파일이름 받아오기 용
  if (fn == NULL) return TID_ERROR;

  strlcpy(fn_copy, file_name, PGSIZE);
  strlcpy(fn, file_name, PGSIZE);

  char *file_end = strchr(fn, ' ');  // file_name은 그대로두고 fn_copy를 건드림
  if (file_end) *file_end = '\0';
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(fn, PRI_DEFAULT, initd, fn_copy);
  if (tid == TID_ERROR) palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif

  process_init();

  if (process_exec(f_name) < 0) PANIC("Fail to launch initd\n");
  NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_) {
  /* Clone current thread to new thread.*/
  // if_ 전달 위해 구조체 생성
  struct fork_aux *aux = (struct fork_aux *)malloc(sizeof(struct fork_aux));
  if (!aux) {
    return TID_ERROR;
  }
  aux->parent_if = if_;
  aux->parent = thread_current();
  // printf("FORK : i'm : %s, forking : %s\n", aux->parent->name, name);
  // if (!strcmp(name, "child_49_O")) {
  //   printf("stop!\n");
  // }
  sema_init(&aux->fork_sema, 0);  // 자식프로세스가 완전히 만들어지기 전까지는 나가지 않기 위해서
  tid_t tid;
  tid = thread_create(name, PRI_DEFAULT, __do_fork, aux);
  // thread_create 가 실패했을 경우
  if (tid == TID_ERROR) {
    // printf("fail to create %s\n", name);
    free(aux);
    return TID_ERROR;
  }
  sema_down(&aux->fork_sema);  // fork가 실패했을 경우 얘를 탈출할수 있게 해야함.
  // printf("escape sema down! forking %s\n", name);
  // tid 검사 (fork 루틴 중 실패했을 경우)
  lock_acquire(&aux->parent->children_lock);
  // child_list 순회
  struct list_elem *e;
  for (e = list_begin(&aux->parent->child_list); e != list_end(&aux->parent->child_list);
       e = list_next(e)) {
    struct child_info *child = list_entry(e, struct child_info, child_elem);
    if (child->child_tid == tid) {
      if (child->has_exited && !child->fork_success) {  // do fork 중에 자식이 종료되었다면
        lock_release(&aux->parent->children_lock);
        free(aux);
        return TID_ERROR;
      }
      break;
    }
  }
  lock_release(&aux->parent->children_lock);

  free(aux);
  return tid;
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
  if (is_kern_pte(pte)) return true;

  /* 2. Resolve VA from the parent's page map level 4. */
  parent_page = pml4_get_page(parent->pml4, va);

  /* 3. TODO: Allocate new PAL_USER page for the child and set result to
   *    TODO: NEWPAGE. */
  newpage = palloc_get_page(PAL_USER);
  /* 4. TODO: Duplicate parent's page to the new page and
   *    TODO: check whether parent's page is writable or not (set WRITABLE
   *    TODO: according to the result). */

  if (!parent_page || !newpage)
    return false;  // parent_page, newpage가 하나라도 null이라면 false return

  writable = is_writable(pte);
  /* 5. Add new page to child's page table at address VA with WRITABLE
   *    permission. */
  if (!pml4_set_page(current->pml4, va, newpage,
                     writable)) {  //매핑만 시켜놓음 실제로 데이터 복사는 안함
    /* 6. TODO: if fail to insert page, do error handling. */
    return true;
  }
  memcpy(newpage, parent_page, PGSIZE);  // 여기서 데이터 복사가 이루어짐
  return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(struct fork_aux *aux) {
  struct intr_frame if_;
  struct thread *parent = aux->parent;
  struct thread *current = thread_current();
  /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
  struct intr_frame *parent_if = aux->parent_if;
  bool succ = true;
  /* 1. Read the cpu context to local stack. */
  memcpy(&if_, parent_if, sizeof(struct intr_frame));
  if_.R.rax = 0;  // 자식의 fork 반환값은 0으로 설정
  /* 2. Duplicate PT */
  current->pml4 = pml4_create();
  if (current->pml4 == NULL) goto error;
  process_activate(current);

#ifdef VM
  supplemental_page_table_init(&current->spt);
  if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
  if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif
  /* TODO: Your code goes here.
   * TODO: Hint) To duplicate the file object, use `file_duplicate`
   * TODO:       in include/filesys/file.h. Note that parent should not return
   * TODO:       from the fork() until this function successfully duplicates
   * TODO:       the resources of parent.*/

  for (int i = 0; i < parent->fd_size; i++) {
    if (!parent->fd_table[i]) continue;
    if (parent->fd_table[i] == get_std_in() ||
        parent->fd_table[i] == get_std_out()) {  //표준 입출력일경우
      current->fd_table[i] = parent->fd_table[i];
    } else {
      if (parent->fd_table[i]->dup_count >= 2) {  // dup2 관계라면

        /* curr fdtable에서 복제할지 말지 결정*/
        bool has_duplicated = false;
        for (int j = 0; j < i; j++) {  // dup2쌍중에서 가장 index가 작은쪽이 fdtable을 복제
          if (parent->fd_table[i] == parent->fd_table[j]) {
            has_duplicated = true;
            current->fd_table[i] = current->fd_table[j];
            current->fd_table[j]->dup_count++;
            break;
          }
        }

        if (!has_duplicated) {  //복제해둔 curr fdtable이 없다면 직접 복제
          struct file *new_file = file_duplicate(parent->fd_table[i]);
          if (!new_file) {
            goto error;
          }
          current->fd_table[i] = new_file;
          current->fd_table[i]->dup_count = 1;
        }

      } else {  // dup2 관계가 아니라면 그냥 복제
        struct file *new_file = file_duplicate(parent->fd_table[i]);
        if (!new_file) {
          ;
          goto error;
        }
        current->fd_table[i] = new_file;
        current->fd_table[i]->dup_count = 1;
      }
    }
    current->fd_max = i;  // fd_max 갱신
  }
  // process_init();

  /* 정상적으로 fork 되었음을 알림 */
  lock_acquire(&parent->children_lock);
  // child_list 순회
  struct list_elem *e;
  for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e)) {
    struct child_info *child = list_entry(e, struct child_info, child_elem);
    if (child->child_tid == current->tid) {
      child->fork_success = true;
      break;
    }
  }
  lock_release(&parent->children_lock);

  sema_up(&aux->fork_sema);  // 이제 부모 프로세스가 fork를 탈출할 수 있음.

  /* Finally, switch to the newly created process. */
  if (succ) do_iret(&if_);
error:
  // printf("before semaup\n");
  sema_up(&aux->fork_sema);
  // printf("after semaup\n");
  system_exit(-1);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
  /* argument parsing start */
  char **argv = palloc_get_page(0);  //스택 프레임에 들어있어서 process_cleanup()시에 소멸하게 된다.
  char *token, *save_ptr;

  int i = 0;
  for (token = strtok_r(f_name, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    argv[i] = malloc((strlen(token) + 1) * sizeof(char));
    memcpy(argv[i++], token, strlen(token) + 1);
  }
  argv[i] = NULL;
  /* argument parsing end */

  char *file_name = argv[0];
  bool success;
  /* We cannot use the intr_frame in the thread structure.
   * This is because when current thread rescheduled,
   * it stores the execution information to the member. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS;

  /* We first kill the current context */
  process_cleanup();
  // for (i = 0; argv[i] != NULL; i++) printf("exec : argv[%d] : %s\n", i, argv[i]);
  /* And then load the binary */
  success = load(argv, &_if);

  /* 메모리 반환 */
  for (int j = 0; j <= i; j++) {
    free(argv[j]);
  }
  palloc_free_page(argv);
  /* If load failed, quit. */
  if (!success) return -1;

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
int process_wait(tid_t child_tid) {
  /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
   * XXX:       to add infinite loop here before
   * XXX:       implementing the process_wait. */
  struct thread *curr = thread_current();
  // printf("WAIT : i'm %s, waiting tid: %d\n", curr->name, child_tid);
  struct child_info *target_child = NULL;
  /* child_tid로 기다릴 child 스레드 찾기 */
  lock_acquire(&curr->children_lock);  // child_list 순회하니까
  struct list_elem *e;
  for (e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e)) {
    struct child_info *child = list_entry(e, struct child_info, child_elem);
    if (child->child_tid == child_tid) {  // tid로 기다리려는 자식 찾기
      target_child = child;
      break;
    }
  }
  lock_release(&curr->children_lock);

  // child_tid가 내 자식이 아니거나, 이미 그 자식을 누군가 기다리고 있다면 -1
  if (!target_child || !list_empty(&target_child->wait_sema.waiters)) return -1;
  if (!target_child->has_exited)
    sema_down(&target_child->wait_sema);  // 아직 종료 안되었다면 기다리기
  // 종료되었으면
  /* 여기서 수거작업이 이루어지면 됨 */
  lock_acquire(&curr->children_lock);
  list_remove(&target_child->child_elem);  // child_list에서 삭제
  lock_release(&curr->children_lock);
  int child_exit_status = target_child->exit_status;
  free(target_child);
  return child_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
  /* TODO: Your code goes here.
   * TODO: Implement process termination message (see
   * TODO: project2/process_termination.html).
   * TODO: We recommend you to implement process resource cleanup here. */

  process_cleanup();
  struct thread *curr = thread_current();
  // printf("fd size : %d, fd_max : %d\n", curr->fd_size, curr->fd_max);
  for (int i = 0; i < curr->fd_size; i++) {
    if (curr->fd_table[i] == get_std_in() || curr->fd_table[i] == get_std_out()) {
      curr->fd_table[i] = NULL;
    }
    if (curr->fd_table[i]) {
      exit_close(i);
    }
  }
  free(curr->fd_table);  // fd table 반환

  if (!strcmp(curr->name, "main")) {  // main이 꺼질경우 std_in, std_out으로 받았던 메모리 반환
    free(get_std_in());
    free(get_std_out());
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char **argv, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  const char *file_name = argv[0];

  /* Allocate and activate page directory. */
  t->pml4 = pml4_create();
  if (t->pml4 == NULL) goto done;
  process_activate(thread_current());

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 0x3E  // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
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
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(if_)) goto done;  // setup_stack 호출 후 rsp가 유저 프로그램 스택의 최고 주소임.
  /* Start address. */
  if_->rip = ehdr.e_entry;

  /* TODO: Your code goes here.
   * TODO: Implement argument passing (see project2/argument_passing.html). */
  // 일단 argc도 구해야한다. rdi : argc, rsi : argv주소
  int argc = 0;
  int str_len = 0;
  while (argv[argc] != NULL) {
    str_len += strlen(argv[argc]) + 1;  // 널문자까지 더해줘야해서 +1
    argc++;
  }
  if_->R.rdi = argc;  // rdi에 argc 값 넣기
  // argc + 1(널) + 인자 문자열들이 필요한 8byte짜리 칸 갯수 + return address 이게 홀수면
  // padding이 필요함
  int need_8byte = argc + 1 + ((str_len + 7) / 8) + 1;
  bool is_need_8byte = need_8byte % 2;
  need_8byte += is_need_8byte;
  char **moved_argv_ptr = (char **)palloc_get_page(0);
  if (moved_argv_ptr == NULL) goto done;
  for (int i = argc - 1; i >= 0; i--) {  //실제 인자 문자열을 넣는 동작
    int length = strlen(argv[i]) + 1;    // 메모리에 집어 넣을 문자열 길이
    if_->rsp = memcpy(if_->rsp - length, argv[i], length);  // rsp-length부터 값 집어넣기
    moved_argv_ptr[i] = if_->rsp;  // 집어넣은 각 문자열 시작지점 저장해두기
  }

  if_->rsp = if_->rsp & (~0x7);                              // 8byte로 정렬
  if (is_need_8byte) if_->rsp = memset(if_->rsp - 8, 0, 8);  // 8byte padding
  if_->rsp = memset(if_->rsp - 8, 0, 8);  // argv[argc], 즉 널문자가 담긴 라인

  for (int i = argc - 1; i >= 0; i--) {  //실제 인자 문자열을 넣는 동작
    if_->rsp = memcpy(if_->rsp - 8, &moved_argv_ptr[i], 8);
  }
  if_->R.rsi = if_->rsp;                  // rsi에 스택포인터 주소 집어넣기
  if_->rsp = memset(if_->rsp - 8, 0, 8);  // return address

  // hex_dump(if_->rsp, (void *)if_->rsp, need_8byte * 8, true);
  palloc_free_page(moved_argv_ptr);
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
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
    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, aux))
      return false;

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
