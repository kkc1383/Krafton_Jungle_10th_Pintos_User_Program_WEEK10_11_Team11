#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* f->R. 뭐시기 하며 하면 자꾸 실수해서 바꿈 */
#define SC_NO(f)   ((f)->R.rax)
#define ARG0(f)    ((f)->R.rdi)
#define ARG1(f)    ((f)->R.rsi)
#define ARG2(f)    ((f)->R.rdx)
#define ARG3(f)    ((f)->R.r10)   /* 4th is r10 */
#define ARG4(f)    ((f)->R.r8)
#define ARG5(f)    ((f)->R.r9)
#define RETVAL(f)  ((f)->R.rax)

/* 프로토 타입 */
static void sys_exit (int status) NO_RETURN;
static long sys_write (int fd, const void *buf, unsigned size);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */
/* 시스템 콜.
 *
 * 과거에는 시스템 콜 서비스가 인터럽트 핸들러(예: 리눅스의 int 0x80)에 의해
 * 처리되었다. 하지만 x86-64에서는 제조사가 `syscall` 명령을 통해 시스템 콜을
 * 요청하는 더 효율적인 경로를 제공한다.
 *
 * `syscall` 명령은 모델별 레지스터(MSR)의 값을 읽어 동작한다.
 * 자세한 내용은 매뉴얼을 참고하라. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
/* 세그먼트 셀렉터 MSR */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
/* 롱 모드 SYSCALL 진입 지점 주소 MSR */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
/* EFLAGS 마스크를 설정하는 MSR */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	/* syscall_entry가 유저랜드 스택을 커널 모드 스택으로 교체하기 전까지는
	 * 인터럽트 서비스 루틴이 어떤 인터럽트도 처리하면 안 된다.
	 * 따라서 EFLAGS의 해당 비트들을 마스킹(비활성화)했다. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
/* 주요 시스템 콜 인터페이스 */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// TODO: 구현을 이곳에 작성하라.
	switch (SC_NO(f))
	{
	case SYS_EXIT: {
		int status = (int) ARG0(f);
		sys_exit(status);
		__builtin_unreachable();
	}
	case SYS_WRITE: {
		int fd = (int)ARG0(f);
		const void *buf = (const void *)ARG1(f);
		unsigned size = (unsigned)ARG2(f);
		RETVAL(f) = sys_write(fd, buf, size);
		break;
	}
	default:
		sys_exit(-1);
	}
}

static void
sys_exit (int status) {
	struct thread *cur = thread_current();
	cur->exit_status = status;
	thread_exit();
	__builtin_unreachable();
}

static long
sys_write (int fd, const void *buf, unsigned size) {
  if (fd == 1) {              // STDOUT만 지원
    if (buf == NULL) return -1;
    putbuf(buf, size);        // 콘솔로 바로 출력
    return (long)size;
  }
  return -1;                  // 나머지는 아직 미지원
}
