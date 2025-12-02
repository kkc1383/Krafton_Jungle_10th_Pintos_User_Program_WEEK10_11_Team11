# KAIST Pintos Project 2: User Program

본 프로젝트는 KAIST CS330 운영체제 과목의 Pintos Project 2로, 사용자 프로그램 실행을 위한 핵심 기능들을 구현한 결과물입니다.

## 프로젝트 개요

Pintos 운영체제에서 사용자 프로그램이 안전하게 실행될 수 있도록 프로세스 관리, 시스템 콜, 메모리 보호 등의 핵심 기능을 구현했습니다. 모든 구현은 x86-64 아키텍처를 기반으로 하며, QEMU 에뮬레이터 환경에서 동작합니다.

## 구현 과제

### 1. Argument Passing (인자 전달)

**구현 위치:** [pintos/userprog/process.c](pintos/userprog/process.c)

프로그램 실행 시 명령행 인자를 사용자 스택에 적절히 배치하여 전달하는 기능을 구현했습니다.

#### 구현 내용

- **인자 파싱** ([process.c:260-301](pintos/userprog/process.c#L260-L301))
  - `process_exec()` 함수에서 `strtok_r()`을 사용하여 명령행을 공백 기준으로 토큰화
  - 각 인자를 동적 메모리에 할당하고 `argv[]` 배열로 관리

- **스택 구성** ([process.c:549-577](pintos/userprog/process.c#L549-L577))
  - `load()` 함수 내에서 사용자 스택(`USER_STACK = 0x47480000`)에 인자 배치
  - 스택 구조 (높은 주소 → 낮은 주소):
    ```
    [인자 문자열들] → [8바이트 정렬 패딩] → [argv 포인터 배열] →
    [argv 주소] → [argc] → [반환 주소]
    ```

#### 신경 쓴 부분

- **x86-64 호출 규약 준수**: RDI 레지스터에 argc, RSI 레지스터에 argv 주소 전달
- **16바이트 스택 정렬**: x86-64 ABI 요구사항에 따라 스택을 16바이트 경계로 정렬
- **역순 배치**: 인자 문자열과 포인터 배열을 역순으로 푸시하여 올바른 메모리 레이아웃 구성

---

### 2. User Memory (사용자 메모리 접근 검증)

**구현 위치:** [pintos/userprog/syscall.c](pintos/userprog/syscall.c), [pintos/userprog/exception.c](pintos/userprog/exception.c)

커널이 사용자로부터 전달받은 포인터를 역참조하기 전에 유효성을 검증하여 커널 메모리를 보호합니다.

#### 구현 내용

- **메모리 검증 함수** ([syscall.c:333-340](pintos/userprog/syscall.c#L333-L340))
  ```c
  static void validate_user_string(const char *str) {
    // 1단계: NULL 및 커널 주소 공간 체크
    if (str == NULL || !is_user_vaddr(str)) {
      system_exit(-1);
    }

    // 2단계: 페이지 테이블 매핑 확인
    if (pml4_get_page(thread_current()->pml4, str) == NULL) {
      system_exit(-1);
    }
  }
  ```

- **예외 처리** ([exception.c:112-146](pintos/userprog/exception.c#L112-L146))
  - 페이지 폴트 발생 시 `page_fault()` 핸들러가 처리
  - 유효하지 않은 메모리 접근은 프로세스 종료(`system_exit(-1)`)

#### 신경 쓴 부분

- **2단계 검증**: 주소 범위 체크와 페이지 테이블 검증을 모두 수행하여 보안 강화
- **일관된 오류 처리**: 모든 시스템 콜에서 사용자 포인터 접근 전에 검증 수행
- **문자열 처리**: `validate_user_string()`으로 NULL 종료 문자열의 안전성 보장

---

### 3. System Calls (시스템 콜)

**구현 위치:** [pintos/userprog/syscall.c](pintos/userprog/syscall.c)

사용자 프로그램이 커널 서비스를 요청할 수 있도록 13개의 시스템 콜을 구현했습니다.

#### 구현 내용

**시스템 콜 디스패처** ([syscall.c:64-117](pintos/userprog/syscall.c#L64-L117))
- RAX 레지스터에서 시스템 콜 번호 추출
- 인자는 RDI, RSI, RDX, R10, R8, R9 레지스터 순으로 전달

**프로세스 제어 시스템 콜**
- `halt` ([syscall.c:118](pintos/userprog/syscall.c#L118)): 시스템 종료
- `exit` ([syscall.c:119-143](pintos/userprog/syscall.c#L119-L143)): 프로세스 종료 및 상태 반환
- `fork` ([syscall.c:144](pintos/userprog/syscall.c#L144)): 현재 프로세스 복제
- `exec` ([syscall.c:145-151](pintos/userprog/syscall.c#L145-L151)): 새 프로그램 실행
- `wait` ([syscall.c:152](pintos/userprog/syscall.c#L152)): 자식 프로세스 대기

**파일 시스템 콜**
- `create` ([syscall.c:153-160](pintos/userprog/syscall.c#L153-L160)): 파일 생성
- `remove` ([syscall.c:161-167](pintos/userprog/syscall.c#L161-L167)): 파일 삭제
- `open` ([syscall.c:168-204](pintos/userprog/syscall.c#L168-L204)): 파일 열기 및 fd 할당
- `filesize` ([syscall.c:205-217](pintos/userprog/syscall.c#L205-L217)): 파일 크기 조회
- `read` ([syscall.c:218-237](pintos/userprog/syscall.c#L218-L237)): 파일/stdin 읽기
- `write` ([syscall.c:238-258](pintos/userprog/syscall.c#L238-L258)): 파일/stdout 쓰기
- `seek` ([syscall.c:259-271](pintos/userprog/syscall.c#L259-L271)): 파일 포인터 이동
- `tell` ([syscall.c:272-285](pintos/userprog/syscall.c#L272-L285)): 현재 파일 위치 조회
- `close` ([syscall.c:286-302](pintos/userprog/syscall.c#L286-L302)): 파일 닫기

#### 신경 쓴 부분

- **파일 시스템 동기화**: 전역 `filesys_lock` 사용으로 race condition 방지
- **표준 입출력 처리**: fd 0(stdin), 1(stdout) 특수 처리
- **오류 처리**: 잘못된 fd, NULL 포인터 등에 대한 철저한 검증
- **메모리 안전성**: 모든 사용자 포인터 인자에 대해 `validate_user_string()` 적용

---

### 4. Process Termination Messages (프로세스 종료 메시지)

**구현 위치:** [pintos/userprog/syscall.c](pintos/userprog/syscall.c)

프로세스 종료 시 표준화된 형식으로 종료 메시지를 출력하고 부모 프로세스에게 상태를 전달합니다.

#### 구현 내용

**종료 처리 흐름** ([syscall.c:119-143](pintos/userprog/syscall.c#L119-L143))
1. 부모 스레드를 `parent_tid`로 탐색
2. 부모의 `children_lock` 획득
3. 부모의 `child_list`에서 자신의 `child_info` 구조체 검색
4. 종료 정보 업데이트:
   ```c
   child_info->exit_status = status;
   child_info->has_exited = true;
   ```
5. 부모에게 `sema_up(&wait_sema)`로 신호 전달
6. 종료 메시지 출력: `printf("%s: exit(%d)\n", name, status)`
7. `thread_exit()` 호출

**자료구조** ([threads/thread.h:140-148](pintos/include/threads/thread.h#L140-L148))
```c
struct child_info {
  tid_t child_tid;           // 자식 TID
  int exit_status;           // 종료 상태 코드
  bool has_exited;           // 종료 여부
  bool fork_success;         // fork 성공 여부
  struct semaphore wait_sema; // 부모-자식 동기화
  struct list_elem elem;
};
```

#### 신경 쓴 부분

- **부모-자식 동기화**: 세마포어를 통한 정확한 wait 구현
- **메시지 형식 준수**: `<프로세스명>: exit(<상태코드>)` 형식 엄수
- **race condition 방지**: `children_lock`으로 자식 리스트 접근 보호

---

### 5. Denying Writes to Executables (실행 파일 쓰기 거부)

**구현 위치:** [pintos/userprog/syscall.c](pintos/userprog/syscall.c), [pintos/filesys/file.c](pintos/filesys/file.c)

실행 중인 프로세스의 바이너리 파일에 대한 쓰기를 방지하여 코드 무결성을 보장합니다.

#### 구현 내용

**파일 열기 시 보호 설정** ([syscall.c:201](pintos/userprog/syscall.c#L201))
```c
// system_open() 내부
if (!strcmp(curr->name, file)) {
  file_deny_write(open_file);  // 자신의 실행 파일이면 쓰기 금지
}
```

**파일 구조체 확장** ([filesys/file.h](pintos/include/filesys/file.h))
```c
struct file {
  struct inode *inode;
  off_t pos;
  bool deny_write;    // 쓰기 금지 플래그
  int dup_count;      // 참조 카운트
};
```

**쓰기 시도 차단** ([syscall.c:252](pintos/userprog/syscall.c#L252))
```c
// system_write() 내부
if (write_file->deny_write) return 0;  // 보호된 파일은 쓰기 실패
```

#### 신경 쓴 부분

- **inode 레벨 보호**: `file_deny_write()`가 내부적으로 `inode_deny_write()` 호출
- **자동 해제**: 프로세스 종료 시 `file_allow_write()` 자동 호출
- **이름 기반 비교**: 프로세스 이름과 파일 이름 비교로 실행 파일 판단

---

### 6. Extend File Descriptor (확장 파일 디스크립터)

**구현 위치:** [pintos/userprog/syscall.c](pintos/userprog/syscall.c), [pintos/threads/thread.c](pintos/threads/thread.c)

정적 배열 대신 동적 확장 가능한 파일 디스크립터 테이블과 `dup2` 시스템 콜을 구현했습니다.

#### 구현 내용

**동적 FD 테이블** ([threads/thread.h:122-124](pintos/include/threads/thread.h#L122-L124))
```c
struct thread {
  struct file **fd_table;  // 동적 파일 포인터 배열
  size_t fd_max;           // 현재 사용 중인 최대 fd
  size_t fd_size;          // 테이블 크기
};
```

**테이블 확장 메커니즘** ([syscall.c:341-354](pintos/userprog/syscall.c#L341-L354))
- `expend_fd_table()` 함수로 필요 시 동적 확장
- 32개 단위(MAX_FILES)로 증가
- `calloc`/`realloc` 패턴 사용
- 기존 엔트리를 새 테이블로 복사

**표준 입출력** ([syscall.c](pintos/userprog/syscall.c))
- fd 0: stdin (`init_std()` 함수로 생성)
- fd 1: stdout (`init_std()` 함수로 생성)
- 특수 처리: close 시 파일만 닫고 엔트리는 NULL로 설정

**dup2 시스템 콜** ([syscall.c:303-331](pintos/userprog/syscall.c#L303-L331))
```c
int system_dup2(int oldfd, int newfd) {
  // oldfd 유효성 검증
  // oldfd == newfd인 경우 그대로 반환
  // newfd 이미 열려있으면 닫기
  // 필요시 fd_table 확장
  // file_duplicate()로 파일 복제
  // dup_count 증가
  // fd_max 업데이트
}
```

**참조 카운트 관리**
- `file` 구조체에 `dup_count` 필드 추가 (기본값 1)
- `file_duplicate()`: 같은 inode와 위치를 가진 파일 복제
- `system_close()`: `dup_count` 감소, 0이 되면 실제 파일 닫기

#### 신경 쓴 부분

- **메모리 효율성**: 필요할 때만 확장하여 메모리 낭비 최소화
- **fork 호환성**: `__do_fork()`에서 부모의 전체 fd_table 복제 ([process.c:203-233](pintos/userprog/process.c#L203-L233))
- **dup2 관계 유지**: fork 시 dup2로 연결된 파일들의 참조 관계 올바르게 복제
- **정확한 정리**: `process_exit()`에서 모든 fd 닫고 메모리 해제 ([process.c:343-365](pintos/userprog/process.c#L343-L365))
- **동기화**: 파일 작업 시 `filesys_lock` 사용으로 race condition 방지

---

## 핵심 파일 구조

```
pintos/
├── userprog/
│   ├── process.c          # 프로세스 생성, fork, exec, wait 구현
│   ├── syscall.c          # 시스템 콜 핸들러 및 구현
│   └── exception.c        # 예외 처리 (페이지 폴트 등)
│
├── threads/
│   ├── thread.c           # 스레드 관리, fd_table 초기화
│   └── thread.h           # thread, child_info 구조체 정의
│
├── filesys/
│   ├── file.c             # 파일 연산, file_duplicate, file_deny_write
│   └── file.h             # file 구조체 (deny_write, dup_count)
│
└── include/
    └── lib/syscall-nr.h   # 시스템 콜 번호 정의
```

## 빌드 및 테스트

```bash
# 컨테이너에서 pintos 환경 활성화
source /workspaces/week10_11_Pintos_User_Program_Team11/pintos/activate

# userprog 디렉토리로 이동
cd /workspaces/week10_11_Pintos_User_Program_Team11/pintos/userprog

# 빌드
make

# 개별 테스트 실행
make tests/userprog/args-single.result
make tests/userprog/open-normal.result
make tests/userprog/fork-once.result

# 전체 테스트 실행
make check
```

## 구현 결과

모든 하위 과제를 성공적으로 구현하여 Pintos에서 사용자 프로그램이 안전하고 효율적으로 실행될 수 있는 환경을 구축했습니다. 특히 메모리 보호, 동기화, 자원 관리 측면에서 운영체제의 핵심 원리를 실제로 구현하는 경험을 얻었습니다.

## 참고 자료

- [KAIST Pintos 공식 문서](https://casys-kaist.github.io/pintos-kaist/)
- [Project 2: User Programs](https://casys-kaist.github.io/pintos-kaist/project1/introduction.html)
