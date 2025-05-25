#include "userprog/process.h"
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
#include "userprog/tss.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
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
    char *fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /* Create a new thread to execute FILE_NAME. */

    /* ------------------------- */
    // 여기가 프린트를 할 수 있는 마지막 기회다.

    // char *argv[128];
    // int argc = 0;

    char *picked;
    char *other;

    // printf("파일이름 출력: %s\n", file_name);

    // picked = strtok_r(file_name, " ", &other);
    strtok_r(file_name, " ", &other);

    // printf("argv[%d] 출력: %s\n", argc, picked);

    // while (picked != NULL) {
    //     argv[argc] = picked;
    //     picked = strtok_r(NULL, " ", &other);

    //     argc++;
    //     printf("argv[%d] 출력: %s\n", argc, picked);
    // }

    // // 파싱 이후
    // printf("파일이름 출력: %s\n", file_name);

    // printf("파일 이름 카피: %s\n", fn_copy);
    // // result: 테스트 출력: args-single onearg

    /*
    결론
    - strtok_r 후 파일 이름 바뀜
    - 처음 한 번 번만 분리됨.
    */
    /* ------------------------- */

    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
    /* Clone current thread to new thread.*/
    return thread_create(name, PRI_DEFAULT, __do_fork, thread_current());
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

    /* 2. Resolve VA from the parent's page map level 4. */
    parent_page = pml4_get_page(parent->pml4, va);

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
     *    TODO: NEWPAGE. */

    /* 4. TODO: Duplicate parent's page to the new page and
     *    TODO: check whether parent's page is writable or not (set WRITABLE
     *    TODO: according to the result). */

    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        /* 6. TODO: if fail to insert page, do error handling. */
    }
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_if;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/

    process_init();

    /* Finally, switch to the newly created process. */
    if (succ)
        do_iret(&if_);
error:
    thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
    char *file_name = f_name;
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

    // 로드에 진짜 파일이름만 넘기기

    char *argv[128];
    int argc = 0;

    char *picked;
    char *other;

    uint64_t argv_addr;

    picked = strtok_r(file_name, " ", &other);

    while (picked != NULL) {
        argv[argc] = picked;
        picked = strtok_r(NULL, " ", &other);
        argc++;
    }

    success = load(file_name, &_if);

    /* If load failed, quit. */
    if (!success)
        return -1;
    /*
    메모리 적재
    */

    // 캐릭터 배열의 주소 저장 공간
    void *arg_addresses[128];

    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        // 스텍포인터 내리기
        _if.rsp -= len;
        memcpy((void *)_if.rsp, argv[i], len);
        arg_addresses[i] = (void *)_if.rsp;
    }
    // 패딩
    while (_if.rsp % 8 != 0) {
        _if.rsp--;
        *(uint8_t *)_if.rsp = 0;
    }
    // 마지막 값 0
    _if.rsp -= 8;
    *(char **)_if.rsp = 0;

    // 포인터
    for (int i = argc - 1; i >= 0; i--) {
        _if.rsp -= 8;
        *(uint64_t **)_if.rsp = (uint64_t)arg_addresses[i];
    }

    argv_addr = (uint64_t)_if.rsp;

    _if.rsp -= 8;
    *(uint64_t **)_if.rsp = argc;

    _if.rsp -= 8;
    *(uint64_t **)_if.rsp = 0;

    /* 4) 레지스터 세팅 */
    _if.R.rdi = argc;
    // _if.R.rsi = (uint64_t)_if.rsp;
    // _if.R.rsi = (uint64_t)_if.rsp + sizeof(void *);
    _if.R.rsi = argv_addr;

    // 하나씩 다시 쌓아보자...ㅋ
    // _if.rsp -=8;
    // *(char **)_if.rsp

    palloc_free_page(file_name);

    // hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);
    /* 5) 사용자 모드로 진입 */
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

    for (int i = 0; i < 2000000000; i++) {
    }
    return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    struct thread *curr = thread_current();
    /* TODO: Your code goes here.
     * TODO: Implement process termination message (see
     * TODO: project2/process_termination.html).
     * TODO: We recommend you to implement process resource cleanup here. */

    process_cleanup();
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    // 페이지 생성 / 메모리 부족 등으로 실패 시 goto done
    t->pml4 = pml4_create();
    if (t->pml4 == NULL)
        goto done;
    // 현재 스레드(프로세스)의 페이지 테이블을 활성화시킴
    process_activate(thread_current());

    // 실행 파일열기 / 실행파일 이 없으면 goto done
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    // 실행파일을 읽고 헤더를 확인
    /*
        file_read 인자 : 읽을 파일, 버퍼(파일 내용을 저장할 메모리 주소), 읽을
       바이트 수
        - ELF헤더를 제대로 읽지 못하는 경우
        - 정확히 "\177ELF\2\1\1"과 일치하지 않아 ELF 포맷이 아닌 경우
        - ELF파일의 타입이 2가 이나어서 실행 가능한 파일 (ET_EXEC)이 아닌 경우
        - 0x3E = x86-64(amd64)아키텍쳐가 아닌 경우
        - ELF 버전이 1이 아닌 경우
        - 프로그램 헤더 테이블의 각 엔트리 크기가 실제 struct Phdr 구조체의
       크기와 같지 않은 경우
        - 프로그램 헤더 수가 1024를 넘어 비정상적으로 많은 경우
        goto done
    */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 0x3E // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
        ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /*
        ELF 파일 안의 로딩 가능한 세그먼트(PT_LOAD)들을 찾아,
        적절한 위치에 메모리 할당 + 내용 복사 + 초기화
    */
    // ehdr.e_phoff: 프로그램 헤더들이 파일 안에서 시작하는 위치
    // ehdr.e_phnum: 프로그램 헤더 개수
    // - for 문이 모든 프로그램 헤더를 순회
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;
        // 헤더 위치가 파일 범위를 벗어나면 goto dnoe
        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;

        // 해당 프로그램 헤더 위치로 이동
        file_seek(file, file_ofs);
        // struct Phdr 크기만큼 읽어와서 phdr에 저장 / goto done 조건은 위의
        // read 중 하나와 같음.
        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        // phdr 크기 만큼 이동하여 위치 갱신
        file_ofs += sizeof phdr;
        // phdr.p_type 분기 처리
        switch (phdr.p_type) {
        // 무시해도 되는 메타 데이터 / break
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        // 동적 링커가 필요 (Pintos는 지원 안함) / goto done 해버리기ㅋ
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        // 실제로 로드해야 할 코드/데이터 세그먼트 / 메모리에 로드
        case PT_LOAD:
            // PF_W 플래그 확인해서 쓰기 가능 여부 판단
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                // 파일 내에서 읽기 시작할 페이지 단위 위치
                uint64_t file_page = phdr.p_offset & ~PGMASK;
                // 메모리에 로드할 시작 가상주소 (페이지 정렬)
                uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                // 페이지 내에서 실제 데이터 시작 오프셋
                uint64_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                // phdr.p_filesz: 파일에서 읽을 바이트 수
                // phdr.p_memsz: 메모리에 확보할 총 바이트 수(더 큼)
                // -> 남은 공간은 0으로 초기화 해야 함(BSS 영역)
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                     * Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) -
                                  read_bytes);
                } else {
                    /* Entirely zero.
                     * Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                // 실제 로딩!!
                /*
                load_segment()함수
                - 파일에서 읽어와서 메모리에 복사
                - 나머지는 0으로 초기화
                - writable 여부를 포함한 페이지 권한 설정 수행
                */
                if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                                  zero_bytes, writable))
                    goto done;
            } else
                goto done;
            break;
        }
    }

    // 스텍 셋업
    if (!setup_stack(if_))
        goto done;

    /* Start address. */
    // 사용자 진입 지점이 이동됨?
    if_->rip = ehdr.e_entry;

    /* TODO: Your code goes here.
     * TODO: Implement argument passing (see project2/argument_passing.html). */

    // 이 코드 전 done 레이블로 goto 되면 실패 했다는 뜻.
    // goto done -> 무엇인가 문제가 있다.
    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    // 나증에 파일 클로즈 하지 말고 예외처리해야 하지 않을까?
    file_close(file);
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
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
        if (kpage == NULL)
            return false;

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
// 셋업 스택은 단 한번만 실행됨. -> 스택 부족시 page fault로 죽음.
static bool setup_stack(struct intr_frame *if_) {
    uint8_t *kpage; // 커널에서 할당받은 물리 주소를 저장 할 포인터
    bool success = false;
    // 페이지 할당 (사용주 주소 공간에 할당 | 메모리 공간을 0으로 초기화)
    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        /*
         - USER_STACK 아래 1페이지를 kpage 물리 메모리에 매핑한다.
         - install_page()는 가상주소를 실제 주소와 매핑(추상화)(PML4를
         공부해라!!)
         - 스택이니까 낮은 주소 방향으로.
         - 프로세스 마다 추상화된 가상공간을 가지니 항상 동일한 주소의 가상
         공간을 사용 가능.
         - 깨달았다.
         + 실제로는 낮은 주소 방향으로 커짐
         + but 프로그램 입장에서는 높은 주소로 접근(push, load)하니까
         (USER_STACK - PGSIZE)로 명시.
         + 스택 입장에서는마지막 주소임.
        */
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        // 가상 주소 매핑이 성공하면 포인터 설정
        if (success) {
            /*
                Address	    Name	        Data	    Type
                0x4747fffc	argv[3][...]	'bar\0'	    char[4]     / -4
                0x4747fff8	argv[2][...]	'foo\0'	    char[4]     / -8
                0x4747fff5	argv[1][...]	'-l\0'	    char[3]     / -3
                0x4747ffed	argv[0][...]	'/bin/ls\0'	char[8]     / -8
                0x4747ffe8	word-align	    0	        uint8_t[]   / -5
                0x4747ffe0	argv[4]	        0	        char *      / -8
                0x4747ffd8	argv[3]	        0x4747fffc	char *      / -8
                0x4747ffd0	argv[2]	        0x4747fff8	char *      / -8
                0x4747ffc8	argv[1]	        0x4747fff5	char *      / -8
                0x4747ffc0	argv[0]	        0x4747ffed	char *      / -8
                0x4747ffb8	return address	0	        void (*) () / -8
            */
            // 이거 그대로 구현 하면 아마 args 될 듯??
            // 일단 숫자는 작아져야 함.
            // 사용자 스택 위치(rps)는 47480000
            if_->rsp = USER_STACK;
            // 어? 여기 아닌듯...
        }

        else
            palloc_free_page(kpage);
    }
    // 성공 여부를 반환
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
    return (pml4_get_page(t->pml4, upage) == NULL &&
            pml4_set_page(t->pml4, upage, kpage, writable));
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
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
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
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                            lazy_load_segment, aux))
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
