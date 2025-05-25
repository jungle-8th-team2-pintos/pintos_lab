#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include <list.h>
#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/directory.h"
#include "filesys/fat.h"
#include "filesys/inode.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_exit(int status);
bool sys_create(const char *file, unsigned initial_size);
bool validate_user_address(void *address);

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
    write_msr(MSR_STAR,
              ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void syscall_handler(struct intr_frame *f) {
    uint64_t syscall_num = f->R.rax;

    switch (syscall_num) {
    case SYS_HALT:
        power_off();
        break;

    case SYS_EXIT:
        sys_exit(f->R.rdi);
        break;

    case SYS_CREATE:
        // printf("시스템콜 번호:%d\n", SYS_CREATE);
        // printf("레지스터 값: %s, %d\n", f->R.rdi, f->R.rsi);
        f->R.rax = sys_create(f->R.rdi, f->R.rsi);
        // printf("결과: %s \n", sys_create(f->R.rdi, f->R.rsi));
        break;

    case SYS_OPEN:
        // printf("시스템콜 번호:%d\n", SYS_OPEN);
        f->R.rax = sys_open(f->R.rdi);
        break;

    case SYS_CLOSE:
        break;

    case SYS_READ:
        break;

    case SYS_WRITE:
        f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_FORK:

        break;

    case SYS_EXEC:

        break;

    case SYS_WAIT:

        break;

    default:
        printf("Unknown syscall number: %lld\n", syscall_num);
        thread_exit();
    }
}

bool validate_user_address(void *address) {
    if (!is_user_vaddr(address) ||
        pml4_get_page(thread_current()->pml4, address) == NULL) {
        return false;
    }
    return true;
}

int sys_write(int fd, const void *buffer, unsigned size) {
    if (fd == 1) { // STDOUT
        putbuf(buffer, size);
        return size;
    }
    return -1;
}

void sys_exit(int status) {
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}

bool sys_create(const char *file, unsigned initial_size) {
    // printf("크레이트니?");
    // 나중에 메모리 체크
    if (!validate_user_address(file)) {
        sys_exit(-1);
    }
    return filesys_create(file, initial_size);
}

int sys_open(const char *name) {
    // 주소 유효성 검사
    if (!validate_user_address(name)) {
        sys_exit(-1);
    }
    // 파일 오픈 -> 구조체 반환 받기
    struct file *open_tried_file = filesys_open(name);
    // NULL 파일 처리
    if (open_tried_file == NULL) {
        return;
    }
    // 스레드 내의 fd 테이블 (아마 함수 처리?)
    int fd = set_file_on_fdt(open_tried_file);

    return fd;
}

int set_file_on_fdt(struct file *open_tried_file) {
    struct thread *cur = thread_current();
    struct file *fdt = cur->fdt;

    if (cur->pas_fd >= FD_MAX) {
        return -1;
    }

    for (size_t i = cur->pas_fd; i < FD_MAX; i++) {
        cur->pas_fd = i;
        if (cur->fdt[cur->pas_fd]) {
            break;
        }
    }

    return cur->pas_fd;
}

void fd_to_file(int fd) {
    struct file *file;
    return file;
}