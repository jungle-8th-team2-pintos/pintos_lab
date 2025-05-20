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

void syscall_handler(struct intr_frame *f UNUSED) {

    // printf("[DEBUG] syscall_handler invoked! rax=%lld\n", f->R.rax);

    uint64_t syscall_num = f->R.rax;

    switch (syscall_num) {
    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_EXIT:
        exit(f->R.rdi);
        break;

    default:
        printf("Unknown syscall number: %lld\n", syscall_num);
        thread_exit();
    }
}

// todo: This is temporary measure for test
int write(int fd, const void *buffer, unsigned size) {
    const char *buf = buffer;

    if (fd == 1) {
        for (unsigned i = 0; i < size; i++) {
            putchar(buf[i]);
        }
        return size;
    }
    return -1;
}

void exit(int status) {
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}
