#ifndef THREADS_INTERRUPT_H
#define THREADS_INTERRUPT_H

#include <stdbool.h>
#include <stdint.h>

/* Interrupts on or off? */
enum intr_level {
    INTR_OFF, /* Interrupts disabled. */
    INTR_ON   /* Interrupts enabled. */
};

enum intr_level intr_get_level(void);
enum intr_level intr_set_level(enum intr_level);
enum intr_level intr_enable(void);
enum intr_level intr_disable(void);

/* Interrupt stack frame. */
struct gp_registers {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rsi; // 인자 2(argv) (Source Index)
    uint64_t rdi; // 인자 1(argc) (Destination Index)
    uint64_t rbp; // 함수 프레임 기준 (Base Pointer)
    uint64_t rdx; // 인자 전달 복잡한 연산 (Data)
    uint64_t rcx; // 루프 카운터, syscall 넘버 (Counter)
    uint64_t rbx; // 호출 보존, 변수 저장 (Base Register)
    uint64_t rax; // 함수 결과 반환 (Return Value)
} __attribute__((packed));


// CPU의 레지스터 상태를 저장하고 복원하는 데 사용.
struct intr_frame {
    /* Pushed by intr_entry in intr-stubs.S.
       These are the interrupted task's saved registers. */
    struct gp_registers R; // 일반 레지스터
    uint16_t es;
    uint16_t __pad1;
    uint32_t __pad2;
    uint16_t ds;
    uint16_t __pad3;
    uint32_t __pad4;
    /* Pushed by intrNN_stub in intr-stubs.S. */
    uint64_t vec_no; /* Interrupt vector number. */
                     /* Sometimes pushed by the CPU,
                        otherwise for consistency pushed as 0 by intrNN_stub.
                        The CPU puts it just under `eip', but we move it here. */
    uint64_t error_code;
    /* Pushed by the CPU.
       These are the interrupted task's saved registers. */
    uintptr_t rip; // 사용자 진입 지점
    uint16_t cs;
    uint16_t __pad5;
    uint32_t __pad6;
    uint64_t eflags;
    uintptr_t rsp; // 사용자 스택 위치
    uint16_t ss;
    uint16_t __pad7;
    uint32_t __pad8;
} __attribute__((packed));

typedef void intr_handler_func(struct intr_frame *);

void intr_init(void);
void intr_register_ext(uint8_t vec, intr_handler_func *, const char *name);
void intr_register_int(uint8_t vec, int dpl, enum intr_level,
                       intr_handler_func *, const char *name);
bool intr_context(void);
void intr_yield_on_return(void);

void intr_dump_frame(const struct intr_frame *);
const char *intr_name(uint8_t vec);

#endif /* threads/interrupt.h */
