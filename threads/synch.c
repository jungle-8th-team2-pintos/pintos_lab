/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdio.h>
#include <string.h>

bool is_high_priority_sema(const struct list_elem *a, const struct list_elem *b,
                           void *aux);

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value) {
    ASSERT(sema != NULL);

    sema->value = value;
    list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void sema_down(struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);
    ASSERT(!intr_context());
    old_level = intr_disable();
    while (sema->value == 0) {
        // list_push_back(&sema->waiters, &thread_current()->elem);
        list_insert_ordered(&sema->waiters, &thread_current()->elem,
                            is_high_priority, NULL);
        thread_block();
    }
    sema->value--;
    intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema) {
    enum intr_level old_level;
    bool success;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (sema->value > 0) {
        sema->value--;
        success = true;
    } else
        success = false;
    intr_set_level(old_level);

    return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);
    old_level = intr_disable();
    if (!list_empty(&sema->waiters)) {

        list_sort(&sema->waiters, is_high_priority, NULL);

        thread_unblock(
            list_entry(list_pop_front(&sema->waiters), struct thread, elem));
    }
    sema->value++;
    intr_set_level(old_level);

    thread_yield();
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
    struct semaphore sema[2];
    int i;

    printf("Testing semaphores...");
    sema_init(&sema[0], 0);
    sema_init(&sema[1], 0);
    thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++) {
        sema_up(&sema[0]);
        sema_down(&sema[1]);
    }
    printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void *sema_) {
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++) {
        sema_down(&sema[0]);
        sema_up(&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock) {
    ASSERT(lock != NULL);

    lock->holder = NULL;
    sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    Thread *cur_thread = thread_current();
    struct lock *l = lock;

    cur_thread->waiting_lock = l;

    // 홀더 존재 + 홀더 보다 큼
    // 결국 현제 기다린 lock이 -> l

    // 나중에 while로 바꿔서 중첩기부 해결해야 함.
    while (l && l->holder && cur_thread->priority > l->holder->priority) {
        Thread *holder = l->holder;
        // 홀더에게 우선순위를 기부
        holder->priority = cur_thread->priority;

        // 홀더의 기부자로 등록
        list_insert_ordered(&holder->donation_list, &cur_thread->elem,
                            is_high_priority, NULL);

        /*
        락을 소유하고 있지만 다른 애를 기다릴 수 있음.
             -> 결론: 현재 내 자원의 lock을 소유하고 있지만 동시에 누군가를
        기다릴 수있음
             -> 중복기부를 해줘야함.
             실행함수 -> 가 기다리는 락을 소유한 스레드 -> 가 기다리는 락을
        소유한 스레드 -> ...
        */
        cur_thread = holder;
        l = cur_thread->waiting_lock;
    }

    // 위에서 걸러지지 않음. (홀더보다 작다면 바로 여기로)

    sema_down(&lock->semaphore);
    // 세마 다운이 성공하면 더이상 기다리는 것이 아니지...
    cur_thread->waiting_lock = NULL;
    lock->holder = thread_current();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock) {
    bool success;

    ASSERT(lock != NULL);
    ASSERT(!lock_held_by_current_thread(lock));

    success = sema_try_down(&lock->semaphore);
    if (success)
        lock->holder = thread_current();
    return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

    lock->holder = NULL;

    Thread *cur_thread = thread_current();

    // donation list에서 동일한 lock을 기다리는 애 지워주기
    while (!list_empty(&cur_thread->donation_list)) {
        struct list_elem *front_of_list =
            list_front(&cur_thread->donation_list);
        Thread *donater = list_entry(front_of_list, Thread, elem);
        if (donater->waiting_lock == lock) {
            list_remove(front_of_list);
        }

        donater = list_next(&donater->elem);
    }

    // 우선순위
    if (list_empty(&cur_thread->donation_list)) {
        // donation list가 비었다면
        // 과거 우선순위로 복귀
        cur_thread->priority = cur_thread->old_priority;
    } else {
        // donation list가 비지 않았다면
        // donation list에서 우선순위가 가장 높은 것을 가져오면 됨
        /*
        우선순위로 삽입을 하였음.
            -> 우선순위가 바뀔 가능성 -> 가장 앞의 스레드의 우선순위
        */
        cur_thread->priority =
            list_entry(list_front(&cur_thread->donation_list), Thread, elem)
                ->priority;
    }

    // if (list_empty(&cur_thread->donation_list)) {
    //     cur_thread->priority = cur_thread->old_priority;
    // } else {
    //     struct thread *max_donater = list_entry(
    //         list_max(&cur_thread->donation_list, is_high_priority, NULL),
    //         struct thread, elem);
    //     cur_thread->priority = max_donater->priority;
    // }

    sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock) {
    ASSERT(lock != NULL);

    return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
    struct list_elem elem;      /* List element. */
    struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond) {
    ASSERT(cond != NULL);

    list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

bool is_high_priority_sema(const struct list_elem *a, const struct list_elem *b,
                           void *aux UNUSED) {

    const struct semaphore_elem *sema_elem_a =
        list_entry(a, struct semaphore_elem, elem);
    const struct semaphore_elem *sema_elem_b =
        list_entry(b, struct semaphore_elem, elem);

    // waiter가 안 비어도 waiters가 비었을 수도 있네....ㅋㅋㅋㅋ
    if (list_empty(&sema_elem_a->semaphore.waiters))
        return false;

    const struct thread *t1 = list_entry(
        list_front(&sema_elem_a->semaphore.waiters), struct thread, elem);
    const struct thread *t2 = list_entry(
        list_front(&sema_elem_b->semaphore.waiters), struct thread, elem);

    return t1->priority > t2->priority;
}

void cond_wait(struct condition *cond, struct lock *lock) {
    struct semaphore_elem waiter;

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    sema_init(&waiter.semaphore, 0);
    // list_push_back(&cond->waiters, &waiter.elem);
    list_insert_ordered(&cond->waiters, &waiter.elem, is_high_priority_sema,
                        NULL);
    lock_release(lock);
    sema_down(&waiter.semaphore);
    lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));
    if (!list_empty(&cond->waiters)) {
        list_sort(&cond->waiters, is_high_priority_sema, NULL);
        sema_up(&list_entry(list_pop_front(&cond->waiters),
                            struct semaphore_elem, elem)
                     ->semaphore);
    }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);

    while (!list_empty(&cond->waiters))
        cond_signal(cond, lock);
}
