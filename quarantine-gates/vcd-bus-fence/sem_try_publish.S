/* LOCAL OFFLINE CANDIDATE. No module, installer, device pointer or caller.
 * r0: independently qualified existing static bsem (never from allocating lookup)
 * r1: expected current task PID, nonzero; checked against native thread_info/task.
 * REQUIRED caller-owned region: SVC, IRQ masked, preempt_count EXACTLY 1.
 * This helper NEVER changes IRQ mask or preempt count; caller must restore its
 * saved state AND honor native reschedule obligations after this finite region.
 * 0 acquired semaphore lease; 1 busy/CAS contention; -1 bad context/PID;
 * -2 inconsistent unheld descriptor. Internal lock always released if acquired.
 * Semaphore lease is intentionally retained on success. NO sig_sem/free/reset.
 */
.syntax unified
.arm
.text
.align 2
.global bb_sem_try_critical
.type bb_sem_try_critical,%function
bb_sem_try_critical:
    push {r4,r5,r6,r7,r8,lr}
    mov r4,r0
    mov r5,r1
    mrs r6,cpsr
    and r2,r6,#0x9f
    cmp r2,#0x93
    bne bad_context
    cmp r4,#0
    beq bad_context
    tst r4,#3
    bne bad_context
    mov r7,sp
    bic r7,r7,#0x1fc0
    bic r7,r7,#0x3f
    ldr r2,[r7,#4]
    cmp r2,#1
    bne bad_context
    cmp r5,#0
    beq bad_context
    ldr r2,[r7,#0xc]
    ldr r2,[r2,#0x104]
    cmp r2,r5
    bne bad_context
    ldrex r2,[r4]
    tst r2,#0x80000000
    bne busy_unowned
    orr r3,r6,#0x80000000
    strex r2,r3,[r4]
    cmp r2,#0
    bne busy_unowned
    dmb sy
    ldrh r2,[r4,#4]
    cmp r2,#0
    movne r0,#1
    bne unlock
    ldr r2,[r4,#8]
    ldr r3,[r4,#0xc]
    orrs r2,r2,r3
    mvnne r0,#1
    bne unlock
    mov r2,#1
    strh r2,[r4,#4]
    str r5,[r4,#0xc]
    mov r0,#0
unlock:
    dmb sy
    mov r2,#0
    str r2,[r4]
    pop {r4,r5,r6,r7,r8,pc}
busy_unowned:
    clrex
    mov r0,#1
    pop {r4,r5,r6,r7,r8,pc}
bad_context:
    mvn r0,#0
    pop {r4,r5,r6,r7,r8,pc}
.size bb_sem_try_critical,.-bb_sem_try_critical

/* Task entry wrapper. Requires ordinary SVC / IRQ enabled / preempt_count 0.
 * r1 is this transaction own qualified lease_held word. Successful acquisition
 * is published before restoring IRQ/preemption and before scheduler entry.
 * It creates and restores the helper's short region, THEN honors NEED_RESCHED
 * using the independently bound original preempt_schedule. That final native
 * scheduler can wait: CPU/critical-section bounds are NOT wall-clock bounds.
 * Never install with an unresolved or guessed scheduler address.
 */
.align 2
.global bb_sem_try_task_publish
.type bb_sem_try_task_publish,%function
bb_sem_try_task_publish:
    push {r4,r5,r6,r7,r8,lr}
    mov r4,r0
    mov r8,r1
    cmp r8,#0
    beq task_bad_context
    tst r8,#3
    bne task_bad_context
    mrs r5,cpsr
    and r2,r5,#0x9f
    cmp r2,#0x13
    bne task_bad_context
    mov r7,sp
    bic r7,r7,#0x1fc0
    bic r7,r7,#0x3f
    ldr r2,[r7,#4]
    cmp r2,#0
    bne task_bad_context
    ldr r2,[r7,#0xc]
    ldr r1,[r2,#0x104]
    mov r2,#1
    str r2,[r7,#4]
    cpsid i
    mov r0,r4
    bl bb_sem_try_critical
    mov r4,r0
    cmp r4,#0
    moveq r2,#1
    movne r2,#0
    str r2,[r8]
    dmb sy
    msr cpsr_c,r5
    ldr r2,[r7,#4]
    sub r2,r2,#1
    str r2,[r7,#4]
    ldr r2,[r7]
    tst r2,#2
    beq task_done
    ldr r3,native_scheduler
    blx r3
task_done:
    mov r0,r4
    pop {r4,r5,r6,r7,r8,pc}
task_bad_context:
    mvn r0,#0
    pop {r4,r5,r6,r7,r8,pc}
.align 2
native_scheduler:
    .word bb_native_preempt_schedule
.size bb_sem_try_task_publish,.-bb_sem_try_task_publish
