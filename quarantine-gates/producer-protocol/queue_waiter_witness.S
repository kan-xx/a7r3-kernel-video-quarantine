/* OFFLINE ONLY. Existing native queue lock, single try, no spin or queue edit.
 * r0 immutable profile, r1 private result. Task SVC/IRQ-enabled/preempt0 only.
 * Calling task owns publisher controller lock, NOT either F3/F5 worker.
 * Static instruction/critical-section bound; native rescheduling after context
 * restore can take time. Therefore not a hard real-time wall-clock bound.
 */
.syntax unified
.arm
.text
.align 2
.global qw_probe_task
.type qw_probe_task,%function
qw_probe_task:
 push {r4,r5,r6,r7,r8,r9,r10,lr}
 mov r4,r0
 mov r5,r1
 mov r2,#0
 str r2,[r5]
 mov r2,#1
 str r2,[r5,#4]
 mrs r6,cpsr
 and r2,r6,#0x9f
 cmp r2,#0x13
 bne bad_context
 mov r7,sp
 bic r7,r7,#0x1fc0
 bic r7,r7,#0x3f
 sub r2,sp,r7
 cmp r2,#512
 blo bad_context
 ldr r2,[r7,#4]
 cmp r2,#0
 bne bad_context
 ldr r2,[r7,#12]
 ldr r3,tasks
 ldr r0,[r3]
 cmp r2,r0
 beq bad_context
 ldr r3,[r3,#8]
 cmp r2,r3
 beq bad_context
 mov r0,r4
 bl qw_resolve
 cmp r0,#0
 beq not_qualified
 mov r8,r0
 mov r2,#1
 str r2,[r7,#4]
 cpsid i
 ldrex r2,[r8]
 tst r2,#0x80000000
 bne busy
 orr r3,r6,#0x80000000
 strex r2,r3,[r8]
 cmp r2,#0
 bne busy
 dmb sy
 mov r0,r4
 mov r1,r5
 bl qw_validate_locked
 mov r9,r0
 dmb sy
 mov r2,#0
 str r2,[r8]
 b restored
busy:
 clrex
 mov r9,#0
restored:
 msr cpsr_c,r6
 ldr r2,[r7,#4]
 sub r2,r2,#1
 str r2,[r7,#4]
 ldr r2,[r7]
 tst r2,#2
 beq done
 ldr r3,scheduler
 blx r3
done:
 mov r0,r9
 pop {r4,r5,r6,r7,r8,r9,r10,pc}
not_qualified:
 mov r0,#0
 pop {r4,r5,r6,r7,r8,r9,r10,pc}
bad_context:
 mov r2,#3
 str r2,[r5,#4]
 mvn r0,#0
 pop {r4,r5,r6,r7,r8,r9,r10,pc}
.align 2
scheduler:.word qw_native_preempt_schedule
tasks:.word wa_tasks
.size qw_probe_task,.-qw_probe_task
