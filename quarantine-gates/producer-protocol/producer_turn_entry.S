/* OFFLINE. Single existing queue try-lock; no spin, dequeue, wake or MMIO. */
.syntax unified
.arm
.text
.align 2
.global pp_arm_task
.type pp_arm_task,%function
pp_arm_task:
 push {r4,r5,r6,r7,r8,lr}
 mov r4,r0
 mrs r5,cpsr
 and r2,r5,#0x9f
 cmp r2,#0x13
 bne bad
 mov r7,sp
 bic r7,r7,#0x1fc0
 bic r7,r7,#0x3f
 sub r2,sp,r7
 cmp r2,#512
 blo bad
 ldr r2,[r7,#4]
 cmp r2,#0
 bne bad
 bl pp_resolve
 cmp r0,#0
 beq declined
 mov r6,r0
 mov r2,#1
 str r2,[r7,#4]
 cpsid i
 ldrex r2,[r6]
 tst r2,#0x80000000
 bne busy
 orr r3,r5,#0x80000000
 strex r2,r3,[r6]
 cmp r2,#0
 bne busy
 dmb sy
 mov r0,r4
 bl pp_arm_locked
 mov r8,r0
 dmb sy
 mov r2,#0
 str r2,[r6]
 b restore
busy:
 clrex
 mov r8,#0
restore:
 msr cpsr_c,r5
 ldr r2,[r7,#4]
 sub r2,r2,#1
 str r2,[r7,#4]
 ldr r2,[r7]
 tst r2,#2
 beq done
 ldr r3,scheduler
 blx r3
done:
 mov r0,r8
 pop {r4,r5,r6,r7,r8,pc}
declined:
 mov r0,#0
 pop {r4,r5,r6,r7,r8,pc}
bad:
 mvn r0,#0
 pop {r4,r5,r6,r7,r8,pc}
.align 2
scheduler:.word pp_native_preempt_schedule
.size pp_arm_task,.-pp_arm_task

/* Whole-boot resident combined +1e0 entry. Native SYSV SP/LR/r0-r11 stay
 * unchanged at original LIRO entry. Other routes go to frozen F3/F5 gateway.
 * Observation runs only BEFORE original receive; no added native stack depth.
 */
.align 2
.global pp_receive_entry
.type pp_receive_entry,%function
pp_receive_entry:
 ldr ip,sysv
 cmp r0,ip
 bne other
 ldr ip,wrapper_lr
 cmp lr,ip
 bne original
 tst sp,#7
 bne original
 ubfx ip,sp,#0,#13
 cmp ip,#512
 blo original
 push {r0,r1,r2,r3,r4,r5,ip,lr}
 add r1,sp,#32
 mov r2,lr
 ldr r3,[sp,#4]
 ldr r0,profile
 bl pp_receive_before
 pop {r0,r1,r2,r3,r4,r5,ip,lr}
original:
 ldr ip,native_receive
 bx ip
other:
 ldr ip,other_receive
 bx ip
.align 2
sysv:.word 0xc2019f
wrapper_lr:.word 0x635e45b3
profile:.word pp_profile
native_receive:.word pp_native_receive
other_receive:.word pp_other_receive_entry
.size pp_receive_entry,.-pp_receive_entry
