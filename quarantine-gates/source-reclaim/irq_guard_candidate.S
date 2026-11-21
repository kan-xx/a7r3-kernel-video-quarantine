/* Bounded original raw-spin acquisition; no allocation or retries.
 * sr_irq_lock_try(lock, saved_cpsr*) returns1 on native lease,0 on busy.
 * Only verified SVC/recovery-owner context may call. No installation provided.
 */
.syntax unified
.arm
.text
.global sr_irq_lock_try
.type sr_irq_lock_try,%function
sr_irq_lock_try:
 push {r4,r5,r6,lr}
 mov r5,r1
 mrs r4,cpsr
 cpsid i
 ldr ip,=0x603b7518
 blx ip
 cmp r0,#0
 streq r0,[r5]
 msreq cpsr_c,r4
 strne r4,[r5]
 pop {r4,r5,r6,pc}
.size sr_irq_lock_try,.-sr_irq_lock_try
