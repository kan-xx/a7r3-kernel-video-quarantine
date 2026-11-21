/* OFFLINE ABI CANDIDATE ONLY. Six already-qualified Common public callsites.
 * No installer/patch publisher; wd_original_raii is an explicit unmodified
 * trampoline contract for other calls. Future publisher must prove atomic
 * install/cache sync/lifetime; this object is NOT a deployable hot patch.
 * Active=false -> transparent original behavior. Active=true -> finite attempt.
 * On rejection each fixed byte is latched1; a recovery must not authorize any
 * callback completion/free/resume after ANY denial. Void APIs have no native
 * error return, so their event is not claimed consumed successfully.
 */
.syntax unified
.arm
.text
.align 2
.global wd_acquire_gate
.type wd_acquire_gate,%function
wd_acquire_gate:
 push {r4,r5,r6,r7,r8,r9,lr}
 sub sp,sp,#4
 mov r4,r0
 mov r5,r1
 mov r7,lr
 ldr r3,gate_active
 ldr r3,[r3]
 cmp r3,#1
 bne fallback
 dmb sy
 ldr r3,ret_create
 cmp r7,r3
 ldreq r6,fail_create
 moveq r8,#0
 beq matched
 ldr r3,ret_remove
 cmp r7,r3
 ldreq r6,fail_remove
 moveq r8,#1
 beq matched
 ldr r3,ret_load
 cmp r7,r3
 ldreq r6,fail_load
 moveq r8,#2
 beq matched
 ldr r3,ret_proc
 cmp r7,r3
 ldreq r6,fail_proc
 moveq r8,#3
 beq matched
 ldr r3,ret_irq
 cmp r7,r3
 ldreq r6,fail_irq
 moveq r8,#4
 beq matched
 ldr r3,ret_param
 cmp r7,r3
 ldreq r6,fail_param
 moveq r8,#5
 bne fallback
matched:
 str r5,[r4]
 mov r3,#0
 strb r3,[r4,#4]
 ldr r3,common_root
 cmp r5,r3
 bne denied
 cmp r2,#1
 bne denied
 ldr r3,[r5]
 ldr r9,common_id
 cmp r3,r9
 bne denied
 ldr r0,descriptor_cell
 ldr r0,[r0]
 bl bb_sem_try_task
 cmp r0,#0
 bne denied
 mov r3,#1
 strb r3,[r4,#4]
 mov r0,r4
 add sp,sp,#4
 pop {r4,r5,r6,r7,r8,r9,pc}
denied:
 ldr r3,denial_bytes
 mov r2,#1
 strb r2,[r3,r8]
 dmb sy
 /* Existing normal failure/dtor epilogue, with native frame intact. */
 str r6,[sp,#28]
 cmp r8,#5
 moveq r3,#0
 streq r3,[sp,#4] /* parameter wrapper's bool-result r4=0 => native error1 */
 mov r0,r4
 add sp,sp,#4
 pop {r4,r5,r6,r7,r8,r9,pc}
fallback:
 mov r0,r4
 mov r1,r5
 add sp,sp,#4
 pop {r4,r5,r6,r7,r8,r9,lr}
 ldr ip,original_raii
 bx ip
.align 2
ret_create:.word 0x639d526b
ret_remove:.word 0x639d546f
ret_load:.word 0x639d5699
ret_proc:.word 0x639d57d3
ret_irq:.word 0x63d3ea63
ret_param:.word 0x63d3eab7
fail_create:.word 0x639d53b3
fail_remove:.word 0x639d5611
fail_load:.word 0x639d5763
fail_proc:.word 0x639d5835
fail_irq:.word 0x63d3ea8b
fail_param:.word 0x63d3eadf
common_root:.word 0x6436b670
common_id:.word 0x6805e6
descriptor_cell:.word wd_common_descriptor
gate_active:.word wd_gate_active
denial_bytes:.word wd_gate_denials
original_raii:.word wd_original_raii
.size wd_acquire_gate,.-wd_acquire_gate
