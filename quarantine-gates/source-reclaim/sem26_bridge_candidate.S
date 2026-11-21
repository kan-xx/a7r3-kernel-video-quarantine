/* New module-owned entry frames, exact original LIRO continuation ABI.
 * Arguments r0=26,r1=0 for take,r2=qualified profile.
 * Original SP/prologue layout is reproduced so its own epilogue returns to
 * this entry's caller. No original instruction is patched. Not deployable.
 */
.syntax unified
.arm
.text
.global sl_take_once
.type sl_take_once,%function
sl_take_once:
 mov ip,sp
 push {r4,r5,r6,r7,r8,fp,ip,lr,pc}
 sub fp,ip,#4
 sub sp,sp,#0x24
 mov r6,#0
 mov r7,r0
 mov r8,r2
 sub r1,fp,#0x28
 bl sl_lookup_once
 cmp r0,#0
 bne 1f
 mov r4,#0
 ldr ip,[r8]
 add ip,ip,#0x1b00
 add ip,ip,#0x68
 bx ip
1:
 sub sp,fp,#0x20
 ldm sp,{r4,r5,r6,r7,r8,fp,sp,pc}
.size sl_take_once,.-sl_take_once
.global sl_give_once
.type sl_give_once,%function
sl_give_once:
 mov ip,sp
 push {r4,r5,fp,ip,lr,pc}
 sub fp,ip,#4
 sub sp,sp,#8
 mov r5,r0
 mov r4,r2
 sub r1,fp,#0x18
 bl sl_lookup_once
 cmp r0,#0
 bne 2f
 ldr ip,[r4]
 mov r4,#0
 add ip,ip,#0x1a00
 add ip,ip,#0xcc
 bx ip
2:
 sub sp,fp,#0x14
 ldm sp,{r4,r5,fp,sp,pc}
.size sl_give_once,.-sl_give_once
