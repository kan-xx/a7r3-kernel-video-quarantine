/* Boot-resident invoker bridge. Native SP is restored before the native call.
 * r8 is sampled before C; AAPCS callees and the original two methods preserve it.
 * First three permanent row words: committed, original r4, original LR.
 */
.text
.arm
.balign 4
.global pig_gateway
.type pig_gateway,%function
pig_gateway:
 ldr ip,=0x63cbb87d
 cmp lr,ip
 bne .Lforward
 ubfx ip,sp,#0,#12
 cmp ip,#1024
 blo .Lforward
 push {r0,r1,r2,r3,r4,lr}
 add r0,sp,#24
 mov r1,sp
 mov r2,r8
 bl pig_prepare
 mov ip,r0
 pop {r0,r1,r2,r3,r4,lr}
 cmp ip,#0
 beq .Lforward
 str r4,[ip,#4]
 str lr,[ip,#8]
 mov r4,ip
 adr lr,.Lreturned
 ldr ip,=0x63cb3e05
 bx ip
.Lreturned:
 push {r0,r4,r5,lr}
 mov r5,r4
 mov r1,r4
 bl pig_finish
 mov ip,r5
 pop {r0,r4,r5,lr}
 ldr r4,[ip,#4]
 ldr lr,[ip,#8]
 bx lr
.Lforward:
 ldr ip,=0x63cb3e05
 bx ip
.ltorg
.size pig_gateway,.-pig_gateway
