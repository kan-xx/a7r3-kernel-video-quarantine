/* EMULATOR-ONLY integration bridge. No installation address or publication.
 * The real candidate returns FENCE_ONLY=2, never cleanup permission1.
 * Calling convention and failure epilogue match the frozen original analysis.
 */
.syntax unified
.thumb
.text
.align 2
.global host_action_gate
.type host_action_gate,%function
.thumb_func
host_action_gate:
    push {r4,lr}
    ldr r3, host_contract_pointer
    blx r3
    pop {r4,lr}
    cmp r0,#1
    bne host_failed
    bx lr
host_failed:
    movs r0,#0
    ldr r3, failure_epilogue
    bx r3
.align 2
host_contract_pointer:
    .word host_contract
failure_epilogue:
    .word 0x639d82cd
.size host_action_gate,.-host_action_gate
