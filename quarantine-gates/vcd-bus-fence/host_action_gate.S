/* Offline ABI fixture only. No executable installation address is supplied.
 * Candidate boundary: original common_reset_action's BL at 0x639d826a.
 * bounded_stop_contract must return EXACTLY 1 only with all cleanup gates met.
 * This investigation supplies no production adapter capable of returning 1.
 */
.syntax unified
.thumb
.text
.align 2
.global action_gate
.type action_gate,%function
.thumb_func
action_gate:
    push {r4,lr}
    ldr r3, contract_pointer
    blx r3
    pop {r4,lr}
    cmp r0,#1
    bne failed
    bx lr
failed:
    movs r0,#0
    ldr r3, failure_epilogue
    bx r3
.align 2
contract_pointer:
    .word bounded_stop_contract
failure_epilogue:
    .word 0x639d82cd
.size action_gate,.-action_gate
