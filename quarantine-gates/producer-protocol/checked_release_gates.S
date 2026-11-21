/* OFFLINE candidate, not an installable patch.
 * hs_checked_stop_contract is deliberately UNRESOLVED: it must perform the
 * checked hardware stop and producer/IRQ exclusion in the caller-owned native
 * transaction. A zero value is a release grant, not merely bit31 == 0.
 * No vtable+4 return value is used: native H/V cleanup is a void ABI.
 */
.syntax unified
.arm
.text
.balign 4
.global hs_controller_release_gate
.type hs_controller_release_gate,%function
hs_controller_release_gate:
    push {r4, lr}
    mov r4, r0
    ldr r1, [r4, #0x20]
    cmp r1, #2
    movne r0, #1
    bne 2f
    /* Before this grant no sequence state/driver/list/index is changed. */
    bl hs_checked_stop_contract
    cmp r0, #0
    bne 2f
    /* The checked contract performed cleanup; DO NOT call unsafe cc9e again.
     * Reproduce its successful state5 assignment then native cf02 twice.
     * The contract must validate index and cohort and retain exclusivity.
     */
    ldr r2, [r4, #0x80]
    add r1, r4, #0x60
    ldr r0, [r1, r2, lsl #2]
    cmp r0, #0
    movne r1, #5
    strne r1, [r0, #0x174]
    mov r0, r4
    ldr ip, =0x63d5cf03
    blx ip
    mov r0, r4
    ldr ip, =0x63d5cf03
    blx ip
    mov r0, #0
2:  pop {r4, pc}
.size hs_controller_release_gate,.-hs_controller_release_gate

/* Candidate continuation at original 63a25bc2, with the original 72B Release
 * frame intact. r10 is the original lock wrapper and r4 is job id.
 * Failure preserves original error in r5, enters native unlock2 then epilogue,
 * and skips registry_remove AND job_admission_clear.
 * Success resumes original mov r8,r0 / test and normal resource successors.
 * This does not supply a safe publication mechanism for the direct callsite.
 */
.global hs_public_release_result_gate
.type hs_public_release_result_gate,%function
hs_public_release_result_gate:
    cmp r0, #0
    ldreq ip, =0x63a25bc3
    bxeq ip
    mov r5, r0
    ldr ip, =0x63a25c9f
    bx ip
.size hs_public_release_result_gate,.-hs_public_release_result_gate
.ltorg
