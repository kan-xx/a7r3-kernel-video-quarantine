/* Emulator supplies three absolute pointers below. Not a camera entry. */
.syntax unified
.arm
.text
.align 2
.global host_contract
.type host_contract,%function
host_contract:
    ldr r1, binding_pointer
    ldr r2, result_pointer
    ldr r3, fence_pointer
    bx r3
.align 2
binding_pointer: .word host_binding
result_pointer: .word host_result
fence_pointer: .word br_native_fence_only
.size host_contract,.-host_contract
