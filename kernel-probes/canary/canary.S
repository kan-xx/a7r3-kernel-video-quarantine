/* Independent no-op ARMv7 module. No Sony executable code is reused.
 * Only .gnu.linkonce.this_module ABI size/offsets and vermagic are
 * derived from verified FW3.10 nls_utf8.ko; see abi-provenance.json.
 * SPDX-License-Identifier: GPL-2.0-only
 */
.syntax unified
.arch armv7-a
.arm

.section .init.text,"ax",%progbits
.balign 4
.global init_module
.type init_module,%function
init_module:
    mov r0, #0
    bx lr
.size init_module, .-init_module

.section .exit.text,"ax",%progbits
.balign 4
.global cleanup_module
.type cleanup_module,%function
cleanup_module:
    bx lr
.size cleanup_module, .-cleanup_module

.section .gnu.linkonce.this_module,"aw",%progbits
.balign 4
.global __this_module
.type __this_module,%object
__this_module:
    .zero 0x0c
    .asciz "a7r3_abi_canary_1101a"
    .zero 0xbc - (. - __this_module)
    .word init_module
    .zero 0x134 - (. - __this_module)
    .word cleanup_module
    .zero 0x13c - (. - __this_module)
.size __this_module, .-__this_module

.section .modinfo,"a",%progbits
.asciz "license=GPL"
.asciz "description=Independent no-op ABI canary; no hooks or resource registration"
.asciz "depends="
.asciz "vermagic=3.0.27_nl-rt106+ SMP preempt mod_unload ARMv7 "

.section .note.GNU-stack,"",%progbits
