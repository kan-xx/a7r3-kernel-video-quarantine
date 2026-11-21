/* OFFLINE continuation candidates; no publication or native-call entry API.
 * These exact epilogues make the three proven native wait boundaries capable
 * of returning an explicit failure to an OWNED recovery caller. They do not
 * alter a hardware completion bit and do not grant any downstream release.
 * The native lock acquisition remains outside this proof. A real caller must
 * consume these nonzero results; ordinary void-vtable callers may ignore them.
 */
.syntax unified
.arm
.text
.balign 4
.global sgc_capture_failed
.type sgc_capture_failed,%function
sgc_capture_failed:
    /* Enter at 63cbc49e: capture helper has its real 16-byte saved frame;
     * parent 6376fe08 has its real 24-byte frame and owns lock 0x13. */
    pop {r4, r5, r6, lr}
    mov r0, #0x13
    ldr ip, =0x635e4125
    blx ip
    movw r0, #0x1001
    pop {r2, r3, r4, r5, r6, pc}
.size sgc_capture_failed,.-sgc_capture_failed
.global sgc_window_not_ready
.type sgc_window_not_ready,%function
sgc_window_not_ready:
    /* Enter at 6376fee0, AFTER native unlock. Skip the native delay/retry. */
    movw r0, #0x1002
    pop {r2, r3, r4, r5, r6, pc}
.size sgc_window_not_ready,.-sgc_window_not_ready
.global sgc_final_not_idle
.type sgc_final_not_idle,%function
sgc_final_not_idle:
    /* Enter at 6376fecc before next final status sample. Lock already free;
     * base+0x200 is zero, but +0x210 bit16 has not cleared. */
    movw r0, #0x1003
    pop {r2, r3, r4, r5, r6, pc}
.size sgc_final_not_idle,.-sgc_final_not_idle
.ltorg
