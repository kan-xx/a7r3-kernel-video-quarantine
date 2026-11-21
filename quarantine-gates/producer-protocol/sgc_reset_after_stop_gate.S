/* Offline ABI continuation candidate at 63d0f664.
 * r0: checked SGC stop result (NOT the old void result contract).
 * r4: original SGC object. Original caller frame {r4,lr} remains.
 * A nonzero result must propagate to a recovery-owned consumer. Existing
 * callers of 63d0f65a do not establish this final propagation contract.
 * No publication mechanism or installer is supplied.
 */
.syntax unified
.arm
.text
.global sgc_reset_after_stop_gate
.type sgc_reset_after_stop_gate,%function
sgc_reset_after_stop_gate:
    cmp r0, #0
    popne {r4, pc}
    ldr r3, [r4]
    mov r0, r4
    ldr r3, [r3, #8]
    blx r3
    pop {r4, pc}
.size sgc_reset_after_stop_gate,.-sgc_reset_after_stop_gate
