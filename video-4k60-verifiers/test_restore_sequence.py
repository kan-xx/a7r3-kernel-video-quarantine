#!/usr/bin/env python3
"""Stub-free Unicorn counterexample: 6-table cache persistence after clearing 0x6402f4e0."""
from __future__ import annotations

import json
import struct

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)

from fw_env import (
    END_VA as END,
    IMX251_PARAM_WORDS,
    IMX251_TABLE_SPECS,
    OVERRIDE_SLOT_VA as SLOT,
    RAM_BASE as RAM,
    create_imx251_vm,
    load_avcam,
    parse_fw_root,
)


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    av_bytes = load_avcam(fw_root)
    u, _, ctrl_va = create_imx251_vm(av_bytes)

    index = 33  # Mode 76
    arg_va = RAM + 0x2000
    out_va = RAM + 0x3000
    allowed = [
        (IMX251_PARAM_WORDS[off // 4] + index * n, IMX251_PARAM_WORDS[off // 4] + (index + 1) * n)
        for off, n in IMX251_TABLE_SPECS
    ]
    pcs: set[int] = set()

    def on_code(uc, a, n, _):
        pcs.add(a)
        assert a not in (0x6395B314, 0x635E4584, 0x637A01D0)

    def on_write(uc, access, a, n, value, _):
        assert RAM <= a < a + n <= RAM + 0x20000 or any(lo <= a < a + n <= hi for lo, hi in allowed)

    u.hook_add(UC_HOOK_CODE, on_code)
    u.hook_add(UC_HOOK_MEM_WRITE, on_write)

    def call(label: str, slot: bytes, mode: int = 76) -> dict:
        pcs.clear()
        u.mem_write(SLOT, slot)
        u.mem_write(arg_va, struct.pack("<II", mode, 0))
        u.mem_write(out_va, b"\x00" * 0x144)
        for reg, val in [
            (UC_ARM_REG_R0, ctrl_va),
            (UC_ARM_REG_R1, 0),
            (UC_ARM_REG_R2, arg_va),
            (UC_ARM_REG_R3, out_va),
            (UC_ARM_REG_SP, RAM + 0xF000),
            (UC_ARM_REG_LR, END | 1),
        ]:
            u.reg_write(reg, val)
        u.emu_start(0x63CD67F9, END, count=50000)
        assert u.reg_read(UC_ARM_REG_PC) == END and u.reg_read(UC_ARM_REG_R0) == 0
        return {
            "label": label,
            "recalc_called": 0x637A6540 in pcs,
            "drvparam": bytes(u.mem_read(out_va, 0x144)).hex(),
            "mode76_tables": {
                hex(off): bytes(u.mem_read(IMX251_PARAM_WORDS[off // 4] + index * n, n)).hex()
                for off, n in IMX251_TABLE_SPECS
            },
        }

    baseline = bytes.fromhex("02034e0701bb0a21")  # PAL 25p descriptor at index 33 (0x21)
    fast = bytes.fromhex("40014e0701bba021")      # 60p candidate descriptor
    disabled = b"\xff" * 8

    rows = [
        call("baseline_25_native_recalc", baseline),
        call("candidate_60_native_recalc", fast),
        call("disable_slot_get76_counterexample", disabled),
        call("intermediate_safe_HD5_getparam_only", disabled, 5),
        call("back_to_get76_still_stale", disabled),
        call("restore_original25_override_recalc", baseline),
        call("remove_override_after_recalc_get76", disabled),
    ]
    base = rows[0]
    assert rows[1]["mode76_tables"] == rows[2]["mode76_tables"] == rows[3]["mode76_tables"] == rows[4]["mode76_tables"]
    assert not rows[2]["recalc_called"] and not rows[4]["recalc_called"]
    assert rows[5]["mode76_tables"] == base["mode76_tables"] and rows[5]["drvparam"] == base["drvparam"]
    assert rows[6]["mode76_tables"] == base["mode76_tables"] and rows[6]["drvparam"] == base["drvparam"]
    assert not rows[6]["recalc_called"]

    print(json.dumps({"test": "restore_sequence", "steps": len(rows), "passed": True}))


if __name__ == "__main__":
    main()
