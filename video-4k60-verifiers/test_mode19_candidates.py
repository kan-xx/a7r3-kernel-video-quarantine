#!/usr/bin/env python3
"""Stub-free Unicorn counterexample: Mode 19 half-H 8-bit ratio truncation (0x637a3da8)."""
from __future__ import annotations

import json
import math
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


def slot_bytes(h: int, v: int, flag: int = 0, den: int = 0, num: int = 0, index: int = 15) -> bytes:
    return struct.pack("<HHBBBB", h, v, flag, den, num, index)


def run_mode_getparam(av_bytes: bytes, slot: bytes, mode: int = 19, index: int = 15) -> dict:
    u, _, ctrl_va = create_imx251_vm(av_bytes)
    arg_va = RAM + 0x2000
    out_va = RAM + 0x3000
    u.mem_write(arg_va, struct.pack("<II", mode, 0))
    u.mem_write(SLOT, slot + b"\xff" * 8)

    allowed = [(RAM, RAM + 0x20000)]
    for off, stride in IMX251_TABLE_SPECS:
        base = IMX251_PARAM_WORDS[off // 4]
        allowed.append((base + index * stride, base + (index + 1) * stride))

    pcs: set[int] = set()

    def on_code(uc, a, n, _):
        pcs.add(a)
        if a in (0x6395B314, 0x635E4584, 0x637A01D0):
            raise AssertionError(f"Unexpected OS/log/HW call at {a:#x}")

    def on_write(uc, access, a, n, value, _):
        assert any(lo <= a < a + n <= hi for lo, hi in allowed), (
            f"Unexpected write {a:#x} at PC {uc.reg_read(UC_ARM_REG_PC):#x}"
        )

    u.hook_add(UC_HOOK_CODE, on_code)
    u.hook_add(UC_HOOK_MEM_WRITE, on_write)
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

    out = bytes(u.mem_read(out_va, 0x144))
    h_int = struct.unpack_from("<I", out, 0x38)[0]
    untrunc = math.floor(1050 / h_int * 100 + 0.5)
    return {
        "output": out,
        "ratio_bytes": list(out[0x24:0x26]),
        "ratio_overflow": untrunc > 255,
        "secondary_descriptor": out[0x98:0xA4].hex(),
        "ran_recalc": 0x637A6540 in pcs,
        "ran_override_reader": 0x637A31B8 in pcs,
        "ran_postprocess": 0x637A3DA8 in pcs,
    }


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    av_bytes = load_avcam(fw_root)
    cases = [
        ("mode19_pal25", b"\xff" * 8),
        ("mode19_ntsc_700_1716", slot_bytes(700, 1716)),
        ("mode19_half_H350_1716_TRUNCATED", slot_bytes(350, 1716)),
        ("mode19_exact60_H349_plus93over143_TRUNCATED", slot_bytes(349, 1716, 1, 143, 93)),
        ("mode19_H525_V1144", slot_bytes(525, 1144)),
        ("mode19_H524_plus68over143_V1144", slot_bytes(524, 1144, 1, 143, 68)),
        ("mode19_H420_V1430", slot_bytes(420, 1430)),
    ]
    rows = [run_mode_getparam(av_bytes, s) for _, s in cases]
    assert rows[1]["ratio_bytes"] == [150, 100]
    assert rows[2]["ratio_bytes"] == [44, 100] and rows[2]["ratio_overflow"] is True
    assert rows[3]["ratio_bytes"] == [45, 100] and rows[3]["ratio_overflow"] is True
    assert rows[4]["ratio_bytes"] == [200, 100] and rows[4]["ratio_overflow"] is False
    assert rows[5]["ratio_bytes"] == [200, 100]
    assert rows[6]["ratio_bytes"] == [250, 100]
    assert all(r["secondary_descriptor"] == rows[0]["secondary_descriptor"] for r in rows)
    assert all(r["ran_recalc"] and r["ran_override_reader"] and r["ran_postprocess"] for r in rows[1:])

    print(json.dumps({"test": "mode19_candidates", "cases": len(rows), "passed": True}))


if __name__ == "__main__":
    main()
