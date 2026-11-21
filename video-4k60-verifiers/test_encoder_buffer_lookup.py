#!/usr/bin/env python3
"""Stub-free Unicorn verifier for secondary encoder resource lookup (0x63e29854)."""
from __future__ import annotations

import json
import struct

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_PC,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_SP,
)

from fw_env import AVCAM_BASE as B, RAM_BASE as RAM, load_avcam, parse_fw_root


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    b = load_avcam(fw_root)
    TABLE = 0x63E29854

    def word(va: int) -> int:
        return struct.unpack_from("<I", b, va - B)[0]

    stops = {
        0x639E7EB2: "wildcard_exact_rate",
        0x639E7F24: "exact_discriminator",
        0x639E7F8C: "fallback_same_dimensions",
        0x639E7FE8: "fallback_same_height",
        0x639E8098: "no_profile",
    }
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(B, (len(b) + 4095) & ~4095)
    u.mem_write(B, b)
    u.mem_map(RAM, 65536)

    def stop(uc, a, size, data):
        if a in stops:
            uc.emu_stop()

    u.hook_add(UC_HOOK_CODE, stop)
    cases = 0
    for kind in (4, 5):
        for rate in (0, 1, 2, 3, 5, 6):
            msg = RAM + 0x1000
            u.mem_write(msg, bytes(0x88))
            u.mem_write(msg + 8, struct.pack("<HH", 3840, 2160))
            for off, v in [(0x14, kind), (0x18, 0), (0x1C, 0), (0x20, rate), (0x34, 11)]:
                u.mem_write(msg + off, struct.pack("<I", v))
            for reg, v in [
                (UC_ARM_REG_R4, RAM),
                (UC_ARM_REG_R5, msg),
                (UC_ARM_REG_R6, TABLE),
                (UC_ARM_REG_R7, TABLE),
                (UC_ARM_REG_R8, 0),
                (UC_ARM_REG_R9, 0),
                (UC_ARM_REG_SP, RAM + 0xF000),
            ]:
                u.reg_write(reg, v)
            u.emu_start(0x639E7E77, 0x71000000, count=20000)
            pc = u.reg_read(UC_ARM_REG_PC)
            assert pc in stops, hex(pc)
            index = u.reg_read(UC_ARM_REG_R8 if pc == 0x639E7EB2 else UC_ARM_REG_R6)
            expected = "wildcard_exact_rate" if rate in (2, 3, 5) else "fallback_same_dimensions"
            assert stops[pc] == expected and 0 <= index < 168, (kind, rate, hex(pc), index)
            a = TABLE + 40 * index
            selected = word(a + 8)
            assert word(a) == kind and selected == (rate if rate in (2, 3, 5) else 2)
            cases += 1

    print(json.dumps({"test": "encoder_buffer_lookup", "cases": cases, "passed": True}))


if __name__ == "__main__":
    main()
