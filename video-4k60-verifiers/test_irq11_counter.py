#!/usr/bin/env python3
"""Stub-free Unicorn counterexample: camIntHandler1 / IRQ11 (0x63796f01) fake counter."""
from __future__ import annotations

import json
import struct

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_THUMB, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP

from fw_env import AVCAM_BASE as B, END_VA as END, RAM_BASE as RAM, load_avcam, parse_fw_root


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    b = load_avcam(fw_root)

    for fact in (0, 1, 0x40000, 0xFFFFFFFF):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(B, (len(b) + 4095) & ~4095)
        u.mem_write(B, b)
        u.mem_map(RAM, 0x10000)
        u.mem_map(END, 0x1000)
        u.mem_map(0xFC0A0000, 0x1000)
        u.mem_write(0x641FDED4, struct.pack("<I", 9))
        u.mem_write(0xFC0A0020, struct.pack("<I", fact))

        def on_write(uc, access, a, n, value, _):
            assert RAM <= a < a + n <= RAM + 0x10000 or (a, n) in [
                (0x641FDED4, 4),
                (0xFC0A0020, 4),
            ], hex(a)

        def on_code(uc, a, n, _):
            assert a != 0x6395B314, "unexpected native log"

        u.hook_add(UC_HOOK_MEM_WRITE, on_write)
        u.hook_add(UC_HOOK_CODE, on_code)
        u.reg_write(UC_ARM_REG_SP, RAM + 0xF000)
        u.reg_write(UC_ARM_REG_LR, END | 1)
        u.emu_start(0x63796F01, END, count=10000)
        assert u.reg_read(UC_ARM_REG_PC) == END
        counter = struct.unpack("<I", u.mem_read(0x641FDED4, 4))[0]
        assert counter == 10

    print(json.dumps({"test": "irq11_counter", "cases": 4, "passed": True}))


if __name__ == "__main__":
    main()
