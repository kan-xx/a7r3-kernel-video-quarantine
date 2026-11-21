#!/usr/bin/env python3
"""Stub-free Unicorn verifier for RTOS format/rate matrix (0x63f79232) & helpers."""
from __future__ import annotations

import json
import struct

from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_SP,
)

from fw_env import AVCAM_BASE as B, END_VA as END, RAM_BASE as RAM, load_avcam, parse_fw_root


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    raw = load_avcam(fw_root)
    T = 0x63F79232
    HT = 0x63E375C8

    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(B, (len(raw) + 4095) & ~4095)
    u.mem_write(B, raw)
    u.mem_map(RAM, 65536)
    u.mem_map(END, 4096)

    checks = 0

    def run(addr: int, r0: int, r1: int, r2: int = 0) -> int:
        nonlocal checks
        for r, v in [
            (UC_ARM_REG_R0, r0),
            (UC_ARM_REG_R1, r1),
            (UC_ARM_REG_R2, r2),
            (UC_ARM_REG_SP, RAM + 0xFFF0),
            (UC_ARM_REG_LR, END | 1),
        ]:
            u.reg_write(r, v)
        u.emu_start(addr | 1, END, count=100)
        assert u.reg_read(UC_ARM_REG_PC) == END
        checks += 1
        return u.reg_read(UC_ARM_REG_R0)

    for size in [*range(8), 127, 255]:
        for fps in [*range(7), 127, 255]:
            u.mem_write(RAM, bytes([size, fps]))
            out = run(0x63BC03A8, RAM, RAM + 1)
            expected = raw[T - B + size * 6 + fps] if size < 7 and fps < 6 else 0
            assert out == expected and bytes(u.mem_read(RAM, 2)) == bytes([size, fps])

    for size in range(8):
        for height in range(9):
            u.mem_write(RAM, bytes([size, height]))
            out = run(0x63BC03D8, RAM, RAM + 1)
            word = struct.unpack_from("<I", raw, HT - B + 4 * (size * 8 + height))[0] if size < 7 and height < 8 else 0
            assert out == bool(word)
            actual = u.mem_read(RAM + 1, 1)[0]
            assert actual == (word if height == 0 and word else height)

    for addr in (0x63BC03A8, 0x63BC03D8):
        for a, b_arg in [(0, 0), (0, RAM), (RAM, 0)]:
            assert run(addr, a, b_arg) == 0

    for usecase in (0, 1, 0x22):
        for value in range(10):
            out = run(0x6367B768, RAM, value, usecase)
            assert out == (10 if usecase == 0x22 else [5, 4, 3, 2, 1, 0, 8, 6, 9, 7][value])

    patch = T + 4 * 6 + 1  # 0x63f7924b: 4K (size=4) @ 59.94/50p (fr=1)
    assert raw[patch - B] == 0
    u.mem_write(RAM, bytes([4, 1]))
    assert run(0x63BC03A8, RAM, RAM + 1) == 0
    u.mem_write(patch, b"\x01")
    assert run(0x63BC03A8, RAM, RAM + 1) == 1
    u.mem_write(patch, b"\x00")
    assert run(0x63BC03A8, RAM, RAM + 1) == 0

    print(json.dumps({"test": "original_tables", "checks": checks, "passed": True}))


if __name__ == "__main__":
    main()
