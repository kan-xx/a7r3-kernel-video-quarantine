#!/usr/bin/env python3
"""Stub-free Unicorn verifier for RTOS SET_STEPFOCUS / FOCUS_DRIVE & 4K60 decoder strings."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

AVCAM_SHA256 = "35e3ff3f931fa725928ab8c7493d4b9842e1f90c3fa7b90ab4e23274256dd800"
B = 0x635C6000
DATA = 0x645F7FF0
MSG = 0x70000000
RET = 0x71000000


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")

    b = (Path(args.fw_root) / "nflasha3/export/av-cam.bin").read_bytes()
    if os.environ.get("A7R3_SKIP_FW_SHA256") != "1":
        assert hashlib.sha256(b).hexdigest() == AVCAM_SHA256

    checks = 0

    def check(cond: bool) -> None:
        nonlocal checks
        assert cond
        checks += 1

    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(B, (len(b) + 4095) & ~4095)
    u.mem_write(B, b)
    u.mem_map(MSG, 0x20000)
    u.mem_map(RET, 4096)
    u.mem_write(RET, b"\x70\x47")
    u.mem_write(0x6433A462, b"\x00")

    def run(addr: int, msg: bytes) -> None:
        u.mem_write(MSG, msg)
        u.reg_write(UC_ARM_REG_SP, MSG + 0x1FFF0)
        u.reg_write(UC_ARM_REG_LR, RET | 1)
        u.reg_write(UC_ARM_REG_R0, MSG)
        u.emu_start(addr | 1, RET, count=200)
        check(u.reg_read(UC_ARM_REG_R0) == 1)

    for seq in (0, 1, 127, 254, 255):
        for direction in (0, 1, 2, 3, 255):
            init = bytearray(0x600)
            init[0x56C] = 77
            init[0x56D] = seq
            struct.pack_into("<I", init, 0x574, 99)
            u.mem_write(DATA, bytes(init))
            msg = bytearray(16)
            msg[8] = direction
            run(0x63BC13AC, bytes(msg))
            result = bytes(u.mem_read(DATA, 0x600))
            expected = bytearray(init)
            expected[0x56D] = (seq + (-1 if direction == 1 else 1 if direction == 2 else 0)) & 255
            struct.pack_into("<I", expected, 0x578, 2)
            check(result == expected)

    for speed in (0, 1, 5, 255):
        for direction in (0, 1, 2, 3):
            init = bytearray(0x600)
            init[0x56D] = 50
            u.mem_write(DATA, bytes(init))
            msg = bytearray(16)
            msg[8] = speed
            msg[9] = direction
            run(0x63BC3D14, bytes(msg))
            expected = bytearray(init)
            expected[0x56C] = speed
            expected[0x56D] = (50 + (-1 if direction == 1 else 1 if direction == 2 else 0)) & 255
            struct.pack_into("<I", expected, 0x578, 1)
            check(bytes(u.mem_read(DATA, 0x600)) == expected)

    for direction in (0, 1, 2, 3, 255):
        init = bytes(0x600)
        u.mem_write(DATA, init)
        msg = bytearray(16)
        msg[8] = direction
        run(0x63BC3CD8, bytes(msg))
        expected = bytearray(init)
        struct.pack_into("<I", expected, 0x574, direction)
        check(bytes(u.mem_read(DATA, 0x600)) == expected)

    formats = {}
    for value in range(57):
        u.reg_write(UC_ARM_REG_SP, MSG + 0x1FFF0)
        u.reg_write(UC_ARM_REG_LR, RET | 1)
        u.reg_write(UC_ARM_REG_R0, 0)
        u.reg_write(UC_ARM_REG_R1, value)
        u.emu_start(0x63661089, RET, count=30)
        ptr = u.reg_read(UC_ARM_REG_R0)
        check(B <= ptr < B + len(b))
        formats[value] = bytes(u.mem_read(ptr, 100)).split(b"\x00", 1)[0].decode("ascii")

    assert formats[29] == "3840X2160_60_50P"
    assert formats[42] == "4096X2160_59_94P_50P"
    assert checks == 149

    print(json.dumps({"test": "original_focus", "checks": checks, "passed": True}))


if __name__ == "__main__":
    main()
