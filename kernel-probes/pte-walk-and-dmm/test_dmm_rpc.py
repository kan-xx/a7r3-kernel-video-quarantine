#!/usr/bin/env python3
"""Verify av-cam.bin DMM Free RPC wrapper (0x639d4ae0) & negative controls in Unicorn."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB, Uc
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_SP,
)

AVCAM_SHA256 = "35e3ff3f931fa725928ab8c7493d4b9842e1f90c3fa7b90ab4e23274256dd800"
B = 0x635C6000
END = 0x7000FF00


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Set A7R3_FW_ROOT or pass --fw-root")

    raw = (Path(args.fw_root) / "nflasha3/export/av-cam.bin").read_bytes()
    if os.environ.get("A7R3_SKIP_FW_SHA256") != "1":
        assert hashlib.sha256(raw).hexdigest() == AVCAM_SHA256

    inputs = [
        ("valid", 0, 0, 0x1111, 0, 0x8004, 0xE0BF, 0),
        ("transport-positive", 1, 0, 0x1111, 0, 0x8004, 0xE0BF, 1),
        ("transport-negative", -52, 0, 0x1111, 0, 0x8004, 0xE0BF, 1),
        ("reply-copy-error", 0, 1, 0x1111, 0, 0x8004, 0xE0BF, 1),
        ("wrong-marker", 0, 0, 0x4445, 0, 0x8004, 0xE0BF, 1),
        ("positive-peer-status", 0, 0, 0x1111, 1, 0x8004, 0xE0BF, 1),
        ("negative-peer-status", 0, 0, 0x1111, 0xFFFF, 0x8004, 0xE0BF, 1),
        ("wrong-opcode-not-validated-here", 0, 0, 0x1111, 0, 0x9999, 0xE0BF, 0),
        ("handle-truncated-to-u16", 0, 0, 0x1111, 0, 0x8004, 0x1234E0BF, 0),
    ]

    for name, transport, copyrc, marker, peerstatus, opcode, handle, expected in inputs:
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(B, (len(raw) + 4095) & ~4095)
        u.mem_write(B, raw)
        u.mem_map(0x70000000, 65536)
        events: list[str] = []
        messages: dict[int, bytes] = {}
        result: dict[str, int] = {}
        reply = bytearray(112)
        struct.pack_into("<4H", reply, 0, opcode, peerstatus, handle & 0xFFFF, marker)

        def ret(value: int = 0) -> None:
            u.reg_write(UC_ARM_REG_R0, value & 0xFFFFFFFF)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

        def code(uc, pc, size, unused):
            r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            if pc == END:
                result["value"] = r[0]
                uc.emu_stop()
                return
            if pc == 0x63AB3A04:
                uc.mem_write(r[0], bytes([r[1] & 255]) * r[2])
                ret(r[0])
                return
            if pc in (0x63AAD8AC, 0x63AAD89C):
                events.append("sender-ctor" if pc == 0x63AAD8AC else "sender-dtor")
                ret(r[0])
                return
            if pc == 0x63AACCA4:
                uc.mem_write(r[0], bytes(0x110))
                ret(r[0])
                return
            if pc == 0x63AACCC0:
                assert r[2] == 112
                messages[r[0]] = bytes(uc.mem_read(r[1], r[2]))
                events.append("set-request")
                ret()
                return
            if pc == 0x63D76F4C:
                uc.mem_write(r[0] + 12, struct.pack("<I", r[1]))
                ret(r[0])
                return
            if pc == 0x63AAD8E4:
                assert r[1] == 0x0061003C
                req = messages[r[2]]
                assert struct.unpack_from("<H", req, 0)[0] == 4
                assert struct.unpack_from("<H", req, 2)[0] == handle & 0xFFFF
                assert struct.unpack_from("<2H", req, 20) == (0x1111, 2)
                assert struct.unpack("<I", uc.mem_read(r[2] + 12, 4))[0] == 0x006800F3
                events.append("sync-transport-fixture")
                ret(transport)
                return
            if pc == 0x63AACD04:
                assert r[2] == 112
                events.append("copy-reply")
                if not copyrc:
                    uc.mem_write(r[1], bytes(reply))
                ret(copyrc)
                return
            if pc == 0x63AACC94:
                events.append("message-dtor")
                ret(r[0])
                return
            if pc == 0x639ED874:
                ret()
                return
            if pc == 0x63D4A326:
                events.append("log")
                ret()
                return
            assert any(
                lo <= pc < hi
                for lo, hi in [
                    (0x639D4904, 0x639D4920),
                    (0x639D4928, 0x639D4948),
                    (0x639D4AE0, 0x639D4B80),
                    (0x63D4A200, 0x63D4A26A),
                    (0x639ED520, 0x639ED5A4),
                ]
            ), hex(pc)

        u.hook_add(UC_HOOK_CODE, code)
        u.reg_write(UC_ARM_REG_SP, 0x7000F000)
        u.reg_write(UC_ARM_REG_LR, END | 1)
        u.reg_write(UC_ARM_REG_R0, handle)
        u.emu_start(0x639D4AE1, END + 4, count=10000)
        assert result.get("value") == expected, (name, result)
        assert (
            events.count("sync-transport-fixture") == 1
            and events.count("message-dtor") == 1
            and events.count("sender-dtor") == 1
        )
        assert events.count("log") == 1 + expected

    print(json.dumps({"test": "dmm_rpc", "cases": len(inputs), "passed": True}))


if __name__ == "__main__":
    main()
