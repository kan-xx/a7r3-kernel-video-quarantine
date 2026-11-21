#!/usr/bin/env python3
"""Stub-free Unicorn verifier for PIG A/B event predicates & SplitEESub pool free-list."""
from __future__ import annotations

import json
import struct

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

from fw_env import AVCAM_BASE as B, END_VA as END, RAM_BASE as RAM, load_avcam, parse_fw_root


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    b = load_avcam(fw_root)

    def word_rom(va: int) -> int:
        return struct.unpack_from("<I", b, va - B)[0]

    def w(u: Uc, a: int, v: int) -> None:
        u.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))

    def rd(u: Uc, a: int) -> int:
        return struct.unpack("<I", u.mem_read(a, 4))[0]

    def fresh() -> Uc:
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(B, (len(b) + 4095) & ~4095)
        u.mem_write(B, b)
        u.mem_map(RAM, 0x20000)
        u.mem_map(END, 4096)
        return u

    def call(u: Uc, a: int, args: list[int]) -> None:
        u.reg_write(UC_ARM_REG_SP, RAM + 0x1F000)
        u.reg_write(UC_ARM_REG_LR, END | 1)
        for reg, v in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            u.reg_write(reg, v)
        u.emu_start(a | 1, END, count=50000)
        assert u.reg_read(UC_ARM_REG_PC) == END, hex(u.reg_read(UC_ARM_REG_PC))

    def ret(u: Uc, value: int = 0) -> None:
        u.reg_write(UC_ARM_REG_R0, value)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    cases = 0
    specs = [
        (0xD8, 0x63CB7FCA, "CamHead", 1, 1),
        (0x250, 0x6376DA04, "CamArc", 2, 6),
        (0x2D8, 0x63CB6F0C, "CamCas", 4, 8),
        (0x34C, 0x63CB71F8, "CamDcv", 8, 0x10),
        (0x3D0, 0x63CB9180, "CamNrMov", 0x20, 0x80),
        (0x444, 0x63CB91B2, "CamNrStl", 0x20, 0x80),
        (0x4B8, 0x63CBA406, "CamSigMov", 0x40, 0x100),
        (0x52C, 0x63CBA43A, "CamSigStl", 0x40, 0x100),
        (0x5A0, 0x63CB770E, "CamDev", 0x100, 0x800),
    ]
    for off, fn, name, mask_a, mask_b in specs:
        u = fresh()
        call(u, 0x63CBBF6A, [RAM, 0, 0, 0])
        vt = rd(u, RAM + off)
        ti = word_rom(vt - 4)
        nm = word_rom(ti + 4)
        native_name = b[nm - B : b.index(b"\x00", nm - B)].decode("ascii")
        assert name in native_name
        call(u, fn, [RAM + off, RAM + 0x10000, RAM + 0x804, 0])
        assert rd(u, RAM + off + 0x18) == mask_a and rd(u, RAM + off + 0x1C) == mask_b
        cases += 1

    for fn, stage, offset in [(0x63CBB96C, 0x4000000, 0x20), (0x6376F1B0, 0x8000000, 0x24)]:
        for mask in (0, 0x161, 0x3399F, 0xFFFFFFFF):
            u = fresh()
            obj = RAM + 0x1000
            fun = RAM + 0x2000
            hw = RAM + 0x8000
            call(u, 0x6376F3F8, [obj, 1, 0, 0])
            w(u, obj + 0x10, hw)
            u.mem_write(fun, struct.pack("<5I", 0x63CB3E05, 0, 0x63CB4F4F, 0, 0x641F1258))
            calls = []

            def hook(uc, a, n, _):
                if a in (0x635E4108, 0x635E4124):
                    assert uc.reg_read(UC_ARM_REG_R0) == 0x13
                    calls.append((hex(a), 0x13))
                    ret(uc)
                elif a == 0x6376EE00:
                    calls.append(("register", uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)))
                    ret(uc, 1)
                elif a == 0x6376F184:
                    calls.append(("endpoint_ack", uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)))
                    ret(uc)

            u.hook_add(UC_HOOK_CODE, hook)
            call(u, fn, [obj, mask, fun, 0])
            assert rd(u, hw + offset) == mask
            assert ("register", 0x40000000 | stage, fun) in calls
            assert rd(u, hw + 0x10) == stage >> 24 and rd(u, hw + 0x14) == stage >> 24
            assert rd(u, hw + 0x50) & stage
            cases += 1

    for oldhead in (0, RAM + 0x1CC0):
        u = fresh()
        obj = RAM + 0x1000
        pool = RAM + 0x5000
        w(u, pool, oldhead)
        w(u, pool + 8, int(bool(oldhead)))
        w(u, obj, 0x646908F8)
        w(u, obj + 0x30, 0)
        w(u, obj + 0x98, 0x640CFF78)

        def hook2(uc, a, n, _):
            if a in (0x635E4108, 0x635E4124):
                assert uc.reg_read(UC_ARM_REG_R0) == 0x11
                ret(uc)

        u.hook_add(UC_HOOK_CODE, hook2)
        call(u, 0x63CB5554, [pool, obj, 0, 0])
        assert rd(u, obj) == oldhead and rd(u, pool) == obj and rd(u, obj + 0x98) == 0x640CFF78
        call(u, 0x6376C00C, [pool - 4, 0, 0, 0])
        assert u.reg_read(UC_ARM_REG_R0) == obj and rd(u, obj) == 0x646908F8 and rd(u, pool) == oldhead
        assert rd(u, obj + 0x30) == 0
        cases += 1

    u = fresh()
    obj = RAM + 0x1000
    w(u, obj + 0x18, 0x161)
    w(u, obj + 0x1C, 0x3399F)
    call(u, 0x63CB3F8A, [obj])
    assert u.reg_read(UC_ARM_REG_R0) == 0x161
    call(u, 0x63CB3F8E, [obj])
    assert u.reg_read(UC_ARM_REG_R0) == 0x3399F
    cases += 1

    print(json.dumps({"test": "native_semantics", "cases": cases, "passed": True}))


if __name__ == "__main__":
    main()
