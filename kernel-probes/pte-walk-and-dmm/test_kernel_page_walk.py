#!/usr/bin/env python3
"""Verify Linux 3.0.27 software-PTE walk against vmlinux vmalloc_to_page in Unicorn."""
from __future__ import annotations

import argparse
import json
import os
import struct
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R3, UC_ARM_REG_SP

import kernel_queue_read as kqr


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Set A7R3_FW_ROOT or pass --fw-root")

    b = kqr.kq_verify_vmlinux_anchors(args.fw_root)
    rows = []
    for va in [
        0x5F000000,
        0x5F047000,
        0x5F04D70C,
        0x5F04E344,
        0x5F1FFFE0,
        0x5F200000,
        0x5F3FFFF0,
        0x5FFFFFFF,
    ]:
        u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for start, size in [
            (0x60104000, 0x4000),
            (0x601A2000, 0x1000),
            (0x604C8000, 0x1000),
            (0x62000000, 0x1000),
            (0x70000000, 0x1000),
        ]:
            u.mem_map(start, size)
        u.mem_write(0x601A2670, b[0x9A670 : 0x9A670 + 140])
        u.mem_write(0x604C8ECC, struct.pack("<I", 0x60104000))
        pmd_va = 0x60104000 + (va >> 21) * 8
        pmd = 0x02000811
        pte_va = 0x62000000 + ((va >> 12) & 0x1FF) * 4
        pte = 0x0812300F
        u.mem_write(pmd_va, struct.pack("<I", pmd))
        u.mem_write(pte_va, struct.pack("<I", pte))
        u.reg_write(UC_ARM_REG_SP, 0x70000FF0)
        u.reg_write(UC_ARM_REG_R0, va)

        def stop(uc, pc, size, user):
            if pc == 0x601A26B8:
                uc.emu_stop()

        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0x601A2670, 0x601A26B8, count=60)
        assert u.reg_read(UC_ARM_REG_R3) == pte and u.reg_read(UC_ARM_REG_R0) == 1

        cells = {pmd_va - 0x60000000: pmd, pte_va - 0x60000000: pte}
        reads: list[int] = []

        def rd(pa: int, label: str) -> int:
            reads.append(pa)
            return cells[pa]

        kqr.kq_u32 = rd  # type: ignore[assignment]
        pa, _ = kqr.kq_translate(va, "host")
        assert reads == [pmd_va - 0x60000000, pte_va - 0x60000000]
        assert pa == 0x08123000 + (va & 0xFFF)
        rows.append({"va": hex(va), "pa": hex(pa)})

    rejects = []
    for label, va, pmd, pte in [
        ("outside-module", 0x60000000, 0x02000811, 0x0812300F),
        ("zero-pmd", 0x5F047000, 0, 0x0812300F),
        ("section", 0x5F047000, 0x02000002, 0x0812300F),
        ("absent-pte", 0x5F047000, 0x02000811, 0x0812300E),
        ("mmio-pfn", 0x5F047000, 0x02000811, 0xF4000001),
    ]:
        kqr.kq_u32 = lambda pa, name, _pmd=pmd, _pte=pte: _pmd if name.endswith("-pmd") else _pte  # type: ignore[assignment]
        try:
            kqr.kq_translate(va, "host")
        except AssertionError:
            rejects.append(label)
        else:
            raise AssertionError(label)

    print(
        json.dumps(
            {
                "test": "kernel_page_walk",
                "native_prefix_cases": len(rows),
                "fail_closed_cases": len(rejects),
                "passed": True,
            }
        )
    )


if __name__ == "__main__":
    main()
