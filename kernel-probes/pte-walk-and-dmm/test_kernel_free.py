#!/usr/bin/env python3
"""Verify relocated dmm.ko dmm_ctrl_FreeUnitHdlr refcount/rendezvous semantics in Unicorn."""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "kernel-probes/rc-gateway"))
from elf_image import Elf32Rel, SHN_ABS, SHN_UNDEF, SHT_NOBITS  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Set A7R3_FW_ROOT or pass --fw-root")

    ko_path = Path(args.fw_root) / "nflasha15/export/kmod/dmm.ko"
    e = Elf32Rel(ko_path.read_bytes())
    symbols = e.symbols
    named = {s["name"]: s for s in symbols if s["name"]}
    sections = {
        s["index"]: bytearray(s["data"] if s["sh_type"] != SHT_NOBITS else bytes(s["sh_size"]))
        for s in e.sections
        if (s["sh_flags"] & 2) and s["sh_size"]
    }
    bases = {i: 0x10000000 + i * 0x01000000 for i in sections}
    rel_text = e.section_by_name(".rel.text")
    relocs = e.relocations(rel_text)

    T = bases[1]
    BSS = bases[21]
    calls: dict[int, dict] = {}
    for r_off, r_type, r_sym in relocs:
        sym = symbols[r_sym]
        sec = sym["st_shndx"]
        if r_type == 2:
            add = struct.unpack_from("<I", sections[1], r_off)[0]
            assert sec in bases or sec in (SHN_UNDEF, SHN_ABS)
            resolved = (
                bases[sec] + sym["st_value"]
                if sec in bases
                else sym["st_value"]
                if sec == SHN_ABS
                else 0x60000000 + 16 * r_sym
            )
            struct.pack_into("<I", sections[1], r_off, (resolved + add) & 0xFFFFFFFF)
        else:
            assert r_type == 28
            calls[T + r_off] = sym

    END = 0x7000FF00
    request = 0x70002000
    reply = 0x70003000
    extent = 0x70001000
    unit_index = 0x4BF
    serial = 24
    handle = (unit_index & 0x3FF) | ((unit_index >> 10) << 15) | (serial << 10)
    unit = BSS + 0x94678 + unit_index * 0x150 + 0xB20

    inputs = [
        ("one-owner-one-open", 1, 1, 0, 2, 2, serial, 0),
        ("remaining-open", 1, 2, 0, 2, 2, serial, 0),
        ("remaining-allocation-owner", 2, 2, 0, 2, 2, serial, 0),
        ("rendezvous-retained", 1, 1, 1, 2, 2, serial, 0),
        ("stale-serial", 1, 1, 0, 2, 2, serial - 1, 0),
        ("unsupported-subtype", 1, 1, 0, 2, 1, serial, 0),
        ("already-closed", 1, 0, 0, 1, 2, serial, 0),
        ("extent-free-error-recycle-success", 1, 1, 0, 2, 2, serial, -1),
        ("extent-free-error-retained", 1, 1, 0, 2, 2, serial, -1),
    ]

    expected_map = {
        "one-owner-one-open": (0, 1, 0, 0),
        "remaining-open": (3, 1, 0, 0),
        "remaining-allocation-owner": (0, 0, 1, 1),
        "rendezvous-retained": (0, 0, 0, 0),
        "stale-serial": (-5, 0, 1, 1),
        "unsupported-subtype": (-4, 0, 1, 1),
        "already-closed": (0, 1, 0, 0),
        "extent-free-error-recycle-success": (0, 1, 0, 0),
        "extent-free-error-retained": (-1, 1, 0, 0),
    }

    for name, alloc, opened, rdv, status, subtype, storedserial, extentrc in inputs:
        u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        for i, blob in sections.items():
            u.mem_map(bases[i], (len(blob) + 4095) & ~4095)
            u.mem_write(bases[i], bytes(blob))
        u.mem_map(0x70000000, 65536)
        u.mem_write(unit, struct.pack("<4BHH", alloc, opened, rdv, storedserial, status, 1))
        u.mem_write(unit - 8, struct.pack("<I", 0x36B))
        u.mem_write(unit + 8, struct.pack("<I", extent))
        u.mem_write(extent + 16, struct.pack("<I", 2))
        req = bytearray(128)
        struct.pack_into("<I", req, 4, 0x006800F3)
        struct.pack_into("<2H", req, 12, 4, handle)
        struct.pack_into("<2H", req, 32, 0x1111, subtype)
        u.mem_write(request, bytes(req))
        events: list[str] = []
        ended: list[int] = []

        def ret_from_call(pc: int, value: int) -> None:
            u.reg_write(UC_ARM_REG_R0, value & 0xFFFFFFFF)
            u.reg_write(UC_ARM_REG_PC, pc + 4)

        def code(uc, pc, size, unused):
            r0 = uc.reg_read(UC_ARM_REG_R0)
            if pc == END:
                ended.append(r0)
                uc.emu_stop()
                return
            if pc == T + 0x848C:
                events.append("recycle-record-fixture")
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                return
            if pc not in calls:
                return
            sym = calls[pc]
            sname = sym["name"]
            if sname == "dmm_ext_ctrl_FreeExtent":
                assert r0 == extent
                events.append("free-extent-fixture")
                ret_from_call(pc, extentrc)
                return
            if sname == "dmm_ext_tbl_GetSsbiExtentCnt":
                ret_from_call(pc, 1 if name == "extent-free-error-retained" else 0)
                return
            if sname == "dmm_ext_tbl_GetSsbiExtentUnitType":
                ret_from_call(pc, 0x36B)
                return
            if sname in ("dmm_upm_SetCodecDdrPowerSave", "dmm_unit_ctrl_SetUnitAccInfo"):
                events.append(sname + "-fixture")
                ret_from_call(pc, 0)
                return
            assert sname in ("dmm_unit_ctrl_Close", "dmm_unit_ctrl_Free"), (hex(pc), sname)
            events.append(sname)
            uc.reg_write(UC_ARM_REG_LR, pc + 4)
            uc.reg_write(UC_ARM_REG_PC, bases[sym["st_shndx"]] + sym["st_value"])

        u.hook_add(UC_HOOK_CODE, code)
        u.reg_write(UC_ARM_REG_SP, 0x7000F000)
        u.reg_write(UC_ARM_REG_LR, END)
        u.reg_write(UC_ARM_REG_R0, request)
        u.reg_write(UC_ARM_REG_R1, reply)
        u.emu_start(T + named["dmm_ctrl_FreeUnitHdlr"]["st_value"], END + 4, count=10000)
        assert ended == [2], (name, events)
        response = bytes(u.mem_read(reply, 12))
        after = struct.unpack("<4BHH", u.mem_read(unit, 8))
        status_reply = struct.unpack_from("<h", response, 2)[0]
        assert struct.unpack_from("<H", response, 0)[0] == 0x8004
        assert struct.unpack_from("<H", response, 6)[0] == 0x1111
        assert (status_reply, events.count("free-extent-fixture"), after[0], after[1]) == expected_map[name]
        if name == "rendezvous-retained":
            assert after[2] == 1 and after[4] == 4

    print(json.dumps({"test": "dmm_kernel_free", "cases": len(inputs), "passed": True}))


if __name__ == "__main__":
    main()
