#!/usr/bin/env python3
"""Verify br_native_fence_only (LDREX/STREX + preempt_schedule + 0xf4001000 fence) in Unicorn."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from unicorn import (
    UC_ARCH_ARM,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MODE_ARM,
    Uc,
)
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_SP,
)

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "kernel-probes/rc-gateway"))
from elf_image import Elf32Rel, SHN_UNDEF  # noqa: E402

VMLINUX_SHA256 = "4de22c8e052a1942aec48d5c1840e0550adefe9bd1a0ce59c50d472581e664c8"
CB = 0x71000000
SB = 0x71001000
END = 0x7000FF00
CTX = 0x70002000
OUT = 0x70001000
SEM = 0x60802000
TASK = 0x70004000
KB = 0x60108000


def link_obj_text(obj_path: Path, base: int, ext_syms: dict[str, int]) -> tuple[bytes, dict[str, int]]:
    e = Elf32Rel(obj_path.read_bytes())
    text_sec = e.section_by_name(".text")
    text_idx = text_sec["index"]
    code = bytearray(text_sec["data"])
    if e.has_section(".rel.text"):
        for r_off, r_type, r_sym in e.relocations(e.section_by_name(".rel.text")):
            sym = e.symbols[r_sym]
            target = ext_syms.get(sym["name"])
            if target is None:
                assert sym["st_shndx"] != SHN_UNDEF
                target = base + sym["st_value"]
            if r_type == 28:
                disp = ((target - (base + r_off + 8)) >> 2) & 0xFFFFFF
                struct.pack_into("<I", code, r_off, 0xEB000000 | disp)
            elif r_type == 2:
                struct.pack_into("<I", code, r_off, target)
            else:
                raise AssertionError(f"Unexpected relocation type {r_type}")
    defined = {
        s["name"]: base + s["st_value"]
        for s in e.symbols
        if s["name"] and s["st_shndx"] == text_idx
    }
    return bytes(code), defined


def find_strex_va(code: bytes, base: int) -> int:
    for off in range(0, len(code), 4):
        w = struct.unpack_from("<I", code, off)[0]
        if (w & 0x0FF000F0) == 0x01800090:
            return base + off
    raise AssertionError("STREX instruction not found in sem_try_publish.o")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")

    vmlinux = (Path(args.fw_root) / "nflasha3/export/vmlinux.bin").read_bytes()
    if os.environ.get("A7R3_SKIP_FW_SHA256") != "1":
        assert hashlib.sha256(vmlinux).hexdigest() == VMLINUX_SHA256

    cc = os.environ.get("CLANG") or ("/usr/bin/clang" if Path("/usr/bin/clang").is_file() else shutil.which("clang"))
    assert cc, "clang is required"

    with tempfile.TemporaryDirectory(prefix="a7r3-busfence-") as tmp:
        t = Path(tmp)
        common = [
            cc,
            "--target=armv7-linux-gnueabi",
            "-march=armv7-a",
            "-mfpu=none",
            "-marm",
            "-O2",
            "-g0",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pic",
            "-fno-pie",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-c",
        ]
        subprocess.run([*common, str(HERE / "sem_try_publish.S"), "-o", str(t / "sem.o")], check=True)
        subprocess.run([*common, str(HERE / "native_bus_candidate.c"), "-o", str(t / "bus.o")], check=True)

        sc, ss = link_obj_text(t / "sem.o", SB, {"bb_native_preempt_schedule": 0x603B52AC})
        cc_bytes, csy = link_obj_text(t / "bus.o", CB, {"bb_sem_try_task_publish": ss["bb_sem_try_task_publish"]})
        strex_va = find_strex_va(sc, SB)

    def run(
        name: str,
        statuses=(0,),
        budget: int = 3,
        held: int = 0,
        lock: int = 0,
        flags: int = 0,
        lpj: int = 1024,
        expected_lpj: int | None = None,
        bad_owner: bool = False,
        bad_base: bool = False,
        phase: int = 0,
        change_after_acquire: bool = False,
        cas_fail: bool = False,
        schedule_returns: bool = True,
    ) -> dict:
        u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        u.mem_map(KB, (len(vmlinux) + 4095) & ~4095)
        u.mem_write(KB, vmlinux)
        for va, n in [
            (CB, 0x2000),
            (0x70000000, 0x10000),
            (SEM, 0x1000),
            (0x6466D000, 0x1000),
            (0xF4000000, 0x2000),
        ]:
            u.mem_map(va, n)
        u.mem_write(CB, cc_bytes)
        u.mem_write(SB, sc)

        def put(a: int, *vals: int) -> None:
            u.mem_write(a, struct.pack("<" + "I" * len(vals), *(x & 0xFFFFFFFF for x in vals)))

        def word(a: int) -> int:
            return struct.unpack("<I", u.mem_read(a, 4))[0]

        put(CTX, 0x64372450, SEM, budget, lpj if expected_lpj is None else expected_lpj)
        put(OUT, phase, 0, 0, 0, 0, 0)
        put(SEM, lock, held, 0, 0)
        put(0x6466D490, 0xF4000004 if bad_base else 0xF4000000)
        put(0x604B74E8, lpj)
        put(0x7000E000, flags, 0)
        put(0x7000E00C, TASK)
        put(TASK + 0x104, 1234)
        events = []
        polls = [0]
        changed = [False]

        def on_code(uc, pc, size, _):
            if pc == END:
                uc.emu_stop()
                return
            if pc == strex_va and cas_fail:
                uc.reg_write(UC_ARM_REG_R2, 1)
                uc.reg_write(UC_ARM_REG_PC, pc + 4)
                return
            if pc == 0x603B4DF0:
                assert word(0x7000E004) == 0x40000000 and not (uc.reg_read(UC_ARM_REG_CPSR) & 0x80)
                assert word(OUT + 16) == 1 and word(SEM + 4) == 1
                events.append("scheduler_core_fixture")
                if not schedule_returns:
                    uc.emu_stop()
                    return
                put(0x7000E000, 0)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                return
            if CB <= pc < CB + len(cc_bytes) and word(OUT + 16) == 1 and change_after_acquire and not changed[0]:
                put(0x604B74E8, lpj + 1)
                changed[0] = True
            assert (
                CB <= pc < CB + len(cc_bytes)
                or SB <= pc < SB + len(sc)
                or 0x6025799C <= pc <= 0x602579D8
                or 0x603B52AC <= pc <= 0x603B5310
            ), hex(pc)

        def on_read(uc, access, a, size, value, _):
            if a >= 0xF0000000:
                assert a == 0xF4001000 and size == 4
                v = statuses[min(polls[0], len(statuses) - 1)]
                polls[0] += 1
                put(a, v)
                events.append("simulated_status_read")

        def on_write(uc, access, a, size, value, _):
            if a >= 0xF0000000:
                assert a == 0xF4001004 and size == 4 and value == 0
                assert word(OUT + 16) == 1 and word(SEM + 4) == 1
                events.append("simulated_stop_request")

        u.hook_add(UC_HOOK_CODE, on_code)
        u.hook_add(UC_HOOK_MEM_READ, on_read)
        u.hook_add(UC_HOOK_MEM_WRITE, on_write)
        for reg, v in [
            (UC_ARM_REG_CPSR, 0x13),
            (UC_ARM_REG_R0, 0x64372458 + (4 if bad_owner else 0)),
            (UC_ARM_REG_R1, CTX),
            (UC_ARM_REG_R2, OUT),
            (UC_ARM_REG_SP, 0x7000F000),
            (UC_ARM_REG_LR, END),
        ]:
            u.reg_write(reg, v)
        u.emu_start(csy["br_native_fence_only"], END + 4, count=5000000)
        done = u.reg_read(UC_ARM_REG_PC) == END
        if done:
            assert u.reg_read(UC_ARM_REG_SP) == 0x7000F000 and word(0x7000E004) == 0
        return {
            "name": name,
            "returned": done,
            "result": u.reg_read(UC_ARM_REG_R0) if done else None,
            "fields": list(struct.unpack("<6I", u.mem_read(OUT, 24))),
            "sem": list(struct.unpack("<4I", u.mem_read(SEM, 16))),
            "events": events,
        }

    cases = [
        run("zero"),
        run("pending_then_zero", statuses=(0x170, 1, 0)),
        run("timeout", statuses=(1,)),
        run("zero_last_allowed", statuses=(1, 1, 0)),
        run("max_budget_timeout", statuses=(1,), budget=64),
        run("lease_busy", held=1),
        run("spinlock_busy", lock=0x80000013),
        run("exclusive_contention", cas_fail=True),
        run("bad_owner", bad_owner=True),
        run("bad_base", bad_base=True),
        run("bad_lpj", expected_lpj=2048),
        run("zero_budget", budget=0),
        run("excess_budget", budget=65),
        run("reentry", phase=4),
        run("binding_changes_after_acquire", change_after_acquire=True),
        run("native_schedule_then_poll", flags=2),
        run("native_scheduler_blocks", flags=2, schedule_returns=False),
        run("observed_old_epoch_lpj_delay", statuses=(1, 0), lpj=1757184),
    ]
    for c in cases:
        assert c["result"] != 1
        assert c["events"].count("simulated_stop_request") <= 1
        if c["fields"][4] == 1:
            assert c["sem"][1] == 1 and c["sem"][3] == 1234
    for i in (0, 1, 3, 15, 17):
        assert cases[i]["result"] == 2 and cases[i]["fields"][0] == 3
    for i in (2, 4):
        assert cases[i]["result"] == 0xFFFFFFFB and cases[i]["fields"][0] == 4
    for i in range(5, 15):
        assert not any(e.startswith("simulated") for e in cases[i]["events"])
    assert cases[14]["result"] == 0xFFFFFFFD and cases[14]["fields"][4] == 1
    assert not cases[16]["returned"] and cases[16]["fields"][4] == 1 and cases[16]["fields"][0] == 1

    print(json.dumps({"test": "vcd_bus_fence", "cases": len(cases), "passed": True}))


if __name__ == "__main__":
    main()
