#!/usr/bin/env python3
"""Build zero-hook freestanding Linux 3.0.27 passive ABI canary (canary.ko)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "kernel-probes/rc-gateway"))
from elf_image import Elf32Rel  # noqa: E402

EXPECTED_VERMAGIC = b"vermagic=3.0.27_nl-rt106+ SMP preempt mod_unload ARMv7 "
EXPECTED_NLS_UTF8_SHA256 = "a864c392a246bca50425e8583b7b802439286fa12edb47df8351bfa83e50ef7c"


def build_canary_ko(output: Path, fw_root: Path | None = None, clang: str | None = None) -> dict:
    cc = clang or os.environ.get("CLANG") or "/usr/bin/clang"
    if not Path(cc).is_file():
        cc = shutil.which("clang") or "clang"
    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        cc,
        "--target=armv7-linux-gnueabi",
        "-march=armv7-a",
        "-marm",
        "-g0",
        "-ffreestanding",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-c",
        str(HERE / "canary.S"),
        "-o",
        str(output),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"canary.ko build failed:\n{res.stderr}")

    raw = output.read_bytes()
    e = Elf32Rel(raw)
    assert e.e_flags == 0x05000000
    modinfo = e.section_by_name(".modinfo")["data"]
    vm = [x for x in modinfo.split(b"\x00") if x.startswith(b"vermagic=")][0]
    assert vm == EXPECTED_VERMAGIC
    assert not e.has_section("__versions")

    fw_checked = False
    if fw_root is not None:
        orig_ko = fw_root / "nflasha15/export/kmod/nls_utf8.ko"
        orig_raw = orig_ko.read_bytes()
        assert hashlib.sha256(orig_raw).hexdigest() == EXPECTED_NLS_UTF8_SHA256
        orig_e = Elf32Rel(orig_raw)
        orig_tm = orig_e.section_by_name(".gnu.linkonce.this_module")
        assert orig_tm["sh_size"] == 0x13C and orig_tm["sh_flags"] == 3
        fw_checked = True

    return {
        "name": output.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "e_flags": hex(e.e_flags),
        "vermagic": vm.decode("ascii"),
        "fw_abi_verified": fw_checked,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fw-root", type=Path, default=os.environ.get("A7R3_FW_ROOT"))
    p.add_argument("--clang", help="Path to clang supporting --target=armv7-linux-gnueabi")
    args = p.parse_args()
    fw = Path(args.fw_root) if args.fw_root else None
    print(json.dumps(build_canary_ko(args.output, fw, args.clang), indent=2))


if __name__ == "__main__":
    main()
