#!/usr/bin/env python3
"""Scan av-cam.bin Thumb literal-pool LDR + ADD PC PIC xrefs to Focus/4K strings."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
from pathlib import Path

BASE = 0x635C6000
AVCAM_SHA256 = "35e3ff3f931fa725928ab8c7493d4b9842e1f90c3fa7b90ab4e23274256dd800"
ASCII_RE = re.compile(rb"[ -~]{6,120}\x00")


def collect_target_strings(b: bytes) -> dict[int, str]:
    targets: dict[int, str] = {}
    for m in ASCII_RE.finditer(b):
        s = m.group(0)[:-1].decode("ascii", errors="ignore")
        if ("SET_FOCUS" in s or "SET_STEPFOCUS" in s or "CheckSetFocus" in s or "3840X2160" in s or "sfmc_dec_input_video" in s):
            targets[m.start()] = s
    return targets


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    p.add_argument("--output", type=Path, help="Optional JSON output path")
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")

    b = (Path(args.fw_root) / "nflasha3/export/av-cam.bin").read_bytes()
    assert hashlib.sha256(b).hexdigest() == AVCAM_SHA256
    targets = collect_target_strings(b)

    try:
        from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        cs.detail = True
    except ImportError:
        cs = None

    hits = []
    for at in range(0, 0x8B0000 - 64, 2):
        h = struct.unpack_from("<H", b, at)[0]
        lit = None
        if (h & 0xF800) == 0x4800:
            reg = (h >> 8) & 7
            lit = ((at + 4) & ~3) + ((h & 255) << 2)
        elif h == 0xF8DF:
            v2 = struct.unpack_from("<H", b, at + 2)[0]
            reg = v2 >> 12
            lit = ((at + 4) & ~3) + (v2 & 4095)
        if lit is None or lit + 4 > len(b):
            continue
        disp = struct.unpack_from("<i", b, lit)[0]
        for a in range(at + 2, at + 62, 2):
            q = struct.unpack_from("<H", b, a)[0]
            if (q & 0xFF78) != 0x4478 or ((q & 7) + ((q >> 4) & 8)) != reg:
                continue
            target = a + 4 + disp
            if target not in targets:
                continue
            if cs is not None:
                ins = list(cs.disasm(b[at : a + 2], BASE + at))
                if not ins or ins[-1].address != BASE + a:
                    continue
                rn = ins[0].operands[0].reg
                if any(rn in x.regs_access()[1] for x in ins[1:-1]):
                    continue
            hits.append(
                {
                    "load": hex(BASE + at),
                    "literal": hex(BASE + lit),
                    "add": hex(BASE + a),
                    "target": hex(BASE + target),
                    "string": targets[target],
                }
            )

    assert len(hits) > 0
    if args.output:
        args.output.write_text(json.dumps({"hits": hits}, indent=2) + "\n")
    print(json.dumps({"test": "native_xrefs", "hits": len(hits), "passed": True}))


if __name__ == "__main__":
    main()
