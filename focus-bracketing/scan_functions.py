#!/usr/bin/env python3
"""Scan FW 3.10 userspace .so .dynsym tables for Focus & Movie candidate symbols."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

GROUPS = {
    "focus": re.compile(
        r"Focus.*(Drive|Move|Step|Position|Near|Far|Distance)|"
        r"(?:Drive|Move|Step|Position).*Focus|FocusBracket",
        re.I,
    ),
    "video": re.compile(
        r"Movie.*(Frame|Format|Rate|Size)|(?:Frame|Format|Rate|Size).*Movie|"
        r"4K|2160|Sensor.*(Mode|Rate)|Encoder.*(Mode|Rate)",
        re.I,
    ),
}


def iter_dynsym_funcs(raw: bytes):
    """Dependency-free ELF32 .dynsym STT_FUNC iterator."""
    if len(raw) < 52 or raw[:4] != b"\x7fELF" or raw[4] != 1 or raw[5] != 1:
        return
    e_shoff = struct.unpack_from("<I", raw, 32)[0]
    e_shentsize, e_shnum = struct.unpack_from("<HH", raw, 46)
    if e_shentsize != 40 or e_shoff + e_shnum * 40 > len(raw):
        return
    sections = [struct.unpack_from("<10I", raw, e_shoff + i * 40) for i in range(e_shnum)]
    for sh_type, sh_offset, sh_size, sh_link in (
        (s[1], s[4], s[5], s[6]) for s in sections
    ):
        if sh_type != 11 or sh_link >= len(sections):  # SHT_DYNSYM = 11
            continue
        str_off, str_sz = sections[sh_link][4], sections[sh_link][5]
        dynstr = raw[str_off : str_off + str_sz]
        symtab = raw[sh_offset : sh_offset + sh_size]
        for i in range(0, len(symtab), 16):
            st_name, st_value, st_size, st_info, _, st_shndx = struct.unpack_from(
                "<IIIBBH", symtab, i
            )
            if (st_info & 0xF) != 2 or st_shndx == 0:  # STT_FUNC = 2, !SHN_UNDEF
                continue
            end = dynstr.find(b"\x00", st_name)
            if end < 0:
                continue
            yield dynstr[st_name:end].decode("ascii", errors="replace"), st_value, st_size


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    p.add_argument("--output", type=Path, help="Optional JSON output path")
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")

    lib_dir = Path(args.fw_root) / "nflasha15/export/lib"
    out: dict[str, list[dict]] = {k: [] for k in GROUPS}
    for path in sorted(lib_dir.iterdir()):
        if not path.is_file() or path.name == "CautionConfig.so" or not path.name.endswith(".so"):
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        for sym_name, va, sz in iter_dynsym_funcs(raw):
            for key, pat in GROUPS.items():
                if pat.search(sym_name):
                    out[key].append({"library": path.name, "symbol": sym_name, "va": hex(va), "bytes": sz})

    cxxfilt = shutil.which("c++filt") or "/usr/bin/c++filt"
    if Path(cxxfilt).is_file():
        for rows in out.values():
            if rows:
                proc = subprocess.run(
                    [cxxfilt, "-n"],
                    input="\n".join(x["symbol"] for x in rows) + "\n",
                    capture_output=True,
                    text=True,
                )
                for row, dem in zip(rows, proc.stdout.splitlines()):
                    row["demangled"] = dem

    # Assert key reverse-engineered symbols in viewUnified2.so
    focus_syms = {r["va"] for r in out["focus"] if r["library"] == "viewUnified2.so"}
    assert "0x2e8ded" in focus_syms or "0x2e8dec" in focus_syms
    if args.output:
        args.output.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({"test": "scan_functions", "focus": len(out["focus"]), "video": len(out["video"]), "passed": True}))


if __name__ == "__main__":
    main()
