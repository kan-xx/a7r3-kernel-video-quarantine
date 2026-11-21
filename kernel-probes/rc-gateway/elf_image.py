#!/usr/bin/env python3
"""Dependency-free ARMv7 ET_REL (.ko) loader, relocation engine & ABI verifier."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

SHT_NOBITS = 8
SHT_REL = 9
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
STB_GLOBAL = 1


def sxt(v: int, bits: int) -> int:
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


class Elf32Rel:
    """Minimal pure-Python 32-bit little-endian ARM ET_REL parser."""

    def __init__(self, raw: bytes):
        self.raw = bytes(raw)
        if len(self.raw) < 52 or self.raw[:4] != b"\x7fELF" or self.raw[4] != 1 or self.raw[5] != 1:
            raise ValueError("Expected 32-bit little-endian ELF")
        (
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = struct.unpack_from("<HHIIIIIHHHHHH", self.raw, 16)
        if self.e_type != 1 or self.e_machine != 40:
            raise ValueError(f"Expected ET_REL EM_ARM, got type={self.e_type} machine={self.e_machine}")

        self.sections: list[dict] = []
        for i in range(self.e_shnum):
            (
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = struct.unpack_from("<10I", self.raw, self.e_shoff + i * 40)
            data = b"" if sh_type == SHT_NOBITS else self.raw[sh_offset : sh_offset + sh_size]
            self.sections.append(
                {
                    "index": i,
                    "sh_name_off": sh_name,
                    "sh_type": sh_type,
                    "sh_flags": sh_flags,
                    "sh_addr": sh_addr,
                    "sh_offset": sh_offset,
                    "sh_size": sh_size,
                    "sh_link": sh_link,
                    "sh_info": sh_info,
                    "sh_addralign": sh_addralign,
                    "sh_entsize": sh_entsize,
                    "data": data,
                    "name": "",
                }
            )
        shstr = self.sections[self.e_shstrndx]["data"]
        for s in self.sections:
            off = s["sh_name_off"]
            end = shstr.find(b"\x00", off)
            s["name"] = shstr[off:end].decode("ascii", errors="replace") if end >= 0 else ""

        sym_sec = self.section_by_name(".symtab")
        strtab = self.sections[sym_sec["sh_link"]]["data"]
        self.symbols: list[dict] = []
        sdata = sym_sec["data"]
        for i in range(0, len(sdata), 16):
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                "<IIIBBH", sdata, i
            )
            end = strtab.find(b"\x00", st_name)
            name = strtab[st_name:end].decode("ascii", errors="replace") if end >= 0 else ""
            self.symbols.append(
                {
                    "index": i // 16,
                    "name": name,
                    "st_value": st_value,
                    "st_size": st_size,
                    "st_info": st_info,
                    "bind": st_info >> 4,
                    "type": st_info & 0xF,
                    "st_shndx": st_shndx,
                }
            )

    def section_by_name(self, name: str) -> dict:
        for s in self.sections:
            if s["name"] == name:
                return s
        raise KeyError(f"Missing section: {name}")

    def has_section(self, name: str) -> bool:
        return any(s["name"] == name for s in self.sections)

    def relocations(self, sec: dict) -> list[tuple[int, int, int]]:
        if sec["sh_type"] != SHT_REL:
            return []
        data = sec["data"]
        out = []
        for i in range(0, len(data), 8):
            r_offset, r_info = struct.unpack_from("<II", data, i)
            out.append((r_offset, r_info & 0xFF, r_info >> 8))
        return out


def load_ko_image(
    ko_path: Path,
    *,
    base: int = 0x50000000,
    expected_module_name: str = "a7r3_rcgate_1101a",
    expected_globals: set[str] | None = None,
    state_section: str | None = ".data.rcgate",
    expected_state_bytes: int | None = 1584,
) -> tuple[bytes, dict[str, int], dict]:
    raw = ko_path.read_bytes()
    e = Elf32Rel(raw)
    if e.e_flags != 0x05000000:
        raise AssertionError(f"Expected original ARM EABI5 flags 0x05000000, got {e.e_flags:#x}")
    if not all(i == 0 or s["st_shndx"] != SHN_UNDEF for i, s in enumerate(e.symbols)):
        raise AssertionError("Freestanding .ko must have zero SHN_UNDEF external imports")
    if expected_globals is not None:
        got_globals = {s["name"] for s in e.symbols if s["bind"] == STB_GLOBAL}
        if got_globals != expected_globals:
            raise AssertionError(f"Global symbol mismatch: {got_globals} vs {expected_globals}")

    addrs: dict[int, int] = {}
    cursor = base
    mem = bytearray(0x10000)
    rels = []

    for s in e.sections:
        i = s["index"]
        if s["sh_flags"] & 0x2:  # SHF_ALLOC
            if (s["sh_flags"] & 0x1) and (s["sh_flags"] & 0x4):
                raise AssertionError(f"Forbidden RWX section: {s['name']}")
            align = max(s["sh_addralign"], 4)
            cursor = (cursor + align - 1) & ~(align - 1)
            addrs[i] = cursor
            sz = s["sh_size"]
            blob = bytes(sz) if s["sh_type"] == SHT_NOBITS else s["data"]
            mem[cursor - base : cursor - base + sz] = blob
            cursor += sz
    if cursor >= base + len(mem):
        raise AssertionError("Allocated module image exceeds 64 KiB test arena")

    def sym_addr(sym_idx: int) -> int:
        sym = e.symbols[sym_idx]
        shndx = sym["st_shndx"]
        if shndx == SHN_ABS:
            return sym["st_value"]
        if shndx not in addrs:
            raise AssertionError(f"Symbol {sym['name']} references non-alloc section {shndx}")
        return addrs[shndx] + sym["st_value"]

    for s in e.sections:
        if s["sh_type"] != SHT_REL or s["sh_info"] not in addrs:
            continue
        target_base = addrs[s["sh_info"]]
        for r_off, r_type, r_sym in e.relocations(s):
            p = target_base + r_off
            o = p - base
            word = struct.unpack_from("<I", mem, o)[0]
            v = sym_addr(r_sym)
            if r_type == 2:  # R_ARM_ABS32
                word = (word + v) & 0xFFFFFFFF
            elif r_type == 42:  # R_ARM_PREL31
                word = ((word + v - p) & 0x7FFFFFFF) | (word & 0x80000000)
            elif r_type in (43, 44):  # R_ARM_MOVW_ABS_NC / R_ARM_MOVT_ABS
                value = sxt(((word >> 4) & 0xF000) | (word & 0xFFF), 16) + v
                if r_type == 44:
                    value >>= 16
                word = (word & 0xFFF0F000) | ((value & 0xF000) << 4) | (value & 0xFFF)
            elif r_type == 28:  # R_ARM_CALL / R_ARM_JUMP24
                value = sxt(word & 0xFFFFFF, 24) * 4 + v - p
                assert value % 4 == 0 and -(1 << 25) <= value < (1 << 25)
                word = (word & 0xFF000000) | ((value >> 2) & 0xFFFFFF)
            else:
                raise AssertionError(f"Unexpected ARM relocation type: {r_type}")
            struct.pack_into("<I", mem, o, word)
            rels.append(
                {
                    "at": hex(p),
                    "type": r_type,
                    "symbol": e.symbols[r_sym]["name"],
                    "target": hex(v),
                }
            )

    names = {
        s["name"]: addrs[s["st_shndx"]] + s["st_value"]
        for s in e.symbols
        if s["st_shndx"] in addrs and s["name"]
    }
    this_mod = e.section_by_name(".gnu.linkonce.this_module")["data"]
    expect = bytearray(316)
    enc_name = expected_module_name.encode("ascii") + b"\x00"
    expect[12 : 12 + len(enc_name)] = enc_name
    if this_mod != bytes(expect):
        raise AssertionError(".gnu.linkonce.this_module header mismatch")
    if struct.unpack_from("<I", mem, names["__this_module"] - base + 188)[0] != names["init_module"]:
        raise AssertionError("__this_module.init relocation mismatch")

    if state_section is not None and expected_state_bytes is not None:
        if e.section_by_name(state_section)["sh_size"] != expected_state_bytes:
            raise AssertionError(f"Unexpected {state_section} size")

    layout = {
        "base": hex(base),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "symbols": {k: hex(v) for k, v in names.items() if not k.startswith("$")},
        "sections": [
            {
                "name": s["name"],
                "address": hex(addrs[s["index"]]),
                "size": s["sh_size"],
                "flags": s["sh_flags"],
            }
            for s in e.sections
            if s["index"] in addrs
        ],
        "relocations": rels,
        "no_external_symbols": True,
    }
    return bytes(mem), names, layout


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ko", type=Path, required=True, help="Path to freestanding ARMv7 .ko")
    p.add_argument("--module-name", default="a7r3_rcgate_1101a")
    args = p.parse_args()
    _, _, layout = load_ko_image(args.ko, expected_module_name=args.module_name)
    print(
        json.dumps(
            {
                "bytes": layout["bytes"],
                "sha256": layout["sha256"],
                "relocations": len(layout["relocations"]),
                "no_external_symbols": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
