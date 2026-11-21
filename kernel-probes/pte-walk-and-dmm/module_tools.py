#!/usr/bin/env python3
"""Offline ET_REL kernel module (.ko) symbol & relocation inspector."""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "kernel-probes/rc-gateway"))
from elf_image import Elf32Rel, SHT_NOBITS, SHT_REL  # noqa: E402


class Module:
    """Read-only inspector for extracted FW 3.10 Linux 3.0.27 .ko modules."""

    def __init__(self, name: str, fw_root: Path | str | None = None):
        root = Path(fw_root or os.environ["A7R3_FW_ROOT"])
        self.path = root / "nflasha15/export/kmod" / f"{name}.ko"
        self.name = name
        self.raw = self.path.read_bytes()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        self.elf = Elf32Rel(self.raw)
        self.symbols = self.elf.symbols
        self.named = {s["name"]: s for s in self.symbols if s["name"]}
        self.sections = {
            s["index"]: {
                "name": s["name"],
                "data": s["data"] if s["sh_type"] != SHT_NOBITS else bytes(s["sh_size"]),
                "size": s["sh_size"],
                "flags": s["sh_flags"],
            }
            for s in self.elf.sections
        }
        self.relocs: dict[tuple[int, int], tuple[int, int, int]] = {}
        for sec in self.elf.sections:
            if sec["sh_type"] == SHT_REL:
                for r_off, r_type, r_sym in self.elf.relocations(sec):
                    self.relocs[(sec["sh_info"], r_off)] = (r_off, r_type, r_sym)
