"""Software-PTE translation helper matching Linux 3.0.27 vmalloc_to_page."""
from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

KQ_PGD = 0x60104000
VMLINUX_SHA256 = "4de22c8e052a1942aec48d5c1840e0550adefe9bd1a0ce59c50d472581e664c8"


def kq_u32(pa: int, label: str) -> int:
    raise NotImplementedError("Override kq_u32(pa, label) in host/Unicorn test fixture")


def kq_verify_vmlinux_anchors(fw_root: Path | str | None = None) -> bytes:
    root = Path(fw_root or os.environ["A7R3_FW_ROOT"])
    vmlinux = (root / "nflasha3/export/vmlinux.bin").read_bytes()
    if os.environ.get("A7R3_SKIP_FW_SHA256") != "1":
        assert hashlib.sha256(vmlinux).hexdigest() == VMLINUX_SHA256
    # vmalloc_to_page at 0x601a267c loads literal 0x604c8ea8 (+24 -> init_mm.pgd = 0x604c8ecc)
    assert struct.unpack_from("<I", vmlinux, 0x601A26F4 - 0x60108000)[0] == 0x604C8EA8
    return vmlinux


def kq_translate(va: int, label: str) -> tuple[int, tuple[int, int, int, int]]:
    """Translate module vmalloc VA [0x5f000000, 0x60000000) via 2-level coarse PTE walk."""
    assert 0x5F000000 <= va < 0x60000000, "outside module vmalloc window"
    assert KQ_PGD == 0x60104000
    pmd_pa = KQ_PGD - 0x60000000 + (va >> 21) * 8
    pmd = kq_u32(pmd_pa, label + "-pmd")
    assert pmd & 3 == 1, "not a coarse page table"
    pte_pa = (pmd & ~0xFFF) + ((va >> 12) & 0x1FF) * 4
    pte = kq_u32(pte_pa, label + "-pte")
    assert pte & 1, "non-present Linux PTE"
    pa = (pte & ~0xFFF) + (va & 0xFFF)
    assert 0x00100000 <= pa < 0x18800000, "outside cached DDR0 System RAM"
    return pa, (pmd_pa, pmd, pte_pa, pte)
