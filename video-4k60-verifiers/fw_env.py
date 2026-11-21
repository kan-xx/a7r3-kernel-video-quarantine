"""Shared read-only firmware resolver & pure-av-cam.bin IMX251 Unicorn setup."""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
from pathlib import Path

AVCAM_BASE = 0x635C6000
AVCAM_SHA256 = "35e3ff3f931fa725928ab8c7493d4b9842e1f90c3fa7b90ab4e23274256dd800"
VCD_SHA256 = "18b06ba859d7849c702b3d77c9e86c9141f29b70c0989aa036758dc8f1c09cb2"
VMLINUX_SHA256 = "4de22c8e052a1942aec48d5c1840e0550adefe9bd1a0ce59c50d472581e664c8"

RAM_BASE = 0x70000000
END_VA = 0x71000000
OVERRIDE_SLOT_VA = 0x6402F4E0

# Static C_ImagerParam_IMX251 table layout in FW 3.10 av-cam.bin (46 modes)
IMX251_PARAM_WORDS = (
    0x64692848,  # vtable (C_ImagerParam_IMX251)
    46,          # mode count
    0x63E11168,  # mode ID table
    1,           # initialized (PAL = 1)
    0x64200ED4,  # +0x10 CS mutable table (46 * 48 B)
    0x641FEFA4,  # +0x14 CC mutable table (46 * 120 B)
    0x6420057C,  # +0x18 EC mutable table (46 * 52 B)
    0x6460925A,  # +0x1c LC mutable table (46 * 18 B)
    0x63E11220,  # +0x20 ROM mode table
    0x63E3F902,  # +0x24 ROM table
    0x63E131D0,  # +0x28 ROM table
    0x63E3F59A,  # +0x2c ROM source LC table
    0x63E13A00,  # +0x30 ROM source CS table
    0x63E122A8,  # +0x34 ROM source CC table
    0x63E11390,  # +0x38 ROM primary timing descriptors
    0x63E117E0,  # +0x3c ROM secondary timing descriptors
    0x641FE64C,  # +0x40 ZAF-EC mutable table (46 * 52 B)
    0x64609596,  # +0x44 ZAF-LC mutable table (46 * 18 B)
    0x63E11C30,  # +0x48 ROM ZAF descriptors
    0,
)

# Stock FW 3.10 IMX251 72 MHz PLL / clock initialization struct (33 u32 words)
IMX251_INIT_WORDS = (
    0x10001, 3, 5, 3, 1, 0x1000, 0, 0, 0x15FC, 0, 1, 1, 2, 72, 1, 0,
    0, 2, 1, 0x10000001, 0x1000, 0, 1, 27, 72000000, 0x339DE67C, 13,
    0x0E16DB44, 0x10F1FA2A, 0x010A0383, 23, 0x140100, 0,
)

IMX251_TABLE_SPECS = (
    (0x10, 48),
    (0x14, 120),
    (0x18, 52),
    (0x1C, 18),
    (0x40, 52),
    (0x44, 18),
)


def parse_fw_root(description: str = "") -> Path:
    p = argparse.ArgumentParser(description=description)
    p.add_argument(
        "--fw-root",
        default=os.environ.get("A7R3_FW_ROOT"),
        help="Path to extracted A7R III FW 3.10 filesystems root (or set A7R3_FW_ROOT)",
    )
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")
    root = Path(args.fw_root)
    if not root.is_dir():
        raise FileNotFoundError(f"A7R3_FW_ROOT directory not found: {root}")
    return root


def load_avcam(fw_root: Path) -> bytes:
    raw = (fw_root / "nflasha3/export/av-cam.bin").read_bytes()
    if hashlib.sha256(raw).hexdigest() != AVCAM_SHA256:
        raise AssertionError("av-cam.bin SHA-256 mismatch")
    return raw


def load_vcd(fw_root: Path) -> bytes:
    raw = (fw_root / "nflasha15/export/codec/vcd_firmware.bin").read_bytes()
    if hashlib.sha256(raw).hexdigest() != VCD_SHA256:
        raise AssertionError("vcd_firmware.bin SHA-256 mismatch")
    return raw


def create_imx251_vm(av_bytes: bytes):
    """Create Unicorn Thumb+VFPv3 VM and natively initialize all 46 IMX251 modes."""
    from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc
    from unicorn.arm_const import (
        UC_ARM_REG_C1_C0_2,
        UC_ARM_REG_FPEXC,
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R2,
        UC_ARM_REG_SP,
    )

    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.mem_map(AVCAM_BASE, (len(av_bytes) + 4095) & ~4095)
    u.mem_write(AVCAM_BASE, av_bytes)
    u.mem_map(RAM_BASE, 0x20000)
    u.mem_map(END_VA, 0x1000)
    u.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)
    u.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

    param_va = RAM_BASE
    init_va = RAM_BASE + 0x100
    ctrl_va = RAM_BASE + 0x1000
    u.mem_write(param_va, struct.pack("<20I", *IMX251_PARAM_WORDS))
    init_blob = struct.pack("<33I", *IMX251_INIT_WORDS)
    u.mem_write(init_va, init_blob)

    # Verify pre-relocated GOT slot for override singleton (0x6472d188 -> 0x6402f460)
    assert struct.unpack_from("<I", av_bytes, 0x6472D188 - AVCAM_BASE)[0] == 0x6402F460
    u.mem_write(OVERRIDE_SLOT_VA, b"\xff" * 16)

    # Execute native C_ImagerParam_IMX251::Initialize(param, sys=1 [PAL], init)
    for r, v in [
        (UC_ARM_REG_R0, param_va),
        (UC_ARM_REG_R1, 1),
        (UC_ARM_REG_R2, init_va),
        (UC_ARM_REG_SP, RAM_BASE + 0xF000),
        (UC_ARM_REG_LR, END_VA | 1),
    ]:
        u.reg_write(r, v)
    u.emu_start(0x63CD6D4B, END_VA, count=500000)
    assert u.reg_read(UC_ARM_REG_PC) == END_VA and u.reg_read(UC_ARM_REG_R0) == 0
    # Flush pre-hook JIT translation blocks so subsequent UC_HOOK_CODE sees every PC
    u.ctl_remove_cache(AVCAM_BASE, AVCAM_BASE + ((len(av_bytes) + 4095) & ~4095))

    ctrl = bytearray(0x400)
    struct.pack_into("<I", ctrl, 0x000, 0x64692730)  # C_ImagerCtrl_IMX251 vtable
    ctrl[0x124 : 0x124 + len(init_blob)] = init_blob
    struct.pack_into("<I", ctrl, 0x270, param_va)
    u.mem_write(ctrl_va, bytes(ctrl))
    return u, param_va, ctrl_va
