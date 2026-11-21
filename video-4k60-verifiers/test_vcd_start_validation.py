#!/usr/bin/env python3
"""Stub-free MIPS32 LE Unicorn verifier for VCD command-0x1e start validation."""
from __future__ import annotations

import json
import struct

from unicorn import (
    UC_ARCH_MIPS,
    UC_HOOK_CODE,
    UC_HOOK_MEM_WRITE,
    UC_MODE_LITTLE_ENDIAN,
    UC_MODE_MIPS32,
    Uc,
    UcError,
)
from unicorn.mips_const import (
    UC_MIPS_REG_A0,
    UC_MIPS_REG_A1,
    UC_MIPS_REG_A2,
    UC_MIPS_REG_A3,
    UC_MIPS_REG_GP,
    UC_MIPS_REG_PC,
    UC_MIPS_REG_RA,
    UC_MIPS_REG_SP,
    UC_MIPS_REG_V0,
)

from fw_env import load_vcd, parse_fw_root

VISIT = {
    0x800E3900: "command_table_dispatch",
    0x80116378: "encode_start_check",
    0x80118C98: "baseband_check",
    0x80118E98: "encoder_config_check",
    0x80119140: "avc_basic_check",
    0x80116994: "gop_relations_check",
}


def run_vcd_case(
    vcd_bytes: bytes,
    name: str,
    *,
    width: int = 3840,
    height: int = 2160,
    stride: int = 3840,
    level: int = 51,
    tick: int = 1001,
    timescale: int = 60000,
    slice_count: int = 1,
    channel: int = 0,
    extra: int = 0,
    codec: int = 1,
    baseband_alignment: int = 0,
    n: int = 30,
    expected: int | None = 0,
    entry: int = 0x800E3900,
    manager_state: int = 0,
    mailbox_group: int = 0,
) -> dict:
    u = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN)
    u.mem_map(0, 0x1000000)
    u.mem_write(0, vcd_bytes)
    u.mem_write(0x660000, struct.pack("<III", 0x10000000, 0, 0x10720000))

    bb = bytearray(128)
    struct.pack_into("<III", bb, 12, width, height, stride)
    u.mem_write(0x700000, bytes(bb))

    c = bytearray(448)
    c[0] = codec
    c[12] = 1
    struct.pack_into("<HH", c, 16, n, n)
    c[21] = slice_count
    c[23] = 100
    c[24] = level
    c[25] = 1
    struct.pack_into("<H", c, 54, tick)
    struct.pack_into("<I", c, 56, timescale)
    u.mem_write(0x701000, bytes(c))

    p = bytearray(64)
    p[0] = mailbox_group
    p[1] = 30
    p[4] = channel
    p[7] = 1
    p[8] = extra
    struct.pack_into("<II", p, 12, 0x10700000 + baseband_alignment, 0x10701000)
    u.mem_write(0x702000, bytes(p))

    if entry == 0x800DBC24:
        u.mem_map(0x1F044000, 0x1000)
        u.mem_write(0x666A9C, b"\x01")
        u.mem_write(0x667A28, b"\x01")
        u.mem_write(0x704000, struct.pack("<I", manager_state))
        u.reg_write(UC_MIPS_REG_A0, 0x80704000)
    else:
        u.reg_write(UC_MIPS_REG_A0, 0x80703000)

    u.reg_write(UC_MIPS_REG_A1, 0x80702000)
    u.reg_write(UC_MIPS_REG_SP, 0x809FF000)
    u.reg_write(UC_MIPS_REG_GP, 0x802F2920)
    u.reg_write(UC_MIPS_REG_RA, 0x80900000)

    visited: list[str] = []
    acks: list[dict] = []
    events: list[dict] = []

    def hook(uc, address, size, data):
        if address == 0x80006CEC:
            raise RuntimeError("Native assertion reached")
        if address in VISIT and VISIT[address] not in visited:
            visited.append(VISIT[address])
        if entry == 0x800DBC24 and address == 0x800DC2A4:
            events.append(
                {
                    "arguments": [
                        uc.reg_read(r)
                        for r in (UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3)
                    ],
                    "acks_already_written": len(acks),
                }
            )
            uc.reg_write(UC_MIPS_REG_V0, 0)
            uc.reg_write(UC_MIPS_REG_PC, uc.reg_read(UC_MIPS_REG_RA))

    def memory_write(uc, access, address, size, value, data):
        if (address & 0x1FFFF000) == 0x1F044000:
            acks.append(
                {
                    "address": hex(address),
                    "size": size,
                    "value": hex(value),
                    "native_pc": hex(uc.reg_read(UC_MIPS_REG_PC)),
                }
            )

    u.hook_add(UC_HOOK_CODE, hook)
    if entry == 0x800DBC24:
        u.hook_add(UC_HOOK_MEM_WRITE, memory_write, begin=0x1F044000, end=0x1F044FFF)

    try:
        u.emu_start(entry, 0x80900000, count=100000)
    except UcError as exc:
        raise RuntimeError((name, str(exc), hex(u.reg_read(UC_MIPS_REG_PC)), visited)) from exc

    assert u.reg_read(UC_MIPS_REG_PC) == 0x80900000
    result = u.reg_read(UC_MIPS_REG_V0)
    if expected is not None:
        assert result == expected, (name, hex(result), hex(expected))
    return {
        "name": name,
        "result": result,
        "mailbox_writes": acks,
        "async_notification_fixtures": events,
    }


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    vcd = load_vcd(fw_root)
    cases = []
    for hz, tick, scale in [("25", 1, 50), ("50", 1, 100), ("59.94", 1001, 120000), ("60", 1, 120)]:
        for level in (51, 52):
            cases.append(run_vcd_case(vcd, f"4k_{hz}_level_{level}", tick=tick, timescale=scale, level=level))
    cases.extend(
        [
            run_vcd_case(vcd, "level_byte_255_unchecked", level=255),
            run_vcd_case(vcd, "zero_timescale_unchecked", timescale=0),
            run_vcd_case(vcd, "width_4096_allowed", width=4096, stride=4096),
            run_vcd_case(vcd, "width_4098_rejected", width=4098, stride=4128, expected=0x3706),
            run_vcd_case(vcd, "odd_width_rejected", width=3839, expected=0x3706),
            run_vcd_case(vcd, "odd_height_rejected", height=2159, expected=0x3707),
            run_vcd_case(vcd, "short_stride_rejected", stride=3824, expected=0x3708),
            run_vcd_case(vcd, "slice_2_rejected", slice_count=2, expected=0x3845),
            run_vcd_case(vcd, "channel_16_rejected", channel=16, expected=0x3100),
            run_vcd_case(vcd, "extra_flag_2_rejected", extra=2, expected=0x3500),
            run_vcd_case(vcd, "unaligned_baseband_rejected", baseband_alignment=1, expected=0x3700),
            run_vcd_case(vcd, "codec_3_rejected", codec=3, expected=0x3801),
            run_vcd_case(vcd, "gop_n_0_rejected", n=0, expected=0x3842),
        ]
    )
    print(json.dumps({"test": "vcd_start_validation", "cases": len(cases), "passed": True}))


if __name__ == "__main__":
    main()
