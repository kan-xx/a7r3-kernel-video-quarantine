#!/usr/bin/env python3
"""Offline build & relocation unit test for freestanding .ko probes & ARMv7 gates."""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "kernel-probes/rc-gateway"))
sys.path.insert(0, str(REPO / "kernel-probes/canary"))

import build as canary_build  # noqa: E402
import decode as rcgate_decode  # noqa: E402
from elf_image import Elf32Rel, SHN_UNDEF, load_ko_image  # noqa: E402


def find_arm_clang() -> str:
    cand = os.environ.get("CLANG") or ("/usr/bin/clang" if Path("/usr/bin/clang").is_file() else shutil.which("clang"))
    if not cand:
        raise FileNotFoundError("clang not found")
    return cand


def main() -> None:
    cc = find_arm_clang()
    checks = 0

    def ck(cond: bool, msg: str = "") -> None:
        nonlocal checks
        if not cond:
            raise AssertionError(msg or "check failed")
        checks += 1

    base_flags = [
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
        "-Wall",
        "-Wextra",
        "-Werror",
    ]

    with tempfile.TemporaryDirectory(prefix="a7r3-kotest-") as tmp:
        t = Path(tmp)

        # 1. Build passive canary.ko and verify ABI invariants
        c_info = canary_build.build_canary_ko(t / "canary.ko", fw_root=None, clang=cc)
        ck(c_info["e_flags"] == "0x5000000")
        ck("3.0.27_nl-rt106+" in c_info["vermagic"])

        # 2. Build rcgate .ko and run pure-Python ET_REL relocation + layout audit
        rcgate_ko = t / "a7r3_rcgate_1101a.ko"
        subprocess.run(
            [*base_flags, "-c", str(REPO / "kernel-probes/rc-gateway/gateway.c"), "-o", str(rcgate_ko)],
            check=True,
        )
        mem, syms, layout = load_ko_image(
            rcgate_ko,
            expected_module_name="a7r3_rcgate_1101a",
            expected_globals={"rcgate_entry", "rcgate_body", "__this_module", "init_module", "rcgate_state"},
            state_section=".data.rcgate",
            expected_state_bytes=1584,
        )
        ck(layout["no_external_symbols"] is True and len(layout["relocations"]) >= 2)
        ck("rcgate_entry" in syms and "rcgate_state" in syms)

        # 3. Compile all additional RC / PIG .ko gateways to prove warning-free ARMv7 freestanding build
        for label, src in [
            ("rcdual", REPO / "kernel-probes/rc-gateway/rc-dual/gateway.c"),
            ("rchv", REPO / "kernel-probes/rc-gateway/rc-hv-input/gateway.c"),
            ("rchcy", REPO / "kernel-probes/rc-gateway/rc-h-cycle/gateway.c"),
            ("pig_gw", REPO / "kernel-probes/pig-coupling/gateway.c"),
            ("pig_tbl", REPO / "kernel-probes/pig-coupling/table_protocol.c"),
            ("pig_br", REPO / "kernel-probes/pig-coupling/pig_bridge.S"),
        ]:
            out_o = t / f"{label}.o"
            subprocess.run([*base_flags, "-I" + str(src.parent), "-c", str(src), "-o", str(out_o)], check=True)
            e = Elf32Rel(out_o.read_bytes())
            ck(e.e_flags == 0x05000000, label)

        # 4. Compile all C + ARMv7 .S fail-closed quarantine gates to verify syntax & ABI cleanliness
        gate_files = [
            *sorted((REPO / "quarantine-gates/vcd-bus-fence").glob("*.c")),
            *sorted((REPO / "quarantine-gates/vcd-bus-fence").glob("*.S")),
            *sorted((REPO / "quarantine-gates/producer-protocol").glob("*.c")),
            *sorted((REPO / "quarantine-gates/producer-protocol").glob("*.S")),
            *sorted((REPO / "quarantine-gates/source-reclaim").glob("*.c")),
            *sorted((REPO / "quarantine-gates/source-reclaim").glob("*.S")),
        ]
        for idx, gf in enumerate(gate_files):
            out_o = t / f"gate_{idx}_{gf.stem}.o"
            subprocess.run(
                [
                    cc,
                    "--target=armv7-linux-gnueabi",
                    "-march=armv7-a",
                    "-marm",
                    "-O2",
                    "-g0",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-pic",
                    "-fno-pie",
                    "-I" + str(gf.parent),
                    "-c",
                    str(gf),
                    "-o",
                    str(out_o),
                ],
                check=True,
            )
            e = Elf32Rel(out_o.read_bytes())
            ck(e.e_flags == 0x05000000, gf.name)

    # 5. Test rc-gateway decode.py on synthetic valid & malformed 1584-byte state images
    buf = bytearray(1584)
    struct.pack_into(
        "<12I",
        buf,
        0,
        0x52434731,  # magic "1GCR"
        1,           # abi
        32,          # capacity
        48,          # record_bytes
        2,           # phase = sealed
        2,           # reserved = 2
        0,           # contention = 0
        1,           # restore_result = restored
        0x64696ED4,  # target slot
        0x63D5F5E9,  # original callee
        0x5F080000,  # module gateway VA
        1,           # resident
    )
    for rec_idx in range(2):
        struct.pack_into(
            "<12I",
            buf,
            48 + rec_idx * 48,
            rec_idx + 1,
            0x64100000,
            0x64200000,
            0x64300000,
            0x64400000,
            5 + rec_idx * 3,
            0x63900000,
            0x63901001,
            0x63902001,
            0,
            1,
            0,
        )
    decoded = rcgate_decode.decode(bytes(buf))
    ck(decoded["phase"] == "sealed" and decoded["closed_record_set"] is True and len(decoded["records"]) == 2)

    bad = bytearray(buf)
    struct.pack_into("<I", bad, 40, 0x70000000)  # invalid gateway VA outside 0x5f000000..0x60000000
    try:
        rcgate_decode.decode(bytes(bad))
        raise AssertionError("Expected decoder rejection of out-of-range gateway VA")
    except ValueError:
        checks += 1

    print(
        json.dumps(
            {
                "passed": True,
                "test": "ko_builder_and_gates",
                "quarantine_gate_units_compiled": len(gate_files),
                "checks": checks,
            }
        )
    )


if __name__ == "__main__":
    main()
