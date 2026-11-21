#!/usr/bin/env python3
"""Run all real-firmware Unicorn stub-free verifiers (`A7R3_FW_ROOT=... make verify-fw`)."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")
    fw_root = Path(args.fw_root)
    if not fw_root.is_dir():
        raise FileNotFoundError(f"A7R3_FW_ROOT directory not found: {fw_root}")

    suites = [
        ("canary_fw_abi", [str(REPO / "kernel-probes/canary/build.py"), "--fw-root", str(fw_root)]),
        ("kernel_page_walk", [str(REPO / "kernel-probes/pte-walk-and-dmm/test_kernel_page_walk.py"), "--fw-root", str(fw_root)]),
        ("dmm_rpc", [str(REPO / "kernel-probes/pte-walk-and-dmm/test_dmm_rpc.py"), "--fw-root", str(fw_root)]),
        ("dmm_kernel_free", [str(REPO / "kernel-probes/pte-walk-and-dmm/test_kernel_free.py"), "--fw-root", str(fw_root)]),
        ("vcd_bus_fence", [str(REPO / "quarantine-gates/vcd-bus-fence/test_vcd_bus_fence.py"), "--fw-root", str(fw_root)]),
        ("original_tables", [str(REPO / "video-4k60-verifiers/test_original_tables.py"), "--fw-root", str(fw_root)]),
        ("encoder_buffer_lookup", [str(REPO / "video-4k60-verifiers/test_encoder_buffer_lookup.py"), "--fw-root", str(fw_root)]),
        ("mode19_candidates", [str(REPO / "video-4k60-verifiers/test_mode19_candidates.py"), "--fw-root", str(fw_root)]),
        ("readout_windows", [str(REPO / "video-4k60-verifiers/test_readout_windows.py"), "--fw-root", str(fw_root)]),
        ("restore_sequence", [str(REPO / "video-4k60-verifiers/test_restore_sequence.py"), "--fw-root", str(fw_root)]),
        ("irq11_counter", [str(REPO / "video-4k60-verifiers/test_irq11_counter.py"), "--fw-root", str(fw_root)]),
        ("native_semantics", [str(REPO / "video-4k60-verifiers/test_native_semantics.py"), "--fw-root", str(fw_root)]),
        ("vcd_start_validation", [str(REPO / "video-4k60-verifiers/test_vcd_start_validation.py"), "--fw-root", str(fw_root)]),
        ("vcd_command_ack", [str(REPO / "video-4k60-verifiers/test_vcd_command_ack.py"), "--fw-root", str(fw_root)]),
        ("focus_scan_functions", [str(REPO / "focus-bracketing/scan_functions.py"), "--fw-root", str(fw_root)]),
        ("focus_native_xrefs", [str(REPO / "focus-bracketing/native_xrefs.py"), "--fw-root", str(fw_root)]),
        ("original_focus", [str(REPO / "focus-bracketing/test_original_focus.py"), "--fw-root", str(fw_root)]),
    ]

    results = {}
    with tempfile.TemporaryDirectory(prefix="a7r3-quarantine-fw-") as tmp:
        t = Path(tmp)
        for name, cmd_args in suites:
            extra = ["--output", str(t / "canary.ko")] if name == "canary_fw_abi" else []
            res = subprocess.run(
                [sys.executable, *cmd_args, *extra],
                check=True,
                text=True,
                capture_output=True,
                env=dict(os.environ, A7R3_FW_ROOT=str(fw_root)),
            )
            parsed = json.loads(res.stdout.strip())
            results[name] = parsed
            print(f"  [PASS] {name}: {json.dumps(parsed)}")

    print(json.dumps({"passed": True, "verified_suites": len(results)}))


if __name__ == "__main__":
    main()
