#!/usr/bin/env python3
"""Stub-free MIPS32 LE Unicorn verifier: VCD ACK precedes async error (0x800dbc24)."""
from __future__ import annotations

import json

from fw_env import load_vcd, parse_fw_root
from test_vcd_start_validation import run_vcd_case


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    vcd = load_vcd(fw_root)
    cases = 0
    for width, expected_ack in [(4098, 0x80003706), (3840, 0x80000000)]:
        for mailbox_group in range(4):
            r = run_vcd_case(
                vcd,
                f"route_w{width}_mb{mailbox_group}",
                width=width,
                stride=4128 if width > 4096 else 3840,
                level=52,
                tick=1001,
                timescale=120000,
                entry=0x800DBC24,
                manager_state=0,
                expected=None,
                mailbox_group=mailbox_group,
            )
            assert len(r["mailbox_writes"]) == 1
            assert int(r["mailbox_writes"][0]["value"], 16) == expected_ack
            assert r["mailbox_writes"][0]["native_pc"] == "0x800dc834"
            assert int(r["mailbox_writes"][0]["address"], 16) == 0x1F044020 + mailbox_group * 4
            if width == 3840:
                assert len(r["async_notification_fixtures"]) == 1
                assert r["async_notification_fixtures"][0]["acks_already_written"] == 1
                assert r["async_notification_fixtures"][0]["arguments"][2:] == [1, 0x2000]
            else:
                assert not r["async_notification_fixtures"]
            cases += 1

    print(json.dumps({"test": "vcd_command_ack", "cases": cases, "passed": True}))


if __name__ == "__main__":
    main()
