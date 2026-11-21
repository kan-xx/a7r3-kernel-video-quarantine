#!/usr/bin/env python3
"""Stub-free Unicorn verifier for IMX251 LC readout window model (0x635ca140)."""
from __future__ import annotations

import json
import struct

from fw_env import AVCAM_BASE as B, load_avcam, parse_fw_root
from test_mode19_candidates import run_mode_getparam, slot_bytes


def main() -> None:
    fw_root = parse_fw_root(__doc__)
    av_bytes = load_avcam(fw_root)
    cases = [
        (19, 15, "pal25", b"\xff" * 8),
        (19, 15, "ntsc_H700_V1716", slot_bytes(700, 1716)),
        (19, 15, "half_V_only_H700_V858_INVALID_window", slot_bytes(700, 858)),
        (19, 15, "arithmetic5994_H525_V1144", slot_bytes(525, 1144)),
        (19, 15, "model_boundary_H525_V1138", slot_bytes(525, 1138)),
        (19, 15, "model_overrun_H525_V1137", slot_bytes(525, 1137)),
        (19, 15, "cc_height_half_only_H525_V1118_INVALID_window", slot_bytes(525, 1118)),
        (76, 33, "pal25", b"\xff" * 8),
        (76, 33, "arithmetic5994_H770_V780", slot_bytes(770, 780, 0, 0, 0, 33)),
        (76, 33, "arithmetic60_H769_plus3over13_V780", slot_bytes(769, 780, 1, 13, 3, 33)),
        (76, 33, "model_boundary_H770_V744", slot_bytes(770, 744, 0, 0, 0, 33)),
        (76, 33, "model_overrun_H770_V743", slot_bytes(770, 743, 0, 0, 0, 33)),
        (76, 33, "arithmetic60_H320_plus160over187_V1870", slot_bytes(320, 1870, 1, 187, 160, 33)),
    ]

    rows = []
    for mode, idx, label, s in cases:
        r = run_mode_getparam(av_bytes, s, mode=mode, index=idx)
        out = r["output"]
        lc = struct.unpack_from("<8H2B", out, 0xDC)
        cs = av_bytes[0x63E13A00 + idx * 32 - B : 0x63E13A00 + (idx + 1) * 32 - B]
        cc = av_bytes[0x63E122A8 + idx * 76 - B : 0x63E122A8 + (idx + 1) * 76 - B]
        src_lc = av_bytes[0x63E3F59A + idx * 4 - B : 0x63E3F59A + (idx + 1) * 4 - B]
        mult = struct.unpack_from("<H", cs, 0x12)[0]
        n, d = cs[0x16:0x18]
        height = struct.unpack_from("<I", cc, 0x3C)[0]
        start = struct.unpack_from("<H", src_lc)[0] + sum(
            struct.unpack_from("<I", cc, k)[0] for k in (0x30, 0x34, 0x38)
        ) * n / d
        min_v = (start + height * n / d) / mult
        rows.append(
            {
                "mode": mode,
                "label": label,
                "spare_ticks": lc[0] - lc[1] - lc[2],
                "min_primary_V": min_v,
            }
        )

    assert next(r for r in rows if r["label"] == "arithmetic5994_H525_V1144")["spare_ticks"] == 22
    assert next(r for r in rows if r["label"] == "model_boundary_H525_V1138")["spare_ticks"] == 0
    assert next(r for r in rows if r["label"] == "half_V_only_H700_V858_INVALID_window")["spare_ticks"] < 0
    assert all(r["min_primary_V"] == 1138 for r in rows if r["mode"] == 19)
    assert next(r for r in rows if r["label"] == "arithmetic5994_H770_V780")["spare_ticks"] == 200
    assert next(r for r in rows if r["label"] == "model_overrun_H770_V743")["spare_ticks"] < 0

    print(json.dumps({"test": "readout_windows", "cases": len(rows), "passed": True}))


if __name__ == "__main__":
    main()
