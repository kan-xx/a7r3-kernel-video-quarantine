#!/usr/bin/env python3
"""Offline synthetic stream auditor test (true 60p vs 25p vs 29.97->59.94 frame doubling)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from audit_video_sample import audit  # noqa: E402


def main() -> None:
    rows = []
    with tempfile.TemporaryDirectory(prefix="a7r3-video-audit-") as tmp:
        d = Path(tmp)
        for name, source_rate, filter_, should_pass, duplicates in [
            ("true60", "60000/1001", None, True, False),
            ("stock25", "25", None, False, False),
            ("doubled30", "30000/1001", "fps=60000/1001", True, True),
        ]:
            path = d / f"{name}.mkv"
            cmd = [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                f"testsrc2=size=320x180:rate={source_rate}",
                "-t",
                "1",
            ]
            if filter_:
                cmd += ["-vf", filter_]
            subprocess.run(cmd + ["-c:v", "ffv1", str(path)], check=True, timeout=60)
            result = audit(path, width=320, height=180, seconds=1)
            assert result["file_timing_and_dimensions_pass"] == should_pass, (name, result["checks"])
            assert bool(result["adjacent_exact_repeats"]) == duplicates, (name, result["adjacent_exact_repeats"])
            assert result["full_camera_acceptance"] is False
            rows.append(
                {
                    "name": name,
                    "file_timing_pass": result["file_timing_and_dimensions_pass"],
                    "frames": result["decoded_frames"],
                    "exact_duplicates": result["adjacent_exact_repeats"],
                }
            )
    print(json.dumps({"passed": True, "test": "video_auditor", "cases": rows}))


if __name__ == "__main__":
    main()
