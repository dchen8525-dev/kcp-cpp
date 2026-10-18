#!/usr/bin/env python3
"""clang-format compliance check for kcp-cpp (Google style + deviation D8: 100 columns).

Fails when any C++ source under include/, src/, tests/, examples/ or bench/ is not formatted. The
clang-format binary is taken from the CLANG_FORMAT environment variable, else from PATH.

Exit code 0 when everything is clean, 1 otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ("include", "src", "tests", "examples", "bench")
SUFFIXES = (".h", ".cc")


def find_clang_format() -> str | None:
    env = os.environ.get("CLANG_FORMAT")
    if env and Path(env).exists():
        return env
    return shutil.which("clang-format")


def main() -> int:
    binary = find_clang_format()
    if binary is None:
        print("check_format: clang-format not found (set CLANG_FORMAT or add it to PATH)",
              file=sys.stderr)
        return 1

    files: list[Path] = []
    for directory in SOURCE_DIRS:
        base = ROOT / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in SUFFIXES:
                files.append(path)

    if not files:
        print("check_format: no source files found", file=sys.stderr)
        return 1

    result = subprocess.run(
        [binary, "--dry-run", "--Werror", *[str(p) for p in files]],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("check_format: FAILED", file=sys.stderr)
        # clang-format reports one line per violation; cap the noise.
        lines = [line for line in result.stderr.splitlines() if line.strip()]
        for line in lines[:40]:
            print(f"  {line}", file=sys.stderr)
        if len(lines) > 40:
            print(f"  ... {len(lines) - 40} more", file=sys.stderr)
        print("  fix with: clang-format -i <files>", file=sys.stderr)
        return 1

    print(f"check_format: OK ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
