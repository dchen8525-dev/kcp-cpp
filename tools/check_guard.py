#!/usr/bin/env python3
"""Header-guard compliance check for kcp-cpp.

Google C++ Style requires:
  * no #pragma once
  * every header wraps its body in #define KCP_<PATH>_<FILE>_H_, where the name derives from the
    path relative to include/ (kcp/udp_session.h -> KCP_UDP_SESSION_H_).

Exit code 0 when every header complies, 1 otherwise. Runs in P0 and later gates.
"""

from __future__ import annotations

import sys
from pathlib import Path

INCLUDE_DIR = Path(__file__).resolve().parents[1] / "include"
# Guards are named after the path below include/kcp: kcp/platform/socket.h ->
# KCP_PLATFORM_SOCKET_H_ (the "KCP_" prefix already carries the namespace name).
GUARD_ROOT = INCLUDE_DIR / "kcp"


def strip_leading_comments(lines: list[str], start: int) -> int:
    """Returns the index of the first line that is neither blank nor comment-only."""
    i = start
    in_block = False
    while i < len(lines):
        line = lines[i].strip()
        if in_block:
            if "*/" in line:
                in_block = False
                line = line.split("*/", 1)[1].strip()
            else:
                i += 1
                continue
        if not line:
            i += 1
            continue
        if line.startswith("//"):
            i += 1
            continue
        if line.startswith("/*"):
            in_block = "*/" not in line
            i += 1
            continue
        return i
    return i


def expected_guard(header: Path) -> str:
    rel = header.relative_to(GUARD_ROOT).as_posix()
    return "KCP_" + rel.upper().replace("/", "_").replace(".", "_") + "_"


def main() -> int:
    headers = sorted(INCLUDE_DIR.rglob("*.h"))
    if not headers:
        print(f"check_guard: no headers found under {INCLUDE_DIR}", file=sys.stderr)
        return 1

    failures: list[str] = []
    for header in headers:
        rel = header.relative_to(INCLUDE_DIR.parent).as_posix()
        lines = header.read_text(encoding="utf-8").splitlines()

        for number, line in enumerate(lines, start=1):
            if line.strip().startswith("#pragma once"):
                failures.append(f"{rel}:{number}: #pragma once is forbidden, use #define guards")

        index = strip_leading_comments(lines, 0)
        if index >= len(lines):
            failures.append(f"{rel}: header has no content")
            continue
        want = expected_guard(header)
        first = lines[index].strip()
        second = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if first != f"#ifndef {want}":
            failures.append(f"{rel}:{index + 1}: expected '#ifndef {want}', got '{first}'")
        if second != f"#define {want}":
            failures.append(f"{rel}:{index + 2}: expected '#define {want}', got '{second}'")

        tail = "\n".join(lines[index + 2 :])
        if f"#endif  // {want}" not in tail:
            failures.append(f"{rel}: missing closing '#endif  // {want}'")

    if failures:
        print("check_guard: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"check_guard: OK ({len(headers)} headers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
