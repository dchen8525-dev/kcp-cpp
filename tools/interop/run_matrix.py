#!/usr/bin/env python3
"""Cross-language acceptance matrix for kcp-cpp (PORTING-PLAN.md P7).

Sixteen cells: 2 directions x 4 ciphers x 2 FEC settings.

  cpp->go : C++ client  -> Go server   (xtaci/kcp-go as the reference)
  go->cpp : Go client   -> C++ server

Each cell transfers 1 MiB, the server echoes it, and the client verifies the bytes it got back. One
echo therefore exercises both directions of every cell. The expected digest is computed here in
Python from the same payload rule the two clients use (`payload[i] = i*7 + 11`, see
examples/echo_client.cc and tools/interop/goclient), so a bug in both implementations cannot hide
behind a shared constant.

The cipher list covers the three implementation branches: none (no cipher), aes (16-byte CFB),
aes-gcm (AEAD) and salsa20 (stream cipher). TEA/XTEA (8-byte CFB) are a recorded gap - see the
coverage note in PORTING-PLAN.md P7.

Usage:
  python tools/interop/run_matrix.py                 # all 16 cells, 3 rounds each
  python tools/interop/run_matrix.py --rounds 1      # quick pass
  python tools/interop/run_matrix.py --out matrix.md

Exit code is 0 only when every cell passes every round.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import threading

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "interop"))
import dump_packet  # noqa: E402  (single definition of the capture format, shared with the decoder)
PAYLOAD_SIZE = 1 << 20
CIPHERS = ("none", "aes", "aes-gcm", "salsa20")
FECS = ((0, 0), (10, 3))
DIRECTIONS = (
    ("cpp->go", "cpp", "go"),
    ("go->cpp", "go", "cpp"),
)
RESULT_RE = re.compile(r"^RESULT\s+(.*)$")
KV_RE = re.compile(r"(\w+)=(\S+)")

# One port per cell. Reusing a port lets a server that has not finished dying serve the next cell
# with the previous cell's cipher, which looks exactly like a protocol bug.
_NEXT_PORT = [17000 + (os.getpid() % 2000)]


def expected_digest() -> str:
    """The digest both clients print, computed independently of either implementation."""
    payload = bytes(((i * 7) + 11) & 0xFF for i in range(PAYLOAD_SIZE))
    return hashlib.sha256(payload).hexdigest()


def locate(which: str) -> tuple[Path, Path]:
    suffix = ".exe" if os.name == "nt" else ""
    if which == "cpp":
        for base in (
            ROOT / "build/windows-x64/bin/Release",
            ROOT / "build/windows-x64/bin/Debug",
            ROOT / "build/linux-x64-release/bin",
            ROOT / "build/linux-x64/bin",
        ):
            server = base / f"echo_server{suffix}"
            client = base / f"echo_client{suffix}"
            if server.exists() and client.exists():
                return server, client
        raise SystemExit("run_matrix: build the C++ echo tools first (build.bat / build.sh)")

    base = ROOT / "build/gobin"
    server = base / f"goecho_server{suffix}"
    client = base / f"goecho_client{suffix}"
    if not (server.exists() and client.exists()):
        raise SystemExit(
            "run_matrix: build the Go tools first: (cd tools/interop && "
            f"go build -o ../../build/gobin/goecho_server{suffix} ./goserver && "
            f"go build -o ../../build/gobin/goecho_client{suffix} ./goclient)"
        )
    return server, client


def workload_args(crypt: str, data: int, parity: int) -> list[str]:
    # Explicit everywhere: kcp-go's defaults differ from the ported ones, so a matrix that leaned on
    # defaults would compare two different protocols.
    return [
        "-crypt",
        crypt,
        "-data",
        str(data),
        "-parity",
        str(parity),
        "-sndwnd",
        "32",
        "-rcvwnd",
        "32",
        "-mtu",
        "1400",
    ]


def start_server(path: Path, addr: str, args: list[str]) -> subprocess.Popen:
    proc = subprocess.Popen(
        [str(path), "-addr", addr, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    watchdog = threading.Timer(15.0, proc.kill)
    watchdog.start()
    try:
        while True:
            line = proc.stdout.readline()
            if line.startswith("READY"):
                return proc
            if not line or proc.poll() is not None:
                raise RuntimeError(f"server exited before READY")
    finally:
        watchdog.cancel()


def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()


def run_client(path: Path, addr: str, args: list[str], which: str) -> dict:
    command = [
        str(path),
        "-addr",
        addr,
        *args,
        "-bytes",
        str(PAYLOAD_SIZE),
        "-iters",
        "1",
        # Go parses this as time.Duration, C++ as milliseconds: "30s" vs "30000".
        "-timeout",
        "30s" if which == "go" else "30000",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        # A hung client fails this cell, not the whole matrix: the other 15 cells still deserve
        # their rounds, and the exit code is still non-zero through the cell verdict.
        return {"exit": -1, "output": f"{which} client timed out after 120s"}
    result: dict = {"exit": proc.returncode, "output": proc.stdout.strip()}
    for line in proc.stdout.splitlines():
        match = RESULT_RE.match(line.strip())
        if match:
            result.update(KV_RE.findall(match.group(1)))
    return result


def check(want: str, got: dict, which: str) -> str:
    """Returns an empty string on success, or a failure description."""
    if got.get("exit") != 0:
        return f"{which} client exit {got['exit']}: {got['output'][:200]}"
    if got.get("ok") != "1":
        return f"{which} client reported failure: {got['output'][:200]}"
    if got.get("sha256") != want:
        return f"{which} digest {got.get('sha256')} != expected {want}"
    if int(got.get("bytes", -1)) != PAYLOAD_SIZE:
        return f"{which} client counted {got.get('bytes')} of {PAYLOAD_SIZE} bytes"
    return ""


def captures_match(sent: Path, received: Path) -> str:
    """The sender's first datagram and the receiver's first datagram must be the same bytes."""
    try:
        _, len_sent, data_sent = dump_packet.load(sent)
        _, len_received, data_received = dump_packet.load(received)
    except SystemExit as exc:
        return str(exc)
    except OSError as exc:
        return f"capture unreadable: {exc}"
    if len_sent != len_received:
        return f"first datagram is {len_sent} bytes on the wire but {len_received} at the peer"
    if data_sent == data_received:
        return ""
    at = next(i for i in range(len_sent) if data_sent[i] != data_received[i])
    return f"first datagram differs at offset {at}: {data_sent[at]:02x} vs {data_received[at]:02x}"


def main() -> int:
    parser = argparse.ArgumentParser(description="kcp-cpp cross-language matrix (P7)")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--out", default="", help="also write a markdown table here")
    parser.add_argument(
        "--dump-dir",
        default="",
        help="capture the first datagram of both peers per cell and assert they are byte-identical",
    )
    args = parser.parse_args()
    if args.rounds < 1:
        # Zero rounds would mark every cell PASS without running a single client.
        parser.error("--rounds must be at least 1")

    want = expected_digest()
    tools = {"cpp": locate("cpp"), "go": locate("go")}
    print(f"expected sha256 of {PAYLOAD_SIZE} bytes: {want}")
    dump_dir = Path(args.dump_dir) if args.dump_dir else None
    if dump_dir is not None:
        dump_dir.mkdir(parents=True, exist_ok=True)
        print(f"per-cell first-datagram captures -> {dump_dir}")

    rows: list[tuple[str, str, str, bool, str]] = []
    failures = 0
    for label, server_impl, client_impl in DIRECTIONS:
        for crypt in CIPHERS:
            for data, parity in FECS:
                config = f"{crypt} fec={data}/{parity}"
                detail = ""
                ok = True
                for round_index in range(args.rounds):
                    _NEXT_PORT[0] += 1
                    addr = f"127.0.0.1:{_NEXT_PORT[0]}"
                    server_path = tools[server_impl][0]
                    client_path = tools[client_impl][1]
                    common = workload_args(crypt, data, parity)
                    server_args = list(common)
                    client_args = list(common)
                    server_capture = client_capture = None
                    if dump_dir is not None:
                        # '>' is not a legal filename character on Windows.
                        stem = f"{label.replace('->', '_to_')}_{crypt}_{data}_{parity}_r{round_index + 1}"
                        server_capture = dump_dir / f"{stem}_server.hex"
                        client_capture = dump_dir / f"{stem}_client.hex"
                        server_args += ["-dump-packet", str(server_capture)]
                        client_args += ["-dump-packet", str(client_capture)]
                    try:
                        server = start_server(server_path, addr, server_args)
                    except RuntimeError as exc:
                        ok, detail = False, f"round {round_index + 1}: {exc}"
                        break
                    try:
                        got = run_client(client_path, addr, client_args, client_impl)
                    finally:
                        stop_server(server)
                    problem = check(want, got, client_impl)
                    if not problem and client_capture is not None:
                        problem = captures_match(client_capture, server_capture)
                    if problem:
                        ok, detail = False, f"round {round_index + 1}: {problem}"
                        break
                    detail = f"{float(got['mbps']):.1f} MB/s"
                print(f"{label:8s} {config:16s} {'PASS' if ok else 'FAIL'}  {detail}", flush=True)
                if not ok:
                    failures += 1
                rows.append((label, config, f"{args.rounds}", ok, detail))

    if args.out:
        lines = [
            "# Cross-language matrix",
            "",
            f"1 MiB echo per cell, {args.rounds} round(s), digest verified against an independent "
            "Python computation of the payload.",
            "",
            "| direction | config | rounds | result | note |",
            "| --- | --- | --- | --- | --- |",
        ]
        for label, config, rounds, ok, detail in rows:
            lines.append(f"| {label} | {config} | {rounds} | {'PASS' if ok else 'FAIL'} | {detail} |")
        Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"written: {args.out}")

    total = len(rows)
    print(f"\n{total - failures}/{total} cells passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
