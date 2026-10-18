#!/usr/bin/env python3
"""Fold the P8.0 PROFILE line into us-per-datagram and check the books (PORTING-PLAN.md P8.0).

examples/echo_client -profile prints raw counters after RESULT. This script is the single place that
turns them into the decomposition table, because the same fold has to be applied to every
measurement - retyping the arithmetic per run is how two runs end up not comparable.

What it checks (the P8.0 gate, "the books must add up"):

  1. Closure: main + writer + read_thread + post_thread + update_cpu must account for the process
     CPU of the window within --tol (default 10%). wcall_cpu/rcall_cpu are NOT added: they are
     subsets of the writer/main threads that issued those calls.
  2. Syscall pricing, two tiers because the two failure modes are an order of magnitude apart:
     tx_us/tx_n within --syscall-tol (default 150%) of the bench/syscall_cost price is a FAIL
     (that is a lying counter: the wrong quantity got accumulated), and beyond 50% is a WARN.
     Exact agreement is impossible by construction - syscall_cost sends to a socket in its own
     process, while a session sends to a live peer in another process and pays the cross-process
     wake-up on top. That wake-up is ~1 us on an idle machine and grows past 2x when the peer is
     descheduled by concurrent load, which is a WARN, not a counter bug.
  3. Sanity: rx_n >= tx_n (an echo answers every datagram, sometimes with duplicates counted),
     and probe_n inside [rx_n - 2, rx_n] - ReadLoop probes *after* each receive to decide whether
     to keep draining, so the window's slack is exactly one close() race plus one EWOULDBLOCK.

Usage:
  # measure: starts a server, runs the client with -profile, folds and checks
  python tools/bench/profile_split.py                     # none fec=0/0, 100 MB, single stream
  python tools/bench/profile_split.py --config aes-gcm --mb 50 --rounds 3

  # re-fold saved output (server log, a file with RESULT/PROFILE lines, or stdin)
  python tools/bench/profile_split.py --fold run.log
  cat run.log | python tools/bench/profile_split.py --fold -

Prints a markdown fragment for PORTING-PLAN.md section 6.3.2 and exits non-zero when a gate fails,
so it can be wired into a build step.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE_RE = re.compile(r"^PROFILE\s+(.*)$")
RESULT_RE = re.compile(r"^RESULT\s+(.*)$")
KV_RE = re.compile(r"(\w+)=(\S+)")
CONFIGS = {
    "none": ("none", 0, 0),
    "aes-gcm": ("aes-gcm", 10, 3),
    "salsa20": ("salsa20", 10, 3),
}
# Server binary candidates, newest first. Mirrors run_bench.locate().
CPP_BASES = [
    ROOT / "build/windows-x64/bin/Release",
    ROOT / "build/windows-x64/bin/Debug",
    ROOT / "build/linux-x64-release/bin",
    ROOT / "build/linux-x64/bin",
]


def parse_kv(text: str) -> dict[str, str]:
    return dict(KV_RE.findall(text))


# ---------------------------------------------------------------------------------------------
# Fold
# ---------------------------------------------------------------------------------------------


def fold(profile: dict[str, str], result: dict[str, str] | None) -> dict[str, float]:
    """Raw counters -> per-datagram microseconds. Pure arithmetic; no I/O."""
    f = {key: float(value) for key, value in profile.items()}
    out_pkts = f["out_pkts"]
    if out_pkts <= 0:
        raise SystemExit("profile_split: out_pkts=0, nothing to divide by")

    def per(key: str, n: float = out_pkts) -> float:
        return f[key] / n

    # The five CPU buckets that partition the process. wcall/rcall are subsets of writer/main.
    cpu_buckets = {
        "main": f["main_cpu_us"],
        "writer": f["writer_cpu_us"],
        "read_thread": f["read_thread_cpu_us"],
        "post_thread": f["post_thread_cpu_us"],
        "update": f["update_cpu_us"],
    }
    cpu_sum = sum(cpu_buckets.values())
    return {
        "out_pkts": out_pkts,
        "span_us": f["span_us"],
        "wall_per_pkt": f["span_us"] / out_pkts,
        "proc_cpu_us": f["proc_cpu_us"],
        "cpu_sum_us": cpu_sum,
        "cpu_closure_pct": (cpu_sum - f["proc_cpu_us"]) / f["proc_cpu_us"] * 100.0,
        "cpu_per_pkt": f["proc_cpu_us"] / out_pkts,
        "main_per_pkt": cpu_buckets["main"] / out_pkts,
        "writer_per_pkt": cpu_buckets["writer"] / out_pkts,
        "read_thread_per_pkt": cpu_buckets["read_thread"] / out_pkts,
        "post_thread_per_pkt": cpu_buckets["post_thread"] / out_pkts,
        "update_per_pkt": cpu_buckets["update"] / out_pkts,
        "wcall_n": f["wcall_n"],
        "wcall_per_pkt": f["wcall_cpu_us"] / out_pkts,
        "rcall_n": f["rcall_n"],
        "rcall_per_pkt": f["rcall_cpu_us"] / out_pkts,
        "tx_n": f["tx_n"],
        "tx_us_per_call": f["tx_us"] / f["tx_n"] if f["tx_n"] else 0.0,
        "tx_per_pkt": f["tx_us"] / out_pkts,
        "rx_n": f["rx_n"],
        "rx_us_per_call": f["rx_us"] / f["rx_n"] if f["rx_n"] else 0.0,
        "rx_per_pkt": f["rx_us"] / out_pkts,
        "probe_n": f["probe_n"],
        "probe_us_per_call": f["probe_us"] / f["probe_n"] if f["probe_n"] else 0.0,
        "probe_per_pkt": f["probe_us"] / out_pkts,
        "wait_n": f["wait_n"],
        "wait_us_per_call": f["wait_us"] / f["wait_n"] if f["wait_n"] else 0.0,
        "wait_per_pkt": f["wait_us"] / out_pkts,
        "mbps": float(result["mbps"]) if result and "mbps" in result else 0.0,
    }


# ---------------------------------------------------------------------------------------------
# Measurement driver (server + client with -profile), same shape as run_bench.py
# ---------------------------------------------------------------------------------------------


def start_server(server: Path, addr: str, config: tuple[str, int, int]) -> subprocess.Popen:
    crypt, data, parity = config
    proc = subprocess.Popen(
        [
            str(server),
            "-addr", addr,
            "-crypt", crypt,
            "-data", str(data),
            "-parity", str(parity),
            "-sndwnd", "32",
            "-rcvwnd", "32",
            "-mtu", "1400",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    watchdog = threading.Timer(10.0, proc.kill)
    watchdog.start()
    try:
        while True:
            line = proc.stdout.readline()
            if line.startswith("READY"):
                return proc
            if not line or proc.poll() is not None:
                raise SystemExit(f"profile_split: server exited before READY: {line.strip()}")
    finally:
        watchdog.cancel()


def locate_server() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    for base in CPP_BASES:
        server = base / f"echo_server{suffix}"
        if server.exists():
            return server
    raise SystemExit("profile_split: build the C++ echo tools first (build.bat / build.sh)")


def locate_client() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    for base in CPP_BASES:
        client = base / f"echo_client{suffix}"
        if client.exists():
            return client
    raise SystemExit("profile_split: build the C++ echo tools first (build.bat / build.sh)")


def measure(config: tuple[str, int, int], mb: int, iters: int, port: int) -> tuple[dict, dict]:
    addr = f"127.0.0.1:{port}"
    server = start_server(locate_server(), addr, config)
    try:
        crypt, data, parity = config
        proc = subprocess.Popen(
            [
                str(locate_client()),
                "-addr", addr,
                "-crypt", crypt,
                "-data", str(data),
                "-parity", str(parity),
                "-sndwnd", "32",
                "-rcvwnd", "32",
                "-mtu", "1400",
                "-bytes", str(mb * 1024 * 1024),
                "-iters", str(iters),
                # echo_common parses timeout as milliseconds on every platform, unlike the Go
                # client which takes a duration string (run_bench.py passes "120s" only to Go).
                "-timeout", "120000",
                "-profile",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        out, _ = proc.communicate(timeout=300)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    profile = result = None
    for line in out.splitlines():
        match = PROFILE_RE.match(line.strip())
        if match:
            profile = parse_kv(match.group(1))
        match = RESULT_RE.match(line.strip())
        if match:
            result = parse_kv(match.group(1))
    if profile is None:
        raise SystemExit(f"profile_split: no PROFILE line in client output: {out.strip()[:400]}")
    if result is None or result.get("ok") != "1":
        raise SystemExit(f"profile_split: client failed: {out.strip()[:400]}")
    return profile, result


# ---------------------------------------------------------------------------------------------
# Syscall pricing cross-check (bench/syscall_cost)
# ---------------------------------------------------------------------------------------------


def syscall_prices() -> dict[str, float]:
    suffix = ".exe" if os.name == "nt" else ""
    tool = ROOT / f"build/windows-x64/bin/Release/syscall_cost{suffix}"
    if not tool.exists():
        tool = ROOT / f"build/windows-x64/bin/Debug/syscall_cost{suffix}"
    if not tool.exists():
        return {}
    proc = subprocess.run([str(tool)], capture_output=True, text=True, timeout=300)
    prices: dict[str, float] = {}
    wanted = {"sendto_us", "recv_ok_us", "probe_ready_us"}
    for line in proc.stdout.splitlines():
        if not line.startswith(("SYSCALL", "SENDPATH")):
            continue
        for key, value in KV_RE.findall(line):
            if key in wanted:
                prices[key] = float(value)
    return prices


# ---------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------


def render(f: dict[str, float], prices: dict[str, float], tol_pct: float,
           syscall_tol_pct: float) -> tuple[list[str], list[str]]:
    """Returns (markdown lines for section 6.3.2, gate verdicts)."""
    lines = [
        "",
        f"### P8.0 decomposition: {f['mbps']:.2f} MB/s, {f['out_pkts']:.0f} datagrams, "
        f"{f['wall_per_pkt']:.1f} us wall per datagram, {f['cpu_per_pkt']:.1f} us CPU per datagram",
        "",
        "| segment | us / datagram | share of CPU | note |",
        "| --- | --- | --- | --- |",
        f"| read thread (recv + decrypt + Input) | {f['read_thread_per_pkt']:.2f} | "
        f"{f['read_thread_per_pkt'] / f['cpu_per_pkt'] * 100:.0f}% | whole-thread CPU |",
        f"| post thread (FEC + CRC + encrypt + sendto) | {f['post_thread_per_pkt']:.2f} | "
        f"{f['post_thread_per_pkt'] / f['cpu_per_pkt'] * 100:.0f}% | whole-thread CPU |",
        f"| update callback (Kcp::Update + flush) | {f['update_per_pkt']:.2f} | "
        f"{f['update_per_pkt'] / f['cpu_per_pkt'] * 100:.0f}% | shared TimedSched, per call |",
        f"| writer (write -> Kcp::Send) | {f['writer_per_pkt']:.2f} | "
        f"{f['writer_per_pkt'] / f['cpu_per_pkt'] * 100:.0f}% | caller thread |",
        f"| reader (read + verify) | {f['main_per_pkt']:.2f} | "
        f"{f['main_per_pkt'] / f['cpu_per_pkt'] * 100:.0f}% | caller thread |",
        "",
        "| syscall | calls | us / call | us / datagram | syscall_cost price | verdict |",
        "| --- | --- | --- | --- | --- | --- |",
        f"| sendto | {f['tx_n']:.0f} | {f['tx_us_per_call']:.2f} | {f['tx_per_pkt']:.2f} | "
        f"{prices.get('sendto_us', float('nan')):.2f} | {_syscall_verdict(f['tx_us_per_call'], prices.get('sendto_us'), syscall_tol_pct)} |",
        f"| recvfrom | {f['rx_n']:.0f} | {f['rx_us_per_call']:.2f} | {f['rx_per_pkt']:.2f} | "
        f"{prices.get('recv_ok_us', float('nan')):.2f} | {_syscall_verdict(f['rx_us_per_call'], prices.get('recv_ok_us'), syscall_tol_pct)} |",
        f"| select(0) probe | {f['probe_n']:.0f} | {f['probe_us_per_call']:.2f} | "
        f"{f['probe_per_pkt']:.2f} | {prices.get('probe_ready_us', float('nan')):.2f} | "
        f"{_syscall_verdict(f['probe_us_per_call'], prices.get('probe_ready_us'), syscall_tol_pct)} |",
        f"| select(50 ms) wait | {f['wait_n']:.0f} | {f['wait_us_per_call']:.2f} | "
        f"{f['wait_per_pkt']:.2f} | - | idle, not work |",
        "",
        "In-session prices include the cross-process wake-up a same-process microbench cannot show",
        f"(observed: sendto ~+40% idle, ~+100% under load; probe ~+45%); the gate warns past 50% and",
        f"fails past {syscall_tol_pct:.0f}%, where a lying counter would sit at 10x.",
        "",
        f"CPU closure: buckets {f['cpu_sum_us'] / 1000:.1f} ms vs process "
        f"{f['proc_cpu_us'] / 1000:.1f} ms -> {f['cpu_closure_pct']:+.1f}% "
        f"(tolerance {tol_pct:.0f}%).",
    ]
    verdicts: list[str] = []
    if abs(f["cpu_closure_pct"]) > tol_pct:
        verdicts.append(
            f"CLOSURE FAIL: buckets are {f['cpu_closure_pct']:+.1f}% off process CPU "
            f"(tolerance {tol_pct:.0f}%)"
        )
    else:
        verdicts.append(f"closure ok ({f['cpu_closure_pct']:+.1f}%)")
    if f["rx_n"] < f["tx_n"]:
        verdicts.append(
            f"SANITY FAIL: rx_n {f['rx_n']:.0f} < tx_n {f['tx_n']:.0f} (echo must answer every datagram)"
        )
    if f["probe_n"] > f["rx_n"] or f["probe_n"] + 2 < f["rx_n"]:
        verdicts.append(
            f"SANITY FAIL: probe_n {f['probe_n']:.0f} vs rx_n {f['rx_n']:.0f} outside the drain "
            "pattern's [rx_n - 2, rx_n] (ReadLoop probes after each receive; the slack covers one "
            "close() race and one EWOULDBLOCK)"
        )
    for name, measured, price in (
        ("sendto", f["tx_us_per_call"], prices.get("sendto_us")),
        ("recvfrom", f["rx_us_per_call"], prices.get("recv_ok_us")),
        ("select(0)", f["probe_us_per_call"], prices.get("probe_ready_us")),
    ):
        verdict = _syscall_verdict(measured, price, syscall_tol_pct)
        if verdict.startswith("FAIL"):
            verdicts.append(f"PRICING FAIL: {name} {verdict}")
        elif verdict.startswith("warn"):
            verdicts.append(f"pricing warn: {name} {verdict} (cross-process peer, not a counter bug)")
    if not any(v.startswith(("CLOSURE", "SANITY", "PRICING")) and "FAIL" in v for v in verdicts):
        verdicts.append("all gates passed")
    return lines, verdicts


def _syscall_verdict(measured: float, price: float | None, fail_pct: float) -> str:
    """Two tiers: WARN past 50% (cross-process wake-up, grows under load), FAIL past fail_pct
    (default 150%): a counter that accumulated the wrong quantity lands at 10x, never at 2x."""
    if price is None or price <= 0:
        return "n/a (no syscall_cost)"
    drift = (measured - price) / price * 100.0
    if abs(drift) > fail_pct:
        return f"FAIL {drift:+.0f}% off"
    if abs(drift) > 50.0:
        return f"warn {drift:+.0f}% off"
    return f"ok ({drift:+.0f}%)"


# ---------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", choices=sorted(CONFIGS), default="none")
    parser.add_argument("--mb", type=int, default=100)
    parser.add_argument("--iters", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--port", type=int, default=15000)
    parser.add_argument("--tol", type=float, default=10.0, help="CPU closure tolerance, percent")
    parser.add_argument(
        "--syscall-tol",
        type=float,
        default=150.0,
        help="syscall pricing FAIL band, percent; in-session calls include cross-process wake-up "
        "that a same-process microbench cannot show (up to ~2x under load), so this separates "
        "lying counters from scheduling, it is not an equality check",
    )
    parser.add_argument(
        "--fold",
        metavar="FILE|-",
        help="re-fold saved output instead of measuring; '-' reads stdin",
    )
    args = parser.parse_args()

    prices = syscall_prices()
    if not prices:
        print("profile_split: warning: bench/syscall_cost not found, pricing check skipped")

    exit_code = 0
    for round_index in range(args.rounds):
        if args.fold:
            text = (
                sys.stdin.read()
                if args.fold == "-"
                else Path(args.fold).read_text(encoding="utf-8")
            )
            profile = result = None
            for line in text.splitlines():
                match = PROFILE_RE.match(line.strip())
                if match:
                    profile = parse_kv(match.group(1))
                match = RESULT_RE.match(line.strip())
                if match:
                    result = parse_kv(match.group(1))
            if profile is None:
                raise SystemExit("profile_split: no PROFILE line in folded input")
            # A fold file may hold several rounds; fold every PROFILE line it contains.
            profiles = [parse_kv(m.group(1)) for m in PROFILE_RE.finditer(text)]
            results = [parse_kv(m.group(1)) for m in RESULT_RE.finditer(text)]
        else:
            profiles, results = [], []

        if not profiles and args.fold:
            profiles, results = [profile], [result]
        if not args.fold:
            profile, result = measure(CONFIGS[args.config], args.mb, args.iters,
                                      args.port + round_index)
            profiles, results = [profile], [result]

        for index, profile in enumerate(profiles):
            result = results[index] if index < len(results) else None
            f = fold(profile, result)
            lines, verdicts = render(f, prices, args.tol, args.syscall_tol)
            print("\n".join(lines))
            for verdict in verdicts:
                print(f"  gate: {verdict}")
                if "FAIL" in verdict:
                    exit_code = 1
            if args.rounds > 1:
                print(f"  (round {round_index + 1}/{args.rounds}, sample {index + 1})")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
