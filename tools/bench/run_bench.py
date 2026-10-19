#!/usr/bin/env python3
"""Throughput baseline for kcp-cpp (PORTING-PLAN.md §6.3).

Runs the same echo workload through two implementations and reports throughput, round-trip time and
CPU time, so a shortfall is a number instead of an opinion:

  * cpp - examples/echo_server + examples/echo_client, the code under test
  * go  - tools/interop/goserver + goclient, i.e. xtaci/kcp-go itself

Both are driven with identical parameters (§6.3 / #68): conv=1, mtu=1400, no-delay(1,10,2,1),
snd/rcv window 32/32, same cipher and FEC tuple.

Usage:
  python tools/bench/run_bench.py                    # full matrix, 5 rounds
  python tools/bench/run_bench.py --rounds 1 --impl cpp # smoke the harness
  python tools/bench/run_bench.py --impl cpp         # only the C++ half

Writes bench.md at the repository root (the file README links to) and prints a summary.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = (
    ("none", 0, 0),
    ("aes-gcm", 10, 3),
    ("salsa20", 10, 3),
)
SCENARIOS = ("single", "concurrent")
CONCURRENCY = 10
RESULT_RE = re.compile(r"^RESULT\s+(.*)$")
KV_RE = re.compile(r"(\w+)=(\S+)")

# Every measurement gets its own port. Reusing one lets a server that has not finished dying serve
# the next cell with the previous cell's cipher, which looks exactly like a protocol bug.
_NEXT_PORT = [14000 + (os.getpid() % 2000)]


# ---------------------------------------------------------------------------------------------
# Process CPU time. Sampled from outside so both implementations are measured the same way.
# ---------------------------------------------------------------------------------------------


class CpuSampler:
    """Polls a process' kernel+user time until it exits and keeps the last successful reading."""

    def __init__(self, pid: int):
        self.pid = pid
        self.max_ms = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "CpuSampler":
        self._thread.start()
        return self

    def stop(self) -> float:
        self._stop.set()
        self._thread.join(timeout=1.0)
        return self.max_ms

    def _run(self) -> None:
        while not self._stop.is_set():
            value = _read_cpu_ms(self.pid)
            if value is None:
                return
            self.max_ms = max(self.max_ms, value)
            self._stop.wait(0.02)


if os.name == "nt":
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    def _read_cpu_ms(pid: int) -> float | None:
        handle = _KERNEL32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            creation = _FileTime()
            exit_time = _FileTime()
            kernel = _FileTime()
            user = _FileTime()
            ok = _KERNEL32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            )
            if not ok:
                return None
            total = ((kernel.high << 32) | kernel.low) + ((user.high << 32) | user.low)
            return total / 10000.0  # 100 ns ticks -> ms
        finally:
            _KERNEL32.CloseHandle(handle)

else:

    def _read_cpu_ms(pid: int) -> float | None:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
                fields = handle.read().split()
        except OSError:
            return None
        ticks = int(fields[13]) + int(fields[14])
        return ticks * 1000.0 / os.sysconf("SC_CLK_TCK")


# ---------------------------------------------------------------------------------------------
# Implementation drivers
# ---------------------------------------------------------------------------------------------


class Impl:
    def __init__(self, name: str, server: Path, client: Path):
        self.name = name
        self.server = server
        self.client = client


def locate(which: str) -> Impl:
    if which == "cpp":
        bases = [
            ROOT / "build/windows-x64/bin/Release",
            ROOT / "build/windows-x64/bin/Debug",
            ROOT / "build/linux-x64-release/bin",
            ROOT / "build/linux-x64/bin",
        ]
        suffix = ".exe" if os.name == "nt" else ""
        for base in bases:
            server = base / f"echo_server{suffix}"
            client = base / f"echo_client{suffix}"
            if server.exists() and client.exists():
                return Impl("cpp", server, client)
        raise SystemExit("run_bench: build the C++ echo tools first (build.bat / build.sh)")

    suffix = ".exe" if os.name == "nt" else ""
    base = ROOT / "build/gobin"
    server = base / f"goecho_server{suffix}"
    client = base / f"goecho_client{suffix}"
    if not (server.exists() and client.exists()):
        raise SystemExit(
            "run_bench: build the Go tools first: "
            "(cd tools/interop && go build -o ../../build/gobin/goecho_server"
            f"{suffix} ./goserver && go build -o ../../build/gobin/goecho_client{suffix} ./goclient)"
        )
    return Impl("go", server, client)


def workload_args(config: tuple[str, int, int]) -> list[str]:
    crypt, data, parity = config
    # §6.3 parameter tuple, passed explicitly so neither implementation's defaults leak in.
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


def start_server(impl: Impl, addr: str, config: tuple[str, int, int]) -> subprocess.Popen:
    proc = subprocess.Popen(
        [str(impl.server), "-addr", addr, *workload_args(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    # The READY line is the ready handshake. Without it the first client races the bind and the run
    # looks like a protocol stall: the client's window fills, every segment is retransmitted, and
    # nothing is ever received. A watchdog kills the server if it hangs before printing, otherwise
    # readline() below can block past the deadline.
    watchdog = threading.Timer(10.0, proc.kill)
    watchdog.start()
    try:
        while True:
            line = proc.stdout.readline()
            if line.startswith("READY"):
                return proc
            if not line or proc.poll() is not None:
                raise SystemExit(f"run_bench: {impl.name} server exited before READY")
    finally:
        watchdog.cancel()


def run_client(impl: Impl, addr: str, config: tuple[str, int, int], mb: int, iters: int) -> dict:
    args = [
        str(impl.client),
        "-addr",
        addr,
        *workload_args(config),
        "-bytes",
        str(mb * 1024 * 1024),
        "-iters",
        str(iters),
        # Go parses this as a time.Duration, C++ as milliseconds: "120s" vs "120000". Both peers get
        # an explicit value so neither falls back to a default that could expire mid-run.
        "-timeout",
        "120s" if impl.name == "go" else "120000",
    ]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    sampler = CpuSampler(proc.pid).start()
    try:
        out, _ = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        # Kill the client before unwinding: a leaked echo_client keeps the port and the CPU, and
        # the sampler thread outlives the process it was pricing.
        proc.kill()
        proc.wait()
        raise SystemExit(f"run_bench: {impl.name} client timed out after 300s")
    finally:
        cpu_ms = sampler.stop()
    result: dict = {"cpu_ms": cpu_ms}
    for line in out.splitlines():
        match = RESULT_RE.match(line.strip())
        if match:
            for key, value in KV_RE.findall(match.group(1)):
                result[key] = value
    if result.get("ok") != "1":
        raise SystemExit(f"run_bench: {impl.name} client failed: {out.strip()[:400]}")
    return result


def measure(impl: Impl, config: tuple[str, int, int], scenario: str, mb: int, iters: int) -> dict:
    _NEXT_PORT[0] += 1
    addr = f"127.0.0.1:{_NEXT_PORT[0]}"
    server = start_server(impl, addr, config)
    try:
        if scenario == "single":
            result = run_client(impl, addr, config, mb, iters)
            return {
                "mbps": float(result["mbps"]),
                "cpu_ms": result["cpu_ms"],
                "elapsed_ms": float(result["elapsed_ms"]),
                "srtt_ms": float(result.get("srtt_ms", 0.0)),
                "bytes": int(result["bytes"]),
            }

        results: list[dict] = []
        failures: list[str] = []
        threads: list[threading.Thread] = []
        lock = threading.Lock()

        def worker() -> None:
            try:
                value = run_client(impl, addr, config, mb, 1)
            except BaseException as exc:  # surfaced after the threads join, never swallowed
                with lock:
                    failures.append(str(exc))
                return
            with lock:
                results.append(value)

        start = time.time()
        for _ in range(CONCURRENCY):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        wall_ms = (time.time() - start) * 1000.0
        if failures:
            raise SystemExit(f"run_bench: {len(failures)}/{CONCURRENCY} clients failed: {failures[0]}")
        total_bytes = sum(int(r["bytes"]) for r in results)
        return {
            "mbps": total_bytes / (1024 * 1024) / (wall_ms / 1000.0),
            "cpu_ms": sum(r["cpu_ms"] for r in results),
            "elapsed_ms": wall_ms,
            "srtt_ms": statistics.median(float(r.get("srtt_ms", 0.0)) for r in results),
            "bytes": total_bytes,
        }
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


# ---------------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------------


def summarize(samples: list[dict]) -> dict:
    # Drop the first round: it carries page faults and the initial window ramp.
    used = samples[1:] if len(samples) > 1 else samples
    mbps = [s["mbps"] for s in used]
    cpu = [s["cpu_ms"] / max(s["elapsed_ms"], 1.0) * 100.0 for s in used]
    srtt = [s["srtt_ms"] for s in used]
    return {
        "mbps_median": statistics.median(mbps),
        "mbps_min": min(mbps),
        "mbps_max": max(mbps),
        "cpu_pct_median": statistics.median(cpu),
        "srtt_ms_median": statistics.median(srtt),
    }


def calibration() -> dict:
    """Engine-only, platform-only and AES-only numbers that explain the session result."""
    suffix = ".exe" if os.name == "nt" else ""
    bases = [
        ROOT / "build/windows-x64/bin/Release",
        ROOT / "build/linux-x64-release/bin",
    ]
    base = None
    pump = None
    for candidate in bases:
        path = candidate / f"kcp_pump{suffix}"
        if path.exists():
            base = candidate
            pump = path
            break
    if base is None or pump is None:
        return {}

    out: dict = {}
    result = subprocess.run([str(pump)], capture_output=True, text=True, timeout=120)
    # The line reads "kcp_pump: 40.0 MB in 0.019s = 2152.3 MB/s (mss=1376)" - mind the space
    # after '='; the engine number swings with CPU state (788-2152 MB/s observed), which is why it
    # is only used as an order-of-magnitude argument, never as a threshold.
    match = re.search(r"=\s*([\d.]+) MB/s", result.stdout)
    if match:
        out["kcp_engine_mbps"] = float(match.group(1))

    pingpong = base / f"udp_pingpong{suffix}"
    if pingpong.exists():
        result = subprocess.run([str(pingpong), "-rounds", "20000"], capture_output=True, text=True)
        match = re.search(r"rtt_us=([\d.]+)", result.stdout)
        if match:
            out["udp_rtt_us"] = float(match.group(1))

    # Per-syscall pricing. This is the number the P8 ordering rests on: sendto() costs an order of
    # magnitude more than WSASendTo() on Windows, and that is not a property of the datagram or of
    # the address, so it has to be measured rather than assumed.
    syscall_cost = base / f"syscall_cost{suffix}"
    if syscall_cost.exists():
        result = subprocess.run([str(syscall_cost)], capture_output=True, text=True, timeout=300)
        wanted = {"sendto_us", "sendto_deep_us", "wsa_send_to_null_ov_us", "connected_send_us",
                  "recv_ok_us", "recv_empty_us", "probe_ready_us", "probe_notready_us"}
        for line in result.stdout.splitlines():
            if not line.startswith(("SYSCALL", "SENDPATH")):
                continue
            for key, value in KV_RE.findall(line):
                if key in wanted:
                    out[key] = float(value)

    aes = base / f"aes_bench{suffix}"
    if aes.exists():
        result = subprocess.run(
            [str(aes), "-mb", "64", "-rounds", "3"], capture_output=True, text=True, timeout=300
        )
        for line in result.stdout.splitlines():
            for key, value in KV_RE.findall(line):
                if key.endswith("_mbps") or key.endswith("_ratio"):
                    out[key] = float(value)
    return out


def render_markdown(table: dict, calib: dict, rounds: int) -> str:
    lines = [
        "# Throughput baseline",
        "",
        "Generated by `tools/bench/run_bench.py` (PORTING-PLAN.md §6.3). Parameters are fixed and",
        "passed explicitly to both implementations: `crypt`/`fec` per row, mtu 1400, no-delay",
        "(1, 10, 2, 1), snd/rcv window 32/32, loopback on this machine.",
        "",
        f"Rounds per cell: {rounds} (first round dropped as warm-up), median reported with min/max.",
        "CPU is the client side only: the single-stream row is one client's share of a single core;",
        "the concurrent row sums all clients over wall time, so it can exceed 100%.",
        "",
        "## Session throughput",
        "",
        "| config | scenario | impl | MB/s (median) | min | max | CPU % | srtt ms |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for key, entries in table.items():
        config, scenario = key
        for impl in ("cpp", "go"):
            if impl not in entries:
                continue
            s = entries[impl]
            lines.append(
                f"| {config} | {scenario} | {impl} | {s['mbps_median']:.1f} | "
                f"{s['mbps_min']:.1f} | {s['mbps_max']:.1f} | "
                f"{s['cpu_pct_median']:.0f} | {s['srtt_ms_median']:.3f} |"
            )

    lines += [
        "",
        "## Ratio against the Go baseline",
        "",
        "| config | scenario | cpp / go |",
        "| --- | --- | --- |",
    ]
    for key, entries in table.items():
        if "cpp" in entries and "go" in entries:
            ratio = entries["cpp"]["mbps_median"] / entries["go"]["mbps_median"]
            lines.append(f"| {key[0]} | {key[1]} | {ratio:.2f}x |")

    if calib:
        lines += [
            "",
            "## Calibration (why the session numbers look the way they do)",
            "",
            "| measurement | value | meaning |",
            "| --- | --- | --- |",
        ]
        if "kcp_engine_mbps" in calib:
            lines.append(
                f"| KCP state machine, no I/O (`bench/kcp_pump`) | "
                f"{calib['kcp_engine_mbps']:.0f} MB/s | the protocol engine is not the limit "
                f"(order of magnitude only: it swings with CPU frequency, 0.8-2.2 GB/s observed) |"
            )
        if "udp_rtt_us" in calib:
            lines.append(
                f"| one cross-thread UDP round trip (`bench/udp_pingpong`) | "
                f"{calib['udp_rtt_us']:.1f} us | what one OS wake-up costs "
                f"({1e6 / calib['udp_rtt_us']:.0f} round trips/s unbatched); the session layer beats "
                f"this by draining a burst per wake |"
            )
        if "sendto_us" in calib:
            lines.append(
                f"| one datagram send, `sendto()` (`bench/syscall_cost`) | "
                f"{calib['sendto_us']:.1f} us wall | the call this port uses today; "
                f"`sendto_deep_us` {calib.get('sendto_deep_us', 0):.1f} us keeps a full receive "
                f"queue, i.e. the cost is not queue-related |"
            )
        if "wsa_send_to_null_ov_us" in calib:
            lines.append(
                f"| the same datagram via `WSASendTo` | "
                f"{calib['wsa_send_to_null_ov_us']:.1f} us | "
                f"{calib['sendto_us'] / calib['wsa_send_to_null_ov_us']:.1f}x cheaper with a null "
                f"OVERLAPPED (synchronous), so it is neither the async path nor the address "
                f"argument; `connected_send_us` "
                f"{calib.get('connected_send_us', 0):.1f} us agrees |"
            )
        if "recv_ok_us" in calib:
            lines.append(
                f"| one datagram receive, `recvfrom` | {calib['recv_ok_us']:.1f} us | "
                f"the read path is two orders of magnitude below the send path, which is why the "
                f"first P8 lever is on the send side |"
            )
        if "probe_ready_us" in calib:
            lines.append(
                f"| readiness probe the drain loop pays per datagram | "
                f"{calib['probe_ready_us']:.2f} us | `recv_empty_us` "
                f"{calib.get('recv_empty_us', 0):.2f} us is what a non-blocking recvfrom costs "
                f"instead, so replacing the probe is worth ~"
                f"{calib['probe_ready_us'] - calib.get('recv_empty_us', 0):.2f} us per datagram |"
            )
        if "cfb_ni_mbps" in calib:
            lines.append(
                f"| AES-CFB, AES-NI (`bench/aes_bench`) | {calib['cfb_ni_mbps']:.0f} MB/s | "
                f"{calib.get('cfb_ratio', 0):.2f}x the T-table path "
                f"({calib.get('cfb_table_mbps', 0):.0f} MB/s) |"
            )
        if "gcm_ni_mbps" in calib:
            lines.append(
                f"| AES-GCM, AES-NI (`bench/aes_bench`) | {calib['gcm_ni_mbps']:.0f} MB/s | "
                f"{calib.get('gcm_ratio', 0):.2f}x the T-table path "
                f"({calib.get('gcm_table_mbps', 0):.0f} MB/s) |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="kcp-cpp throughput baseline (§6.3)")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--mb", type=int, default=1, help="payload size per iteration")
    parser.add_argument("--iters", type=int, default=100, help="iterations for the single-stream case")
    parser.add_argument("--impl", choices=("cpp", "go", "both"), default="both")
    parser.add_argument("--out", default=str(ROOT / "bench.md"))
    parser.add_argument("--json", default="", help="also write the raw table here")
    args = parser.parse_args()
    if args.rounds < 1:
        # A zero-round run would summarize no samples: median([]) raises and every gate below it
        # never runs, which is a crash rather than a result - refuse it up front instead.
        parser.error("--rounds must be at least 1")

    impls = []
    if args.impl in ("cpp", "both"):
        impls.append(locate("cpp"))
    if args.impl in ("go", "both"):
        impls.append(locate("go"))

    table: dict = {}
    for config in CONFIGS:
        label = f"{config[0]} fec={config[1]}/{config[2]}"
        for scenario in SCENARIOS:
            key = (label, scenario)
            table[key] = {}
            for impl in impls:
                samples = []
                for round_index in range(args.rounds):
                    iters = args.iters if scenario == "single" else 1
                    sample = measure(impl, config, scenario, args.mb, iters)
                    samples.append(sample)
                    print(
                        f"  {label} {scenario} {impl.name} round {round_index + 1}: "
                        f"{sample['mbps']:.1f} MB/s cpu={sample['cpu_ms']:.0f}ms",
                        flush=True,
                    )
                table[key][impl.name] = summarize(samples)

    calib = calibration()
    markdown = render_markdown(table, calib, args.rounds)
    Path(args.out).write_text(markdown, encoding="utf-8")
    if args.json:
        # JSON keys must be strings; the table is keyed by (config, scenario) tuples.
        flat = {f"{config}|{scenario}": entries for (config, scenario), entries in table.items()}
        Path(args.json).write_text(json.dumps(flat, indent=2), encoding="utf-8")
    print()
    print(markdown)
    print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
