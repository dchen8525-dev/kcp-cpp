# kcp-cpp

C++17 port of [xtaci/kcp-go](https://github.com/xtaci/kcp-go) v5: KCP ARQ core, FEC (Reed-Solomon),
block crypto (CFB variants + AES-GCM), and the UDP session/listener layer.

Goal: **wire-compatible** with kcp-go, zero third-party dependencies.

The porting plan (scope, wire formats, golden vectors, gates, deviations) lives in
[`PORTING-PLAN.md`](PORTING-PLAN.md). Every wire-format statement in that document carries a
kcp-go source line number; when code and plan disagree, the plan's line reference decides.

## Status

| Stage | Content | State |
|---|---|---|
| P0 | scaffolding, golden vectors, interop tools | **done** |
| P1 | crc32 / sha1 / pbkdf2 / entropy / snmp / bufferpool | in progress |
| P2 | AES (AES-NI + T-table), GCM, Salsa20, TEA/XTEA, CFB variants | pending |
| P3 | Reed-Solomon GF(2^8) | pending |
| P4 | FEC encoder/decoder | pending |
| P5 | KCP ARQ state machine | pending |
| P6 | UDP session + listener | pending |
| P7 | cross-language interop verification (Go <-> C++) | pending |

## Build

Windows (MSVC):

```bat
build.bat            rem Release
build.bat Debug
```

Linux (Ninja + GCC/Clang):

```sh
./build.sh           # Debug
./build.sh Release
```

## Golden vectors

`tools/golden` emits byte-level vectors from the reference implementation. The emitter lives in
`ref/golden_ref.go.txt` and is injected into the kcp-go package with `go test -overlay`, because the
FEC layer and the CFB initial vector are unexported; this keeps the reference checkout untouched.
C++ tests compare against the committed `out/*.json`; a mismatch means a porting bug, never a vector
bug. Regenerate with:

```bat
cd tools\golden && gen.bat
```

`tools/interop` holds the Go echo server/client used for cross-language acceptance (P7) and for the
Go<->Go throughput baseline that the C++ numbers are compared against (P6). Both endpoints bind
`127.0.0.1` by default, so the test matrix never needs a firewall rule.

## Build gates

`build.bat` runs, in order: configure, build, `check_guard.py` (Google `#define` guards, no
`#pragma once`), `check_format.py` (clang-format, Google + 100 columns), then `ctest`.

## Conventions

Google C++ Style with one recorded deviation (D8: 100-column limit). Files are `.h` / `.cc`,
headers use `#define KCP_*_H_` guards (`#pragma once` is forbidden), and every ported file keeps the
upstream MIT header. Deviations from kcp-go behavior are listed in PORTING-PLAN.md §3.4.1 and must
be extended before adding a new one.
