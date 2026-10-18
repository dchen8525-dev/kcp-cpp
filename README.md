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
| P0 | scaffolding, golden vectors, interop tools | in progress |
| P1 | crc32 / sha1 / pbkdf2 / entropy / snmp / bufferpool | pending |
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

`tools/golden` is a Go program that links the reference implementation
(`replace github.com/xtaci/kcp-go/v5 => D:/work/kcp-go`) and emits byte-level vectors into
`tools/golden/out/`. C++ tests compare against those files; a mismatch means a porting bug, never a
vector bug. Regenerate with:

```bat
cd tools\golden && gen.bat
```

`tools/interop` holds the Go echo server/client used for cross-language acceptance (P7) and for the
Go<->Go throughput baseline that the C++ numbers are compared against (P6).

## Conventions

Google C++ Style with one recorded deviation (D8: 100-column limit). Files are `.h` / `.cc`,
headers use `#define KCP_*_H_` guards (`#pragma once` is forbidden), and every ported file keeps the
upstream MIT header. Deviations from kcp-go behavior are listed in PORTING-PLAN.md §3.4.1 and must
be extended before adding a new one.
