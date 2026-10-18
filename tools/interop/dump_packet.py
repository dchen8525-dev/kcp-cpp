#!/usr/bin/env python3
"""Locate a cross-language mismatch by offset (PORTING-PLAN.md §6.1).

Reads the captures produced by `-dump-packet` on any of the four tools (examples/echo_* and
tools/interop/goecho_*) and either decodes one capture field by field against the §4 layout, or
diffs two captures of the same datagram and reports the first differing offset with context.

Why this exists: when a wire-format change breaks a cell of tools/interop/run_matrix.py, "timeout"
says nothing. The offset of the first differing byte maps directly onto a chapter of §4 - nonce,
CRC, FEC header, KCP segment - and the fix follows from the field name.

Capture format (both implementations emit it identically):

    KCPDUMP 1 dir=out len=36
    00000000 3c000000f1f10000...

Usage:
  python tools/interop/dump_packet.py --decode cpp_client.hex
  python tools/interop/dump_packet.py cpp_client.hex go_server.hex
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

# §4.2: the six layouts. The cipher header is what both sides must agree on before anything else.
CRYPT_HEADER = {
    "none": 0,
    "aes-cfb": 20,  # 16-byte nonce + 4-byte CRC32 (kCryptHeaderSize)
    "aes-gcm": 12,  # nonce only; the tag is appended at the end
}
FEC_HEADER_SIZE = 8
KCP_OVERHEAD = 24
FEC_TYPES = {0xF1: "data", 0xF2: "parity", 0xF3: "oob"}
KCP_CMDS = {81: "push", 82: "ack", 83: "wask", 84: "window"}


def load(path: Path) -> tuple[str, int, bytes]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("KCPDUMP"):
        raise SystemExit(f"dump_packet: {path} is not a capture (missing KCPDUMP header)")
    header = dict(part.split("=", 1) for part in lines[0].split()[2:])
    blob = bytearray()
    for line in lines[1:]:
        if not line.strip():
            continue
        offset, hexdigits = line.split(None, 1)
        if int(offset, 16) != len(blob):
            raise SystemExit(f"dump_packet: {path} has a gap at offset {offset}")
        blob.extend(bytes.fromhex(hexdigits))
    declared = int(header.get("len", -1))
    if declared != len(blob):
        raise SystemExit(f"dump_packet: {path} declares {declared} bytes but holds {len(blob)}")
    return header.get("dir", "?"), declared, bytes(blob)


def decode(direction: str, data: bytes) -> None:
    print(f"direction={direction} length={len(data)}")

    # The cipher header cannot be identified from the bytes alone - a 12-byte GCM nonce and a
    # 16-byte CFB nonce are both random - so all three interpretations are printed and the reader
    # picks the one matching the cipher the run was configured with. Which one applies:
    #
    #   20 bytes  a BlockCrypt is installed: aes, salsa20, tea, xtea, simplexor - and also "none",
    #             which is a BlockCrypt whose Encrypt is a no-op (kCryptHeaderSize stays 20, the
    #             nonce and CRC32 are still written). "none" is NOT the same as no crypt object.
    #   12 bytes  an AeadCrypt is installed (aes-gcm); the tag rides at the end of the datagram.
    #    0 bytes  no crypt object at all - kcp::Listen / kcp::Dial without options.
    print("\n-- first 20 bytes, as the §4.2 cipher header candidates --")
    print(f"  block/CFB (20): nonce={data[0:16].hex()} crc={data[16:20].hex()}")
    print(f"  AEAD/GCM  (12): nonce={data[0:12].hex()}")
    print(f"  no crypt   (0): the FEC header starts at offset 0")

    print("\n-- assuming a 20-byte block-cipher header --")
    walk(data, 20)
    print("\n-- assuming a 12-byte AEAD header --")
    walk(data, 12)
    print("\n-- assuming no cipher header --")
    walk(data, 0)
    print("\nNote: unless the run used no crypt object at all, the bytes after the cipher header are")
    print("ciphertext - only the header, the lengths and the FEC flag offset can be checked here.")


def walk(data: bytes, header: int) -> None:
    if len(data) < header + FEC_HEADER_SIZE + KCP_OVERHEAD:
        if len(data) < header + KCP_OVERHEAD:
            print("  too short to hold a segment")
            return
    body = data[header:]
    if len(body) < FEC_HEADER_SIZE + KCP_OVERHEAD:
        print("  no FEC header (raw segment)")
        segment(body, "  ")
        return

    (fec_flag,) = struct.unpack_from("<H", body, 4)
    kind = FEC_TYPES.get(fec_flag)
    if kind is None:
        print("  FEC flag at +4 is not f1/f2/f3 -> treated as a bare KCP segment")
        segment(body, "  ")
        return

    seqid, _, size = struct.unpack_from("<IHH", body, 0)
    print(f"  FEC  seqid={seqid} type={kind} size={size} (size covers this field and the segment)")
    rest = body[FEC_HEADER_SIZE:]
    if kind == "parity":
        print(f"  parity payload {len(rest)} bytes (no conv, no segment header)")
        return
    if kind == "oob":
        (conv,) = struct.unpack_from("<I", rest, 0)
        print(f"  OOB conv={conv} payload {len(rest) - 4} bytes")
        return
    segment(rest, "  ")


def segment(data: bytes, indent: str) -> None:
    if len(data) < KCP_OVERHEAD:
        print(f"{indent}segment truncated: {len(data)} bytes, need {KCP_OVERHEAD}")
        return
    conv, cmd, frg, wnd, ts, sn, una, length = struct.unpack_from("<IBBHIIII", data, 0)
    print(f"{indent}KCP  conv={conv} cmd={cmd}({KCP_CMDS.get(cmd, '?')}) frg={frg} wnd={wnd}")
    print(f"{indent}     ts={ts} sn={sn} una={una} len={length}")
    payload = data[KCP_OVERHEAD:]
    if len(payload) != length:
        print(f"{indent}     payload is {len(payload)} bytes but len says {length}")
    else:
        print(f"{indent}     payload {len(payload)} bytes OK")


def diff(path_a: Path, path_b: Path) -> int:
    dir_a, len_a, data_a = load(path_a)
    dir_b, len_b, data_b = load(path_b)
    print(f"{path_a.name}: dir={dir_a} len={len_a}")
    print(f"{path_b.name}: dir={dir_b} len={len_b}")
    if len_a != len_b:
        print(f"MISMATCH: lengths differ ({len_a} vs {len_b})")
        return 1
    if data_a == data_b:
        print("IDENTICAL: the two captures are the same bytes")
        return 0

    at = next(i for i in range(len_a) if data_a[i] != data_b[i])
    print(f"MISMATCH at offset {at} (0x{at:x}): {data_a[at]:02x} vs {data_b[at]:02x}")
    low = max(0, at - 32)
    high = min(len_a, at + 32)
    print(f"  context [{low}, {high}):")
    print(f"    {path_a.name}: {data_a[low:high].hex()}")
    print(f"    {path_b.name}: {data_b[low:high].hex()}")
    print(f"                     {' ' * (2 * (at - low))}^")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="decode or diff a -dump-packet capture (§6.1)")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--decode", action="store_true", help="field-by-field decode of the first file")
    args = parser.parse_args()

    if args.decode:
        direction, _, data = load(args.files[0])
        decode(direction, data)
        return 0
    if len(args.files) != 2:
        parser.error("give one file with --decode, or two files to diff")
    return diff(args.files[0], args.files[1])


if __name__ == "__main__":
    sys.exit(main())
