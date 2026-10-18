// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#ifndef KCP_INTERNAL_CONSTANTS_H_
#define KCP_INTERNAL_CONSTANTS_H_

#include <cstddef>
#include <cstdint>

namespace kcp {

// Wire and protocol constants from the reference implementation. Every value here carries the
// kcp-go source location in PORTING-PLAN.md §4.7; changing one without changing the plan is a bug.

// sess.go:77 - upper bound for a UDP packet, also the buffer pool granularity.
constexpr std::size_t kMtuLimit = 1500;

// sess.go:68,71,74 - CFB framing: random nonce + CRC32 + ciphertext.
constexpr std::size_t kNonceSize = 16;
constexpr std::size_t kCrcSize = 4;
constexpr std::size_t kCryptHeaderSize = kNonceSize + kCrcSize;

// sess.go:80 - conv field width; oob_max_size() = mtu - kConvSize.
constexpr std::size_t kConvSize = 4;

// sess.go:86 - post-processing queue depth. Full means drop, never block (#38).
constexpr std::size_t kDevBacklog = 2048;

// sess.go:91,698 - the value sess.go passes to fecEncoder.encode(); it decides whether a shard set
// is continuous enough to emit parity.
constexpr int kMaxFecEncodeLatencyMs = 500;

// sess.go:94 - token bucket burst base.
constexpr std::size_t kMaxBatchSize = 64;

// fec.go:51-52 - FEC header: seqid(4) + type(2), plus a 2-byte payload size.
constexpr std::size_t kFecHeaderSize = 6;
constexpr std::size_t kFecHeaderSizePlus2 = kFecHeaderSize + 2;

// fec.go:53-55 - FEC packet types, carried in the low 16 bits of the header.
constexpr std::uint16_t kTypeData = 0xf1;
constexpr std::uint16_t kTypeParity = 0xf2;
constexpr std::uint16_t kTypeOob = 0xf3;

// fec.go:58 - how many incomplete shard sets may exist before the oldest is discarded.
constexpr int kMaxShardSets = 3;

// crypt.go:50 - CFB feedback seed. Encrypting this with the session key produces the first
// feedback block; it is not itself transmitted.
constexpr std::uint8_t kInitialVector[16] = {167, 115, 79,  156, 18,  172, 27,  1,
                                             164, 21,  242, 193, 252, 120, 230, 107};

// crypt.go:51 - PBKDF2 salt for NewSimpleXORBlockCrypt (32 iterations, kMtuLimit bytes out).
constexpr char kSaltXor[] = "sH3CIVoF#rWLtJo6";

// kcp.go:58 - segment header size, conv included.
constexpr std::size_t kOverhead = 24;

// kcp.go:53 - default MTU, also the value the construction path passes to SetMtu.
constexpr int kMtuDef = 1400;

// crypt.go:273-277 - PBKDF2 parameters for the simple XOR cipher.
constexpr int kSimpleXorIterations = 32;

}  // namespace kcp

#endif  // KCP_INTERNAL_CONSTANTS_H_
