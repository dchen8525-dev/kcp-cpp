// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Tests for the process-wide singletons: the buffer pool and the SNMP counters. Both are shared by
// every session, so the invariants checked here (exact buffer size, rejected size mismatch, counter
// ordering matching the header names) are what keeps later stages from corrupting shared state.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "kcp/internal/bufferpool.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/rate_limiter.h"
#include "kcp/snmp.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

#define CHECK(expr)                    \
  do {                                 \
    if (!(expr)) {                     \
      Fail(__FILE__, __LINE__, #expr); \
    }                                  \
  } while (0)

void TestBufferPool() {
  using kcp::internal::BufferPool;

  BufferPool pool(kcp::kMtuLimit);
  CHECK(pool.buffer_size() == 1500);
  CHECK(pool.FreeCount() == 0);

  std::vector<std::uint8_t> first = pool.Get();
  CHECK(first.size() == kcp::kMtuLimit);
  CHECK(first.capacity() >= kcp::kMtuLimit);

  // A caller may shorten the buffer for a packet; Put resets it to the full size.
  first.resize(200);
  CHECK(pool.Put(std::move(first)));
  CHECK(pool.FreeCount() == 1);

  std::vector<std::uint8_t> second = pool.Get();
  CHECK(second.size() == kcp::kMtuLimit);
  CHECK(pool.FreeCount() == 0);
  CHECK(pool.Put(std::move(second)));

  // Wrong capacity must be rejected, mirroring errBufferSizeMismatch (bufferpool.go:60).
  std::vector<std::uint8_t> wrong(64);
  CHECK(!pool.Put(std::move(wrong)));

  // An oversized buffer is rejected too: accepting it would hand a bigger buffer to a caller that
  // assumes mtuLimit and let it write past the packet boundary.
  std::vector<std::uint8_t> oversized(kcp::kMtuLimit + 1);
  CHECK(!pool.Put(std::move(oversized)));

  CHECK(pool.FreeCount() == 1);

  // Buffers handed out concurrently must be distinct allocations.
  std::vector<std::uint8_t> a = pool.Get();
  std::vector<std::uint8_t> b = pool.Get();
  CHECK(a.data() != b.data());
  pool.Put(std::move(a));
  pool.Put(std::move(b));

  // The default pool is the 1500-byte one and is a single shared instance.
  CHECK(&kcp::internal::DefaultBufferPool() == &kcp::internal::DefaultBufferPool());
  CHECK(kcp::internal::DefaultBufferPool().buffer_size() == kcp::kMtuLimit);
}

void TestSnmp() {
  kcp::Snmp& snmp = kcp::DefaultSnmp();
  snmp.Reset();

  kcp::SnmpSnapshot zero = snmp.Snapshot();
  CHECK(zero.bytes_sent == 0);
  CHECK(zero.fec_recovered == 0);

  snmp.bytes_sent.fetch_add(123);
  snmp.fec_recovered.fetch_add(7);
  snmp.oob_packets.fetch_add(1);

  kcp::SnmpSnapshot snap = snmp.Snapshot();
  CHECK(snap.bytes_sent == 123);
  CHECK(snap.fec_recovered == 7);
  CHECK(snap.oob_packets == 1);
  CHECK(snap.bytes_received == 0);

  // HeaderNames and ToArray must describe the same counter in the same position. Spot-check the
  // two sequences that are easy to transpose (FECFullShardSet is labelled "FECFullShards")
  // (snmp.go:91).
  const char* const* names = kcp::Snmp::HeaderNames();
  CHECK(std::strcmp(names[0], "BytesSent") == 0);
  CHECK(std::strcmp(names[20], "FECFullShards") == 0);
  CHECK(std::strcmp(names[21], "FECParityShards") == 0);
  CHECK(std::strcmp(names[29], "OOBPackets") == 0);

  const auto values = snmp.ToArray();
  CHECK(values.size() == kcp::Snmp::kFieldCount);
  CHECK(values[0] == 123);  // BytesSent
  CHECK(values[23] == 7);   // FECRecovered, per Header() order
  CHECK(values[29] == 1);   // OOBPackets

  snmp.Reset();
  const auto after = snmp.ToArray();
  std::uint64_t total = 0;
  for (std::uint64_t v : after) {
    total += v;
  }
  CHECK(total == 0);

  // The global accessor must return the same object every time (function-local static).
  CHECK(&kcp::DefaultSnmp() == &kcp::DefaultSnmp());
}

void TestRateLimiter() {
  using kcp::internal::RateLimiter;

  // Unlimited (rate 0 == rate.Inf): acquiring any amount is a no-op.
  RateLimiter unlimited(0);
  CHECK(unlimited.unlimited());
  unlimited.Acquire(1u << 30);

  const double burst = static_cast<double>(kcp::kMaxBatchSize * kcp::kMtuLimit);
  CHECK(burst == 96000.0);

  // Drain the bucket with one burst-sized request (the initial token count is the burst), then ask
  // for one byte more. x/time/rate.WaitN rejects a request over the burst without reserving a
  // token, so sess.go transmits it immediately; blocking to refill a whole burst here would cost
  // burst/rate = ~96s at 1 kB/s. A generous 2s bound separates "immediate" from "waited".
  RateLimiter limited(1000);
  CHECK(!limited.unlimited());
  limited.Acquire(static_cast<std::size_t>(burst));

  const auto start = std::chrono::steady_clock::now();
  limited.Acquire(static_cast<std::size_t>(burst) + 1);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
  CHECK(elapsed < 2000);
}

}  // namespace

int main() {
  TestBufferPool();
  TestSnmp();
  TestRateLimiter();

  if (g_failures != 0) {
    std::fprintf(stderr, "foundation_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("foundation_test: OK\n");
  return 0;
}
