// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Entropy source checks. These cannot prove randomness; they catch the failure modes that actually
// matter for KCP framing: an all-zero buffer (never seeded), a constant source (broken syscall
// wrapper), and a source that does not honour the requested length.

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "kcp/platform/entropy_backend.h"

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

void TestLengthAndNonZero() {
  // Odd lengths matter: nonces are 12 bytes (GCM) and 16 bytes (CFB), and the wrapper must not
  // round them up or down.
  for (std::size_t len :
       {std::size_t{1}, std::size_t{12}, std::size_t{16}, std::size_t{37}, std::size_t{1500}}) {
    std::vector<std::uint8_t> buffer(len + 8, 0xAA);  // canary past the requested length
    const bool ok = kcp::platform::FillRand(buffer.data(), len);
    CHECK(ok);

    bool all_zero = true;
    for (std::size_t i = 0; i < len; ++i) {
      if (buffer[i] != 0) {
        all_zero = false;
        break;
      }
    }
    CHECK(!all_zero);

    // Bytes past the requested range must be untouched.
    for (std::size_t i = len; i < buffer.size(); ++i) {
      CHECK(buffer[i] == 0xAA);
    }
  }
}

void TestDistinct() {
  // Two 16-byte draws colliding is a 2^-128 event; a constant source would fail immediately.
  std::set<std::string> seen;
  for (int i = 0; i < 256; ++i) {
    std::uint8_t buffer[16];
    CHECK(kcp::platform::FillRand(buffer, sizeof(buffer)));
    const std::string key(reinterpret_cast<const char*>(buffer), sizeof(buffer));
    CHECK(seen.insert(key).second);
  }
}

void TestZeroLength() {
  std::uint8_t canary = 0x5a;
  CHECK(kcp::platform::FillRand(&canary, 0));
  CHECK(canary == 0x5a);
}

}  // namespace

int main() {
  TestLengthAndNonZero();
  TestDistinct();
  TestZeroLength();

  if (g_failures != 0) {
    std::fprintf(stderr, "entropy_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("entropy_test: OK\n");
  return 0;
}
