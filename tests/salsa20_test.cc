// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Salsa20 gate for PORTING-PLAN.md P2. Keys and nonces are the ECRYPT "set 6" vectors that
// golang.org/x/crypto/salsa20 tests against; the expected keystream bytes were produced by
// x/crypto's own XORKeyStream with an all-zero input, so they pin the 8-byte-nonce variant that
// kcp-go actually uses (crypt.go:175-181).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "kcp/internal/salsa20.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

std::vector<std::uint8_t> FromHex(const char* hex) {
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  };
  std::vector<std::uint8_t> out;
  const std::size_t len = std::strlen(hex);
  for (std::size_t i = 0; i + 1 < len; i += 2) {
    const int hi = nibble(hex[i]);
    const int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string ToHex(const std::uint8_t* data, std::size_t len) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0f]);
  }
  return out;
}

void TestEcryptVectors() {
  struct Case {
    const char* key_hex;
    const char* nonce_hex;
    const char* keystream_hex;
  };
  const Case cases[] = {
      {"0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d", "0d74db42a91077de",
       "f5fad53f79f9df58c4aea0d0ed9a9601f278112ca7180d565b420a48019670ea"
       "f24ce493a86263f677b46ace1924773d2bb25571e1aa8593758fc382b1280b71"},
      {"0558abfe51a4f74a9df04396e93c8fe23588db2e81d4277acd2073c6196cbf12", "167de44bb21980e7",
       "3944f6dc9f85b128083879fdf190f7dee4053a07bc09896d51d0690bd4da4ac1"
       "062f1e47d3d0716f80a9b4d85e6d6085ee06947601c85f1a27a2f76e45a6aa87"},
  };

  for (const Case& c : cases) {
    const std::vector<std::uint8_t> key = FromHex(c.key_hex);
    const std::vector<std::uint8_t> nonce = FromHex(c.nonce_hex);
    kcp::internal::Salsa20 salsa(key.data(), key.size());
    std::vector<std::uint8_t> zeros(64, 0);
    std::vector<std::uint8_t> stream(64, 0);
    salsa.XorKeyStream(stream.data(), zeros.data(), stream.size(), nonce.data());
    const std::string got = ToHex(stream.data(), stream.size());
    if (got != c.keystream_hex) {
      Fail(__FILE__, __LINE__,
           "keystream mismatch for nonce " + std::string(c.nonce_hex) + ": got " + got + ", want " +
               c.keystream_hex);
    }
  }
}

void TestCounterRestartsPerCall() {
  // Salsa20 in x/crypto is message oriented: every XORKeyStream call rebuilds the input block
  // from the nonce with the counter reset to zero (salsa20.go:56-57, salsa20_ref.go:207). Two
  // calls over the same buffer must therefore agree, and the second call must NOT continue the
  // first one's keystream. This is what makes kcp-go's per-packet nonce header safe.
  const std::vector<std::uint8_t> key = FromHex(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f");
  const std::vector<std::uint8_t> nonce = FromHex("0102030405060708");
  std::vector<std::uint8_t> plain(200);
  for (std::size_t i = 0; i < plain.size(); ++i) {
    plain[i] = static_cast<std::uint8_t>(i * 3 + 1);
  }
  kcp::internal::Salsa20 salsa(key.data(), key.size());

  std::vector<std::uint8_t> first(plain.size());
  std::vector<std::uint8_t> second(plain.size());
  salsa.XorKeyStream(first.data(), plain.data(), plain.size(), nonce.data());
  salsa.XorKeyStream(second.data(), plain.data(), plain.size(), nonce.data());
  if (first != second) {
    Fail(__FILE__, __LINE__, "identical calls produced different keystreams");
  }

  // A restarting counter means the tail of a two-call split differs from the single-shot tail.
  std::vector<std::uint8_t> split(plain.size());
  salsa.XorKeyStream(split.data(), plain.data(), 64, nonce.data());
  salsa.XorKeyStream(split.data() + 64, plain.data() + 64, plain.size() - 64, nonce.data());
  if (std::memcmp(split.data() + 64, first.data() + 64, plain.size() - 64) == 0) {
    Fail(__FILE__, __LINE__, "counter did not restart: split encryption continued the stream");
  }
  if (std::memcmp(split.data(), first.data(), 64) != 0) {
    Fail(__FILE__, __LINE__, "first block of a split encryption differs from the single-shot one");
  }
}

void TestInPlace() {
  const std::vector<std::uint8_t> key(32, 0x42);
  const std::vector<std::uint8_t> nonce = FromHex("1122334455667788");
  std::vector<std::uint8_t> plain(128);
  for (std::size_t i = 0; i < plain.size(); ++i) {
    plain[i] = static_cast<std::uint8_t>(i);
  }
  kcp::internal::Salsa20 salsa(key.data(), key.size());
  std::vector<std::uint8_t> expected(plain.size());
  salsa.XorKeyStream(expected.data(), plain.data(), plain.size(), nonce.data());

  std::vector<std::uint8_t> in_place = plain;
  salsa.XorKeyStream(in_place.data(), in_place.data(), in_place.size(), nonce.data());
  if (in_place != expected) {
    Fail(__FILE__, __LINE__, "in-place keystream differs from out-of-place");
  }
}

void TestShortKey() {
  // crypt.go:169 copies into a zeroed 32-byte array: a 16-byte key behaves as key || zeros.
  const std::vector<std::uint8_t> short_key = FromHex("00112233445566778899aabbccddeeff");
  std::vector<std::uint8_t> long_key(32, 0);
  std::memcpy(long_key.data(), short_key.data(), short_key.size());
  const std::vector<std::uint8_t> nonce = FromHex("0f0e0d0c0b0a0908");
  std::vector<std::uint8_t> zeros(64, 0);
  std::vector<std::uint8_t> a(64);
  std::vector<std::uint8_t> b(64);
  kcp::internal::Salsa20 salsa_short(short_key.data(), short_key.size());
  kcp::internal::Salsa20 salsa_long(long_key.data(), long_key.size());
  salsa_short.XorKeyStream(a.data(), zeros.data(), a.size(), nonce.data());
  salsa_long.XorKeyStream(b.data(), zeros.data(), b.size(), nonce.data());
  if (a != b) {
    Fail(__FILE__, __LINE__, "short key is not zero-padded");
  }
}

}  // namespace

int main() {
  TestEcryptVectors();
  TestCounterRestartsPerCall();
  TestInPlace();
  TestShortKey();

  if (g_failures != 0) {
    std::fprintf(stderr, "salsa20_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("salsa20_test: OK\n");
  return 0;
}
