// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// AES block-cipher gate for PORTING-PLAN.md P2: FIPS-197 appendix C known answers for all three
// key sizes, plus the cross-verification that the AES-NI and T-table implementations produce
// identical ciphertext (decision 6).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "kcp/internal/aes.h"
#include "kcp/internal/gcm.h"

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

using kcp::internal::Aes;
using kcp::internal::AesBackend;

const char* BackendName(AesBackend backend) {
  switch (backend) {
    case AesBackend::kNin:
      return "aes-ni";
    case AesBackend::kTable:
      return "t-table";
    case AesBackend::kAuto:
      break;
  }
  return "auto";
}

// FIPS-197 appendix C: one plaintext, three key schedules.
void TestFips197() {
  const std::vector<std::uint8_t> plaintext = FromHex("00112233445566778899aabbccddeeff");
  struct Case {
    const char* name;
    const char* key_hex;
    const char* cipher_hex;
  };
  const Case cases[] = {
      {"AES-128 (FIPS-197 C.1)", "000102030405060708090a0b0c0d0e0f",
       "69c4e0d86a7b0430d8cdb78070b4c55a"},
      {"AES-192 (FIPS-197 C.2)", "000102030405060708090a0b0c0d0e0f1011121314151617",
       "dda97ca4864cdfe06eaf70a0ec0d7191"},
      {"AES-256 (FIPS-197 C.3)", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
       "8ea2b7ca516745bfeafc49904b496089"},
  };

  for (const AesBackend backend : {AesBackend::kTable, AesBackend::kNin}) {
    for (const Case& c : cases) {
      const std::vector<std::uint8_t> key = FromHex(c.key_hex);
      Aes aes(key.data(), key.size(), backend);
      if (!aes.valid()) {
        Fail(__FILE__, __LINE__, std::string(c.name) + ": key schedule rejected a valid key");
        continue;
      }
      if (backend == AesBackend::kNin && !aes.using_ni()) {
        // No AES-NI on this host; the T-table run above already covers the vector.
        continue;
      }
      std::uint8_t out[16] = {};
      aes.EncryptBlock(out, plaintext.data());
      const std::string got = ToHex(out, sizeof(out));
      if (got != c.cipher_hex) {
        Fail(__FILE__, __LINE__,
             std::string(c.name) + " on " + BackendName(backend) + ": got " + got + ", want " +
                 c.cipher_hex);
      }
    }
  }
}

// Both code paths must agree byte for byte, across key sizes and across lengths that do and do not
// fill a whole number of blocks in the callers.
void TestBackendsAgree() {
  const std::size_t key_lengths[] = {16, 24, 32};
  for (const std::size_t key_len : key_lengths) {
    std::vector<std::uint8_t> key(key_len);
    for (std::size_t i = 0; i < key_len; ++i) {
      key[i] = static_cast<std::uint8_t>(0x11 * (i + 1) + key_len);
    }
    Aes ni(key.data(), key.size(), AesBackend::kNin);
    Aes table(key.data(), key.size(), AesBackend::kTable);
    if (!ni.valid() || !table.valid()) {
      Fail(__FILE__, __LINE__, "valid key rejected for len " + std::to_string(key_len));
      continue;
    }
    if (!ni.using_ni()) {
      std::printf("aes_test: no AES-NI on this host, dual-path cross-check skipped\n");
      return;
    }
    for (int block = 0; block < 512; ++block) {
      std::uint8_t plaintext[16];
      for (int i = 0; i < 16; ++i) {
        plaintext[i] = static_cast<std::uint8_t>((block * 7 + i * 31 + 5) & 0xff);
      }
      std::uint8_t a[16] = {};
      std::uint8_t b[16] = {};
      ni.EncryptBlock(a, plaintext);
      table.EncryptBlock(b, plaintext);
      if (std::memcmp(a, b, 16) != 0) {
        Fail(__FILE__, __LINE__,
             "AES-NI and T-table disagree at block " + std::to_string(block) + " key_len " +
                 std::to_string(key_len) + ": ni=" + ToHex(a, 16) + " table=" + ToHex(b, 16));
        return;
      }
    }
  }
}

void TestInvalidKeyLength() {
  const std::uint8_t key[40] = {};
  for (const std::size_t len :
       {std::size_t{0}, std::size_t{15}, std::size_t{20}, std::size_t{31}, std::size_t{33}}) {
    Aes aes(key, len);
    if (aes.valid()) {
      Fail(__FILE__, __LINE__, "accepted invalid key length " + std::to_string(len));
    }
  }
}

void TestAutoBackendMatchesHost() {
  const std::uint8_t key[16] = {};
  Aes aes(key, sizeof(key));
  if (!aes.valid()) {
    Fail(__FILE__, __LINE__, "16-byte key rejected");
    return;
  }
  if (aes.using_ni() != kcp::internal::AesNiAvailable()) {
    Fail(__FILE__, __LINE__, "auto backend disagrees with AesNiAvailable()");
  }
  std::printf("aes_test: cpu aes-ni = %s\n", kcp::internal::AesNiAvailable() ? "yes" : "no");
}

}  // namespace

int main() {
  TestFips197();
  TestBackendsAgree();
  TestInvalidKeyLength();
  TestAutoBackendMatchesHost();

  if (g_failures != 0) {
    std::fprintf(stderr, "aes_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("aes_test: OK\n");
  return 0;
}
