// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// AES-GCM gate for PORTING-PLAN.md P2. Test case 2 is the published all-zero vector from NIST
// SP 800-38D; the two 60-byte cases use the SP 800-38D test-case-3 inputs with expected output
// produced by Go's crypto/aes + cipher.NewGCM (the same pair kcp-go uses), so they also pin the
// "no additional data" contract that kcp-go relies on (sess.go:718,726).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

void CheckSeal(const char* what, const char* key_hex, const char* nonce_hex, const char* plain_hex,
               const char* want_cipher_hex, const char* want_tag_hex) {
  const std::vector<std::uint8_t> key = FromHex(key_hex);
  const std::vector<std::uint8_t> nonce = FromHex(nonce_hex);
  const std::vector<std::uint8_t> plain = FromHex(plain_hex);
  kcp::internal::AesGcm gcm(key.data(), key.size());
  if (!gcm.valid()) {
    Fail(__FILE__, __LINE__, std::string(what) + ": key rejected");
    return;
  }
  std::vector<std::uint8_t> sealed(plain.size() + gcm.overhead());
  gcm.Seal(sealed.data(), nonce.data(), plain.data(), plain.size());

  const std::string got_cipher = ToHex(sealed.data(), plain.size());
  if (got_cipher != want_cipher_hex) {
    Fail(__FILE__, __LINE__,
         std::string(what) + " ciphertext: got " + got_cipher + ", want " + want_cipher_hex);
  }
  const std::string got_tag = ToHex(sealed.data() + plain.size(), gcm.overhead());
  if (got_tag != want_tag_hex) {
    Fail(__FILE__, __LINE__, std::string(what) + " tag: got " + got_tag + ", want " + want_tag_hex);
  }

  std::vector<std::uint8_t> opened(plain.size());
  if (!gcm.Open(opened.data(), nonce.data(), sealed.data(), sealed.size())) {
    Fail(__FILE__, __LINE__, std::string(what) + ": Open rejected its own Seal output");
    return;
  }
  if (opened != plain) {
    Fail(__FILE__, __LINE__, std::string(what) + ": Open(Seal(x)) != x");
  }
}

void TestNistVectors() {
  // SP 800-38D test case 2: K = P = IV = 0, 128-bit key.
  CheckSeal("gcm tc2", "00000000000000000000000000000000", "000000000000000000000000",
            "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf");

  // SP 800-38D test case 3 inputs (60-byte plaintext, no additional data).
  CheckSeal("gcm tc3", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "cc15abcc191161501aabab46b8fbac85");
}

void TestTamperDetection() {
  const std::vector<std::uint8_t> key = FromHex("0102030405060708090a0b0c0d0e0f10");
  const std::vector<std::uint8_t> nonce = FromHex("0f0e0d0c0b0a090807060504");
  const std::vector<std::uint8_t> plain(64, 0x5a);
  kcp::internal::AesGcm gcm(key.data(), key.size());
  std::vector<std::uint8_t> sealed(plain.size() + gcm.overhead());
  gcm.Seal(sealed.data(), nonce.data(), plain.data(), plain.size());

  std::vector<std::uint8_t> opened(plain.size());

  // Flipping any single ciphertext byte must fail authentication.
  for (std::size_t pos : {std::size_t{0}, std::size_t{31}, plain.size() - 1}) {
    std::vector<std::uint8_t> broken = sealed;
    broken[pos] ^= 0x01;
    if (gcm.Open(opened.data(), nonce.data(), broken.data(), broken.size())) {
      Fail(__FILE__, __LINE__, "accepted tampered ciphertext byte " + std::to_string(pos));
    }
  }

  // Same for the tag itself.
  std::vector<std::uint8_t> broken = sealed;
  broken.back() ^= 0x80;
  if (gcm.Open(opened.data(), nonce.data(), broken.data(), broken.size())) {
    Fail(__FILE__, __LINE__, "accepted tampered tag");
  }

  // A different nonce must also fail.
  std::vector<std::uint8_t> other_nonce = nonce;
  other_nonce[0] ^= 0xff;
  if (gcm.Open(opened.data(), other_nonce.data(), sealed.data(), sealed.size())) {
    Fail(__FILE__, __LINE__, "accepted wrong nonce");
  }
}

void TestEmptyPlaintext() {
  const std::vector<std::uint8_t> key = FromHex("00112233445566778899aabbccddeeff");
  const std::vector<std::uint8_t> nonce = FromHex("0102030405060708090a0b0c");
  kcp::internal::AesGcm gcm(key.data(), key.size());
  std::uint8_t sealed[16] = {};
  gcm.Seal(sealed, nonce.data(), nullptr, 0);
  std::uint8_t opened[1] = {};
  if (!gcm.Open(opened, nonce.data(), sealed, sizeof(sealed))) {
    Fail(__FILE__, __LINE__, "empty plaintext round trip failed");
  }
}

void TestKeySizes() {
  const std::vector<std::uint8_t> nonce = FromHex("0102030405060708090a0b0c");
  std::vector<std::uint8_t> plain(32, 0x11);
  for (const std::size_t key_len : {std::size_t{16}, std::size_t{24}, std::size_t{32}}) {
    std::vector<std::uint8_t> key(key_len, 0x77);
    kcp::internal::AesGcm gcm(key.data(), key.size());
    if (!gcm.valid()) {
      Fail(__FILE__, __LINE__, "key length rejected: " + std::to_string(key_len));
      continue;
    }
    if (gcm.nonce_size() != 12 || gcm.overhead() != 16) {
      Fail(__FILE__, __LINE__, "nonce/overhead mismatch for key length " + std::to_string(key_len));
    }
    std::vector<std::uint8_t> sealed(plain.size() + gcm.overhead());
    gcm.Seal(sealed.data(), nonce.data(), plain.data(), plain.size());
    std::vector<std::uint8_t> opened(plain.size());
    if (!gcm.Open(opened.data(), nonce.data(), sealed.data(), sealed.size()) || opened != plain) {
      Fail(__FILE__, __LINE__, "round trip failed for key length " + std::to_string(key_len));
    }
  }
  kcp::internal::AesGcm bad(nullptr, 20);
  if (bad.valid()) {
    Fail(__FILE__, __LINE__, "accepted 20-byte key");
  }
}

// Decision 6: the T-table fallback must produce the same ciphertext as AES-NI, otherwise a host
// without AES-NI would silently emit different packets than the same binary on a host with it.
void TestBackendsAgree() {
  const std::uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  const std::uint8_t nonce[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                  0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
  const kcp::internal::AesGcm ni(key, sizeof(key), kcp::internal::AesBackend::kNin);
  const kcp::internal::AesGcm table(key, sizeof(key), kcp::internal::AesBackend::kTable);
  if (!ni.valid() || !table.valid()) {
    Fail(__FILE__, __LINE__, "gcm init failed");
    return;
  }

  for (const std::size_t len : {std::size_t{0}, std::size_t{1}, std::size_t{15}, std::size_t{16},
                                std::size_t{17}, std::size_t{1376}, std::size_t{1400}}) {
    std::vector<std::uint8_t> plain(len);
    for (std::size_t i = 0; i < len; ++i) {
      plain[i] = static_cast<std::uint8_t>(i * 13 + 5);
    }
    std::vector<std::uint8_t> sealed_ni(len + ni.overhead());
    std::vector<std::uint8_t> sealed_table(len + table.overhead());
    ni.Seal(sealed_ni.data(), nonce, plain.data(), len);
    table.Seal(sealed_table.data(), nonce, plain.data(), len);
    if (sealed_ni != sealed_table) {
      Fail(__FILE__, __LINE__, "backends disagree at len " + std::to_string(len));
    }
    std::vector<std::uint8_t> opened(len);
    if (!table.Open(opened.data(), nonce, sealed_ni.data(), sealed_ni.size()) || opened != plain) {
      Fail(__FILE__, __LINE__, "cross-backend open failed at len " + std::to_string(len));
    }
  }

  // The host may lack AES-NI; then kNin falls back internally and the loop above proves nothing.
  if (!ni.using_ni()) {
    std::printf("gcm_test: AES-NI unavailable, cross-backend check reduced to a self-compare\n");
  }
}

}  // namespace

int main() {
  TestNistVectors();
  TestTamperDetection();
  TestEmptyPlaintext();
  TestKeySizes();
  TestBackendsAgree();

  if (g_failures != 0) {
    std::fprintf(stderr, "gcm_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("gcm_test: OK\n");
  return 0;
}
