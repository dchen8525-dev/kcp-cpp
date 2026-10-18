// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Known-answer tests for the hand-written primitives. Every vector here is from a public standard
// (FIPS 180-1, RFC 2202, RFC 6070) or from Go's own crc32.IEEE; none is produced by this code.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "json_reader.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/primitives.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
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

void CheckHex(const char* what, const std::uint8_t* got, std::size_t len, const char* want_hex,
              const char* file, int line) {
  const std::string got_hex = ToHex(got, len);
  if (got_hex != want_hex) {
    Fail(file, line, std::string(what) + ": got " + got_hex + ", want " + want_hex);
  }
}

#define CHECK_HEX(what, data, len, want) CheckHex(what, data, len, want, __FILE__, __LINE__)

#define CHECK_EQ(what, got, want)                                                                  \
  do {                                                                                             \
    if ((got) != (want)) {                                                                         \
      Fail(__FILE__, __LINE__,                                                                     \
           std::string(what) + ": got " + std::to_string(got) + ", want " + std::to_string(want)); \
    }                                                                                              \
  } while (0)

void TestCrc32() {
  struct Case {
    const char* data;
    std::uint32_t want;
  };
  const Case cases[] = {
      {"", 0x00000000u},
      {"123456789", 0xcbf43926u},
      {"The quick brown fox jumps over the lazy dog", 0x414fa339u},
      {"a", 0xe8b7be43u},
  };
  for (const Case& c : cases) {
    const std::uint32_t got = kcp::internal::Crc32(c.data, std::strlen(c.data));
    CHECK_EQ(std::string("crc32(\"") + c.data + "\")", got, c.want);
  }

  // Incremental use must match one-shot use: the seed returned by one call feeds the next.
  const char* part1 = "1234";
  const char* part2 = "56789";
  const std::uint32_t incremental =
      kcp::internal::Crc32Update(kcp::internal::Crc32(part1, 4), part2, 5);
  CHECK_EQ("crc32 incremental", incremental, 0xcbf43926u);
}

void TestSha1() {
  struct Case {
    std::string data;
    const char* want_hex;
  };
  const Case cases[] = {
      {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
      {"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
  };
  for (const Case& c : cases) {
    std::uint8_t digest[kcp::internal::Sha1::kDigestSize];
    kcp::internal::Sha1::Compute(c.data.data(), c.data.size(), digest);
    CHECK_HEX("sha1", digest, sizeof(digest), c.want_hex);
  }

  // One million 'a' vectors exercise multi-block streaming and the length encoding.
  std::uint8_t digest[kcp::internal::Sha1::kDigestSize];
  kcp::internal::Sha1 sha;
  std::vector<char> chunk(1000, 'a');
  for (int i = 0; i < 1000; ++i) {
    sha.Update(chunk.data(), chunk.size());
  }
  sha.Final(digest);
  CHECK_HEX("sha1(1e6 * 'a')", digest, sizeof(digest), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");

  // Final() must reset so the object can hash a second message.
  sha.Update("abc", 3);
  sha.Final(digest);
  CHECK_HEX("sha1 reuse after Final", digest, sizeof(digest),
            "a9993e364706816aba3e25717850c26c9cd0d89d");

  // Non-block-aligned split points must not change the digest. Lengths come from the strings
  // themselves so a typo cannot silently hash past the end of a literal.
  const std::string part1 = "abcdbcdecdefdefgefghfghighij";
  const std::string part2 = "hijkijkljklmklmnlmnomnopnopq";
  CHECK_EQ("split halves cover the message", part1.size() + part2.size(), std::size_t{56});
  kcp::internal::Sha1 split;
  split.Update(part1.data(), part1.size());
  split.Update(part2.data(), part2.size());
  split.Final(digest);
  CHECK_HEX("sha1 split update", digest, sizeof(digest),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

void TestHmacSha1() {
  // RFC 2202 test cases 1 and 2.
  {
    const std::vector<std::uint8_t> key(20, 0x0b);
    const char* data = "Hi There";
    std::uint8_t digest[kcp::internal::Sha1::kDigestSize];
    kcp::internal::HmacSha1(key.data(), key.size(), data, std::strlen(data), digest);
    CHECK_HEX("hmac-sha1 rfc2202 #1", digest, sizeof(digest),
              "b617318655057264e28bc0b6fb378c8ef146be00");
  }
  {
    const char* key = "Jefe";
    const char* data = "what do ya want for nothing?";
    std::uint8_t digest[kcp::internal::Sha1::kDigestSize];
    kcp::internal::HmacSha1(key, std::strlen(key), data, std::strlen(data), digest);
    CHECK_HEX("hmac-sha1 rfc2202 #2", digest, sizeof(digest),
              "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
  }
}

void TestPbkdf2() {
  // RFC 6070: P="password", S="salt".
  struct Case {
    int iterations;
    std::size_t out_len;
    const char* want_hex;
  };
  const Case cases[] = {
      {1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
      {2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
      {4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
  };
  for (const Case& c : cases) {
    std::uint8_t out[20];
    const bool ok =
        kcp::internal::Pbkdf2HmacSha1("password", 8, "salt", 4, c.iterations, out, c.out_len);
    if (!ok) {
      Fail(__FILE__, __LINE__, "pbkdf2 returned false");
      continue;
    }
    CHECK_HEX("pbkdf2 rfc6070", out, c.out_len, c.want_hex);
  }

  // Multi-block output (dkLen > hLen) and a long password/salt.
  {
    const char* password = "passwordPASSWORDpassword";
    const char* salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    std::vector<std::uint8_t> out(25);
    const bool ok = kcp::internal::Pbkdf2HmacSha1(password, std::strlen(password), salt,
                                                  std::strlen(salt), 4096, out.data(), out.size());
    if (!ok) {
      Fail(__FILE__, __LINE__, "pbkdf2 multi-block returned false");
    } else {
      CHECK_HEX("pbkdf2 rfc6070 multi-block", out.data(), out.size(),
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    }
  }

  CHECK_EQ("pbkdf2 rejects iterations<1",
           kcp::internal::Pbkdf2HmacSha1("p", 1, "s", 1, 0, nullptr, 0) ? 1 : 0, 0);
}

// Cross-checks the hand-written primitives against the reference implementation's own output.
// These are the two places where a wrong constant cannot be caught by a standard vector:
//   - the simple-XOR keystream fixes the salt, the iteration count and the output length;
//   - the frame CRC fixes the exact byte range the checksum covers (sess.go:730).
void TestGoldenVectors() {
  using kcp::test::Find;
  using kcp::test::GetString;
  using kcp::test::HexToBytes;
  using kcp::test::JsonValue;
  using kcp::test::LoadJsonFile;

  std::string error;
  JsonValue crypt;
  const std::string crypt_path = std::string(KCP_VECTOR_DIR) + "/crypt.json";
  if (!LoadJsonFile(crypt_path, &crypt, &error)) {
    Fail(__FILE__, __LINE__, crypt_path + ": " + error);
    return;
  }
  const JsonValue* vectors = Find(crypt, "vectors");
  if (vectors == nullptr || !vectors->IsArray()) {
    Fail(__FILE__, __LINE__, "crypt.json: missing vectors");
    return;
  }

  bool checked_xor = false;
  for (const JsonValue& v : vectors->array_value) {
    std::string algo;
    if (!GetString(v, "algo", &algo) || algo != "simplexor") {
      continue;
    }
    std::string key_hex;
    std::string plain_hex;
    std::string cipher_hex;
    if (!GetString(v, "key_hex", &key_hex) || !GetString(v, "plain_hex", &plain_hex) ||
        !GetString(v, "cipher_hex", &cipher_hex)) {
      Fail(__FILE__, __LINE__, "simplexor vector missing fields");
      return;
    }
    const std::vector<std::uint8_t> key = HexToBytes(key_hex);
    const std::vector<std::uint8_t> plain = HexToBytes(plain_hex);
    const std::vector<std::uint8_t> cipher = HexToBytes(cipher_hex);
    if (key.empty() || plain.empty() || plain.size() != cipher.size()) {
      Fail(__FILE__, __LINE__, "simplexor vector malformed");
      return;
    }

    // RS: cipher == plain XOR PBKDF2(key, kSaltXor, 32, len).
    std::vector<std::uint8_t> keystream(plain.size());
    if (!kcp::internal::Pbkdf2HmacSha1(key.data(), key.size(), kcp::kSaltXor,
                                       std::strlen(kcp::kSaltXor), kcp::kSimpleXorIterations,
                                       keystream.data(), keystream.size())) {
      Fail(__FILE__, __LINE__, "simplexor pbkdf2 failed");
      return;
    }
    for (std::size_t i = 0; i < plain.size(); ++i) {
      const std::uint8_t xor_keystream = static_cast<std::uint8_t>(plain[i] ^ cipher[i]);
      if (xor_keystream != keystream[i]) {
        Fail(__FILE__, __LINE__, "simplexor keystream mismatch at byte " + std::to_string(i));
        return;
      }
    }
    checked_xor = true;
    break;
  }
  CHECK_EQ("simplexor vector present", checked_xor ? 1 : 0, 1);

  // frame.json (cfb, no FEC): crc32_le is the checksum of the KCP segment alone.
  JsonValue frame;
  const std::string frame_path = std::string(KCP_VECTOR_DIR) + "/frame.json";
  if (!LoadJsonFile(frame_path, &frame, &error)) {
    Fail(__FILE__, __LINE__, frame_path + ": " + error);
    return;
  }
  const JsonValue* frames = Find(frame, "vectors");
  if (frames == nullptr || !frames->IsArray()) {
    Fail(__FILE__, __LINE__, "frame.json: missing vectors");
    return;
  }

  bool checked_crc = false;
  for (const JsonValue& v : frames->array_value) {
    std::string crypt_name;
    std::string seg_hex;
    std::string crc_hex;
    bool fec = true;
    if (!GetString(v, "crypt", &crypt_name) || crypt_name != "cfb") {
      continue;
    }
    if (!kcp::test::GetBool(v, "fec", &fec) || fec) {
      continue;  // FEC frames checksum FEC header + segment; covered once FEC decoding lands.
    }
    if (!GetString(v, "kcp_seg_hex", &seg_hex) || !GetString(v, "crc32_le", &crc_hex)) {
      Fail(__FILE__, __LINE__, "cfb frame missing fields");
      return;
    }
    const std::vector<std::uint8_t> seg = HexToBytes(seg_hex);
    const std::uint32_t want = static_cast<std::uint32_t>(std::stoul(crc_hex, nullptr, 16));
    const std::uint32_t got = kcp::internal::Crc32(seg.data(), seg.size());
    if (got != want) {
      Fail(__FILE__, __LINE__,
           "frame crc32 mismatch: got " + std::to_string(got) + ", want " + std::to_string(want));
      return;
    }
    checked_crc = true;
    break;
  }
  CHECK_EQ("cfb frame crc vector present", checked_crc ? 1 : 0, 1);
}

}  // namespace

int main() {
  TestCrc32();
  TestSha1();
  TestHmacSha1();
  TestPbkdf2();
  TestGoldenVectors();

  if (g_failures != 0) {
    std::fprintf(stderr, "primitives_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("primitives_test: OK\n");
  return 0;
}
