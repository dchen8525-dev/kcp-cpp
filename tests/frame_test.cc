// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Byte-exact gate for PORTING-PLAN.md P6: tools/golden/out/frame.json holds one assembled wire
// packet per configuration (crypt x FEC). This is the only test that pins the *composition* of the
// four layers - cipher header size, FEC header placement, CRC coverage, AEAD tag - so a mistake
// there shows up here even if crypt.json, fec.json and kcp.json all still pass.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "json_reader.h"
#include "kcp/crypt.h"
#include "kcp/internal/byteorder.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/fec.h"
#include "kcp/internal/frame.h"
#include "kcp/internal/primitives.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

using Bytes = std::vector<std::uint8_t>;
using kcp::test::BytesToHex;
using kcp::test::Find;
using kcp::test::GetBool;
using kcp::test::GetInt;
using kcp::test::GetString;
using kcp::test::HexToBytes;
using kcp::test::JsonValue;
using kcp::test::LoadJsonFile;

// golden_ref.go.txt:91 - the key the generator uses for every frame vector.
Bytes GoldenPattern(std::size_t n, std::uint8_t seed) {
  Bytes out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<std::uint8_t>((i * 31 + seed) & 0xff);
  }
  return out;
}

void TestFrameVectors() {
  JsonValue doc;
  std::string error;
  const std::string path = std::string(KCP_VECTOR_DIR) + "/frame.json";
  if (!LoadJsonFile(path, &doc, &error)) {
    Fail(__FILE__, __LINE__, "cannot read " + path + ": " + error);
    return;
  }

  const JsonValue* vectors = Find(doc, "vectors");
  if (vectors == nullptr || !vectors->IsArray() || vectors->size() != 6) {
    Fail(__FILE__, __LINE__, "frame.json must hold the six crypt x fec configurations");
    return;
  }

  const Bytes key = GoldenPattern(16, 0x11);
  std::set<std::string> seen;

  for (const auto& vector : vectors->array_value) {
    std::string crypt;
    std::string seg_hex;
    std::string blob_hex;
    std::string nonce_hex;
    std::string crc_text;
    long long header_size = 0;
    long long data_shards = 0;
    long long parity_shards = 0;
    bool fec = false;

    if (!GetString(vector, "crypt", &crypt) || !GetString(vector, "kcp_seg_hex", &seg_hex) ||
        !GetString(vector, "encrypted_blob_hex", &blob_hex) ||
        !GetInt(vector, "header_size", &header_size) || !GetBool(vector, "fec", &fec) ||
        !GetInt(vector, "data_shards", &data_shards) ||
        !GetInt(vector, "parity_shards", &parity_shards)) {
      Fail(__FILE__, __LINE__, "frame vector is missing a field");
      return;
    }
    const std::string label = crypt + (fec ? "+fec" : "");
    seen.insert(label);

    std::shared_ptr<kcp::BlockCrypt> block;
    std::shared_ptr<kcp::AeadCrypt> aead;
    if (crypt == "cfb") {
      block = kcp::NewAesBlockCrypt(key.data(), key.size());
    } else if (crypt == "aesgcm") {
      aead = kcp::NewAesGcmCrypt(key.data(), key.size());
    } else if (crypt != "none") {
      Fail(__FILE__, __LINE__, "unknown crypt " + crypt);
      return;
    }
    if ((crypt != "none") && block == nullptr && aead == nullptr) {
      Fail(__FILE__, __LINE__, "cipher factory failed for " + label);
      return;
    }

    const std::size_t enc_header = kcp::internal::CipherHeaderSize(block.get(), aead.get());
    const std::size_t expected_header = enc_header + (fec ? kcp::kFecHeaderSizePlus2 : 0);
    if (static_cast<std::size_t>(header_size) != expected_header) {
      Fail(__FILE__, __LINE__,
           label + ": header_size " + std::to_string(header_size) +
               " != " + std::to_string(expected_header));
      return;
    }

    const Bytes seg = HexToBytes(seg_hex);
    const Bytes want = HexToBytes(blob_hex);

    // The allocation carries the tag room; `total` stays the logical length so the comparison
    // below can ignore whatever lies past the wire bytes.
    const std::size_t total = expected_header + seg.size();
    Bytes buffer(total + kcp::internal::kMaxAeadOverhead, 0);
    std::memcpy(buffer.data() + expected_header, seg.data(), seg.size());

    if (fec) {
      auto encoder = kcp::internal::FecEncoder::New(static_cast<int>(data_shards),
                                                    static_cast<int>(parity_shards),
                                                    static_cast<int>(enc_header));
      if (encoder == nullptr) {
        Fail(__FILE__, __LINE__, label + ": FEC encoder rejected the configuration");
        return;
      }
      std::vector<kcp::internal::FecPacket> parity;
      encoder->Encode(buffer.data(), total, kcp::kMaxFecEncodeLatencyMs, &parity);
      // One data packet cannot fill a shard set of ten: parity must stay empty, otherwise the
      // encoder is sealing a partial set.
      if (!parity.empty()) {
        Fail(__FILE__, __LINE__, label + ": parity emitted for a single packet");
        return;
      }
      const std::uint16_t type = kcp::internal::ReadLe16(buffer.data() + enc_header + 4);
      if (type != kcp::kTypeData) {
        Fail(__FILE__, __LINE__, label + ": FEC type is not typeData");
        return;
      }
      const std::uint16_t size =
          kcp::internal::ReadLe16(buffer.data() + enc_header + kcp::kFecHeaderSize);
      // fec.go:406 - the length field covers itself plus the segment, i.e. everything from the size
      // field onward. Measured on the golden blob: 8 header + 1400 segment bytes yields 1402.
      const std::size_t expected_size = total - enc_header - kcp::kFecHeaderSize;
      if (size != expected_size) {
        Fail(__FILE__, __LINE__,
             label + ": FEC length field " + std::to_string(size) +
                 " != " + std::to_string(expected_size));
        return;
      }
    }

    // The CRC the generator recorded is computed over the *plaintext* form, before encryption.
    if (crypt == "cfb") {
      if (!GetString(vector, "crc32_le", &crc_text)) {
        Fail(__FILE__, __LINE__, label + ": missing crc32_le");
        return;
      }
      const std::uint32_t want_crc = static_cast<std::uint32_t>(std::stoul(crc_text, nullptr, 16));
      const std::uint32_t plain_crc = kcp::internal::Crc32(buffer.data() + kcp::kCryptHeaderSize,
                                                           total - kcp::kCryptHeaderSize);
      if (plain_crc != want_crc) {
        char text[64];
        std::snprintf(text, sizeof(text), "0x%08x", plain_crc);
        Fail(__FILE__, __LINE__,
             label + ": crc32 " + text + " != " + crc_text +
                 " (coverage must start after the "
                 "nonce/CRC header)");
        return;
      }
    }

    Bytes nonce;
    if (GetString(vector, "nonce_hex", &nonce_hex)) {
      nonce = HexToBytes(nonce_hex);
    }

    const std::size_t wired =
        kcp::internal::EncryptInPlace(block.get(), aead.get(), buffer.data(), total, buffer.size(),
                                      nonce.empty() ? nullptr : nonce.data());
    if (wired != want.size()) {
      Fail(__FILE__, __LINE__,
           label + ": wire size " + std::to_string(wired) + " != " + std::to_string(want.size()));
      return;
    }
    if (!std::equal(want.begin(), want.end(), buffer.begin())) {
      std::size_t at = 0;
      while (at < want.size() && want[at] == buffer[at]) {
        ++at;
      }
      const std::size_t from = at > 8 ? (at - 8) * 2 : 0;
      Fail(__FILE__, __LINE__,
           label + ": wire bytes differ at offset " + std::to_string(at) + " of " +
               std::to_string(want.size()) + "\n  want " + BytesToHex(want).substr(from, 64) +
               "\n  got  " + BytesToHex(buffer).substr(from, 64));
      return;
    }
  }

  if (seen.size() != 6) {
    Fail(__FILE__, __LINE__, "frame.json did not cover all six configurations");
  }
}

// Nonces must not repeat across packets: a fixed nonce would collapse both CFB and GCM.
void TestNonceIsRandom() {
  const Bytes key = GoldenPattern(16, 0x11);
  auto block = kcp::NewAesBlockCrypt(key.data(), key.size());
  Bytes a(64, 0);
  Bytes b(64, 0);
  kcp::internal::EncryptInPlace(block.get(), nullptr, a.data(), a.size(), a.size(), nullptr);
  kcp::internal::EncryptInPlace(block.get(), nullptr, b.data(), b.size(), b.size(), nullptr);
  if (std::memcmp(a.data(), b.data(), kcp::kNonceSize) == 0) {
    Fail(__FILE__, __LINE__, "two packets got the same nonce");
  }
}

// AEAD capacity accounting: Seal needs len + tag, and the helper must refuse a buffer that is one
// byte short instead of writing past it (deviation D1).
void TestAeadCapacity() {
  const Bytes key = GoldenPattern(16, 0x11);
  auto aead = kcp::NewAesGcmCrypt(key.data(), key.size());
  if (aead == nullptr) {
    Fail(__FILE__, __LINE__, "GCM factory failed");
    return;
  }
  Bytes buf(128, 0);
  const std::size_t nonce = aead->nonce_size();
  if (kcp::internal::EncryptInPlace(nullptr, aead.get(), buf.data(), 64, 64 + 15, nullptr) != 0) {
    Fail(__FILE__, __LINE__, "AEAD seal did not reject a short buffer");
  }
  if (kcp::internal::EncryptInPlace(nullptr, aead.get(), buf.data(), 64, 64 + 16, nullptr) !=
      64 + aead->overhead()) {
    Fail(__FILE__, __LINE__, "AEAD seal did not report the tagged size");
  }
  static_cast<void>(nonce);
}

}  // namespace

int main() {
  TestFrameVectors();
  TestNonceIsRandom();
  TestAeadCapacity();

  if (g_failures != 0) {
    std::fprintf(stderr, "frame_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("frame_test: OK\n");
  return 0;
}
