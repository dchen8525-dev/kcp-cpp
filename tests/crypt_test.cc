// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Byte-exact gate for PORTING-PLAN.md P2: every vector in tools/golden/out/crypt.json must be
// reproduced, for every algorithm, at both an aligned (64) and a non-aligned (37) length. The
// non-aligned lengths are what exercise the CFB tail rule (#43); an implementation that silently
// dropped or re-encrypted the tail would still pass the aligned cases.

#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "json_reader.h"
#include "kcp/crypt.h"
#include "kcp/internal/aes.h"
#include "kcp/internal/cfb.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

using Bytes = std::vector<std::uint8_t>;
using kcp::test::BytesToHex;
using kcp::test::Find;
using kcp::test::GetInt;
using kcp::test::GetString;
using kcp::test::HexToBytes;
using kcp::test::JsonValue;
using kcp::test::LoadJsonFile;

std::shared_ptr<kcp::BlockCrypt> MakeBlockCrypt(const std::string& algo, const Bytes& key) {
  if (algo == "aes128cfb" || algo == "aes192cfb" || algo == "aes256cfb") {
    return kcp::NewAesBlockCrypt(key.data(), key.size());
  }
  if (algo == "tea") {
    return kcp::NewTeaBlockCrypt(key.data(), key.size());
  }
  if (algo == "xtea") {
    return kcp::NewXteaBlockCrypt(key.data(), key.size());
  }
  if (algo == "salsa20") {
    return kcp::NewSalsa20BlockCrypt(key.data(), key.size());
  }
  if (algo == "simplexor") {
    return kcp::NewSimpleXorBlockCrypt(key.data(), key.size());
  }
  if (algo == "none") {
    return kcp::NewNoneBlockCrypt(key.data(), key.size());
  }
  return nullptr;
}

// The AES-CFB wire bytes must not depend on which AES implementation produced them, so every AES
// vector is replayed through both the AES-NI and the T-table code path directly.
void CheckAesCfbBothBackends(const std::string& algo, const Bytes& key, const Bytes& plain,
                             const std::string& want_hex) {
  if (algo != "aes128cfb" && algo != "aes192cfb" && algo != "aes256cfb") {
    return;
  }
  struct Named {
    kcp::internal::AesBackend backend;
    const char* name;
  };
  const Named paths[] = {{kcp::internal::AesBackend::kNin, "aes-ni"},
                         {kcp::internal::AesBackend::kTable, "t-table"}};
  for (const Named& path : paths) {
    kcp::internal::Aes aes(key.data(), key.size(), path.backend);
    if (!aes.valid()) {
      Fail(__FILE__, __LINE__, algo + ": key rejected");
      return;
    }
    Bytes out(plain.size());
    kcp::internal::CfbEncrypt(aes, out.data(), plain.data(), plain.size());
    const std::string got = BytesToHex(out);
    if (got != want_hex) {
      Fail(__FILE__, __LINE__, algo + " via " + path.name + ": got " + got + ", want " + want_hex);
    }
  }
}

void TestBlockVectors() {
  JsonValue root;
  std::string error;
  const std::string path = std::string(KCP_VECTOR_DIR) + "/crypt.json";
  if (!LoadJsonFile(path, &root, &error)) {
    Fail(__FILE__, __LINE__, "cannot load " + path + ": " + error);
    return;
  }
  const JsonValue* vectors = Find(root, "vectors");
  if (vectors == nullptr || !vectors->IsArray()) {
    Fail(__FILE__, __LINE__, "crypt.json has no vectors array");
    return;
  }

  std::set<std::string> block_algos;
  std::set<std::size_t> lengths;
  std::size_t gcm_checked = 0;

  for (const JsonValue& vector : vectors->array_value) {
    std::string algo;
    std::string key_hex;
    std::string plain_hex;
    std::string cipher_hex;
    long long block_size = 0;
    if (!GetString(vector, "algo", &algo) || !GetString(vector, "key_hex", &key_hex) ||
        !GetString(vector, "plain_hex", &plain_hex) ||
        !GetString(vector, "cipher_hex", &cipher_hex) ||
        !GetInt(vector, "block_size", &block_size)) {
      Fail(__FILE__, __LINE__, "crypt vector missing a required field");
      continue;
    }
    const Bytes key = HexToBytes(key_hex);
    const Bytes plain = HexToBytes(plain_hex);
    const Bytes want = HexToBytes(cipher_hex);

    if (algo == "aesgcm") {
      std::string nonce_hex;
      std::string tag_hex;
      if (!GetString(vector, "nonce_hex", &nonce_hex) || !GetString(vector, "tag_hex", &tag_hex)) {
        Fail(__FILE__, __LINE__, "aesgcm vector missing nonce or tag");
        continue;
      }
      const Bytes nonce = HexToBytes(nonce_hex);
      const Bytes want_tag = HexToBytes(tag_hex);
      auto aead = kcp::NewAesGcmCrypt(key.data(), key.size());
      if (aead == nullptr) {
        Fail(__FILE__, __LINE__, "aesgcm: factory returned null");
        continue;
      }
      if (aead->nonce_size() != nonce.size() || aead->overhead() != want_tag.size()) {
        Fail(__FILE__, __LINE__, "aesgcm: nonce or overhead mismatch");
        continue;
      }
      Bytes sealed(plain.size() + aead->overhead());
      const kcp::ErrorCode rc =
          aead->Seal(sealed.data(), sealed.size(), nonce.data(), plain.data(), plain.size());
      if (rc != kcp::ErrorCode::kOk) {
        Fail(__FILE__, __LINE__, "aesgcm: Seal failed");
        continue;
      }
      if (BytesToHex(sealed.data(), plain.size()) != cipher_hex) {
        Fail(__FILE__, __LINE__,
             "aesgcm len=" + std::to_string(plain.size()) + " ciphertext mismatch");
      }
      if (BytesToHex(sealed.data() + plain.size(), aead->overhead()) != tag_hex) {
        Fail(__FILE__, __LINE__, "aesgcm len=" + std::to_string(plain.size()) + " tag mismatch");
      }
      Bytes opened(plain.size());
      if (aead->Open(opened.data(), opened.size(), nonce.data(), sealed.data(), sealed.size()) !=
          kcp::ErrorCode::kOk) {
        Fail(__FILE__, __LINE__, "aesgcm: Open rejected its own Seal output");
      } else if (opened != plain) {
        Fail(__FILE__, __LINE__, "aesgcm: Open(Seal(x)) != x");
      }
      ++gcm_checked;
      continue;
    }

    auto crypt = MakeBlockCrypt(algo, key);
    if (crypt == nullptr) {
      Fail(__FILE__, __LINE__, algo + ": factory returned null");
      continue;
    }
    block_algos.insert(algo);
    lengths.insert(plain.size());

    Bytes out(plain.size(), 0xa5);
    crypt->Encrypt(out.data(), plain.data(), plain.size());
    if (BytesToHex(out) != cipher_hex) {
      Fail(__FILE__, __LINE__,
           algo + " len=" + std::to_string(plain.size()) + ": got " + BytesToHex(out) + ", want " +
               cipher_hex);
    }

    // Decryption must invert the vector, both out of place and in place.
    Bytes back(plain.size(), 0);
    crypt->Decrypt(back.data(), want.data(), want.size());
    if (back != plain) {
      Fail(__FILE__, __LINE__, algo + " len=" + std::to_string(plain.size()) + ": round trip");
    }
    Bytes in_place = plain;
    crypt->Encrypt(in_place.data(), in_place.data(), in_place.size());
    if (BytesToHex(in_place) != cipher_hex) {
      Fail(__FILE__, __LINE__,
           algo + " len=" + std::to_string(plain.size()) + ": in-place encrypt differs");
    }
    crypt->Decrypt(in_place.data(), in_place.data(), in_place.size());
    if (in_place != plain) {
      Fail(__FILE__, __LINE__,
           algo + " len=" + std::to_string(plain.size()) + ": in-place round trip");
    }

    CheckAesCfbBothBackends(algo, key, plain, cipher_hex);
  }

  // Coverage guard: a truncated crypt.json would otherwise make this test silently weaker.
  const char* kExpected[] = {"aes128cfb", "aes192cfb", "aes256cfb", "tea",
                             "xtea",      "salsa20",   "simplexor", "none"};
  for (const char* name : kExpected) {
    if (block_algos.count(name) == 0) {
      Fail(__FILE__, __LINE__, std::string("missing vectors for ") + name);
    }
  }
  if (gcm_checked != 2) {
    Fail(__FILE__, __LINE__, "expected 2 aesgcm vectors, saw " + std::to_string(gcm_checked));
  }
  if (lengths != std::set<std::size_t>({64, 37})) {
    Fail(__FILE__, __LINE__, "vectors must cover both 64-byte and 37-byte lengths");
  }
}

void TestFactoryRejectsBadKeys() {
  const std::uint8_t key[40] = {};
  if (kcp::NewAesBlockCrypt(key, 20) != nullptr) {
    Fail(__FILE__, __LINE__, "NewAesBlockCrypt accepted a 20-byte key");
  }
  if (kcp::NewAesGcmCrypt(key, 8) != nullptr) {
    Fail(__FILE__, __LINE__, "NewAesGcmCrypt accepted an 8-byte key");
  }
  if (kcp::NewTeaBlockCrypt(key, 15) != nullptr) {
    Fail(__FILE__, __LINE__, "NewTeaBlockCrypt accepted a 15-byte key");
  }
  if (kcp::NewXteaBlockCrypt(key, 24) != nullptr) {
    Fail(__FILE__, __LINE__, "NewXteaBlockCrypt accepted a 24-byte key");
  }
  for (const std::size_t len : {std::size_t{16}, std::size_t{24}, std::size_t{32}}) {
    if (kcp::NewAesBlockCrypt(key, len) == nullptr) {
      Fail(__FILE__, __LINE__, "NewAesBlockCrypt rejected a valid key length");
    }
  }
}

void TestAeadCapacityContract() {
  const Bytes key = HexToBytes("0102030405060708090a0b0c0d0e0f10");
  const Bytes nonce = HexToBytes("0f0e0d0c0b0a090807060504");
  const Bytes plain(32, 0x33);
  auto aead = kcp::NewAesGcmCrypt(key.data(), key.size());
  if (aead == nullptr) {
    Fail(__FILE__, __LINE__, "aesgcm factory returned null");
    return;
  }
  Bytes dst(plain.size() + aead->overhead());
  // One byte short of what Seal needs: Go panics here, C++ must report it (deviation D1).
  if (aead->Seal(dst.data(), dst.size() - 1, nonce.data(), plain.data(), plain.size()) !=
      kcp::ErrorCode::kBufferTooSmall) {
    Fail(__FILE__, __LINE__, "Seal did not report kBufferTooSmall");
  }
  if (aead->Seal(nullptr, 0, nonce.data(), plain.data(), plain.size()) !=
      kcp::ErrorCode::kBufferTooSmall) {
    Fail(__FILE__, __LINE__, "Seal accepted a null destination");
  }
  if (aead->Seal(dst.data(), dst.size(), nonce.data(), plain.data(), plain.size()) !=
      kcp::ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "Seal rejected an exactly sized destination");
  }

  Bytes opened(plain.size());
  if (aead->Open(opened.data(), opened.size() - 1, nonce.data(), dst.data(), dst.size()) !=
      kcp::ErrorCode::kBufferTooSmall) {
    Fail(__FILE__, __LINE__, "Open did not report kBufferTooSmall");
  }
  // A ciphertext shorter than the tag can never authenticate.
  if (aead->Open(opened.data(), opened.size(), nonce.data(), dst.data(), aead->overhead() - 1) !=
      kcp::ErrorCode::kIntegrityFailed) {
    Fail(__FILE__, __LINE__, "Open accepted a ciphertext shorter than the tag");
  }
  dst.back() ^= 0x01;
  if (aead->Open(opened.data(), opened.size(), nonce.data(), dst.data(), dst.size()) !=
      kcp::ErrorCode::kIntegrityFailed) {
    Fail(__FILE__, __LINE__, "Open accepted a corrupted tag");
  }
}

void TestEmptyInputs() {
  const Bytes key = HexToBytes("0102030405060708090a0b0c0d0e0f10");
  for (const char* algo : {"none", "simplexor", "tea", "xtea", "salsa20", "aes128cfb"}) {
    auto crypt = MakeBlockCrypt(algo, key);
    if (crypt == nullptr) {
      Fail(__FILE__, __LINE__, std::string(algo) + ": factory returned null");
      continue;
    }
    std::uint8_t dst[1] = {0x7f};
    const std::uint8_t src[1] = {0x7f};
    // Zero-length encryption must be a no-op for every algorithm (crypt.go early returns).
    crypt->Encrypt(dst, src, 0);
    if (dst[0] != 0x7f) {
      Fail(__FILE__, __LINE__, std::string(algo) + ": zero-length encrypt wrote to dst");
    }
  }
}

// NewAeadCrypt is the identity adapter (crypt.go:103); check it does not wrap or copy.
void TestAeadAdapter() {
  const Bytes key = HexToBytes("0102030405060708090a0b0c0d0e0f10");
  auto inner = kcp::NewAesGcmCrypt(key.data(), key.size());
  if (inner == nullptr) {
    Fail(__FILE__, __LINE__, "aesgcm factory returned null");
    return;
  }
  auto outer = kcp::NewAeadCrypt(inner);
  if (outer.get() != inner.get()) {
    Fail(__FILE__, __LINE__, "NewAeadCrypt did not return the same instance");
  }
  if (kcp::NewAeadCrypt(nullptr) != nullptr) {
    Fail(__FILE__, __LINE__, "NewAeadCrypt accepted null");
  }
}

}  // namespace

int main() {
  TestBlockVectors();
  TestFactoryRejectsBadKeys();
  TestAeadCapacityContract();
  TestEmptyInputs();
  TestAeadAdapter();

  if (g_failures != 0) {
    std::fprintf(stderr, "crypt_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("crypt_test: OK\n");
  return 0;
}
