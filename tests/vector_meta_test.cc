// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Validates the golden vector files produced by tools/golden: schema shape, required fields and
// the byte-length invariants that the later stages (P2/P3/P4/P5/P6) depend on. This test does not
// re-run any crypto; it only proves the vectors are complete and self-consistent, which is the one
// thing that must be true before they are used as an oracle.

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "json_reader.h"

namespace {

int g_failures = 0;

void ReportFailure(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

#define CHECK(expr)                             \
  do {                                          \
    if (!(expr)) {                              \
      ReportFailure(__FILE__, __LINE__, #expr); \
    }                                           \
  } while (0)

#define CHECK_MSG(expr, message)                    \
  do {                                              \
    if (!(expr)) {                                  \
      ReportFailure(__FILE__, __LINE__, (message)); \
    }                                               \
  } while (0)

using kcp::test::Find;
using kcp::test::GetInt;
using kcp::test::GetString;
using kcp::test::HexToBytes;
using kcp::test::JsonValue;
using kcp::test::LoadJsonFile;

std::string VectorPath(const char* name) { return std::string(KCP_VECTOR_DIR) + "/" + name; }

// Loads "<name>" and returns false (with a failure recorded) when the file is missing or invalid.
bool LoadVector(const char* name, JsonValue* root) {
  std::string error;
  const std::string path = VectorPath(name);
  if (!LoadJsonFile(path, root, &error)) {
    ReportFailure(__FILE__, __LINE__, "cannot load " + path + ": " + error);
    return false;
  }
  return true;
}

bool CheckMeta(const JsonValue& root, const char* name) {
  const JsonValue* meta = Find(root, "meta");
  if (meta == nullptr || !meta->IsObject()) {
    ReportFailure(__FILE__, __LINE__, std::string(name) + ": missing meta object");
    return false;
  }
  long long schema = 0;
  std::string commit;
  std::string go_version;
  const bool ok_schema = GetInt(*meta, "schema", &schema) && schema >= 1;
  const bool ok_commit = GetString(*meta, "kcp_go_commit", &commit) && commit.size() >= 7;
  const bool ok_go = GetString(*meta, "go_version", &go_version) && !go_version.empty();
  CHECK_MSG(ok_schema, std::string(name) + ": meta.schema must be >= 1");
  CHECK_MSG(ok_commit, std::string(name) + ": meta.kcp_go_commit must be a commit hash");
  CHECK_MSG(ok_go, std::string(name) + ": meta.go_version must be present");
  return ok_schema && ok_commit && ok_go;
}

const JsonValue* Vectors(const JsonValue& root, const char* name) {
  const JsonValue* vectors = Find(root, "vectors");
  if (vectors == nullptr || !vectors->IsArray() || vectors->size() == 0) {
    ReportFailure(__FILE__, __LINE__, std::string(name) + ": vectors must be a non-empty array");
    return nullptr;
  }
  return vectors;
}

void CheckCrypt() {
  JsonValue root;
  if (!LoadVector("crypt.json", &root) || !CheckMeta(root, "crypt.json")) {
    return;
  }
  const JsonValue* vectors = Vectors(root, "crypt.json");
  if (vectors == nullptr) {
    return;
  }

  std::set<std::string> algorithms;
  for (const JsonValue& v : vectors->array_value) {
    std::string algo;
    CHECK(GetString(v, "algo", &algo));
    if (!algo.empty()) {
      algorithms.insert(algo);
    }
    if (!algo.empty() && algo != "none") {
      std::string key_hex;
      CHECK_MSG(GetString(v, "key_hex", &key_hex) && !key_hex.empty(), algo + ": key_hex missing");
    }

    if (algo == "aesgcm") {
      std::string nonce_hex;
      std::string tag_hex;
      std::string cipher_hex;
      CHECK(GetString(v, "nonce_hex", &nonce_hex) && HexToBytes(nonce_hex).size() == 12);
      CHECK(GetString(v, "tag_hex", &tag_hex) && HexToBytes(tag_hex).size() == 16);
      CHECK(GetString(v, "cipher_hex", &cipher_hex) && !HexToBytes(cipher_hex).empty());
      continue;
    }

    std::string plain_hex;
    std::string cipher_hex;
    CHECK(GetString(v, "plain_hex", &plain_hex));
    CHECK(GetString(v, "cipher_hex", &cipher_hex));
    const auto plain = HexToBytes(plain_hex);
    const auto cipher = HexToBytes(cipher_hex);
    // CFB / Salsa20 / XOR are stream-like: ciphertext length == plaintext length at every offset,
    // including the non-block-aligned tails that #43 warns about.
    CHECK_MSG(cipher.size() == plain.size(), algo + ": cipher length must equal plaintext length");
    CHECK_MSG(!plain.empty(), algo + ": plaintext must not be empty");
  }

  // Every algorithm the port must implement, except the unsupported legacy ciphers.
  const char* kRequired[] = {"aes128cfb", "aes192cfb", "aes256cfb", "tea",   "xtea",
                             "salsa20",   "simplexor", "none",      "aesgcm"};
  for (const char* required : kRequired) {
    CHECK_MSG(algorithms.count(required) == 1, std::string("crypt.json missing algo: ") + required);
  }
}

void CheckReedSolomon() {
  JsonValue root;
  if (!LoadVector("rs.json", &root) || !CheckMeta(root, "rs.json")) {
    return;
  }
  const JsonValue* vectors = Vectors(root, "rs.json");
  if (vectors == nullptr) {
    return;
  }
  for (const JsonValue& v : vectors->array_value) {
    long long data_shards = 0;
    long long parity_shards = 0;
    long long shard_size = 0;
    CHECK(GetInt(v, "data_shards", &data_shards) && data_shards > 0);
    CHECK(GetInt(v, "parity_shards", &parity_shards) && parity_shards > 0);
    CHECK(GetInt(v, "shard_size", &shard_size) && shard_size > 0);

    const JsonValue* parity = Find(v, "parity_hex");
    CHECK(parity != nullptr && parity->IsArray());
    if (parity != nullptr) {
      CHECK(static_cast<long long>(parity->size()) == parity_shards);
      for (const JsonValue& shard : parity->array_value) {
        CHECK(shard.IsString());
        CHECK(HexToBytes(shard.string_value).size() == static_cast<std::size_t>(shard_size));
      }
    }

    const JsonValue* data = Find(v, "data_hex");
    CHECK(data != nullptr && data->IsArray());
    if (data != nullptr) {
      CHECK(static_cast<long long>(data->size()) == data_shards);
    }

    // Erasure recovery must name shards and carry the recovered bytes.
    const JsonValue* erased = Find(v, "erased");
    const JsonValue* recovered = Find(v, "recovered_hex");
    CHECK(erased != nullptr && erased->IsArray() && erased->size() > 0);
    CHECK(recovered != nullptr && recovered->IsArray() && recovered->size() > 0);

    // The first rows of the encoding matrix pin the Vandermonde construction bit for bit.
    // Row count is min(4, parity_shards), recorded explicitly in the vector.
    const JsonValue* matrix = Find(v, "matrix_head");
    long long matrix_rows = 0;
    CHECK(GetInt(v, "matrix_rows", &matrix_rows));
    const long long expected_rows = parity_shards < 4 ? parity_shards : 4;
    CHECK_MSG(matrix_rows == expected_rows, "rs.json: matrix_rows must be min(4, parity_shards)");
    CHECK(matrix != nullptr && matrix->IsArray() &&
          static_cast<long long>(matrix->size()) == expected_rows);
    if (matrix != nullptr && matrix->IsArray()) {
      for (const JsonValue& row : matrix->array_value) {
        CHECK(row.IsArray() && row.size() == static_cast<std::size_t>(data_shards));
      }
    }
  }
}

void CheckFec() {
  JsonValue root;
  if (!LoadVector("fec.json", &root) || !CheckMeta(root, "fec.json")) {
    return;
  }
  const JsonValue* vectors = Vectors(root, "fec.json");
  if (vectors == nullptr) {
    return;
  }
  bool saw_encode = false;
  bool saw_decode = false;
  bool saw_oob = false;
  bool saw_varlen = false;
  for (const JsonValue& v : vectors->array_value) {
    std::string kind;
    CHECK(GetString(v, "kind", &kind));
    long long parity_shards = 0;
    CHECK(GetInt(v, "parity_shards", &parity_shards));

    if (kind == "encode") {
      saw_encode = true;
      long long expect = 0;
      CHECK(GetInt(v, "expect_parity_count", &expect));
      CHECK_MSG(expect == parity_shards,
                "fec.json encode: expect_parity_count must equal "
                "parity_shards (deterministic under "
                "maxFECEncodeLatency=500)");
      const JsonValue* parity = Find(v, "parity_hex");
      CHECK(parity != nullptr && parity->IsArray() &&
            static_cast<long long>(parity->size()) == parity_shards);
      const JsonValue* packets = Find(v, "packets_hex");
      CHECK(packets != nullptr && packets->IsArray() && packets->size() > 0);
    } else if (kind == "encode-varlen") {
      saw_varlen = true;
      long long expect = 0;
      CHECK(GetInt(v, "expect_parity_count", &expect));
      CHECK_MSG(expect == parity_shards, "fec.json encode-varlen: expect_parity_count mismatch");
      const JsonValue* parity = Find(v, "parity_hex");
      CHECK(parity != nullptr && parity->IsArray() &&
            static_cast<long long>(parity->size()) == parity_shards);
      const JsonValue* packets = Find(v, "packets_hex");
      CHECK(packets != nullptr && packets->IsArray() &&
            static_cast<long long>(packets->size()) > 1);
      if (packets != nullptr && packets->IsArray()) {
        // The whole point of this vector is unequal shard lengths; equal ones would silently
        // stop covering the zero-extension path.
        const std::size_t first = HexToBytes(packets->array_value[0].string_value).size();
        bool differs = false;
        for (const JsonValue& item : packets->array_value) {
          if (HexToBytes(item.string_value).size() != first) {
            differs = true;
          }
        }
        CHECK_MSG(differs, "fec.json encode-varlen: shard lengths are all equal");
      }
    } else if (kind == "decode") {
      saw_decode = true;
      const JsonValue* dropped = Find(v, "dropped");
      const JsonValue* recovered = Find(v, "recovered_hex");
      CHECK(dropped != nullptr && dropped->IsArray() && dropped->size() > 0);
      CHECK(recovered != nullptr && recovered->IsArray() && recovered->size() > 0);
    } else if (kind == "oob") {
      saw_oob = true;
      std::string packet_hex;
      CHECK(GetString(v, "packet_hex", &packet_hex) && !HexToBytes(packet_hex).empty());
      // OOB frame: FEC header (8 bytes, kFecHeaderSizePlus2) + conv (4) + payload.
      const auto packet = HexToBytes(packet_hex);
      CHECK_MSG(packet.size() >= 12, "fec.json oob: frame must be >= 12 bytes");
    } else {
      ReportFailure(__FILE__, __LINE__, "fec.json: unknown kind '" + kind + "'");
    }
  }
  CHECK(saw_encode);
  CHECK(saw_decode);
  CHECK(saw_oob);
  CHECK(saw_varlen);
}

void CheckKcp() {
  JsonValue root;
  if (!LoadVector("kcp.json", &root) || !CheckMeta(root, "kcp.json")) {
    return;
  }
  const JsonValue* vectors = Vectors(root, "kcp.json");
  if (vectors == nullptr) {
    return;
  }
  bool saw_message = false;
  bool saw_stream = false;
  for (const JsonValue& v : vectors->array_value) {
    bool stream = false;
    CHECK(kcp::test::GetBool(v, "stream", &stream));
    saw_stream = saw_stream || stream;
    saw_message = saw_message || !stream;

    const JsonValue* params = Find(v, "params");
    CHECK(params != nullptr && params->IsObject());
    if (params != nullptr) {
      long long conv = 0;
      long long mtu = 0;
      long long snd_wnd = 0;
      long long rcv_wnd = 0;
      CHECK(GetInt(*params, "conv", &conv) && conv > 0);
      // §4.6: mtu=1400, snd_wnd=32, rcv_wnd=32. rcv_wnd is written into the segment wnd field, so
      // a wrong default silently breaks byte comparison.
      CHECK(GetInt(*params, "mtu", &mtu) && mtu == 1400);
      CHECK(GetInt(*params, "snd_wnd", &snd_wnd) && snd_wnd == 32);
      CHECK(GetInt(*params, "rcv_wnd", &rcv_wnd) && rcv_wnd == 32);
    }

    const JsonValue* segments = Find(v, "segments");
    CHECK(segments != nullptr && segments->IsArray() && segments->size() > 0);
    if (segments == nullptr || !segments->IsArray()) {
      continue;
    }
    for (const JsonValue& seg : segments->array_value) {
      long long len = 0;
      std::string bytes_hex;
      CHECK(GetInt(seg, "len", &len));
      CHECK(GetString(seg, "bytes_hex", &bytes_hex));
      bool ts_masked = false;
      CHECK(kcp::test::GetBool(seg, "ts_masked", &ts_masked) && ts_masked);
      const auto bytes = HexToBytes(bytes_hex);
      // kOverhead = 24 includes conv (§4.7 / #57).
      CHECK_MSG(bytes.size() == static_cast<std::size_t>(len) + 24,
                "kcp.json: segment bytes must be 24-byte header + len payload");
      long long cmd = 0;
      CHECK(GetInt(seg, "cmd", &cmd) && cmd >= 81 && cmd <= 84);
    }
  }
  CHECK_MSG(saw_message, "kcp.json: missing message-mode vector");
  CHECK_MSG(saw_stream, "kcp.json: missing stream-mode vector");
}

void CheckFrame() {
  JsonValue root;
  if (!LoadVector("frame.json", &root) || !CheckMeta(root, "frame.json")) {
    return;
  }
  const JsonValue* vectors = Vectors(root, "frame.json");
  if (vectors == nullptr) {
    return;
  }

  // The six wire configurations of §4.2, keyed by (crypt, fec).
  struct Expected {
    const char* crypt;
    bool fec;
    int header_size;
    int extra_overhead;  // AEAD tag
  };
  const Expected kExpected[] = {
      {"none", false, 0, 0}, {"none", true, 8, 0},      {"cfb", false, 20, 0},
      {"cfb", true, 28, 0},  {"aesgcm", false, 12, 16}, {"aesgcm", true, 20, 16},
  };

  int matched = 0;
  for (const Expected& expected : kExpected) {
    bool found = false;
    for (const JsonValue& v : vectors->array_value) {
      std::string crypt;
      bool fec = false;
      long long header_size = -1;
      if (!GetString(v, "crypt", &crypt) || !kcp::test::GetBool(v, "fec", &fec) ||
          !GetInt(v, "header_size", &header_size)) {
        continue;
      }
      if (crypt != expected.crypt || fec != expected.fec) {
        continue;
      }
      found = true;
      ++matched;
      CHECK_MSG(header_size == expected.header_size,
                std::string("frame.json ") + crypt + (fec ? "+fec" : "") +
                    ": header_size must be " + std::to_string(expected.header_size));

      std::string seg_hex;
      std::string blob_hex;
      CHECK(GetString(v, "kcp_seg_hex", &seg_hex));
      CHECK(GetString(v, "encrypted_blob_hex", &blob_hex));
      const auto seg = HexToBytes(seg_hex);
      const auto blob = HexToBytes(blob_hex);
      CHECK_MSG(blob.size() == seg.size() + static_cast<std::size_t>(expected.header_size) +
                                   static_cast<std::size_t>(expected.extra_overhead),
                std::string("frame.json ") + crypt + (fec ? "+fec" : "") +
                    ": blob length must be header_size + segment (+ tag for AEAD)");

      if (crypt == "cfb") {
        std::string nonce_hex;
        std::string crc32_le;
        CHECK(GetString(v, "nonce_hex", &nonce_hex) && HexToBytes(nonce_hex).size() == 16);
        CHECK(GetString(v, "crc32_le", &crc32_le) && !crc32_le.empty());
      } else if (crypt == "aesgcm") {
        std::string nonce_hex;
        CHECK(GetString(v, "nonce_hex", &nonce_hex) && HexToBytes(nonce_hex).size() == 12);
      }
    }
    CHECK_MSG(found, std::string("frame.json missing configuration: ") + expected.crypt +
                         (expected.fec ? "+fec" : ""));
  }
  CHECK_MSG(matched == 6, "frame.json must cover exactly the six wire configurations");
}

}  // namespace

int main() {
  CheckCrypt();
  CheckReedSolomon();
  CheckFec();
  CheckKcp();
  CheckFrame();

  if (g_failures != 0) {
    std::fprintf(stderr, "vector_meta_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("vector_meta_test: OK\n");
  return 0;
}
