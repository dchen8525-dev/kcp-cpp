// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Gate for PORTING-PLAN.md P3: the encoding matrix must be systematic (top data_shards rows are
// the identity), every parity byte in tools/golden/out/rs.json must be reproduced exactly, and
// erasure recovery must succeed for 1000 randomised rounds split evenly between equal-length and
// variable-length shard sets.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "json_reader.h"
#include "kcp/internal/rs.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

using Bytes = std::vector<std::uint8_t>;
using kcp::internal::ReedSolomon;
using kcp::internal::ShardSet;
using kcp::test::BytesToHex;
using kcp::test::Find;
using kcp::test::GetInt;
using kcp::test::HexToBytes;
using kcp::test::JsonValue;
using kcp::test::LoadJsonFile;

bool ToShardSet(const JsonValue& array, ShardSet* out) {
  out->clear();
  for (const JsonValue& item : array.array_value) {
    if (!item.IsString()) {
      return false;
    }
    out->push_back(HexToBytes(item.string_value));
  }
  return true;
}

// ---------------------------------------------------------------------------
// Matrix shape
// ---------------------------------------------------------------------------

void TestMatrixIsSystematic() {
  const int kConfigs[][2] = {{1, 1}, {2, 1}, {3, 1}, {10, 3}, {20, 10}, {64, 32}, {128, 128}};
  for (const auto& config : kConfigs) {
    const int data = config[0];
    const int parity = config[1];
    auto codec = ReedSolomon::New(data, parity);
    const std::string label = "(" + std::to_string(data) + "," + std::to_string(parity) + ")";
    if (codec == nullptr) {
      Fail(__FILE__, __LINE__, "New failed for " + label);
      continue;
    }
    if (codec->total_shards() != data + parity) {
      Fail(__FILE__, __LINE__, "total_shards wrong for " + label);
    }
    // Identity in the top square: this is the property that makes the code systematic, and the
    // whole reason for the Vandermonde-times-inverse construction.
    for (int r = 0; r < data; ++r) {
      for (int c = 0; c < data; ++c) {
        const std::uint8_t want = (r == c) ? 1 : 0;
        if (codec->MatrixAt(r, c) != want) {
          Fail(__FILE__, __LINE__,
               "matrix not systematic at " + label + " row " + std::to_string(r) + " col " +
                   std::to_string(c) + ": got " + std::to_string(codec->MatrixAt(r, c)));
        }
      }
    }
    // A parity row made only of zeros would be a useless (non-MDS) code. All-ones is legitimate
    // -- with a single parity shard the only sensible code is the XOR of the data shards.
    if (parity > 0) {
      bool all_zero = true;
      for (int c = 0; c < data; ++c) {
        all_zero = all_zero && codec->MatrixAt(data, c) == 0;
      }
      if (all_zero) {
        Fail(__FILE__, __LINE__, "degenerate parity row for " + label);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------

void TestGoldenVectors() {
  JsonValue root;
  std::string error;
  const std::string path = std::string(KCP_VECTOR_DIR) + "/rs.json";
  if (!LoadJsonFile(path, &root, &error)) {
    Fail(__FILE__, __LINE__, "cannot load " + path + ": " + error);
    return;
  }
  const JsonValue* vectors = Find(root, "vectors");
  if (vectors == nullptr || !vectors->IsArray()) {
    Fail(__FILE__, __LINE__, "rs.json has no vectors array");
    return;
  }

  for (std::size_t i = 0; i < vectors->array_value.size(); ++i) {
    const JsonValue& v = vectors->array_value[i];
    long long data_shards = 0;
    long long parity_shards = 0;
    if (!GetInt(v, "data_shards", &data_shards) || !GetInt(v, "parity_shards", &parity_shards)) {
      Fail(__FILE__, __LINE__, "vector " + std::to_string(i) + " missing shard counts");
      continue;
    }
    const std::string label = "vector " + std::to_string(i) + " (" + std::to_string(data_shards) +
                              "," + std::to_string(parity_shards) + ")";
    auto codec = ReedSolomon::New(static_cast<int>(data_shards), static_cast<int>(parity_shards));
    if (codec == nullptr) {
      Fail(__FILE__, __LINE__, "New failed for " + label);
      continue;
    }

    const JsonValue* data_json = Find(v, "data_hex");
    const JsonValue* parity_json = Find(v, "parity_hex");
    const JsonValue* erased_json = Find(v, "erased");
    const JsonValue* recovered_json = Find(v, "recovered_hex");
    const JsonValue* head_json = Find(v, "matrix_head");
    if (data_json == nullptr || parity_json == nullptr || erased_json == nullptr ||
        recovered_json == nullptr || head_json == nullptr) {
      Fail(__FILE__, __LINE__, label + " is missing a field");
      continue;
    }

    ShardSet want_data;
    ShardSet want_parity;
    if (!ToShardSet(*data_json, &want_data) || !ToShardSet(*parity_json, &want_parity)) {
      Fail(__FILE__, __LINE__, label + " has non-string shards");
      continue;
    }

    // matrix_head: the top min(4, parity) rows of the encoding matrix, probed from the Go side
    // through unit-vector encodes.
    for (std::size_t r = 0; r < head_json->array_value.size(); ++r) {
      const JsonValue& row = head_json->array_value[r];
      for (std::size_t c = 0; c < row.array_value.size(); ++c) {
        const long long want = static_cast<long long>(row.array_value[c].number_value);
        const std::uint8_t got = codec->MatrixAt(
            static_cast<int>(data_shards) + static_cast<int>(r), static_cast<int>(c));
        if (got != want) {
          Fail(__FILE__, __LINE__,
               label + " matrix_head mismatch at row " + std::to_string(r) + " col " +
                   std::to_string(c) + ": got " + std::to_string(got) + " want " +
                   std::to_string(want));
        }
      }
    }

    // Encode: data shards untouched, parity must match byte for byte.
    ShardSet shards = want_data;
    for (std::size_t k = 0; k < want_parity.size(); ++k) {
      shards.push_back(Bytes(want_data[0].size(), 0));
    }
    if (codec->Encode(&shards) != kcp::ErrorCode::kOk) {
      Fail(__FILE__, __LINE__, label + " encode returned an error");
      continue;
    }
    for (std::size_t k = 0; k < want_data.size(); ++k) {
      if (shards[k] != want_data[k]) {
        Fail(__FILE__, __LINE__, label + " encode modified data shard " + std::to_string(k));
      }
    }
    for (std::size_t k = 0; k < want_parity.size(); ++k) {
      const Bytes& got = shards[want_data.size() + k];
      if (got != want_parity[k]) {
        Fail(__FILE__, __LINE__,
             label + " parity " + std::to_string(k) + " mismatch\n  got  " + BytesToHex(got) +
                 "\n  want " + BytesToHex(want_parity[k]));
      }
    }

    // ReconstructData: drop the recorded shards, recover them exactly.
    for (const JsonValue& e : erased_json->array_value) {
      const std::size_t index = static_cast<std::size_t>(e.number_value);
      if (index >= shards.size()) {
        Fail(__FILE__, __LINE__, label + " erased index out of range");
        continue;
      }
      shards[index].clear();
    }
    if (codec->ReconstructData(&shards) != kcp::ErrorCode::kOk) {
      Fail(__FILE__, __LINE__, label + " ReconstructData returned an error");
      continue;
    }
    for (std::size_t k = 0; k < want_data.size(); ++k) {
      if (shards[k] != want_data[k]) {
        Fail(__FILE__, __LINE__,
             label + " recovered data shard " + std::to_string(k) + " mismatch\n  got  " +
                 BytesToHex(shards[k]) + "\n  want " + BytesToHex(want_data[k]));
      }
    }
    for (std::size_t k = 0; k < recovered_json->array_value.size(); ++k) {
      const Bytes want = HexToBytes(recovered_json->array_value[k].string_value);
      if (shards[k] != want) {
        Fail(__FILE__, __LINE__, label + " recovered_hex " + std::to_string(k) + " mismatch");
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Randomised erasure recovery
// ---------------------------------------------------------------------------

Bytes RandomBytes(std::mt19937* rng, std::size_t len) {
  Bytes out(len);
  for (std::size_t i = 0; i < len; ++i) {
    out[i] = static_cast<std::uint8_t>((*rng)() & 0xff);
  }
  return out;
}

// Erases `count` distinct random shard indices.
std::vector<std::size_t> PickErasures(std::mt19937* rng, std::size_t total, std::size_t count) {
  std::vector<std::size_t> order(total);
  for (std::size_t i = 0; i < total; ++i) {
    order[i] = i;
  }
  std::shuffle(order.begin(), order.end(), *rng);
  order.resize(count);
  return order;
}

void TestRandomErasuresEqualLength() {
  std::mt19937 rng(0x5eed1234u);
  const int kDataChoices[] = {3, 10, 20, 33};
  const int kParityChoices[] = {1, 3, 10};

  for (int round = 0; round < 500; ++round) {
    const int data = kDataChoices[rng() % 4];
    const int parity = kParityChoices[rng() % 3];
    const std::size_t size = 1 + (rng() % 300);
    auto codec = ReedSolomon::New(data, parity);
    if (codec == nullptr) {
      Fail(__FILE__, __LINE__, "New failed in equal-length round");
      return;
    }

    ShardSet shards;
    for (int i = 0; i < data; ++i) {
      shards.push_back(RandomBytes(&rng, size));
    }
    for (int j = 0; j < parity; ++j) {
      shards.push_back(Bytes(size, 0));
    }
    if (codec->Encode(&shards) != kcp::ErrorCode::kOk) {
      Fail(__FILE__, __LINE__, "encode failed in equal-length round");
      return;
    }
    ShardSet reference = shards;

    // Up to `parity` losses are always recoverable, wherever they fall.
    const std::size_t losses = 1 + (rng() % static_cast<std::size_t>(parity));
    for (std::size_t index : PickErasures(&rng, shards.size(), losses)) {
      shards[index].clear();
    }
    const bool data_only = (rng() & 1) != 0;
    const kcp::ErrorCode rc =
        data_only ? codec->ReconstructData(&shards) : codec->Reconstruct(&shards);
    if (rc != kcp::ErrorCode::kOk) {
      Fail(__FILE__, __LINE__, "reconstruct failed in equal-length round");
      return;
    }
    // ReconstructData leaves missing parity shards missing by design (reedsolomon.go:1186 early
    // out for dataOnly), so only compare what was asked for.
    const std::size_t compare = data_only ? static_cast<std::size_t>(data) : shards.size();
    for (std::size_t k = 0; k < compare; ++k) {
      if (shards[k] != reference[k]) {
        Fail(__FILE__, __LINE__,
             "reconstruct mismatch in equal-length round " + std::to_string(round) + " (" +
                 std::to_string(data) + "," + std::to_string(parity) +
                 ") losses=" + std::to_string(losses) + " shard=" + std::to_string(k));
        return;
      }
    }
  }
}

void TestRandomErasuresVariableLength() {
  // Variable-length shards are the FEC layer's world: pad to maxlen, then the RS layer only ever
  // sees equal lengths (PORTING-PLAN.md #41). Recovery must return the padded content.
  std::mt19937 rng(0xc0ffeeu);
  for (int round = 0; round < 500; ++round) {
    const int data = 3 + static_cast<int>(rng() % 10);
    const int parity = 1 + static_cast<int>(rng() % 3);
    const std::size_t max_len = 1 + (rng() % 200);
    auto codec = ReedSolomon::New(data, parity);
    if (codec == nullptr) {
      Fail(__FILE__, __LINE__, "New failed in variable-length round");
      return;
    }

    ShardSet shards;
    for (int i = 0; i < data; ++i) {
      std::size_t len = max_len;
      if (max_len > 1) {
        len = 1 + (rng() % max_len);
      }
      Bytes raw = RandomBytes(&rng, len);
      Bytes padded(max_len, 0);
      std::memcpy(padded.data(), raw.data(), raw.size());
      shards.push_back(std::move(padded));
    }
    for (int j = 0; j < parity; ++j) {
      shards.push_back(Bytes(max_len, 0));
    }
    if (codec->Encode(&shards) != kcp::ErrorCode::kOk) {
      Fail(__FILE__, __LINE__, "encode failed in variable-length round");
      return;
    }
    const ShardSet reference = shards;

    const std::size_t losses = 1 + (rng() % static_cast<std::size_t>(parity));
    for (std::size_t index : PickErasures(&rng, shards.size(), losses)) {
      shards[index].clear();
    }
    if (codec->Reconstruct(&shards) != kcp::ErrorCode::kOk) {
      Fail(__FILE__, __LINE__, "reconstruct failed in variable-length round");
      return;
    }
    if (shards != reference) {
      Fail(__FILE__, __LINE__,
           "reconstruct mismatch in variable-length round " + std::to_string(round));
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Contracts and failure modes
// ---------------------------------------------------------------------------

void TestTooFewShardsIsRejected() {
  auto codec = ReedSolomon::New(10, 3);
  if (codec == nullptr) {
    Fail(__FILE__, __LINE__, "New(10,3) failed");
    return;
  }
  ShardSet shards;
  for (int i = 0; i < 10; ++i) {
    shards.push_back(Bytes(8, static_cast<std::uint8_t>(i)));
  }
  for (int j = 0; j < 3; ++j) {
    shards.push_back(Bytes(8, 0));
  }
  if (codec->Encode(&shards) != kcp::ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "encode failed");
    return;
  }
  // Four losses with only three parity shards: must refuse and leave the holes empty.
  for (std::size_t i = 0; i < 4; ++i) {
    shards[i].clear();
  }
  const kcp::ErrorCode rc = codec->ReconstructData(&shards);
  if (rc != kcp::ErrorCode::kFecRecoverFailed) {
    Fail(__FILE__, __LINE__, "ReconstructData accepted impossible erasure pattern");
  }
  for (std::size_t i = 0; i < 4; ++i) {
    if (!shards[i].empty()) {
      Fail(__FILE__, __LINE__, "ReconstructData allocated a shard it could not recover");
    }
  }
}

void TestEncodeRejectsBadShapes() {
  auto codec = ReedSolomon::New(3, 2);
  if (codec == nullptr) {
    Fail(__FILE__, __LINE__, "New(3,2) failed");
    return;
  }
  ShardSet short_set(3, Bytes(4, 1));
  if (codec->Encode(&short_set) != kcp::ErrorCode::kInvalidArgument) {
    Fail(__FILE__, __LINE__, "Encode accepted too few shards");
  }
  ShardSet missing(5, Bytes(4, 1));
  missing[2].clear();
  if (codec->Encode(&missing) != kcp::ErrorCode::kInvalidArgument) {
    Fail(__FILE__, __LINE__, "Encode accepted a missing shard");
  }
  ShardSet ragged(5, Bytes(4, 1));
  ragged[4] = Bytes(5, 1);
  if (codec->Encode(&ragged) != kcp::ErrorCode::kInvalidArgument) {
    Fail(__FILE__, __LINE__, "Encode accepted unequal shard lengths");
  }
  ShardSet ragged_recover(5, Bytes(4, 1));
  ragged_recover[1].clear();
  ragged_recover[3] = Bytes(7, 1);
  if (codec->Reconstruct(&ragged_recover) != kcp::ErrorCode::kInvalidArgument) {
    Fail(__FILE__, __LINE__, "Reconstruct accepted unequal shard lengths");
  }
}

void TestNewRejectsBadCounts() {
  if (ReedSolomon::New(0, 4) != nullptr) {
    Fail(__FILE__, __LINE__, "New accepted zero data shards");
  }
  if (ReedSolomon::New(4, -1) != nullptr) {
    Fail(__FILE__, __LINE__, "New accepted negative parity shards");
  }
  if (ReedSolomon::New(200, 100) != nullptr) {
    Fail(__FILE__, __LINE__, "New accepted 300 shards");
  }
  // 256 is the largest addressable configuration and must still build.
  if (ReedSolomon::New(128, 128) == nullptr) {
    Fail(__FILE__, __LINE__, "New rejected 128+128");
  }
  // Parity-free configuration: valid, encodes nothing, recovers nothing.
  auto data_only = ReedSolomon::New(3, 0);
  if (data_only == nullptr) {
    Fail(__FILE__, __LINE__, "New rejected parity_shards = 0");
    return;
  }
  ShardSet shards(3, Bytes(4, 2));
  if (data_only->Encode(&shards) != kcp::ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "encode with no parity failed");
  }
  if (data_only->ReconstructData(&shards) != kcp::ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "no-op reconstruct failed");
  }
}

}  // namespace

int main() {
  TestMatrixIsSystematic();
  TestGoldenVectors();
  TestRandomErasuresEqualLength();
  TestRandomErasuresVariableLength();
  TestTooFewShardsIsRejected();
  TestEncodeRejectsBadShapes();
  TestNewRejectsBadCounts();

  if (g_failures != 0) {
    std::fprintf(stderr, "rs_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("rs_test: OK\n");
  return 0;
}
