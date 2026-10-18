// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Gate for PORTING-PLAN.md P4: tools/golden/out/fec.json must be reproduced byte for byte in all
// three of its shapes (encode, decode-after-loss, OOB), the payload handoff to the caller must be
// the shard payload and nothing else, and the snmp counters must track the scenario exactly - a
// decoder that recovers data while reporting the wrong FECRecovered/FullShardSet would hide a
// regression until a real lossy link exposed it.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "json_reader.h"
#include "kcp/internal/byteorder.h"
#include "kcp/internal/constants.h"
#include "kcp/internal/fec.h"
#include "kcp/snmp.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

using Bytes = std::vector<std::uint8_t>;
using kcp::internal::FecDecoder;
using kcp::internal::FecEncoder;
using kcp::internal::FecPacket;
using kcp::test::BytesToHex;
using kcp::test::Find;
using kcp::test::GetInt;
using kcp::test::GetString;
using kcp::test::HexToBytes;
using kcp::test::JsonValue;
using kcp::test::LoadJsonFile;

// tools/golden/ref/golden_ref.go.txt:91 - the only payload shape the vectors use.
Bytes Pattern(std::size_t length, std::uint8_t seed) {
  Bytes out(length);
  for (std::size_t i = 0; i < length; ++i) {
    out[i] = static_cast<std::uint8_t>((i * 31 + seed) & 0xff);
  }
  return out;
}

constexpr int kGoldenDataShards = 10;
constexpr int kGoldenParityShards = 3;
constexpr std::size_t kGoldenPayloadLen = 200;
constexpr std::uint32_t kGoldenLatencyMs = 500;

JsonValue g_fec;

const JsonValue* FindVector(const std::string& kind) {
  const JsonValue* vectors = Find(g_fec, "vectors");
  if (vectors == nullptr || !vectors->IsArray()) {
    return nullptr;
  }
  for (const JsonValue& vector : vectors->array_value) {
    std::string name;
    if (GetString(vector, "kind", &name) && name == kind) {
      return &vector;
    }
  }
  return nullptr;
}

bool ReadHexArray(const JsonValue& object, const char* key, std::vector<Bytes>* out) {
  const JsonValue* array = Find(object, key);
  if (array == nullptr || !array->IsArray()) {
    return false;
  }
  out->clear();
  for (const JsonValue& item : array->array_value) {
    if (!item.IsString()) {
      return false;
    }
    out->push_back(HexToBytes(item.string_value));
  }
  return true;
}

// Rebuilds the encoder input for shard `index`: a 6-byte header space followed by the pattern the
// reference used. The encoder overwrites both the header and the 2-byte length field, so this is
// the same starting state the Go generator had.
Bytes MakeInput(std::size_t index) {
  Bytes buffer(kcp::kFecHeaderSize + kGoldenPayloadLen, 0);
  const Bytes payload = Pattern(kGoldenPayloadLen, static_cast<std::uint8_t>(index + 1));
  std::memcpy(buffer.data() + kcp::kFecHeaderSize, payload.data(), payload.size());
  return buffer;
}

// ---------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------

void TestGoldenEncode() {
  const JsonValue* vector = FindVector("encode");
  if (vector == nullptr) {
    Fail(__FILE__, __LINE__, "fec.json has no encode vector");
    return;
  }
  std::vector<Bytes> want_packets;
  std::vector<Bytes> want_parity;
  if (!ReadHexArray(*vector, "packets_hex", &want_packets) ||
      !ReadHexArray(*vector, "parity_hex", &want_parity)) {
    Fail(__FILE__, __LINE__, "encode vector is missing packet arrays");
    return;
  }
  long long latency = 0;
  GetInt(*vector, "encode_latency_ms", &latency);

  auto encoder = FecEncoder::New(kGoldenDataShards, kGoldenParityShards, 0);
  if (encoder == nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder::New(10,3,0) returned null");
    return;
  }

  std::vector<FecPacket> got_parity;
  for (std::size_t i = 0; i < want_packets.size(); ++i) {
    Bytes buffer = MakeInput(i);
    encoder->Encode(buffer.data(), buffer.size(), static_cast<std::uint32_t>(latency), &got_parity);
    if (buffer != want_packets[i]) {
      Fail(__FILE__, __LINE__,
           "data packet " + std::to_string(i) + " mismatch\n  got  " + BytesToHex(buffer) +
               "\n  want " + BytesToHex(want_packets[i]));
    }
  }
  if (got_parity.size() != want_parity.size()) {
    Fail(__FILE__, __LINE__,
         "parity count " + std::to_string(got_parity.size()) +
             " != " + std::to_string(want_parity.size()) + " (continuity check or slow machine)");
    return;
  }
  for (std::size_t k = 0; k < want_parity.size(); ++k) {
    if (got_parity[k] != want_parity[k]) {
      Fail(__FILE__, __LINE__,
           "parity packet " + std::to_string(k) + " mismatch\n  got  " + BytesToHex(got_parity[k]) +
               "\n  want " + BytesToHex(want_parity[k]));
    }
  }
  // 10 data + 3 parity consumed the seqid space for this set.
  if (encoder->next() != static_cast<std::uint32_t>(kGoldenDataShards + kGoldenParityShards)) {
    Fail(__FILE__, __LINE__, "next seqid = " + std::to_string(encoder->next()) + ", want 13");
  }
}

void TestGoldenDecode() {
  const JsonValue* vector = FindVector("decode");
  if (vector == nullptr) {
    Fail(__FILE__, __LINE__, "fec.json has no decode vector");
    return;
  }
  std::vector<Bytes> packets;
  std::vector<Bytes> want_recovered;
  if (!ReadHexArray(*vector, "packets_hex", &packets) ||
      !ReadHexArray(*vector, "recovered_hex", &want_recovered)) {
    Fail(__FILE__, __LINE__, "decode vector is missing packet arrays");
    return;
  }
  std::set<std::size_t> dropped;
  const JsonValue* dropped_json = Find(*vector, "dropped");
  if (dropped_json != nullptr) {
    for (const JsonValue& item : dropped_json->array_value) {
      dropped.insert(static_cast<std::size_t>(item.number_value));
    }
  }

  auto decoder = FecDecoder::New(kGoldenDataShards, kGoldenParityShards);
  if (decoder == nullptr) {
    Fail(__FILE__, __LINE__, "FecDecoder::New(10,3) returned null");
    return;
  }
  std::vector<FecPacket> recovered;
  for (std::size_t i = 0; i < packets.size(); ++i) {
    if (dropped.count(i) != 0) {
      continue;
    }
    for (FecPacket& shard : decoder->Decode(packets[i].data(), packets[i].size())) {
      recovered.push_back(std::move(shard));
    }
  }
  if (recovered.size() != want_recovered.size()) {
    Fail(__FILE__, __LINE__,
         "recovered " + std::to_string(recovered.size()) + " shards, want " +
             std::to_string(want_recovered.size()));
    return;
  }
  for (std::size_t k = 0; k < want_recovered.size(); ++k) {
    if (recovered[k] != want_recovered[k]) {
      Fail(__FILE__, __LINE__,
           "recovered shard " + std::to_string(k) + " mismatch\n  got  " +
               BytesToHex(recovered[k]) + "\n  want " + BytesToHex(want_recovered[k]));
    }
  }
}

void TestGoldenOob() {
  const JsonValue* vector = FindVector("oob");
  if (vector == nullptr) {
    Fail(__FILE__, __LINE__, "fec.json has no oob vector");
    return;
  }
  std::string want_hex;
  if (!GetString(*vector, "packet_hex", &want_hex)) {
    Fail(__FILE__, __LINE__, "oob vector has no packet_hex");
    return;
  }
  const Bytes want = HexToBytes(want_hex);

  // The generator built: FEC header(6) | conv(4) | payload(64), then sealed it as OOB.
  const Bytes conv{0x01, 0x00, 0x00, 0x00};
  const Bytes payload = Pattern(64, 0x5a);
  Bytes buffer(kcp::kFecHeaderSize + conv.size() + payload.size(), 0);
  std::memcpy(buffer.data() + kcp::kFecHeaderSize, conv.data(), conv.size());
  std::memcpy(buffer.data() + kcp::kFecHeaderSize + conv.size(), payload.data(), payload.size());

  auto encoder = FecEncoder::New(kGoldenDataShards, kGoldenParityShards, 0);
  if (encoder == nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder::New(10,3,0) returned null");
    return;
  }
  encoder->EncodeOob(buffer.data(), buffer.size());

  if (buffer != want) {
    Fail(__FILE__, __LINE__,
         "oob packet mismatch\n  got  " + BytesToHex(buffer) + "\n  want " + BytesToHex(want));
  }
  // OOB must not disturb the data seqid space.
  if (encoder->next() != 0) {
    Fail(__FILE__, __LINE__, "EncodeOob advanced the seqid");
  }
  const std::uint32_t seqid = kcp::internal::ReadLe32(buffer.data());
  if (seqid != 0xffffffffu) {
    Fail(__FILE__, __LINE__, "oob seqid = " + std::to_string(seqid));
  }
  if (kcp::internal::ReadLe16(buffer.data() + 4) != kcp::kTypeOob) {
    Fail(__FILE__, __LINE__, "oob type mismatch");
  }
}

void TestGoldenEncodeVariableLength() {
  const JsonValue* vector = FindVector("encode-varlen");
  if (vector == nullptr) {
    Fail(__FILE__, __LINE__, "fec.json has no encode-varlen vector");
    return;
  }
  std::vector<Bytes> want_packets;
  std::vector<Bytes> want_parity;
  if (!ReadHexArray(*vector, "packets_hex", &want_packets) ||
      !ReadHexArray(*vector, "parity_hex", &want_parity)) {
    Fail(__FILE__, __LINE__, "encode-varlen vector is missing packet arrays");
    return;
  }

  auto encoder = FecEncoder::New(kGoldenDataShards, kGoldenParityShards, 0);
  if (encoder == nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder::New(10,3,0) returned null");
    return;
  }
  // Replay the uniform round first. The zero-extension rule only bites on a shard cache that
  // still holds a *longer* packet from the previous set, so an encoder starting cold would pass
  // even if the tail were left uninitialised.
  std::vector<FecPacket> parity;
  for (std::size_t i = 0; i < static_cast<std::size_t>(kGoldenDataShards); ++i) {
    Bytes buffer = MakeInput(i);
    encoder->Encode(buffer.data(), buffer.size(), kGoldenLatencyMs, &parity);
  }
  if (parity.size() != static_cast<std::size_t>(kGoldenParityShards)) {
    Fail(__FILE__, __LINE__, "warm-up round did not produce parity");
    return;
  }
  parity.clear();

  for (std::size_t i = 0; i < want_packets.size(); ++i) {
    // The golden packet's bytes from the payload offset on are exactly the encoder input; bytes
    // before it are what Encode writes itself.
    Bytes buffer = want_packets[i];
    std::fill(buffer.begin(),
              buffer.begin() + static_cast<std::ptrdiff_t>(kcp::kFecHeaderSizePlus2), 0);
    encoder->Encode(buffer.data(), buffer.size(), kGoldenLatencyMs, &parity);
    if (buffer != want_packets[i]) {
      Fail(__FILE__, __LINE__,
           "varlen data packet " + std::to_string(i) + " mismatch\n  got  " + BytesToHex(buffer) +
               "\n  want " + BytesToHex(want_packets[i]));
    }
  }
  if (parity.size() != want_parity.size()) {
    Fail(__FILE__, __LINE__,
         "varlen parity count " + std::to_string(parity.size()) +
             " != " + std::to_string(want_parity.size()));
    return;
  }
  for (std::size_t k = 0; k < want_parity.size(); ++k) {
    if (parity[k] != want_parity[k]) {
      Fail(__FILE__, __LINE__,
           "varlen parity packet " + std::to_string(k) + " mismatch\n  got  " +
               BytesToHex(parity[k]) + "\n  want " + BytesToHex(want_parity[k]));
    }
  }
}

// ---------------------------------------------------------------------------
// Continuity window (fec.go:427)
// ---------------------------------------------------------------------------

void TestDiscontinuousBurstSkipsParity() {
  auto encoder = FecEncoder::New(kGoldenDataShards, kGoldenParityShards, 0);
  if (encoder == nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder::New returned null");
    return;
  }
  std::vector<FecPacket> parity;
  // rto = 0 makes `now - ts < 0` false every time: the encoder must treat every packet as
  // non-continuous, emit no parity, and still advance the seqid past the parity slots so the
  // peer sees the gap.
  for (std::size_t i = 0; i < static_cast<std::size_t>(kGoldenDataShards); ++i) {
    Bytes buffer = MakeInput(i);
    encoder->Encode(buffer.data(), buffer.size(), 0, &parity);
  }
  if (!parity.empty()) {
    Fail(__FILE__, __LINE__, "parity emitted despite rto = 0");
  }
  if (encoder->next() != static_cast<std::uint32_t>(kGoldenDataShards + kGoldenParityShards)) {
    Fail(__FILE__, __LINE__,
         "after a skipped set next = " + std::to_string(encoder->next()) + ", want 13");
  }

  // The following data packet must land on seqid 13, i.e. a parity slot: that is exactly how the
  // receiver learns a whole parity block was skipped.
  Bytes buffer = MakeInput(0);
  encoder->Encode(buffer.data(), buffer.size(), 0, &parity);
  const std::uint32_t seqid = kcp::internal::ReadLe32(buffer.data());
  if (seqid != 13) {
    Fail(__FILE__, __LINE__, "seqid after skipped set = " + std::to_string(seqid) + ", want 13");
  }
}

// ---------------------------------------------------------------------------
// Decoder behaviour
// ---------------------------------------------------------------------------

std::vector<Bytes> BuildGoldenPackets() {
  std::vector<Bytes> packets;
  auto encoder = FecEncoder::New(kGoldenDataShards, kGoldenParityShards, 0);
  if (encoder == nullptr) {
    return packets;
  }
  std::vector<FecPacket> parity;
  for (std::size_t i = 0; i < static_cast<std::size_t>(kGoldenDataShards); ++i) {
    Bytes buffer = MakeInput(i);
    encoder->Encode(buffer.data(), buffer.size(), kGoldenLatencyMs, &parity);
    packets.push_back(std::move(buffer));
  }
  for (FecPacket& packet : parity) {
    packets.push_back(std::move(packet));
  }
  return packets;
}

void TestEveryRecoverableDropPattern() {
  const std::vector<Bytes> packets = BuildGoldenPackets();
  if (packets.size() != 13) {
    Fail(__FILE__, __LINE__, "expected 13 golden packets");
    return;
  }
  // All subsets of size 1..3 (parity_shards = 3): every one must recover completely.
  for (std::size_t a = 0; a < packets.size(); ++a) {
    for (std::size_t b = a; b < packets.size(); ++b) {
      for (std::size_t c = b; c < packets.size(); ++c) {
        std::set<std::size_t> dropped;
        dropped.insert(a);
        if (b != a) {
          dropped.insert(b);
        }
        if (c != a && c != b) {
          dropped.insert(c);
        }
        auto decoder = FecDecoder::New(kGoldenDataShards, kGoldenParityShards);
        if (decoder == nullptr) {
          Fail(__FILE__, __LINE__, "FecDecoder::New returned null");
          return;
        }
        std::vector<FecPacket> recovered;
        for (std::size_t i = 0; i < packets.size(); ++i) {
          if (dropped.count(i) != 0) {
            continue;
          }
          for (FecPacket& shard : decoder->Decode(packets[i].data(), packets[i].size())) {
            recovered.push_back(std::move(shard));
          }
        }
        std::size_t want = 0;
        for (std::size_t index : dropped) {
          if (index < static_cast<std::size_t>(kGoldenDataShards)) {
            ++want;
          }
        }
        if (recovered.size() != want) {
          Fail(__FILE__, __LINE__,
               "drop {" + std::to_string(a) + "," + std::to_string(b) + "," + std::to_string(c) +
                   "}: recovered " + std::to_string(recovered.size()) + ", want " +
                   std::to_string(want));
          continue;
        }
        for (std::size_t index : dropped) {
          if (index >= static_cast<std::size_t>(kGoldenDataShards)) {
            continue;
          }
          const Bytes& want_payload = packets[index];
          bool matched = false;
          for (const FecPacket& shard : recovered) {
            if (shard.size() == want_payload.size() - kcp::kFecHeaderSize &&
                std::memcmp(shard.data(), want_payload.data() + kcp::kFecHeaderSize,
                            shard.size()) == 0) {
              matched = true;
              break;
            }
          }
          if (!matched) {
            Fail(__FILE__, __LINE__,
                 "drop {" + std::to_string(a) + "," + std::to_string(b) + "," + std::to_string(c) +
                     "}: no recovered shard matches "
                     "dropped packet " +
                     std::to_string(index));
          }
        }
      }
    }
  }
}

void TestDuplicateAndStalePacketsIgnored() {
  const std::vector<Bytes> packets = BuildGoldenPackets();
  if (packets.empty()) {
    return;
  }
  auto decoder = FecDecoder::New(kGoldenDataShards, kGoldenParityShards);
  if (decoder == nullptr) {
    return;
  }
  for (int i = 0; i < 9; ++i) {
    decoder->Decode(packets[static_cast<std::size_t>(i)].data(),
                    packets[static_cast<std::size_t>(i)].size());
  }
  // Duplicate of an already-buffered shard: no state change, no recovery attempt.
  if (!decoder->Decode(packets[0].data(), packets[0].size()).empty()) {
    Fail(__FILE__, __LINE__, "duplicate packet produced output");
  }
  // seqid >= paws (the OOB sentinel) is not a shard: it must be ignored outright. paws for 13
  // shards is 0xffffffff - (0xffffffff % 13) = 4294967287.
  Bytes oob(16, 0);
  kcp::internal::WriteLe32(oob.data(), 0xffffffffu);
  kcp::internal::WriteLe16(oob.data() + 4, kcp::kTypeOob);
  if (!decoder->Decode(oob.data(), oob.size()).empty()) {
    Fail(__FILE__, __LINE__, "packet beyond paws produced output");
  }
  // A truncated packet is not a shard either.
  if (!decoder->Decode(packets[0].data(), 4).empty()) {
    Fail(__FILE__, __LINE__, "short packet produced output");
  }
}

void TestStaleShardSetsAreDiscarded() {
  auto decoder = FecDecoder::New(kGoldenDataShards, kGoldenParityShards);
  if (decoder == nullptr) {
    return;
  }
  Bytes packet(16, 0);
  kcp::internal::WriteLe16(packet.data() + 4, kcp::kTypeData);
  // One packet from each of shard sets 0..5. After set 5, sets more than maxShardSets (3) behind
  // the newest must be dropped, i.e. 0 and 1 go, leaving 2..5.
  for (std::uint32_t set = 0; set < 6; ++set) {
    kcp::internal::WriteLe32(packet.data(), set * 13);
    decoder->Decode(packet.data(), packet.size());
  }
  if (decoder->shard_set_count() != 4) {
    Fail(__FILE__, __LINE__,
         "shard set count = " + std::to_string(decoder->shard_set_count()) +
             ", want 4 after 6 sets");
  }
  if (decoder->newest_shard_id() != 5) {
    Fail(__FILE__, __LINE__, "newest shard id = " + std::to_string(decoder->newest_shard_id()));
  }
}

// ---------------------------------------------------------------------------
// snmp contract (#51)
// ---------------------------------------------------------------------------

void TestSnmpCounters() {
  kcp::DefaultSnmp().Reset();

  // Scenario: one complete shard set with two data shards lost.
  const std::vector<Bytes> packets = BuildGoldenPackets();
  auto decoder = FecDecoder::New(kGoldenDataShards, kGoldenParityShards);
  if (decoder == nullptr || packets.size() != 13) {
    Fail(__FILE__, __LINE__, "setup failed");
    return;
  }
  std::size_t recovered = 0;
  for (std::size_t i = 0; i < packets.size(); ++i) {
    if (i == 0 || i == 4) {
      continue;
    }
    recovered += decoder->Decode(packets[i].data(), packets[i].size()).size();
  }
  kcp::SnmpSnapshot snapshot = kcp::DefaultSnmp().Snapshot();
  if (recovered != 2) {
    Fail(__FILE__, __LINE__, "recovered " + std::to_string(recovered) + " shards, want 2");
  }
  if (snapshot.fec_recovered != 2) {
    Fail(__FILE__, __LINE__, "fec_recovered = " + std::to_string(snapshot.fec_recovered));
  }
  if (snapshot.fec_parity_shards != 3) {
    Fail(__FILE__, __LINE__, "fec_parity_shards = " + std::to_string(snapshot.fec_parity_shards));
  }
  if (snapshot.fec_full_shard_set != 0) {
    Fail(__FILE__, __LINE__, "fec_full_shard_set = " + std::to_string(snapshot.fec_full_shard_set));
  }
  if (snapshot.fec_errs != 0) {
    Fail(__FILE__, __LINE__, "fec_errs = " + std::to_string(snapshot.fec_errs));
  }
  // Gauge, not a counter: one set is still held (it is only discarded after maxShardSets newer
  // sets show up).
  if (snapshot.fec_shard_set != 1) {
    Fail(__FILE__, __LINE__, "fec_shard_set = " + std::to_string(snapshot.fec_shard_set));
  }
  if (snapshot.fec_shard_min != 0) {
    Fail(__FILE__, __LINE__, "fec_shard_min = " + std::to_string(snapshot.fec_shard_min));
  }

  // Second scenario: a clean shard set, no loss. FullShardSet must move, FECRecovered must not.
  kcp::DefaultSnmp().Reset();
  auto clean = FecDecoder::New(kGoldenDataShards, kGoldenParityShards);
  for (std::size_t i = 0; i < static_cast<std::size_t>(kGoldenDataShards); ++i) {
    if (!clean->Decode(packets[i].data(), packets[i].size()).empty()) {
      Fail(__FILE__, __LINE__, "complete shard set produced recovered shards");
    }
  }
  snapshot = kcp::DefaultSnmp().Snapshot();
  if (snapshot.fec_full_shard_set != 1) {
    Fail(__FILE__, __LINE__,
         "fec_full_shard_set = " + std::to_string(snapshot.fec_full_shard_set) + ", want 1");
  }
  if (snapshot.fec_recovered != 0) {
    Fail(__FILE__, __LINE__, "fec_recovered = " + std::to_string(snapshot.fec_recovered));
  }
  kcp::DefaultSnmp().Reset();
}

void TestNewRejectsBadParameters() {
  if (FecEncoder::New(0, 3, 0) != nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder accepted zero data shards");
  }
  if (FecEncoder::New(10, 0, 0) != nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder accepted zero parity shards");
  }
  if (FecEncoder::New(200, 100, 0) != nullptr) {
    Fail(__FILE__, __LINE__, "FecEncoder accepted 300 shards");
  }
  // FEC(0,0) is how a session says "no FEC": both factories must return null so the caller can
  // branch on it instead of carrying a disabled codec.
  if (FecDecoder::New(0, 0) != nullptr || FecEncoder::New(0, 0, 0) != nullptr) {
    Fail(__FILE__, __LINE__, "FEC(0,0) should not build a codec");
  }
  if (FecDecoder::New(0, 3) != nullptr) {
    Fail(__FILE__, __LINE__, "FecDecoder accepted zero data shards");
  }
  if (FecDecoder::New(10, -1) != nullptr) {
    Fail(__FILE__, __LINE__, "FecDecoder accepted negative parity shards");
  }
  // 128+128 is the largest legal configuration and must still build.
  if (FecEncoder::New(128, 128, 0) == nullptr || FecDecoder::New(128, 128) == nullptr) {
    Fail(__FILE__, __LINE__, "128+128 rejected");
  }
}

}  // namespace

int main() {
  std::string error;
  const std::string path = std::string(KCP_VECTOR_DIR) + "/fec.json";
  if (!LoadJsonFile(path, &g_fec, &error)) {
    std::fprintf(stderr, "FAIL cannot load %s: %s\n", path.c_str(), error.c_str());
    return 1;
  }

  TestGoldenEncode();
  TestGoldenDecode();
  TestGoldenOob();
  TestGoldenEncodeVariableLength();
  TestDiscontinuousBurstSkipsParity();
  TestEveryRecoverableDropPattern();
  TestDuplicateAndStalePacketsIgnored();
  TestStaleShardSetsAreDiscarded();
  TestSnmpCounters();
  TestNewRejectsBadParameters();

  if (g_failures != 0) {
    std::fprintf(stderr, "fec_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("fec_test: OK\n");
  return 0;
}
