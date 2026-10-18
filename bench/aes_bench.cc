// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// AES throughput on the two backends the library ships (PORTING-PLAN.md decision 6): AES-NI and the
// T-table fallback. The P6 gate asks for the delta between them to be recorded in the README, which
// only makes sense measured at the layer where the switch lives.
//
// Two modes are timed:
//   cfb - CfbEncrypt() over whole packets, i.e. exactly what the wire path does for AES-CFB
//   gcm - AesGcm::Seal(), i.e. what the wire path does for AES-GCM (GHASH included)
//
// Usage: aes_bench.exe [-mb 256] [-rounds 5]

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "kcp/internal/aes.h"
#include "kcp/internal/cfb.h"
#include "kcp/internal/gcm.h"

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kPacketSize = 1400;

struct Sample {
  double mbps = 0.0;
};

double Median(std::vector<double> values) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  const std::size_t mid = values.size() / 2;
  if (values.size() % 2 == 1) return values[mid];
  return (values[mid - 1] + values[mid]) / 2.0;
}

// Runs `fn` over the packet buffer until `total_bytes` is consumed and reports MB/s.
template <typename Fn>
double Throughput(std::size_t total_bytes, Fn fn) {
  const std::size_t packets = total_bytes / kPacketSize;
  const auto start = Clock::now();
  for (std::size_t i = 0; i < packets; ++i) fn(i);
  const auto elapsed = Clock::now() - start;
  const double seconds = std::chrono::duration<double>(elapsed).count();
  const double mb = static_cast<double>(packets * kPacketSize) / (1024.0 * 1024.0);
  return seconds > 0.0 ? mb / seconds : 0.0;
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t mb = 256;
  int rounds = 5;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "-mb" && i + 1 < argc) {
      mb = static_cast<std::size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (flag == "-rounds" && i + 1 < argc) {
      rounds = std::atoi(argv[++i]);
    } else {
      std::fprintf(stderr, "aes_bench: unknown argument %s\n", flag.c_str());
      return 2;
    }
  }
  if (rounds < 1) rounds = 1;

  const std::size_t total = mb * 1024 * 1024;
  std::uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  std::vector<std::uint8_t> plain(kPacketSize);
  std::vector<std::uint8_t> cipher(kPacketSize + kcp::internal::AesGcm::kTagSize);
  for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<std::uint8_t>(i * 31 + 7);

  const kcp::internal::Aes ni(key, sizeof(key), kcp::internal::AesBackend::kNin);
  const kcp::internal::Aes table(key, sizeof(key), kcp::internal::AesBackend::kTable);
  if (!ni.using_ni()) {
    std::printf("SKIP aes-ni unavailable on this host\n");
    return 0;
  }
  const kcp::internal::AesGcm gcm_ni(key, sizeof(key), kcp::internal::AesBackend::kNin);
  const kcp::internal::AesGcm gcm_table(key, sizeof(key), kcp::internal::AesBackend::kTable);
  if (!gcm_ni.valid() || !gcm_table.valid()) {
    std::fprintf(stderr, "aes_bench: gcm init failed\n");
    return 1;
  }

  const std::size_t len = kPacketSize - 8;  // one packet minus the nonce header, like the wire path
  std::vector<double> cfb_ni;
  std::vector<double> cfb_table;
  std::vector<double> gcm_ni_samples;
  std::vector<double> gcm_table_samples;

  for (int round = 0; round < rounds; ++round) {
    cfb_ni.push_back(Throughput(total, [&](std::size_t) {
      kcp::internal::CfbEncrypt(ni, cipher.data(), plain.data(), len);
    }));
    cfb_table.push_back(Throughput(total, [&](std::size_t) {
      kcp::internal::CfbEncrypt(table, cipher.data(), plain.data(), len);
    }));
    gcm_ni_samples.push_back(Throughput(
        total, [&](std::size_t) { gcm_ni.Seal(cipher.data(), key, plain.data(), len); }));
    gcm_table_samples.push_back(Throughput(
        total, [&](std::size_t) { gcm_table.Seal(cipher.data(), key, plain.data(), len); }));
  }

  const double cfb_ni_med = Median(cfb_ni);
  const double cfb_table_med = Median(cfb_table);
  const double gcm_ni_med = Median(gcm_ni_samples);
  const double gcm_table_med = Median(gcm_table_samples);

  std::printf("AESBENCH packet=%zu payload=%zu rounds=%d total_mb=%zu\n", kPacketSize, len, rounds,
              mb);
  std::printf("AESBENCH cfb_ni_mbps=%.1f cfb_table_mbps=%.1f cfb_ratio=%.2f\n", cfb_ni_med,
              cfb_table_med, cfb_table_med > 0.0 ? cfb_ni_med / cfb_table_med : 0.0);
  std::printf("AESBENCH gcm_ni_mbps=%.1f gcm_table_mbps=%.1f gcm_ratio=%.2f\n", gcm_ni_med,
              gcm_table_med, gcm_table_med > 0.0 ? gcm_ni_med / gcm_table_med : 0.0);
  return 0;
}
