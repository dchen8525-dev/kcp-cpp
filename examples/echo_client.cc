// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// C++ echo client, the mirror of tools/interop/goclient/goecho_client.go. It drives either the C++
// echo server (the §6.3 baseline) or the Go one (P7 reverse direction) and prints one
// machine-readable RESULT line so the drivers never parse log noise:
//
//   RESULT ok=1 bytes=104857600 sha256=... mbps=12.34 elapsed_ms=8123.4 iters=100
//
// -iters N sends N * -bytes bytes as one continuous stream and verifies the echo against the same
// payload repeated, so the measurement covers sustained throughput rather than N round trips.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "echo_common.h"
#include "kcp/snmp.h"
#include "kcp/udp_session.h"

namespace {

// Same pattern as the Go client: byte(i*7 + 11).
void FillPayload(std::vector<std::uint8_t>* payload) {
  for (std::size_t i = 0; i < payload->size(); ++i) {
    (*payload)[i] = static_cast<std::uint8_t>(i * 7 + 11);
  }
}

}  // namespace

int main(int argc, char** argv) {
  echo::Options options;
  std::string error;
  if (!echo::ParseOptions(argc, argv, &options, &error)) {
    std::fprintf(stderr, "echo_client: %s\n", error.c_str());
    return 2;
  }

  kcp::Crypt crypt;
  if (!echo::MakeCrypt(options.crypt, options.key, &crypt, &error)) {
    std::fprintf(stderr, "echo_client: %s\n", error.c_str());
    return 2;
  }

  std::error_code ec;
  auto session =
      kcp::DialWithOptions(options.addr, crypt, options.data_shards, options.parity_shards, &ec);
  if (!session) {
    std::fprintf(stderr, "echo_client: dial %s: %s\n", options.addr.c_str(), ec.message().c_str());
    return 1;
  }
  if (!echo::ApplyTuning(session, options)) {
    std::fprintf(stderr, "echo_client: mtu %d rejected\n", options.mtu);
    return 2;
  }
  echo::FirstPacketDump dump(options.dump_packet);
  if (!options.dump_packet.empty()) {
    session->SetPacketTrace([&dump](bool outgoing, const std::uint8_t* data, std::size_t len) {
      dump.Record(outgoing, data, len);
    });
  }
  session->SetDeadline(std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(options.timeout_ms));

  std::vector<std::uint8_t> payload(static_cast<std::size_t>(options.bytes));
  FillPayload(&payload);
  const std::string digest = echo::Sha256Hex(payload.data(), payload.size());
  const std::int64_t total =
      static_cast<std::int64_t>(options.bytes) * static_cast<std::int64_t>(options.iters);

  const auto start = std::chrono::steady_clock::now();

  // Writer thread: pushes the whole stream without waiting for echoes, exactly like the Go client.
  std::string write_error_text;
  std::thread writer([&]() {
    const std::size_t chunk = static_cast<std::size_t>(options.chunk);
    std::int64_t written = 0;
    while (written < total) {
      const std::size_t offset = static_cast<std::size_t>(written % options.bytes);
      // Never read past the payload: a chunk that straddles the wrap point is written short.
      const std::size_t take =
          std::min({chunk, static_cast<std::size_t>(total - written), payload.size() - offset});
      std::error_code write_ec;
      const int n = session->write(payload.data() + offset, take, &write_ec);
      if (n < 0) {
        write_error_text = write_ec.message();
        return;
      }
      written += n;
    }
  });

  // Reader: message mode returns one message at a time (§3.6), so accumulate until the stream ends.
  std::vector<std::uint8_t> buffer(64 * 1024);
  std::int64_t received = 0;
  std::string read_error_text;
  while (!options.discard && received < total) {
    std::error_code read_ec;
    const int n = session->read(buffer.data(), buffer.size(), &read_ec);
    if (n < 0) {
      read_error_text = read_ec.message();
      break;
    }
    for (int i = 0; i < n; ++i) {
      const std::size_t expect = static_cast<std::size_t>((received + i) % options.bytes);
      if (buffer[static_cast<std::size_t>(i)] != payload[expect]) {
        read_error_text = "echo mismatch at byte " + std::to_string(received + i);
        break;
      }
    }
    if (!read_error_text.empty()) break;
    received += n;
  }
  // Joining before the timestamp keeps the send-only mode honest: there the reader loop is skipped,
  // so the stream is only complete once the writer returns.
  writer.join();
  const auto elapsed = std::chrono::steady_clock::now() - start;

  std::error_code close_ec;
  session->close(&close_ec);

  const double elapsed_ms =
      std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() / 1000.0;
  if (!write_error_text.empty() || !read_error_text.empty()) {
    const std::string& reason = !write_error_text.empty() ? write_error_text : read_error_text;
    const kcp::SnmpSnapshot snmp = kcp::DefaultSnmp().Snapshot();
    std::printf(
        "RESULT ok=0 error=%s bytes=%lld iters=%d out_pkts=%llu in_pkts=%llu retrans=%llu "
        "lost=%llu srtt_ms=%.3f kcp_in_errors=%llu csum_errors=%llu in_errs=%llu estab=%llu "
        "sock_err=%d closed=%d\n",
        reason.c_str(), static_cast<long long>(received), options.iters,
        static_cast<unsigned long long>(snmp.out_pkts),
        static_cast<unsigned long long>(snmp.in_pkts),
        static_cast<unsigned long long>(snmp.retrans_segs),
        static_cast<unsigned long long>(snmp.lost_segs), session->srtt() / 1000.0,
        static_cast<unsigned long long>(snmp.kcp_in_errors),
        static_cast<unsigned long long>(snmp.in_csum_errors),
        static_cast<unsigned long long>(snmp.in_errs),
        static_cast<unsigned long long>(snmp.curr_estab), session->socket_error_code(),
        session->is_closed() ? 1 : 0);
    return 1;
  }
  if (!options.discard && received != total) {
    std::printf("RESULT ok=0 error=short-read bytes=%lld want=%lld\n",
                static_cast<long long>(received), static_cast<long long>(total));
    return 1;
  }

  const double mb = static_cast<double>(total) / (1024.0 * 1024.0);
  const double mbps = mb / (elapsed_ms / 1000.0);
  // Counters, not decoration: §6.2 judges a lossy run by whether retransmissions went up, and a
  // throughput outlier is first explained by looking at out_pkts.
  const kcp::SnmpSnapshot snmp = kcp::DefaultSnmp().Snapshot();
  const std::int32_t srtt_us = session->srtt();
  std::printf(
      "RESULT ok=1 bytes=%lld sha256=%s mbps=%.2f elapsed_ms=%.1f iters=%d "
      "out_pkts=%llu in_pkts=%llu retrans=%llu lost=%llu fec_recovered=%llu srtt_ms=%.3f\n",
      static_cast<long long>(total), digest.c_str(), mbps, elapsed_ms, options.iters,
      static_cast<unsigned long long>(snmp.out_pkts), static_cast<unsigned long long>(snmp.in_pkts),
      static_cast<unsigned long long>(snmp.retrans_segs),
      static_cast<unsigned long long>(snmp.lost_segs),
      static_cast<unsigned long long>(snmp.fec_recovered), srtt_us / 1000.0);
  std::fflush(stdout);
  return 0;
}
