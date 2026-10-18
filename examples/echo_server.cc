// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// C++ echo server, the mirror of tools/interop/goserver/goecho_server.go. It serves two purposes:
//
//   * the C++<->C++ half of the §6.3 throughput baseline (P6)
//   * the C++ server side of the cross-language matrix (P7)
//
// Usage:
//
//   echo_server.exe -addr 127.0.0.1:9000 -crypt aes -data 10 -parity 3
//
// Every tuning knob is a flag with the same default as the Go tool, so a benchmark run never
// depends on either implementation's built-in defaults (§6.3, #68).

#include <atomic>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "echo_common.h"
#include "kcp/listener.h"
#include "kcp/snmp.h"

namespace {

constexpr std::size_t kReadChunk = 64 * 1024;

// Copies everything the peer sends back to it, preserving message boundaries (§3.6).
void ServeEcho(std::shared_ptr<kcp::UdpSession> session, bool discard) {
  std::vector<std::uint8_t> buffer(kReadChunk);
  for (;;) {
    std::error_code ec;
    const int n = session->read(buffer.data(), buffer.size(), &ec);
    if (n > 0) {
      if (discard) {
        continue;
      }
      std::error_code write_ec;
      if (session->write(buffer.data(), static_cast<std::size_t>(n), &write_ec) < 0) {
        std::fprintf(stderr, "session %s: write: %s\n", session->remote_addr().c_str(),
                     write_ec.message().c_str());
        break;
      }
    }
    if (ec) {
      if (ec != kcp::ErrorCode::kClosedPipe) {
        std::fprintf(stderr, "session %s: read: %s\n", session->remote_addr().c_str(),
                     ec.message().c_str());
      }
      break;
    }
  }
  std::error_code close_ec;
  session->close(&close_ec);
}

}  // namespace

int main(int argc, char** argv) {
  echo::Options options;
  std::string error;
  if (!echo::ParseOptions(argc, argv, &options, &error)) {
    std::fprintf(stderr, "echo_server: %s\n", error.c_str());
    return 2;
  }

  kcp::Crypt crypt;
  if (!echo::MakeCrypt(options.crypt, options.key, &crypt, &error)) {
    std::fprintf(stderr, "echo_server: %s\n", error.c_str());
    return 2;
  }

  std::error_code ec;
  auto listener =
      kcp::ListenWithOptions(options.addr, crypt, options.data_shards, options.parity_shards, &ec);
  if (!listener) {
    std::fprintf(stderr, "echo_server: listen %s: %s\n", options.addr.c_str(),
                 ec.message().c_str());
    return 1;
  }
  // Accepted sessions share the listener's descriptor, so the socket buffers have to be raised
  // here: a listener-owned session reports kInvalidOperation for SetReadBuffer (§3.6/#47).
  static_cast<void>(listener->SetReadBuffer(options.sockbuf));
  static_cast<void>(listener->SetWriteBuffer(options.sockbuf));

  // §6.1: the listener taps the datagram before decryption, so the capture is the wire bytes.
  echo::FirstPacketDump dump(options.dump_packet);
  if (!options.dump_packet.empty()) {
    listener->SetPacketTrace([&dump](bool outgoing, const std::uint8_t* data, std::size_t len) {
      dump.Record(outgoing, data, len);
    });
  }

  // READY is the handshake line the benchmark / matrix scripts wait for before starting a peer.
  std::printf("READY crypt=%s fec=%d/%d addr=%s sndwnd=%d rcvwnd=%d mtu=%d\n",
              options.crypt.c_str(), options.data_shards, options.parity_shards,
              listener->addr().c_str(), options.sndwnd, options.rcvwnd, options.mtu);
  std::fflush(stdout);

  if (options.stats_ms > 0) {
    // Diagnostic only: the counters say whether a stalled client is being starved by the server
    // (in_pkts flat, lost_segs climbing) or by the network.
    std::thread([&options] {
      for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(options.stats_ms));
        const kcp::SnmpSnapshot s = kcp::DefaultSnmp().Snapshot();
        std::fprintf(
            stderr,
            "STATS in_pkts=%llu out_pkts=%llu in_segs=%llu out_segs=%llu lost=%llu "
            "retrans=%llu kcp_in_errors=%llu csum_errors=%llu fec_errs=%llu estab=%llu\n",
            static_cast<unsigned long long>(s.in_pkts), static_cast<unsigned long long>(s.out_pkts),
            static_cast<unsigned long long>(s.in_segs), static_cast<unsigned long long>(s.out_segs),
            static_cast<unsigned long long>(s.lost_segs),
            static_cast<unsigned long long>(s.retrans_segs),
            static_cast<unsigned long long>(s.kcp_in_errors),
            static_cast<unsigned long long>(s.in_csum_errors),
            static_cast<unsigned long long>(s.fec_errs),
            static_cast<unsigned long long>(s.curr_estab));
      }
    }).detach();
  }

  for (;;) {
    std::error_code accept_ec;
    auto session = listener->Accept(&accept_ec);
    if (!session) {
      if (accept_ec != kcp::ErrorCode::kClosedPipe) {
        std::fprintf(stderr, "echo_server: accept: %s\n", accept_ec.message().c_str());
      }
      break;
    }
    if (!echo::ApplyTuning(session, options)) {
      std::fprintf(stderr, "echo_server: mtu %d rejected\n", options.mtu);
      continue;
    }
    std::fprintf(stderr, "session from %s\n", session->remote_addr().c_str());
    // Detached: the session is reference counted and the process is short lived, so joining would
    // only make shutdown ordering harder than it needs to be.
    std::thread(ServeEcho, std::move(session), options.discard).detach();
  }

  std::error_code close_ec;
  listener->close(&close_ec);
  return 0;
}
