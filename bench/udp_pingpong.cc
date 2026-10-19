// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Platform calibration for PORTING-PLAN.md §6.3: how much does one cross-thread datagram round trip
// cost on this host?
//
// The session layer hands every datagram between OS threads (read loop -> KCP -> post-process ->
// socket). Go pays ~1us for the equivalent goroutine handoff; an OS thread wake costs whatever the
// scheduler charges. This tool measures that constant with no KCP, no FEC and no encryption, so a
// throughput shortfall can be attributed instead of guessed.
//
// Usage: udp_pingpong.exe [-rounds 20000]

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "kcp/platform/socket.h"

namespace {

using Clock = std::chrono::steady_clock;

// Binds a UDP socket to 127.0.0.1:0 and reports the address it actually got.
bool BindLoopback(kcp::platform::SocketHandle* fd, kcp::platform::SocketAddress* addr) {
  *fd = kcp::platform::SysSocketUdp();
  if (*fd == kcp::platform::kInvalidSocket) {
    return false;
  }
  kcp::platform::SocketAddress any;
  if (!kcp::platform::SocketAddress::ParseHostPort("127.0.0.1:0", &any)) {
    return false;
  }
  if (kcp::platform::SysBind(*fd, any) != 0) {
    return false;
  }
  return kcp::platform::SysGetSockName(*fd, addr) == 0;
}

}  // namespace

int main(int argc, char** argv) {
  int rounds = 20000;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "-rounds" && i + 1 < argc) {
      rounds = std::atoi(argv[++i]);
    } else {
      std::fprintf(stderr, "udp_pingpong: unknown argument %s\n", flag.c_str());
      return 2;
    }
  }
  if (!kcp::platform::InitSockets()) {
    std::fprintf(stderr, "udp_pingpong: socket init failed\n");
    return 1;
  }

  kcp::platform::SocketHandle a = kcp::platform::kInvalidSocket;
  kcp::platform::SocketHandle b = kcp::platform::kInvalidSocket;
  kcp::platform::SocketAddress a_addr;
  kcp::platform::SocketAddress b_addr;
  if (!BindLoopback(&a, &a_addr) || !BindLoopback(&b, &b_addr)) {
    std::fprintf(stderr, "udp_pingpong: bind failed\n");
    return 1;
  }

  std::uint8_t payload[64] = {};
  std::thread echo([&] {
    std::vector<std::uint8_t> buffer(2048);
    for (int i = 0; i < rounds; ++i) {
      kcp::platform::SocketAddress from;
      const int got = kcp::platform::SysRecvFrom(b, buffer.data(), buffer.size(), &from);
      if (got < 0) {
        return;
      }
      kcp::platform::SysSendTo(b, buffer.data(), static_cast<std::size_t>(got), from);
    }
  });

  const auto start = Clock::now();
  std::vector<std::uint8_t> buffer(2048);
  int completed = 0;
  for (int i = 0; i < rounds; ++i) {
    kcp::platform::SysSendTo(a, payload, sizeof(payload), b_addr);
    if (kcp::platform::SysRecvFrom(a, buffer.data(), buffer.size(), nullptr) < 0) {
      break;
    }
    ++completed;
  }
  const auto elapsed = Clock::now() - start;
  echo.join();

  const double seconds = std::chrono::duration<double>(elapsed).count();
  const double rtt_us = completed > 0 ? seconds * 1e6 / completed : 0.0;
  std::printf("UDPPINGPONG rounds=%d rtt_us=%.2f round_trips_per_s=%.0f\n", completed, rtt_us,
              seconds > 0.0 ? completed / seconds : 0.0);
  kcp::platform::SysClose(a);
  kcp::platform::SysClose(b);
  kcp::platform::ShutdownSockets();
  return 0;
}
