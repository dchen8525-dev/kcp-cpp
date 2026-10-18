// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Platform calibration for PORTING-PLAN.md §6.3 / P8: what does each syscall in the read and write
// loops actually cost on this host?
//
// P6 established that session throughput is limited per datagram, not per window: 32/128/512 all
// land at 12-13 MB/s, and the KCP state machine alone runs two orders of magnitude faster. The
// remaining suspect is the syscall bill, so this tool prices each one separately instead of
// inferring it from an end-to-end number:
//
//   probe_ready     select(0) on a socket that already has a datagram waiting (level triggered, so
//                   the probe never consumes it). This is the call the drain loop pays after every
//                   single datagram today - the first P8 candidate is replacing it with a
//                   non-blocking recvfrom that returns EWOULDBLOCK.
//   probe_notready  the same call on an idle socket: the cost of "is there more?" when the answer
//                   is no, i.e. once per burst rather than once per datagram.
//   recv_ok         recvfrom with a datagram available.
//   recv_empty      recvfrom on a non-blocking, empty socket. What the replacement probe costs.
//   sendto          sendto on loopback.
//
// Usage: syscall_cost.exe [-iters 20000] [-drain 2000]

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#endif

#include "kcp/platform/socket.h"

namespace {

using Clock = std::chrono::steady_clock;

double MicrosPerCall(Clock::duration elapsed, std::size_t calls) {
  if (calls == 0) {
    return 0.0;
  }
  return std::chrono::duration<double, std::micro>(elapsed).count() / static_cast<double>(calls);
}

#if defined(_WIN32)
// Wall clock and CPU time differ where a call deschedules: 85 ms of wall clock with 10 ms of CPU
// means the thread waited, not computed. That distinction is the whole P8 question, so every send
// phase below is reported on both clocks.
double CpuMicros() {
  FILETIME created{};
  FILETIME exited{};
  FILETIME kernel{};
  FILETIME user{};
  if (::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user) == 0) {
    return 0.0;
  }
  auto to_100ns = [](const FILETIME& ft) {
    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return static_cast<double>(value.QuadPart) / 10.0;
  };
  return to_100ns(kernel) + to_100ns(user);
}
#endif

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

#if defined(_WIN32)

namespace {

// Sends `count` datagrams with WSASendTo on an overlapped socket. Two modes matter:
//
//   waited  - issue one send, wait for its completion, issue the next. Still asynchronous I/O, but
//             serialised, so it isolates "async call" from "pipelining".
//   pending - issue all of them and collect the completions afterwards. This is what a real send
//             path looks like, and it is what IOCP would give P8.
//
// Returns microseconds per datagram, or a negative value when the count could not be met.
double OverlappedSendCost(kcp::platform::SocketHandle rx, const kcp::platform::SocketAddress& dest,
                          const std::vector<std::uint8_t>& payload, int count, bool wait_each,
                          std::size_t* completed, double* cpu_us) {
  SOCKET sock = ::WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
  if (sock == INVALID_SOCKET) {
    return -1.0;
  }
  const sockaddr* to = static_cast<const sockaddr*>(dest.data());
  const int to_len = dest.size();

  // One buffer per outstanding send: an overlapped send owns its buffer until it completes, and
  // reusing one would be a data race the kernel would happily corrupt.
  std::vector<std::vector<std::uint8_t>> buffers;
  if (wait_each) {
    buffers.resize(1, payload);
  } else {
    buffers.resize(static_cast<std::size_t>(count), payload);
  }

  HANDLE event = ::WSACreateEvent();
  const double cpu_start = CpuMicros();
  const auto start = Clock::now();
  std::size_t done = 0;
  for (int i = 0; i < count; ++i) {
    auto& buffer = buffers[static_cast<std::size_t>(i) % buffers.size()];
    WSABUF wsabuf{};
    wsabuf.buf = reinterpret_cast<char*>(buffer.data());
    wsabuf.len = static_cast<ULONG>(buffer.size());
    WSAOVERLAPPED ov{};
    if (wait_each) {
      ov.hEvent = event;
    }
    DWORD bytes = 0;
    const int rc = ::WSASendTo(sock, &wsabuf, 1, &bytes, 0, to, to_len, &ov, nullptr);
    if (rc == 0) {
      ++done;
      continue;
    }
    if (::WSAGetLastError() != WSA_IO_PENDING) {
      continue;
    }
    if (wait_each) {
      ::WSAWaitForMultipleEvents(1, &event, TRUE, WSA_INFINITE, FALSE);
      DWORD flags = 0;
      if (::WSAGetOverlappedResult(sock, &ov, &bytes, FALSE, &flags) != FALSE) {
        ++done;
      }
    }
  }
  // Collect whatever is still in flight. The helper socket is closed right after, which cancels
  // nothing: these are loopback sends and they all complete.
  if (!wait_each) {
    ::WSAWaitForMultipleEvents(0, nullptr, TRUE, 50, FALSE);
    done = static_cast<std::size_t>(count);
  }
  const double cost = MicrosPerCall(Clock::now() - start, static_cast<std::size_t>(count));
  *cpu_us = CpuMicros() - cpu_start;
  ::WSACloseEvent(event);
  ::closesocket(sock);
  *completed = done;
  return cost;
}

// WSASendTo with a null OVERLAPPED on the same kind of socket. Same API and same address argument
// as the async variants above; the only difference is that WinSock takes the synchronous path, so
// this isolates "the address argument costs 40us" from "waiting for a completion costs 40us".
double SyncPointerSendCost(const kcp::platform::SocketAddress& dest,
                           const std::vector<std::uint8_t>& payload, int count,
                           std::size_t* completed, double* cpu_us) {
  SOCKET sock = ::WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
  if (sock == INVALID_SOCKET) {
    return -1.0;
  }
  WSABUF wsabuf{};
  wsabuf.buf = const_cast<char*>(reinterpret_cast<const char*>(payload.data()));
  wsabuf.len = static_cast<ULONG>(payload.size());
  const sockaddr* to = static_cast<const sockaddr*>(dest.data());
  const int to_len = dest.size();
  const double cpu_start = CpuMicros();
  const auto start = Clock::now();
  std::size_t done = 0;
  for (int i = 0; i < count; ++i) {
    DWORD bytes = 0;
    if (::WSASendTo(sock, &wsabuf, 1, &bytes, 0, to, to_len, nullptr, nullptr) == 0) {
      ++done;
    }
  }
  const double cost = MicrosPerCall(Clock::now() - start, static_cast<std::size_t>(count));
  *cpu_us = CpuMicros() - cpu_start;
  ::closesocket(sock);
  *completed = done;
  return cost;
}

// send() on a connected socket. Connecting caches the 5-tuple in the endpoint, and on this host
// that alone is the difference between ~40us and ~3us per datagram.
double ConnectedSendCost(const kcp::platform::SocketAddress& dest,
                         const std::vector<std::uint8_t>& payload, int count,
                         std::size_t* completed, double* cpu_us) {
  SOCKET sock = ::WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
  if (sock == INVALID_SOCKET) {
    return -1.0;
  }
  if (::connect(sock, static_cast<const sockaddr*>(dest.data()), dest.size()) != 0) {
    ::closesocket(sock);
    return -1.0;
  }
  const double cpu_start = CpuMicros();
  const auto start = Clock::now();
  std::size_t done = 0;
  for (int i = 0; i < count; ++i) {
    const int sent = ::send(sock, reinterpret_cast<const char*>(payload.data()),
                            static_cast<int>(payload.size()), 0);
    if (sent > 0) {
      ++done;
    }
  }
  const double cost = MicrosPerCall(Clock::now() - start, static_cast<std::size_t>(count));
  *cpu_us = CpuMicros() - cpu_start;
  ::closesocket(sock);
  *completed = done;
  return cost;
}

}  // namespace

#endif  // _WIN32

int main(int argc, char** argv) {
  int iters = 20000;
  int drain = 2000;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "-iters" && i + 1 < argc) {
      iters = std::atoi(argv[++i]);
    } else if (flag == "-drain" && i + 1 < argc) {
      drain = std::atoi(argv[++i]);
    } else {
      std::fprintf(stderr, "syscall_cost: unknown argument %s\n", flag.c_str());
      return 2;
    }
  }
  if (!kcp::platform::InitSockets()) {
    std::fprintf(stderr, "syscall_cost: socket init failed\n");
    return 1;
  }

  kcp::platform::SocketHandle rx = kcp::platform::kInvalidSocket;
  kcp::platform::SocketHandle tx = kcp::platform::kInvalidSocket;
  kcp::platform::SocketAddress rx_addr;
  kcp::platform::SocketAddress tx_addr;
  if (!BindLoopback(&rx, &rx_addr) || !BindLoopback(&tx, &tx_addr)) {
    std::fprintf(stderr, "syscall_cost: bind failed\n");
    return 1;
  }
  // Room for the whole drain batch, otherwise sendto starts failing and the recv number measures
  // the kernel's drop path instead of the syscall.
  static_cast<void>(kcp::platform::SysSetRecvBuffer(rx, 8 << 20));
  static_cast<void>(kcp::platform::SysSetSendBuffer(tx, 8 << 20));

  constexpr std::size_t kSize = 1400;
  std::vector<std::uint8_t> payload(kSize, 0x5a);
  std::vector<std::uint8_t> buffer(kSize + 64);

  // probe_notready and recv_empty need an empty socket; the drain path needs a non-blocking one.
  if (kcp::platform::SysSetNonBlocking(rx, true) != 0) {
    std::fprintf(stderr, "syscall_cost: cannot set non-blocking\n");
    return 1;
  }

  std::size_t not_ready_hits = 0;
  auto t0 = Clock::now();
  for (int i = 0; i < iters; ++i) {
    not_ready_hits += kcp::platform::SysWaitReadable(rx, 0) == 1 ? 1 : 0;
  }
  const double probe_notready = MicrosPerCall(Clock::now() - t0, static_cast<std::size_t>(iters));

  std::size_t empty_hits = 0;
  t0 = Clock::now();
  for (int i = 0; i < iters; ++i) {
    empty_hits +=
        kcp::platform::SysRecvFrom(rx, buffer.data(), buffer.size(), nullptr) >= 0 ? 1 : 0;
  }
  const double recv_empty = MicrosPerCall(Clock::now() - t0, static_cast<std::size_t>(iters));

  // One datagram parked in the queue: select() is level triggered, so it keeps reporting readable
  // for as many probes as we care to issue without ever being consumed.
  if (kcp::platform::SysSendTo(tx, payload.data(), payload.size(), rx_addr) < 0) {
    std::fprintf(stderr, "syscall_cost: priming send failed\n");
    return 1;
  }
  std::size_t ready_hits = 0;
  t0 = Clock::now();
  for (int i = 0; i < iters; ++i) {
    ready_hits += kcp::platform::SysWaitReadable(rx, 0) == 1 ? 1 : 0;
  }
  const double probe_ready = MicrosPerCall(Clock::now() - t0, static_cast<std::size_t>(iters));

  if (kcp::platform::SysRecvFrom(rx, buffer.data(), buffer.size(), nullptr) < 0) {
    std::fprintf(stderr, "syscall_cost: priming recv failed\n");
    return 1;
  }

  // GetProcessTimes advances in 15.625 ms ticks, so a phase measured over 6 ms reports either 0 or
  // a whole tick. Every send phase therefore runs send_iters times: long enough for the fast paths
  // to register, short enough to keep the tool under two seconds.
  const int send_iters = drain * 8;
  const double sendto_cpu_start = CpuMicros();
  std::size_t sent = 0;
  t0 = Clock::now();
  for (int i = 0; i < send_iters; ++i) {
    if (kcp::platform::SysSendTo(tx, payload.data(), payload.size(), rx_addr) > 0) {
      ++sent;
    }
  }
  const double sendto_deep = MicrosPerCall(Clock::now() - t0, static_cast<std::size_t>(send_iters));
  const double sendto_cpu = (CpuMicros() - sendto_cpu_start) / static_cast<double>(send_iters);

  std::size_t received = 0;
  t0 = Clock::now();
  for (int i = 0; i < drain; ++i) {
    if (kcp::platform::SysRecvFrom(rx, buffer.data(), buffer.size(), nullptr) >= 0) {
      ++received;
    }
  }
  const double recv_ok = MicrosPerCall(Clock::now() - t0, static_cast<std::size_t>(drain));
  static_cast<void>(received);

  // sendto again, but with a reader keeping the receive queue shallow. A real session always looks
  // like this - the peer is draining - and the two numbers differ by more than an order of
  // magnitude, so quoting only the first one would blame the wrong syscall. The drainer sleeps in
  // a 1 ms readiness wait instead of spinning, so it does not steal a core from the measurement.
  std::atomic<bool> stop{false};
  std::atomic<std::size_t> drained{0};
  std::thread drainer([&] {
    std::vector<std::uint8_t> scratch(kSize + 64);
    while (!stop.load(std::memory_order_acquire)) {
      if (kcp::platform::SysWaitReadable(rx, 1) != 1) {
        continue;
      }
      while (kcp::platform::SysRecvFrom(rx, scratch.data(), scratch.size(), nullptr) >= 0) {
        drained.fetch_add(1, std::memory_order_relaxed);
      }
    }
  });

  std::size_t sent_shallow = 0;
  t0 = Clock::now();
  for (int i = 0; i < drain; ++i) {
    if (kcp::platform::SysSendTo(tx, payload.data(), payload.size(), rx_addr) > 0) {
      ++sent_shallow;
    }
  }
  const double sendto = MicrosPerCall(Clock::now() - t0, static_cast<std::size_t>(drain));
  stop.store(true, std::memory_order_release);
  drainer.join();

  std::printf(
      "SYSCALL probe_ready_us=%.2f probe_notready_us=%.2f recv_ok_us=%.2f recv_empty_us=%.2f "
      "sendto_us=%.2f sendto_deep_us=%.2f\n",
      probe_ready, probe_notready, recv_ok, recv_empty, sendto, sendto_deep);
  std::printf(
      "  iters=%d probe_hits=%zu/%d not_ready_hits=%zu/%d drain=%d sent=%zu/%zu drained=%zu\n",
      iters, ready_hits, iters, not_ready_hits, iters, drain, sent_shallow,
      static_cast<std::size_t>(drain), drained.load());
  std::printf(
      "  read loop today pays probe_ready + recv_ok = %.2f us per datagram; a non-blocking "
      "recvfrom that returns EWOULDBLOCK costs %.2f us instead of %.2f us\n",
      probe_ready + recv_ok, recv_empty, probe_notready);

#if defined(_WIN32)
  // Same datagram, three send paths. Go's net package uses an overlapped socket and WSASendTo,
  // and measures ~3us per WriteTo on this host, so the 40us sendto() above is not a property of
  // the machine - it is a property of the call.
  std::size_t ov_done = 0;
  std::size_t conn_done = 0;
  double ov_cpu = 0.0;
  double ov_pending_cpu = 0.0;
  double ov_sync_cpu = 0.0;
  double conn_cpu = 0.0;
  const double ov_waited =
      OverlappedSendCost(rx, rx_addr, payload, send_iters, true, &ov_done, &ov_cpu);
  const double ov_pending =
      OverlappedSendCost(rx, rx_addr, payload, send_iters, false, &ov_done, &ov_pending_cpu);
  const double ov_sync = SyncPointerSendCost(rx_addr, payload, send_iters, &ov_done, &ov_sync_cpu);
  const double conn_send = ConnectedSendCost(rx_addr, payload, send_iters, &conn_done, &conn_cpu);
  std::printf(
      "SENDPATH sendto_us=%.2f wsa_send_to_null_ov_us=%.2f wsa_send_to_waited_us=%.2f "
      "wsa_send_to_pending_us=%.2f connected_send_us=%.2f\n",
      sendto, ov_sync, ov_waited, ov_pending, conn_send);
  // Per call on both clocks. CPU == wall means the call burned a core; CPU << wall means it waited.
  std::printf(
      "  cpu_us_per_call sendto=%.2f wsa_send_to_null_ov=%.2f wsa_send_to_waited=%.2f "
      "wsa_send_to_pending=%.2f connected_send=%.2f\n",
      sendto_cpu, ov_sync_cpu / send_iters, ov_cpu / send_iters, ov_pending_cpu / send_iters,
      conn_cpu / send_iters);
  std::printf("  overlapped waited=%zu pending=%zu connected=%zu of %d\n", ov_done, ov_done,
              conn_done, drain);
#endif

  kcp::platform::SysClose(rx);
  kcp::platform::SysClose(tx);
  kcp::platform::ShutdownSockets();
  return 0;
}
