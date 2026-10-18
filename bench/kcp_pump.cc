// Throwaway diagnostic: how fast is the KCP state machine alone, with no sockets and no threads?
// Two Kcp instances in one thread, pumped through callbacks. Establishes whether the 12 MB/s
// session throughput is KCP's doing or the socket/thread layer's.

#include <chrono>
#include <cstdio>
#include <vector>

#include "kcp/kcp.h"

int main() {
  std::vector<std::vector<std::uint8_t>> a_to_b;

  kcp::Kcp a(1, [&a_to_b](const std::uint8_t* buf, std::size_t size) {
    a_to_b.emplace_back(buf, buf + size);
  });
  std::vector<std::vector<std::uint8_t>> b_to_a;
  kcp::Kcp b(1, [&b_to_a](const std::uint8_t* buf, std::size_t size) {
    b_to_a.emplace_back(buf, buf + size);
  });
  a.NoDelay(1, 10, 2, 1);
  b.NoDelay(1, 10, 2, 1);
  a.WndSize(32, 32);
  b.WndSize(32, 32);
  a.SetMtu(1400);
  b.SetMtu(1400);

  std::size_t total = 0;
  const std::size_t kTarget = 40u * 1024u * 1024u;
  const std::size_t kMss = static_cast<std::size_t>(a.mss());
  std::vector<std::uint8_t> chunk(kMss, 0x5a);
  std::vector<std::uint8_t> rcv(64 * 1024);

  const auto start = std::chrono::steady_clock::now();
  while (total < kTarget) {
    while (a.wait_snd() < static_cast<int>(a.snd_wnd())) {
      a.Send(chunk.data(), chunk.size());
    }
    a.Flush(kcp::kFlushFull);
    a.Update();

    for (auto& packet : a_to_b) {
      b.Input(packet.data(), packet.size());
    }
    a_to_b.clear();
    b.Flush(kcp::kFlushFull);
    b.Update();

    for (auto& packet : b_to_a) {
      a.Input(packet.data(), packet.size());
    }
    b_to_a.clear();

    for (;;) {
      const int peek = b.PeekSize();
      if (peek <= 0) break;
      if (static_cast<std::size_t>(peek) > rcv.size()) rcv.resize(peek);
      const int got = b.Recv(rcv.data(), rcv.size());
      if (got <= 0) break;
      total += static_cast<std::size_t>(got);
    }
  }
  const double seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  const double mb = static_cast<double>(total) / (1024.0 * 1024.0);
  std::printf("kcp_pump: %.1f MB in %.3fs = %.1f MB/s (mss=%zu)\n", mb, seconds, mb / seconds,
              kMss);
  return 0;
}
