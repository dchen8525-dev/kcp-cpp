// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Real-UDP lossy relay for PORTING-PLAN.md §6.2 (deviation D13 deferred the socket form to P6).
//
// Two sockets, two forwarding threads, no reordering and no byte damage: a datagram is either
// dropped whole or forwarded unchanged, so KCP sees exactly the loss pattern the model produces and
// nothing else. P5 used an in-process relay with a virtual clock, which was the right tool for a
// pure state machine; the session layer has real sockets and threads, so the gate needs the real
// thing.

#ifndef KCP_TESTS_LOSSY_RELAY_H_
#define KCP_TESTS_LOSSY_RELAY_H_

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "kcp/platform/socket.h"

namespace kcp {
namespace test {

class LossyRelay {
 public:
  struct Config {
    // Uniform per-datagram drop probability (0.0 .. 1.0).
    double loss = 0.0;
    // Gilbert-Elliott burst model: good/bad states with p(good->bad)=0.01, p(bad->good)=0.5 and a
    // mean burst of ~10 datagrams. When enabled it replaces the uniform model.
    bool gilbert = false;
    // Fixed one-way delay. Order is preserved per direction, which is why jitter is deliberately
    // not offered: varying it would reorder datagrams, and §6.2 requires that it must not.
    int delay_ms = 0;
    std::uint32_t seed = 1;
  };

  struct Stats {
    std::uint64_t to_server = 0;
    std::uint64_t to_client = 0;
    std::uint64_t dropped = 0;
  };

  LossyRelay();
  ~LossyRelay();

  LossyRelay(const LossyRelay&) = delete;
  LossyRelay& operator=(const LossyRelay&) = delete;

  // Binds both sockets. `server_addr` is the echo server the relay forwards towards.
  bool Start(const std::string& server_addr, const Config& config, std::string* error);

  // The address the client dials.
  std::string front_addr() const { return front_text_; }

  Stats Snapshot() const;

  void Stop();

 private:
  void ForwardFront();
  void ForwardBack();
  bool Drop();

  Config config_;
  platform::SocketHandle front_ = platform::kInvalidSocket;
  platform::SocketHandle back_ = platform::kInvalidSocket;
  platform::SocketAddress server_addr_;
  // Guarded: the front thread learns the client address while the back thread sends to it.
  mutable std::mutex client_mu_;
  platform::SocketAddress client_addr_;
  std::string front_text_;
  bool have_client_ = false;
  std::uint64_t rng_ = 1;
  bool bad_state_ = false;

  std::atomic<bool> stop_{false};
  std::atomic<std::uint64_t> to_server_{0};
  std::atomic<std::uint64_t> to_client_{0};
  std::atomic<std::uint64_t> dropped_{0};
  std::thread front_thread_;
  std::thread back_thread_;
};

}  // namespace test
}  // namespace kcp

#endif  // KCP_TESTS_LOSSY_RELAY_H_
