// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors

#include "lossy_relay.h"

#include <chrono>
#include <cstdio>

namespace kcp {
namespace test {
namespace {

constexpr std::size_t kRelayBuffer = 2048;

bool BindLoopback(platform::SocketHandle* fd, platform::SocketAddress* addr) {
  *fd = platform::SysSocketUdp();
  if (*fd == platform::kInvalidSocket) {
    return false;
  }
  platform::SocketAddress any;
  if (!platform::SocketAddress::ParseHostPort("127.0.0.1:0", &any)) {
    return false;
  }
  if (platform::SysBind(*fd, any) != 0) {
    return false;
  }
  return platform::SysGetSockName(*fd, addr) == 0;
}

}  // namespace

LossyRelay::LossyRelay() = default;

LossyRelay::~LossyRelay() { Stop(); }

bool LossyRelay::Start(const std::string& server_addr, const Config& config, std::string* error) {
  if (!platform::InitSockets()) {
    *error = "socket layer init failed";
    return false;
  }
  if (!platform::SocketAddress::ParseHostPort(server_addr, &server_addr_)) {
    *error = "cannot parse server address " + server_addr;
    return false;
  }
  platform::SocketAddress front_addr;
  platform::SocketAddress back_addr;
  if (!BindLoopback(&front_, &front_addr) || !BindLoopback(&back_, &back_addr)) {
    *error = "cannot bind relay sockets";
    return false;
  }
  front_text_ = front_addr.ToString();
  // A relay that drops datagrams because its own socket buffer overflowed would silently add loss
  // the model did not ask for, so give both sockets room.
  platform::SysSetRecvBuffer(front_, 4 << 20);
  platform::SysSetSendBuffer(front_, 4 << 20);
  platform::SysSetRecvBuffer(back_, 4 << 20);
  platform::SysSetSendBuffer(back_, 4 << 20);

  config_ = config;
  rng_ = config.seed == 0 ? 1 : config.seed;
  stop_.store(false, std::memory_order_release);
  front_thread_ = std::thread(&LossyRelay::ForwardFront, this);
  back_thread_ = std::thread(&LossyRelay::ForwardBack, this);
  return true;
}

void LossyRelay::Stop() {
  if (stop_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  if (front_thread_.joinable()) {
    front_thread_.join();
  }
  if (back_thread_.joinable()) {
    back_thread_.join();
  }
  if (front_ != platform::kInvalidSocket) {
    platform::SysClose(front_);
    front_ = platform::kInvalidSocket;
  }
  if (back_ != platform::kInvalidSocket) {
    platform::SysClose(back_);
    back_ = platform::kInvalidSocket;
  }
}

LossyRelay::Stats LossyRelay::Snapshot() const {
  Stats stats;
  stats.to_server = to_server_.load(std::memory_order_relaxed);
  stats.to_client = to_client_.load(std::memory_order_relaxed);
  stats.dropped = dropped_.load(std::memory_order_relaxed);
  return stats;
}

// xorshift32: deterministic per seed, which is what makes a 30% run reproducible.
bool LossyRelay::Drop() {
  rng_ ^= rng_ << 13;
  rng_ ^= rng_ >> 17;
  rng_ ^= rng_ << 5;
  const double unit = static_cast<double>(rng_ & 0xffffff) / static_cast<double>(0x1000000);

  if (!config_.gilbert) {
    return unit < config_.loss;
  }
  // Two-state chain: in the bad state every datagram is lost, in the good state none is.
  if (bad_state_) {
    if (unit < 0.5) {
      bad_state_ = false;  // p(bad -> good)
    }
    return true;
  }
  if (unit < 0.01) {
    bad_state_ = true;  // p(good -> bad)
    return true;
  }
  return false;
}

void LossyRelay::ForwardFront() {
  std::vector<std::uint8_t> buffer(kRelayBuffer);
  while (!stop_.load(std::memory_order_acquire)) {
    if (platform::SysWaitReadable(front_, 50) != 1) {
      continue;
    }
    platform::SocketAddress from;
    const int got = platform::SysRecvFrom(front_, buffer.data(), buffer.size(), &from);
    if (got <= 0) {
      continue;
    }
    // The client's address is whatever dialled us first.
    {
      std::lock_guard<std::mutex> lock(client_mu_);
      client_addr_ = from;
      have_client_ = true;
    }
    if (Drop()) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    if (config_.delay_ms > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(config_.delay_ms));
    }
    platform::SysSendTo(back_, buffer.data(), static_cast<std::size_t>(got), server_addr_);
    to_server_.fetch_add(1, std::memory_order_relaxed);
  }
}

void LossyRelay::ForwardBack() {
  std::vector<std::uint8_t> buffer(kRelayBuffer);
  while (!stop_.load(std::memory_order_acquire)) {
    if (platform::SysWaitReadable(back_, 50) != 1) {
      continue;
    }
    platform::SocketAddress from;
    const int got = platform::SysRecvFrom(back_, buffer.data(), buffer.size(), &from);
    if (got <= 0) {
      continue;
    }
    platform::SocketAddress client;
    {
      std::lock_guard<std::mutex> lock(client_mu_);
      if (!have_client_) {
        // Nothing to forward yet: the client has not introduced itself.
        continue;
      }
      client = client_addr_;
    }
    if (Drop()) {
      dropped_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }
    if (config_.delay_ms > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(config_.delay_ms));
    }
    platform::SysSendTo(front_, buffer.data(), static_cast<std::size_t>(got), client);
    to_client_.fetch_add(1, std::memory_order_relaxed);
  }
}

}  // namespace test
}  // namespace kcp
