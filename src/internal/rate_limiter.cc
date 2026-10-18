// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Port of xtaci/kcp-go (MIT, Copyright (c) 2015 xtaci).
// https://github.com/xtaci/kcp-go

#include "kcp/internal/rate_limiter.h"

#include <algorithm>

#include "kcp/internal/constants.h"

namespace kcp {
namespace internal {

RateLimiter::RateLimiter(std::uint32_t bytes_per_second)
    : rate_(static_cast<double>(bytes_per_second)),
      burst_(static_cast<double>(kMaxBatchSize * kMtuLimit)),
      tokens_(static_cast<double>(kMaxBatchSize * kMtuLimit)),
      last_(std::chrono::steady_clock::now()) {}

void RateLimiter::Refill(std::chrono::steady_clock::time_point now) {
  const std::chrono::duration<double> elapsed = now - last_;
  last_ = now;
  tokens_ = std::min(burst_, tokens_ + elapsed.count() * rate_);
}

void RateLimiter::Acquire(std::size_t n) {
  if (unlimited() || n == 0) {
    return;
  }
  // A batch bigger than the bucket can never be satisfied; the reference lets it through and so
  // does this port (WaitN returns an error that sess.go discards).
  const double want = std::min(static_cast<double>(n), burst_);

  std::unique_lock<std::mutex> lock(mu_);
  for (;;) {
    const auto now = std::chrono::steady_clock::now();
    Refill(now);
    if (tokens_ >= want) {
      tokens_ -= want;
      return;
    }
    const double missing = want - tokens_;
    const std::chrono::duration<double> wait(missing / rate_);
    cv_.wait_for(lock, std::chrono::duration_cast<std::chrono::microseconds>(wait) +
                           std::chrono::microseconds(100));
  }
}

}  // namespace internal
}  // namespace kcp
