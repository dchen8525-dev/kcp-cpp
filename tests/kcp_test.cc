// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Gate for PORTING-PLAN.md P5: the first flush of a fresh Kcp must reproduce kcp.json byte for
// byte (with the ts field masked, since it comes from the clock), the segment header fields must
// match what the vector says they are, and the ARQ must survive a lossy link. The lossy runs use
// a virtual clock and an in-process relay instead of real UDP sockets, so a 30% loss run over
// 1 MB takes milliseconds and is bit-for-bit reproducible (deviation D13).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <random>
#include <string>
#include <vector>

#include "json_reader.h"
#include "kcp/internal/byteorder.h"
#include "kcp/internal/constants.h"
#include "kcp/kcp.h"
#include "kcp/snmp.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

#define CHECK(cond)                                     \
  do {                                                  \
    if (!(cond)) {                                      \
      Fail(__FILE__, __LINE__, "CHECK failed: " #cond); \
    }                                                   \
  } while (false)

#define CHECK_EQ(a, b)                                                                         \
  do {                                                                                         \
    const auto lhs = (a);                                                                      \
    const auto rhs = (b);                                                                      \
    if (!(lhs == rhs)) {                                                                       \
      Fail(__FILE__, __LINE__,                                                                 \
           std::string("CHECK_EQ failed: " #a " == " #b " (") + std::to_string(lhs) + " vs " + \
               std::to_string(rhs) + ")");                                                     \
    }                                                                                          \
  } while (false)

using Bytes = std::vector<std::uint8_t>;
using kcp::internal::Segment;
using kcp::internal::WriteLe32;
using kcp::test::BytesToHex;
using kcp::test::Find;
using kcp::test::GetBool;
using kcp::test::GetInt;
using kcp::test::GetString;
using kcp::test::HexToBytes;
using kcp::test::JsonValue;
using kcp::test::LoadJsonFile;

// tools/golden/ref/golden_ref.go.txt:91
Bytes Pattern(std::size_t length, std::uint8_t seed) {
  Bytes out(length);
  for (std::size_t i = 0; i < length; ++i) {
    out[i] = static_cast<std::uint8_t>((i * 31 + seed) & 0xff);
  }
  return out;
}

Bytes EncodeSegment(std::uint32_t conv, std::uint8_t cmd, std::uint8_t frg, std::uint16_t wnd,
                    std::uint32_t ts, std::uint32_t sn, std::uint32_t una, const Bytes& payload) {
  Segment seg;
  seg.conv = conv;
  seg.cmd = cmd;
  seg.frg = frg;
  seg.wnd = wnd;
  seg.ts = ts;
  seg.sn = sn;
  seg.una = una;
  seg.data = payload;
  Bytes out(kcp::kOverhead + payload.size());
  seg.Encode(out.data());
  if (!payload.empty()) {
    std::memcpy(out.data() + kcp::kOverhead, payload.data(), payload.size());
  }
  return out;
}

// ---------------------------------------------------------------------------
// kcp.json
// ---------------------------------------------------------------------------

// The ts field is the only wall-clock byte range in a segment (offset 8..11). The generator zeroes
// it before storing; the C++ side does the same after asserting the clock value actually landed
// there, so a segment that forgot to stamp ts cannot pass by accident.
constexpr std::size_t kTsOffset = 8;

void TestGoldenVectors() {
  JsonValue root;
  std::string error;
  const std::string path = std::string(KCP_VECTOR_DIR) + "/kcp.json";
  if (!LoadJsonFile(path, &root, &error)) {
    Fail(__FILE__, __LINE__, "cannot load " + path + ": " + error);
    return;
  }
  const JsonValue* vectors = Find(root, "vectors");
  if (vectors == nullptr || !vectors->IsArray()) {
    Fail(__FILE__, __LINE__, "kcp.json has no vectors array");
    return;
  }
  if (vectors->size() != 2) {
    Fail(__FILE__, __LINE__, "kcp.json should hold the message-mode and stream-mode vectors");
    return;
  }

  for (const JsonValue& vector : vectors->array_value) {
    bool stream = false;
    GetBool(vector, "stream", &stream);
    const JsonValue* params = Find(vector, "params");
    const JsonValue* segments = Find(vector, "segments");
    if (params == nullptr || segments == nullptr) {
      Fail(__FILE__, __LINE__, "vector is missing params or segments");
      continue;
    }

    long long conv = 0;
    long long mtu = 0;
    long long snd_wnd = 0;
    long long rcv_wnd = 0;
    long long nodelay = 0;
    long long interval = 0;
    long long resend = 0;
    long long nc = 0;
    long long wait_snd = 0;
    GetInt(*params, "conv", &conv);
    GetInt(*params, "mtu", &mtu);
    GetInt(*params, "snd_wnd", &snd_wnd);
    GetInt(*params, "rcv_wnd", &rcv_wnd);
    GetInt(*params, "nodelay", &nodelay);
    GetInt(*params, "interval", &interval);
    GetInt(*params, "resend", &resend);
    GetInt(*params, "nc", &nc);
    GetInt(*params, "wait_snd", &wait_snd);

    std::vector<Bytes> emitted;
    constexpr std::uint32_t kClock = 4321;
    kcp::Kcp k(
        static_cast<std::uint32_t>(conv),
        [&emitted](const std::uint8_t* buf, std::size_t size) {
          emitted.emplace_back(buf, buf + size);
        },
        []() { return kClock; });
    CHECK_EQ(k.SetMtu(static_cast<int>(mtu)), 0);
    CHECK_EQ(k.NoDelay(static_cast<int>(nodelay), static_cast<int>(interval),
                       static_cast<int>(resend), static_cast<int>(nc)),
             0);
    CHECK_EQ(k.WndSize(static_cast<int>(snd_wnd), static_cast<int>(rcv_wnd)), 0);
    if (stream) {
      k.SetStreamMode(true);
    }

    const Bytes payload = Pattern(3000, 0x42);
    CHECK_EQ(k.Send(payload.data(), payload.size()), 0);
    CHECK_EQ(k.wait_snd(), static_cast<int>(wait_snd));

    // One Update is enough: the first call resyncs ts_flush to now and flushes immediately.
    k.Update();

    if (emitted.size() != segments->size()) {
      Fail(__FILE__, __LINE__,
           std::string("segment count mismatch (stream=") + (stream ? "1" : "0") + ", got " +
               std::to_string(emitted.size()) + " want " + std::to_string(segments->size()) + ")");
      continue;
    }

    for (std::size_t i = 0; i < emitted.size(); ++i) {
      const JsonValue& expected = segments->array_value[i];
      long long cmd = 0;
      long long frg = 0;
      long long sn = 0;
      long long una = 0;
      long long len = 0;
      std::string hex;
      GetInt(expected, "cmd", &cmd);
      GetInt(expected, "frg", &frg);
      GetInt(expected, "sn", &sn);
      GetInt(expected, "una", &una);
      GetInt(expected, "len", &len);
      GetString(expected, "bytes_hex", &hex);

      Bytes actual = emitted[i];
      const std::string label =
          std::string("stream=") + (stream ? "1" : "0") + " seg " + std::to_string(i);
      CHECK_EQ(actual.size(), kcp::kOverhead + static_cast<std::size_t>(len));
      if (actual.size() < kcp::kOverhead) {
        continue;
      }
      CHECK_EQ(static_cast<long long>(actual[4]), cmd);
      CHECK_EQ(static_cast<long long>(actual[5]), frg);
      CHECK_EQ(static_cast<long long>(kcp::internal::ReadLe16(actual.data() + 6)), 32);
      CHECK_EQ(static_cast<long long>(kcp::internal::ReadLe32(actual.data() + 12)), sn);
      CHECK_EQ(static_cast<long long>(kcp::internal::ReadLe32(actual.data() + 16)), una);
      CHECK_EQ(static_cast<long long>(kcp::internal::ReadLe32(actual.data() + 20)), len);
      // The clock value must be sitting in the ts field before it gets masked away.
      CHECK_EQ(kcp::internal::ReadLe32(actual.data() + kTsOffset), kClock);

      for (std::size_t b = kTsOffset; b < kTsOffset + 4; ++b) {
        actual[b] = 0;
      }
      if (BytesToHex(actual) != hex) {
        Fail(__FILE__, __LINE__, label + " bytes differ from kcp.json");
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Fragmentation and reassembly at the MTU boundary
// ---------------------------------------------------------------------------

void TestFragmentationBoundary() {
  const auto mss = static_cast<std::size_t>(kcp::kMtuDef) - kcp::kOverhead;
  const std::vector<std::size_t> sizes = {1,
                                          mss - 1,
                                          mss,
                                          mss + 1,
                                          2 * mss,
                                          static_cast<std::size_t>(kcp::kMtuDef) - 1,
                                          static_cast<std::size_t>(kcp::kMtuDef),
                                          static_cast<std::size_t>(kcp::kMtuDef) + 1};

  for (std::size_t size : sizes) {
    std::vector<Bytes> emitted;
    kcp::Kcp sender(7, [&emitted](const std::uint8_t* buf, std::size_t len) {
      emitted.emplace_back(buf, buf + len);
    });
    // nc=1 disables congestion control, so cwnd does not gate the first flush. With the default
    // params the first flush emits nothing and only bootstraps cwnd to 1 (see TestCwndBootstrap).
    sender.NoDelay(1, 10, 2, 1);
    const Bytes payload = Pattern(size, 0x11);
    CHECK_EQ(sender.Send(payload.data(), payload.size()), 0);
    sender.Update();

    // Each fragment has its own header, so the expected datagram count is ceil(size / mss).
    const std::size_t expected_fragments = (size + mss - 1) / mss;
    CHECK_EQ(emitted.size(), expected_fragments);

    // Reassemble through a real peer: PeekSize must report the whole message, and Recv must hand
    // it back unchanged.
    Bytes received;
    kcp::Kcp receiver(7, [](const std::uint8_t*, std::size_t) {});
    for (const Bytes& datagram : emitted) {
      CHECK_EQ(receiver.Input(datagram.data(), datagram.size()), 0);
    }
    CHECK_EQ(receiver.PeekSize(), static_cast<int>(size));
    received.resize(size);
    CHECK_EQ(receiver.Recv(received.data(), received.size()), static_cast<int>(size));
    if (received != payload) {
      Fail(__FILE__, __LINE__, "reassembled payload differs at size " + std::to_string(size));
    }

    // In message mode the fragment count is carried in frg, counting down to zero.
    if (!emitted.empty()) {
      CHECK_EQ(static_cast<std::size_t>(emitted.front()[5]), expected_fragments - 1);
      CHECK_EQ(static_cast<std::size_t>(emitted.back()[5]), 0u);
    }
  }
}

void TestMessageModeFragmentCounts() {
  const auto mss = static_cast<std::size_t>(kcp::kMtuDef) - kcp::kOverhead;
  std::vector<Bytes> emitted;
  kcp::Kcp sender(9, [&emitted](const std::uint8_t* buf, std::size_t len) {
    emitted.emplace_back(buf, buf + len);
  });
  sender.NoDelay(1, 10, 2, 1);
  const Bytes payload = Pattern(3 * mss, 0x22);  // exactly three fragments
  CHECK_EQ(sender.Send(payload.data(), payload.size()), 0);
  sender.Update();
  CHECK_EQ(emitted.size(), 3u);
  if (emitted.size() == 3) {
    CHECK_EQ(emitted[0][5], 2);
    CHECK_EQ(emitted[1][5], 1);
    CHECK_EQ(emitted[2][5], 0);
  }

  // > 255 fragments is rejected rather than silently truncated.
  const Bytes huge = Pattern(255 * mss + 1, 0x33);
  kcp::Kcp other(9, [](const std::uint8_t*, std::size_t) {});
  CHECK_EQ(other.Send(huge.data(), huge.size()), -2);
  CHECK_EQ(other.Send(nullptr, 0), -1);
}

void TestStreamModeMergesTail() {
  std::vector<Bytes> emitted;
  kcp::Kcp k(3, [&emitted](const std::uint8_t* buf, std::size_t len) {
    emitted.emplace_back(buf, buf + len);
  });
  k.SetStreamMode(true);
  k.NoDelay(1, 10, 2, 1);
  const Bytes a = Pattern(100, 1);
  const Bytes b = Pattern(50, 2);
  CHECK_EQ(k.Send(a.data(), a.size()), 0);
  CHECK_EQ(k.Send(b.data(), b.size()), 0);
  k.Update();
  // Both writes fit in one segment, and the merge must preserve order.
  CHECK_EQ(emitted.size(), 1u);
  if (emitted.size() == 1) {
    CHECK_EQ(static_cast<long long>(kcp::internal::ReadLe32(emitted[0].data() + 20)), 150);
    const Bytes payload(emitted[0].begin() + kcp::kOverhead, emitted[0].end());
    Bytes expected = a;
    expected.insert(expected.end(), b.begin(), b.end());
    CHECK(payload == expected);
  }
}

// ---------------------------------------------------------------------------
// Receive semantics
// ---------------------------------------------------------------------------

void TestReassemblyRequiresContiguousFragments() {
  kcp::Kcp k(5, [](const std::uint8_t*, std::size_t) {});
  const Bytes tail = EncodeSegment(5, kcp::kCmdPush, 0, 32, 0, 1, 0, Pattern(16, 2));
  const Bytes head = EncodeSegment(5, kcp::kCmdPush, 1, 32, 0, 0, 0, Pattern(16, 1));

  // The second fragment arrives first: it cannot be read until the first one shows up.
  CHECK_EQ(k.Input(tail.data(), tail.size()), 0);
  CHECK_EQ(k.PeekSize(), -1);

  CHECK_EQ(k.Input(head.data(), head.size()), 0);
  CHECK_EQ(k.PeekSize(), 32);

  // A buffer one byte short must report -2 and leave the message queued.
  Bytes small(31);
  CHECK_EQ(k.Recv(small.data(), small.size()), -2);
  CHECK_EQ(k.PeekSize(), 32);

  Bytes full(32);
  CHECK_EQ(k.Recv(full.data(), full.size()), 32);
  CHECK_EQ(k.PeekSize(), -1);
  CHECK_EQ(k.Recv(full.data(), full.size()), -1);
}

void TestInputRejectsMalformedDatagrams() {
  kcp::Kcp k(5, [](const std::uint8_t*, std::size_t) {});

  Bytes too_short(23);
  CHECK_EQ(k.Input(too_short.data(), too_short.size()), -1);

  const Bytes wrong_conv = EncodeSegment(6, kcp::kCmdPush, 0, 32, 0, 0, 0, Pattern(8, 3));
  CHECK_EQ(k.Input(wrong_conv.data(), wrong_conv.size()), -1);

  // Header promises 100 bytes of payload, only 8 are present.
  Bytes truncated = EncodeSegment(5, kcp::kCmdPush, 0, 32, 0, 0, 0, Pattern(8, 3));
  WriteLe32(truncated.data() + 20, 100);
  CHECK_EQ(k.Input(truncated.data(), truncated.size()), -2);

  Bytes bad_cmd = EncodeSegment(5, 99, 0, 32, 0, 0, 0, Pattern(8, 3));
  CHECK_EQ(k.Input(bad_cmd.data(), bad_cmd.size()), -3);
}

void TestDuplicateIsCountedNotQueued() {
  kcp::DefaultSnmp().Reset();
  kcp::Kcp k(5, [](const std::uint8_t*, std::size_t) {});
  const Bytes seg = EncodeSegment(5, kcp::kCmdPush, 0, 32, 0, 0, 0, Pattern(8, 4));
  CHECK_EQ(k.Input(seg.data(), seg.size()), 0);
  CHECK_EQ(k.Input(seg.data(), seg.size()), 0);
  // The duplicate is acknowledged again (it must be, the ACK may have been lost) but never queued.
  CHECK_EQ(k.PeekSize(), 8);
  CHECK_EQ(static_cast<long long>(kcp::DefaultSnmp().repeat_segs.load()), 1);
}

void TestCwndBootstrap() {
  // Canonical KCP behaviour, and easy to "fix" by accident while porting: cwnd starts at 0, so
  // the very first flush moves nothing. Phase 6 then lifts it to 1, and the next scheduled flush
  // sends exactly one segment. Getting this wrong changes the first tick of every connection.
  std::uint32_t now = 0;
  std::vector<Bytes> emitted;
  kcp::Kcp k(
      11,
      [&emitted](const std::uint8_t* buf, std::size_t len) {
        emitted.emplace_back(buf, buf + len);
      },
      [&now]() { return now; });

  const Bytes payload = Pattern(3000, 0x77);
  CHECK_EQ(k.Send(payload.data(), payload.size()), 0);

  k.Update();
  CHECK_EQ(emitted.size(), 0u);  // cwnd is still 0

  now = 50;
  k.Update();  // too early for the next tick
  CHECK_EQ(emitted.size(), 0u);

  now = 100;  // one default interval later
  k.Update();
  CHECK_EQ(emitted.size(), 1u);  // cwnd is 1, so exactly one segment
  if (emitted.size() == 1) {
    CHECK_EQ(static_cast<long long>(kcp::internal::ReadLe32(emitted[0].data() + 20)), 1376);
    CHECK_EQ(emitted[0][5], 2);  // first of three fragments
  }
  CHECK_EQ(k.wait_snd(), 3);
}

void TestFlushReturnsNextUpdate() {
  // sess.go:807 re-arms the session timer with flush(FULL)'s return value: the milliseconds
  // until the earliest resendts, capped at interval. Update()+Check() cannot express this -
  // Update only flushes on a ts_flush tick, so a resendts that falls between ticks is deferred
  // to the next tick (up to interval of extra tail-loss latency). The return value must
  // therefore carry the true resendts diff whenever it is closer than the interval.
  std::uint32_t now = 30;
  std::vector<Bytes> emitted;
  kcp::Kcp k(
      11,
      [&emitted](const std::uint8_t* buf, std::size_t len) {
        emitted.emplace_back(buf, buf + len);
      },
      [&now]() { return now; });

  const Bytes payload = Pattern(3000, 0x77);
  CHECK_EQ(k.Send(payload.data(), payload.size()), 0);

  k.Update();  // bootstrap: ts_flush = 30, cwnd still 0, nothing sent
  now = 130;
  k.Update();  // tick: one segment in flight, resendts = 130 + 200 (initial rto) = 330
  CHECK_EQ(emitted.size(), 1u);

  now = 280;  // mid-tick: 330 - 280 = 50 < interval (100)
  CHECK_EQ(k.Flush(kcp::kFlushFull), 50u);

  now = 330;  // resendts due: the RTO retransmit must fire on this flush call
  const std::uint64_t lost0 = kcp::DefaultSnmp().lost_segs.load();
  CHECK_EQ(k.Flush(kcp::kFlushFull), 100u);  // rto doubled to 400 -> capped at interval
  CHECK_EQ(kcp::DefaultSnmp().lost_segs.load(), lost0 + 1);
}

void TestSetMtuBoundary() {
  kcp::Kcp k(0, [](const std::uint8_t*, std::size_t) {});
  CHECK_EQ(k.SetMtu(-1), -1);
  CHECK_EQ(k.SetMtu(0), -1);
  CHECK_EQ(k.SetMtu(static_cast<int>(kcp::kOverhead) - 1), -1);
  CHECK_EQ(k.SetMtu(static_cast<int>(kcp::kOverhead)), -1);
  CHECK_EQ(k.SetMtu(static_cast<int>(kcp::kOverhead) + 1), 0);
  CHECK_EQ(k.mtu(), kcp::kOverhead + 1);
  CHECK_EQ(k.SetMtu(kcp::kMtuDef), 0);
  CHECK_EQ(k.mtu(), static_cast<std::uint32_t>(kcp::kMtuDef));

  // The minimum usable MTU leaves room for exactly one payload byte per segment.
  CHECK_EQ(k.SetMtu(static_cast<int>(kcp::kOverhead) + 1), 0);
  std::vector<Bytes> emitted;
  kcp::Kcp small(0, [&emitted](const std::uint8_t* buf, std::size_t len) {
    emitted.emplace_back(buf, buf + len);
  });
  CHECK_EQ(small.SetMtu(static_cast<int>(kcp::kOverhead) + 1), 0);
  small.NoDelay(1, 10, 2, 1);
  const Bytes payload = Pattern(3, 5);
  CHECK_EQ(small.Send(payload.data(), payload.size()), 0);
  small.Update();
  CHECK_EQ(emitted.size(), 3u);
  for (const Bytes& datagram : emitted) {
    CHECK_EQ(datagram.size(), kcp::kOverhead + 1);
  }
}

// ---------------------------------------------------------------------------
// Lossy link
// ---------------------------------------------------------------------------

enum class LossModel { kUniform, kGilbertElliott };

struct QueuedPacket {
  Bytes data;
  std::uint32_t due = 0;
};

// One direction of the link. Packets keep their order and are only ever dropped whole, which is
// what PORTING-PLAN.md §6.2 requires of the relay: no reordering, no corruption.
class Relay {
 public:
  Relay(double loss, LossModel model, std::uint32_t seed, std::uint32_t delay_ms)
      : loss_(loss), model_(model), rng_(seed), delay_(delay_ms) {}

  void Send(const std::uint8_t* buf, std::size_t len) {
    ++offered_;
    if (ShouldDrop()) {
      ++dropped_;
      return;
    }
    queue_.push_back(QueuedPacket{Bytes(buf, buf + len), now_ + delay_});
  }

  void SetNow(std::uint32_t now) { now_ = now; }

  void Deliver(std::uint32_t now, kcp::Kcp* sink) {
    while (!queue_.empty() && queue_.front().due <= now) {
      const Bytes& packet = queue_.front().data;
      sink->Input(packet.data(), packet.size());
      queue_.pop_front();
    }
  }

  std::uint64_t dropped() const { return dropped_; }
  std::uint64_t offered() const { return offered_; }

 private:
  bool ShouldDrop() {
    if (loss_ <= 0.0) {
      return false;
    }
    std::uniform_real_distribution<double> uniform(0.0, 1.0);
    if (model_ == LossModel::kUniform) {
      return uniform(rng_) < loss_;
    }
    // Gilbert-Elliott: a two-state Markov chain, so losses arrive in bursts rather than isolated.
    // p(good->bad) = 0.01, p(bad->good) = 0.5 gives ~10-packet bad runs on average.
    const double flip = uniform(rng_);
    if (in_bad_) {
      if (flip < 0.5) {
        in_bad_ = false;
      }
    } else if (flip < 0.01) {
      in_bad_ = true;
    }
    return in_bad_;
  }

  std::deque<QueuedPacket> queue_;
  double loss_ = 0.0;
  LossModel model_ = LossModel::kUniform;
  std::mt19937 rng_;
  std::uint32_t delay_ = 0;
  std::uint32_t now_ = 0;
  std::uint64_t dropped_ = 0;
  std::uint64_t offered_ = 0;
  bool in_bad_ = false;
};

struct TransferOptions {
  double loss = 0.0;
  LossModel model = LossModel::kUniform;
  std::size_t total = 1u << 20;
  int interval = 10;
  int resend = 2;
  int nc = 1;
  std::uint32_t step_ms = 1;
  std::uint32_t max_ms = 120000;
  std::uint32_t rtt_ms = 200;
};

struct TransferResult {
  bool complete = false;
  std::uint32_t elapsed_ms = 0;
  int max_wait_snd = 0;
  bool dead = false;
  std::uint64_t retrans = 0;
  std::uint64_t dropped = 0;
  Bytes received;
};

TransferResult RunTransfer(const TransferOptions& opt) {
  std::uint32_t now = 0;
  Relay c2s(opt.loss, opt.model, 0x9e3779b9u, opt.rtt_ms / 2);
  Relay s2c(opt.loss, opt.model, 0x85ebca6bu, opt.rtt_ms / 2);

  constexpr std::uint32_t kConv = 88;
  kcp::Kcp client(
      kConv, [&c2s](const std::uint8_t* buf, std::size_t len) { c2s.Send(buf, len); },
      [&now]() { return now; });
  kcp::Kcp server(
      kConv, [&s2c](const std::uint8_t* buf, std::size_t len) { s2c.Send(buf, len); },
      [&now]() { return now; });

  client.NoDelay(1, opt.interval, opt.resend, opt.nc);
  server.NoDelay(1, opt.interval, opt.resend, opt.nc);
  client.WndSize(32, 32);
  server.WndSize(32, 32);

  const Bytes payload = Pattern(opt.total, 0x5a);
  const auto mss = static_cast<std::size_t>(kcp::kMtuDef) - kcp::kOverhead;
  std::size_t fed = 0;

  kcp::DefaultSnmp().Reset();
  TransferResult result;
  Bytes recv_buffer(64 * 1024);

  for (std::uint32_t elapsed = 0; elapsed <= opt.max_ms; elapsed += opt.step_ms) {
    now = elapsed;
    c2s.SetNow(now);
    s2c.SetNow(now);
    c2s.Deliver(now, &server);
    s2c.Deliver(now, &client);

    for (;;) {
      const int n = server.Recv(recv_buffer.data(), recv_buffer.size());
      if (n < 0) {
        break;
      }
      result.received.insert(result.received.end(), recv_buffer.begin(), recv_buffer.begin() + n);
    }

    // The session blocks a writer once the send window is full; the driver mimics that, so the
    // test exercises window-limited flow instead of dumping 1 MB into the queue.
    while (fed < opt.total && client.wait_snd() < 32) {
      const std::size_t chunk = std::min(mss, opt.total - fed);
      if (client.Send(payload.data() + fed, chunk) != 0) {
        break;
      }
      fed += chunk;
    }
    result.max_wait_snd = std::max(result.max_wait_snd, client.wait_snd());

    client.Update();
    server.Update();

    if (client.IsDead()) {
      result.dead = true;
      break;
    }
    if (result.received.size() >= opt.total) {
      result.complete = true;
      result.elapsed_ms = elapsed;
      break;
    }
  }

  result.retrans = kcp::DefaultSnmp().retrans_segs.load();
  result.dropped = c2s.dropped() + s2c.dropped();
  return result;
}

void TestLossyLink(double loss, LossModel model, int interval, int resend, int nc) {
  TransferOptions opt;
  opt.loss = loss;
  opt.model = model;
  opt.interval = interval;
  opt.resend = resend;
  opt.nc = nc;

  const TransferResult result = RunTransfer(opt);
  const std::string label = "loss=" + std::to_string(loss) +
                            (model == LossModel::kGilbertElliott ? " (gilbert)" : "") +
                            " nc=" + std::to_string(nc);
  if (!result.complete) {
    Fail(__FILE__, __LINE__,
         label + ": transfer did not complete within " + std::to_string(opt.max_ms) + "ms (dead=" +
             (result.dead ? "1" : "0") + ", got " + std::to_string(result.received.size()) +
             " bytes, retrans=" + std::to_string(result.retrans) + ")");
    return;
  }
  if (result.dead) {
    Fail(__FILE__, __LINE__, label + ": link was declared dead");
  }

  const Bytes expected = Pattern(opt.total, 0x5a);
  if (result.received != expected) {
    Fail(__FILE__, __LINE__, label + ": payload mismatch");
  }
  if (loss == 0.0 && result.retrans != 0) {
    Fail(__FILE__, __LINE__,
         label + ": clean link caused " + std::to_string(result.retrans) + " retransmissions");
  }
  if (loss > 0.0 && result.retrans == 0) {
    Fail(__FILE__, __LINE__, label + ": lossy link produced no retransmissions");
  }
  if (result.elapsed_ms > 120000) {
    Fail(__FILE__, __LINE__, label + ": exceeded the 120s budget from #69");
  }
  std::printf("  %s: %zu bytes in %ums, retrans=%llu, dropped=%llu, max_wait_snd=%d\n",
              label.c_str(), result.received.size(), result.elapsed_ms,
              static_cast<unsigned long long>(result.retrans),
              static_cast<unsigned long long>(result.dropped), result.max_wait_snd);
}

void TestDeadLink() {
  // 100% loss: every segment must run out of retries. Segment.rto grows by rx_rto/2 per attempt,
  // so 20 attempts at 200ms base land around 23s of virtual time.
  TransferOptions opt;
  opt.loss = 1.0;
  opt.total = 1376;
  opt.step_ms = 5;
  opt.max_ms = 300000;
  const TransferResult result = RunTransfer(opt);
  if (!result.dead) {
    Fail(__FILE__, __LINE__, "100% loss never marked the link dead");
  }
  if (result.complete) {
    Fail(__FILE__, __LINE__, "100% loss delivered data");
  }
}

}  // namespace

int main() {
  TestGoldenVectors();
  TestFragmentationBoundary();
  TestMessageModeFragmentCounts();
  TestStreamModeMergesTail();
  TestReassemblyRequiresContiguousFragments();
  TestInputRejectsMalformedDatagrams();
  TestDuplicateIsCountedNotQueued();
  TestSetMtuBoundary();
  TestCwndBootstrap();
  TestFlushReturnsNextUpdate();

  std::printf("lossy link (virtual clock, 1 MiB, rtt 200ms):\n");
  TestLossyLink(0.0, LossModel::kUniform, 10, 2, 1);
  TestLossyLink(0.1, LossModel::kUniform, 10, 2, 1);
  TestLossyLink(0.3, LossModel::kUniform, 10, 2, 1);
  // Congestion control on: cwnd starts at 0 and grows, so this also covers the slow-start path.
  TestLossyLink(0.1, LossModel::kUniform, 10, 2, 0);
  TestDeadLink();

  if (g_failures != 0) {
    std::fprintf(stderr, "%d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("kcp_test: all checks passed\n");
  return 0;
}
