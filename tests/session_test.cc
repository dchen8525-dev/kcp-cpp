// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// P6 gate for PORTING-PLAN.md §6: real loopback sessions. Everything below talks over 127.0.0.1
// through the actual socket path, so the pipeline composition (FEC, cipher, post-processing queue,
// timers) is exercised end to end rather than in pieces.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "kcp/crypt.h"
#include "kcp/error.h"
#include "kcp/listener.h"
#include "kcp/platform/socket.h"
#include "kcp/snmp.h"
#include "kcp/udp_session.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

using kcp::Deadline;
using kcp::ErrorCode;
using kcp::Listener;
using kcp::UdpSession;

Deadline AfterMs(int ms) {
  return std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
}

std::vector<std::uint8_t> Pattern(std::size_t n, std::uint8_t seed) {
  std::vector<std::uint8_t> out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<std::uint8_t>((i * 31 + seed) & 0xff);
  }
  return out;
}

// One listening socket plus the client that dialled it.
struct Pair {
  std::unique_ptr<Listener> listener;
  std::shared_ptr<UdpSession> client;
  std::shared_ptr<UdpSession> server;
};

void TuneSession(const std::shared_ptr<UdpSession>& session) {
  // nc=1 disables congestion control, so a fresh session does not spend the first ticks
  // bootstrapping cwnd from 0 (P5's TestCwndBootstrap pins that behaviour). A wide window keeps
  // the write path from blocking on loopback.
  session->SetNoDelay(1, 10, 2, 1);
  session->SetWindowSize(1024, 1024);
}

// Dials `crypt` against a fresh listener and waits for Accept(). The first write is what makes the
// listener create the session, so it doubles as the handshake.
bool Establish(Pair* pair, const kcp::Crypt& crypt, int data_shards, int parity_shards,
               const std::string& label) {
  std::error_code ec;
  pair->listener = kcp::ListenWithOptions("127.0.0.1:0", crypt, data_shards, parity_shards, &ec);
  if (!pair->listener) {
    Fail(__FILE__, __LINE__, label + ": listen failed: " + ec.message());
    return false;
  }

  pair->client =
      kcp::DialWithOptions(pair->listener->addr(), crypt, data_shards, parity_shards, &ec);
  if (!pair->client) {
    Fail(__FILE__, __LINE__, label + ": dial failed: " + ec.message());
    return false;
  }
  TuneSession(pair->client);

  const std::string hello = "hello";
  if (pair->client->write(hello.data(), hello.size(), &ec) != static_cast<int>(hello.size())) {
    Fail(__FILE__, __LINE__, label + ": handshake write failed: " + ec.message());
    return false;
  }

  pair->listener->SetReadDeadline(AfterMs(5000));
  pair->server = pair->listener->Accept(&ec);
  if (!pair->server) {
    Fail(__FILE__, __LINE__, label + ": accept failed: " + ec.message());
    return false;
  }
  TuneSession(pair->server);

  std::vector<char> echo(64);
  pair->server->SetReadDeadline(AfterMs(5000));
  const int got = pair->server->read(echo.data(), echo.size(), &ec);
  if (got != static_cast<int>(hello.size()) ||
      std::memcmp(echo.data(), hello.data(), hello.size()) != 0) {
    Fail(__FILE__, __LINE__, label + ": handshake payload mismatch");
    return false;
  }
  return true;
}

// Pushes `total` bytes through a session pair while reading the other end, then compares.
bool Transfer(const Pair& pair, std::size_t total, std::size_t chunk, const std::string& label) {
  const std::vector<std::uint8_t> payload = Pattern(total, 7);
  std::vector<std::uint8_t> received(total, 0);
  std::atomic<std::size_t> got{0};
  std::atomic<bool> failed{false};
  std::string error;

  std::thread reader([&] {
    std::vector<std::uint8_t> buffer(64 * 1024);
    while (got.load() < total && !failed.load()) {
      pair.server->SetReadDeadline(AfterMs(15000));
      std::error_code ec;
      const int n = pair.server->read(buffer.data(), buffer.size(), &ec);
      if (n <= 0) {
        failed.store(true);
        error = label + ": read failed: " + ec.message();
        return;
      }
      const std::size_t have = got.load();
      const std::size_t take = std::min(static_cast<std::size_t>(n), total - have);
      std::memcpy(received.data() + have, buffer.data(), take);
      got.store(have + take);
    }
  });

  std::size_t sent = 0;
  while (sent < total && !failed.load()) {
    const std::size_t n = std::min(chunk, total - sent);
    pair.client->SetWriteDeadline(AfterMs(20000));
    std::error_code ec;
    const int written = pair.client->write(payload.data() + sent, n, &ec);
    if (written <= 0) {
      failed.store(true);
      error = label + ": write failed: " + ec.message();
      break;
    }
    sent += static_cast<std::size_t>(written);
  }

  reader.join();
  if (failed.load()) {
    Fail(__FILE__, __LINE__, error);
    return false;
  }
  if (got.load() != total) {
    Fail(__FILE__, __LINE__,
         label + ": received " + std::to_string(got.load()) + " of " + std::to_string(total));
    return false;
  }
  if (std::memcmp(received.data(), payload.data(), total) != 0) {
    std::size_t at = 0;
    while (at < total && received[at] == payload[at]) {
      ++at;
    }
    Fail(__FILE__, __LINE__, label + ": payload differs at byte " + std::to_string(at));
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------------------------

// Naked path: no cipher, no FEC. 1 MiB is ~762 segments, enough to wrap the send window more than
// once at the default size.
void TestPlainRoundTrip() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "plain")) {
    return;
  }
  Transfer(pair, 1024 * 1024, 32 * 1024, "plain");
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// FEC(10,3) + AES-GCM: the AEAD path with a tag on every packet, parity shards interleaved.
void TestFecGcmRoundTrip() {
  const std::vector<std::uint8_t> key = Pattern(16, 0x21);
  kcp::Crypt crypt;
  crypt.aead = kcp::NewAesGcmCrypt(key.data(), key.size());
  if (!crypt.aead) {
    Fail(__FILE__, __LINE__, "GCM factory failed");
    return;
  }
  Pair pair;
  if (!Establish(&pair, crypt, 10, 3, "fec+gcm")) {
    return;
  }
  Transfer(pair, 256 * 1024, 32 * 1024, "fec+gcm");
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// FEC(10,3) + Salsa20: the CFB family, where the nonce and CRC ride inside the ciphertext.
void TestFecSalsaRoundTrip() {
  const std::vector<std::uint8_t> key = Pattern(32, 0x31);
  kcp::Crypt crypt;
  crypt.block = kcp::NewSalsa20BlockCrypt(key.data(), key.size());
  if (!crypt.block) {
    Fail(__FILE__, __LINE__, "Salsa20 factory failed");
    return;
  }
  Pair pair;
  if (!Establish(&pair, crypt, 10, 3, "fec+salsa20")) {
    return;
  }
  Transfer(pair, 256 * 1024, 32 * 1024, "fec+salsa20");
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// Ten simultaneous sessions on one listener: the stream key is the peer address, so a bug in the
// map or in the accept backlog shows up as cross-talk rather than as a timeout.
void TestConcurrentSessions() {
  constexpr int kSessions = 10;
  constexpr std::size_t kBytes = 256 * 1024;
  std::error_code ec;

  auto listener = kcp::Listen("127.0.0.1:0", &ec);
  if (!listener) {
    Fail(__FILE__, __LINE__, "listen failed: " + ec.message());
    return;
  }

  std::vector<std::shared_ptr<UdpSession>> clients;
  for (int i = 0; i < kSessions; ++i) {
    auto client = kcp::Dial(listener->addr(), &ec);
    if (!client) {
      Fail(__FILE__, __LINE__, "dial failed: " + ec.message());
      return;
    }
    TuneSession(client);
    const std::string hello = "c" + std::to_string(i);
    client->write(hello.data(), hello.size(), &ec);
    clients.push_back(client);
  }

  std::vector<std::shared_ptr<UdpSession>> servers;
  listener->SetReadDeadline(AfterMs(5000));
  for (int i = 0; i < kSessions; ++i) {
    auto server = listener->Accept(&ec);
    if (!server) {
      Fail(__FILE__, __LINE__, "accept " + std::to_string(i) + " failed: " + ec.message());
      return;
    }
    TuneSession(server);
    servers.push_back(server);
  }

  // Drain the per-session handshake byte so the payload comparison starts at offset 0.
  for (int i = 0; i < kSessions; ++i) {
    char hello[8] = {0};
    servers[static_cast<std::size_t>(i)]->SetReadDeadline(AfterMs(5000));
    if (servers[static_cast<std::size_t>(i)]->read(hello, sizeof(hello), &ec) != 2) {
      Fail(__FILE__, __LINE__, "handshake read failed for session " + std::to_string(i));
      return;
    }
  }

  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  for (int i = 0; i < kSessions; ++i) {
    workers.emplace_back([&, i] {
      Pair pair;
      pair.client = clients[static_cast<std::size_t>(i)];
      pair.server = servers[static_cast<std::size_t>(i)];
      if (!Transfer(pair, kBytes, 16 * 1024, "concurrent#" + std::to_string(i))) {
        failures.fetch_add(1);
      }
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }

  for (int i = 0; i < kSessions; ++i) {
    clients[static_cast<std::size_t>(i)]->close(nullptr);
    servers[static_cast<std::size_t>(i)]->close(nullptr);
  }
  if (failures.load() != 0) {
    Fail(__FILE__, __LINE__, std::to_string(failures.load()) + " concurrent transfers failed");
  }
}

// §3.6: read() returns one message (or its remainder) and never fills across a boundary, even when
// the caller's buffer is smaller than the message.
void TestReadMessageBoundaries() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "read-semantics")) {
    return;
  }

  const std::vector<std::uint8_t> first = Pattern(300, 1);
  const std::vector<std::uint8_t> second = Pattern(50, 2);
  std::error_code ec;
  if (pair.client->write(first.data(), first.size(), &ec) != 300 ||
      pair.client->write(second.data(), second.size(), &ec) != 50) {
    Fail(__FILE__, __LINE__, "write failed: " + ec.message());
    return;
  }

  std::vector<std::uint8_t> collected;
  std::vector<std::uint8_t> buffer(100);
  while (collected.size() < first.size() + second.size()) {
    pair.server->SetReadDeadline(AfterMs(5000));
    const int n = pair.server->read(buffer.data(), buffer.size(), &ec);
    if (n <= 0) {
      Fail(__FILE__, __LINE__, "read failed: " + ec.message());
      return;
    }
    collected.insert(collected.end(), buffer.begin(), buffer.begin() + n);
  }

  std::vector<std::uint8_t> want = first;
  want.insert(want.end(), second.begin(), second.end());
  if (collected != want) {
    Fail(__FILE__, __LINE__, "message mode merged or reordered the two writes");
    return;
  }

  // A buffer larger than the message must return exactly the message length, not the buffer size.
  if (pair.client->write(second.data(), second.size(), &ec) != 50) {
    Fail(__FILE__, __LINE__, "second write failed");
    return;
  }
  pair.server->SetReadDeadline(AfterMs(5000));
  const int n = pair.server->read(buffer.data(), buffer.size(), &ec);
  if (n != 50) {
    Fail(__FILE__, __LINE__, "short message read returned " + std::to_string(n) + ", want 50");
  }

  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// §3.1: close() must wake a blocked read() and report kClosedPipe; a second close reports the same.
void TestCloseUnblocksRead() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "close-wakes-read")) {
    return;
  }

  std::atomic<int> result{1};
  std::error_code seen;
  std::thread blocked([&] {
    char byte = 0;
    std::error_code ec;
    const int n = pair.server->read(&byte, 1, &ec);
    seen = ec;
    result.store(n == -1 && ec == ErrorCode::kClosedPipe ? 0 : -1);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  pair.server->close(nullptr);
  blocked.join();

  if (result.load() != 0) {
    Fail(__FILE__, __LINE__, "blocked read did not return kClosedPipe");
  }

  std::error_code second;
  pair.server->close(&second);
  if (second != ErrorCode::kClosedPipe) {
    Fail(__FILE__, __LINE__, "second close did not report kClosedPipe");
  }

  char byte = 0;
  std::error_code ec;
  if (pair.server->read(&byte, 1, &ec) != -1 || ec != ErrorCode::kClosedPipe) {
    Fail(__FILE__, __LINE__, "read after close did not report kClosedPipe");
  }
  pair.client->close(nullptr);
}

// §3.1 item 2: with write delay enabled the datagram is still only in KCP when close() runs, so the
// flush inside close() is the only thing that puts it on the wire.
void TestCloseFlushesTail() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "close-flush")) {
    return;
  }

  const std::vector<std::uint8_t> tail = Pattern(1000, 9);
  pair.client->SetWriteDelay(true);
  std::error_code ec;
  if (pair.client->write(tail.data(), tail.size(), &ec) != 1000) {
    Fail(__FILE__, __LINE__, "write failed: " + ec.message());
    return;
  }
  pair.client->close(nullptr);

  std::vector<std::uint8_t> received(1000, 0);
  std::size_t got = 0;
  while (got < received.size()) {
    pair.server->SetReadDeadline(AfterMs(5000));
    const int n = pair.server->read(received.data() + got, received.size() - got, &ec);
    if (n <= 0) {
      Fail(__FILE__, __LINE__, "tail was lost: " + ec.message());
      return;
    }
    got += static_cast<std::size_t>(n);
  }
  if (received != tail) {
    Fail(__FILE__, __LINE__, "tail payload differs");
  }
  pair.server->close(nullptr);
}

// Deadlines: an idle session must time out instead of blocking forever, and clearing the deadline
// must make the next read block again.
void TestReadDeadline() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "deadline")) {
    return;
  }

  char byte = 0;
  std::error_code ec;
  pair.server->SetReadDeadline(AfterMs(80));
  const auto start = std::chrono::steady_clock::now();
  const int n = pair.server->read(&byte, 1, &ec);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  if (n != -1 || ec != ErrorCode::kTimeout) {
    Fail(__FILE__, __LINE__, "read did not time out");
  }
  if (elapsed < std::chrono::milliseconds(60)) {
    Fail(__FILE__, __LINE__, "read returned before the deadline");
  }

  // A write that fits the window must succeed immediately even with a deadline set.
  pair.client->SetWriteDeadline(AfterMs(1000));
  if (pair.client->write("x", 1, &ec) != 1) {
    Fail(__FILE__, __LINE__, "write with deadline failed: " + ec.message());
  }

  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// Accept() honours the listener deadline, and closing the listener reports kClosedPipe.
void TestListenerDeadlineAndClose() {
  std::error_code ec;
  auto listener = kcp::Listen("127.0.0.1:0", &ec);
  if (!listener) {
    Fail(__FILE__, __LINE__, "listen failed: " + ec.message());
    return;
  }

  listener->SetReadDeadline(AfterMs(60));
  if (listener->Accept(&ec) != nullptr || ec != ErrorCode::kTimeout) {
    Fail(__FILE__, __LINE__, "accept did not time out");
  }
  if (listener->SetWriteDeadline(AfterMs(10)) != ErrorCode::kInvalidOperation) {
    Fail(__FILE__, __LINE__, "listener write deadline must be rejected");
  }

  listener->close(nullptr);
  std::error_code second;
  listener->close(&second);
  if (second != ErrorCode::kClosedPipe) {
    Fail(__FILE__, __LINE__, "second listener close did not report kClosedPipe");
  }
  if (listener->Accept(&ec) != nullptr || ec != ErrorCode::kClosedPipe) {
    Fail(__FILE__, __LINE__, "accept after close did not report kClosedPipe");
  }
}

// OOB is only defined when FEC is on: without it the API must say so rather than silently drop.
void TestOobRequiresFec() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "oob-disabled")) {
    return;
  }
  if (pair.client->SetOobHandler([](const std::uint8_t*, std::size_t) {}) !=
      ErrorCode::kOobRequiresFec) {
    Fail(__FILE__, __LINE__, "SetOobHandler accepted a session without FEC");
  }
  const std::uint8_t payload[4] = {1, 2, 3, 4};
  if (pair.client->SendOob(payload, sizeof(payload)) != ErrorCode::kOobRequiresFec) {
    Fail(__FILE__, __LINE__, "SendOob accepted a session without FEC");
  }
  if (pair.client->oob_max_size() != 0) {
    Fail(__FILE__, __LINE__, "oob_max_size must be 0 without FEC");
  }
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// OOB delivery on the FEC(10,3) path: it bypasses KCP entirely, so this also proves the four-way
// demultiplexing (data / parity / OOB / bare) routes OOB to the handler.
void TestOobRoundTrip() {
  const std::vector<std::uint8_t> key = Pattern(16, 0x41);
  kcp::Crypt crypt;
  crypt.block = kcp::NewAesBlockCrypt(key.data(), key.size());
  if (!crypt.block) {
    Fail(__FILE__, __LINE__, "AES factory failed");
    return;
  }
  Pair pair;
  if (!Establish(&pair, crypt, 10, 3, "oob")) {
    return;
  }

  std::mutex mu;
  std::condition_variable cv;
  std::vector<std::uint8_t> received;
  const ErrorCode registered =
      pair.server->SetOobHandler([&](const std::uint8_t* data, std::size_t len) {
        std::lock_guard<std::mutex> lock(mu);
        received.assign(data, data + len);
        cv.notify_one();
      });
  if (registered != ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "SetOobHandler failed on a FEC session");
    return;
  }

  const int max_size = pair.client->oob_max_size();
  if (max_size <= 0) {
    Fail(__FILE__, __LINE__, "oob_max_size must be positive with FEC");
  }

  const std::vector<std::uint8_t> payload = Pattern(32, 5);
  const std::uint64_t before = kcp::DefaultSnmp().oob_packets.load();
  if (pair.client->SendOob(payload.data(), payload.size()) != ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "SendOob failed");
    return;
  }

  {
    std::unique_lock<std::mutex> lock(mu);
    if (!cv.wait_for(lock, std::chrono::seconds(5), [&] { return !received.empty(); })) {
      Fail(__FILE__, __LINE__, "OOB payload never arrived");
      return;
    }
  }
  if (received != payload) {
    Fail(__FILE__, __LINE__, "OOB payload differs");
  }
  if (kcp::DefaultSnmp().oob_packets.load() <= before) {
    Fail(__FILE__, __LINE__, "oob_packets counter did not move");
  }

  // Oversized payloads are rejected before they reach the queue.
  std::vector<std::uint8_t> huge(static_cast<std::size_t>(max_size) + 1, 0xaa);
  if (pair.client->SendOob(huge.data(), huge.size()) != ErrorCode::kOobTooLarge) {
    Fail(__FILE__, __LINE__, "oversized OOB payload was accepted");
  }

  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// #47/#48 behaviour matrix: socket buffer options only apply to sockets the session owns.
void TestSocketOptionMatrix() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "sockopts")) {
    return;
  }
  if (pair.server->SetReadBuffer(1 << 20) != ErrorCode::kInvalidOperation) {
    Fail(__FILE__, __LINE__, "SetReadBuffer must be rejected on a listener session");
  }
  if (pair.server->SetWriteBuffer(1 << 20) != ErrorCode::kInvalidOperation) {
    Fail(__FILE__, __LINE__, "SetWriteBuffer must be rejected on a listener session");
  }
  if (pair.client->SetReadBuffer(1 << 20) != ErrorCode::kOk) {
    Fail(__FILE__, __LINE__, "SetReadBuffer failed on a dialled session");
  }
  // DSCP is best effort: success on Linux, commonly refused on Windows for an unconnected socket.
  const ErrorCode dscp = pair.client->SetDscp(46);
  if (dscp != ErrorCode::kOk && dscp != ErrorCode::kInvalidOperation) {
    Fail(__FILE__, __LINE__, "SetDscp returned an unexpected code");
  }
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// SetMtu returns true only when KCP accepts the reduced value (§3.7), and the session keeps
// working afterwards.
void TestSetMtu() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "mtu")) {
    return;
  }
  if (!pair.client->SetMtu(1400)) {
    Fail(__FILE__, __LINE__, "SetMtu(1400) failed on a plain session");
  }
  // 24 is the segment header alone, so nothing is left for a payload.
  if (pair.client->SetMtu(24)) {
    Fail(__FILE__, __LINE__, "SetMtu(24) was accepted");
  }
  if (!Transfer(pair, 64 * 1024, 8 * 1024, "post-mtu")) {
    return;
  }
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

// CurrEstab is incremented on creation and decremented exactly once on close.
void TestCurrEstabAccounting() {
  const std::uint64_t base = kcp::DefaultSnmp().curr_estab.load();
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "estab")) {
    return;
  }
  if (kcp::DefaultSnmp().curr_estab.load() != base + 2) {
    Fail(__FILE__, __LINE__, "curr_estab did not grow by two for a client and a server session");
  }
  pair.client->close(nullptr);
  pair.server->close(nullptr);
  if (kcp::DefaultSnmp().curr_estab.load() != base) {
    Fail(__FILE__, __LINE__, "curr_estab did not return to its baseline");
  }
}

// listener.go:1158-1176: Listener.Close closes every child session. Two failure modes hung off the
// missing call: the children kept using the shared socket that was about to be closed, and they
// stayed alive in the listener's map, so destroying the Listener destroyed the map first and then
// ran each session's destructor, which erases from that freed map. That second one showed up as
// STATUS_HEAP_CORRUPTION in roughly one run in ten.
void TestListenerCloseClosesSessions() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "listener-close")) {
    return;
  }
  if (pair.listener->session_count() != 1) {
    Fail(__FILE__, __LINE__, "listener did not track its accepted session");
  }

  pair.listener->close(nullptr);
  if (!pair.server->is_closed()) {
    Fail(__FILE__, __LINE__, "Listener::close did not close the session it owns");
  }
  if (pair.listener->session_count() != 0) {
    Fail(__FILE__, __LINE__, "Listener::close left sessions in the map");
  }

  // The test keeps holding `server`, so it outlives the listener object below. Its destructor must
  // not reach back into a dead listener.
  pair.client->close(nullptr);
  pair.listener.reset();
  pair.server.reset();
}

// Windows reports the ICMP port-unreachable from an earlier sendto on the *next* recvfrom as
// WSAECONNRESET. Treating that as fatal stops the monitor thread and every session on the socket
// starves, which is exactly what a peer closing mid-transfer produces. The listener must survive it
// and keep accepting.
void TestListenerSurvivesPeerDisappearing() {
  std::error_code ec;
  auto listener = kcp::Listen("127.0.0.1:0", &ec);
  if (!listener) {
    Fail(__FILE__, __LINE__, "listen failed: " + ec.message());
    return;
  }

  const std::string addr = listener->addr();
  {
    // First peer: complete a handshake, then vanish without a FIN (UDP has none). The server
    // session keeps its address, so the next echo it sends draws an ICMP unreachable.
    auto client = kcp::Dial(addr, &ec);
    if (!client) {
      Fail(__FILE__, __LINE__, "dial failed: " + ec.message());
      return;
    }
    TuneSession(client);
    const std::string hello = "x";
    client->write(hello.data(), hello.size(), &ec);

    listener->SetReadDeadline(AfterMs(5000));
    auto server = listener->Accept(&ec);
    if (!server) {
      Fail(__FILE__, __LINE__, "accept failed: " + ec.message());
      return;
    }
    TuneSession(server);

    char sink[8] = {0};
    server->SetReadDeadline(AfterMs(5000));
    if (server->read(sink, sizeof(sink), &ec) != 1) {
      Fail(__FILE__, __LINE__, "handshake read failed");
      return;
    }

    client->close(nullptr);
    // Push the echo into the closed peer so the ICMP error is definitely pending.
    const std::string tail(4096, 'z');
    for (int i = 0; i < 4; ++i) {
      server->SetWriteDeadline(AfterMs(2000));
      server->write(tail.data(), tail.size(), &ec);
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }

  // Second peer, same listener: if the monitor thread had returned, this never completes.
  auto client = kcp::Dial(addr, &ec);
  if (!client) {
    Fail(__FILE__, __LINE__, "second dial failed: " + ec.message());
    return;
  }
  TuneSession(client);
  const std::string hello = "still alive";
  client->write(hello.data(), hello.size(), &ec);

  listener->SetReadDeadline(AfterMs(5000));
  auto server = listener->Accept(&ec);
  if (!server) {
    Fail(__FILE__, __LINE__,
         "listener stopped accepting after a peer disappeared: " + ec.message());
    client->close(nullptr);
    return;
  }
  TuneSession(server);

  std::vector<char> echo(64, 0);
  server->SetReadDeadline(AfterMs(5000));
  const int got = server->read(echo.data(), echo.size(), &ec);
  if (got != static_cast<int>(hello.size()) ||
      std::memcmp(echo.data(), hello.data(), hello.size()) != 0) {
    Fail(__FILE__, __LINE__, "session on the surviving listener did not receive its handshake");
  }

  client->close(nullptr);
  server->close(nullptr);
  listener->close(nullptr);
}

// P8.0 regression guard: the accounting instrumentation (SessionProfile / IoCounters / CpuScope)
// must not disturb the pipeline it measures. A transfer with profiling on has to land byte-exact,
// and the counters it leaves behind have to be self-consistent: ACK traffic must come back for the
// window to move (rx_n > 0), and the readiness probes must sit inside the drain pattern's window
// (ReadLoop probes after each receive, so probe_n is within two of rx_n - the slack covers one
// close() race and one EWOULDBLOCK). The CPU buckets are deliberately not asserted - Windows
// GetThreadTimes advances in 15.6 ms ticks and a 1 MiB loopback transfer is shorter than two of
// them, so a non-zero assertion there would be a coin flip. The closure gate lives in
// tools/bench/profile_split.py over 100 MiB runs, where the quantization is negligible.
void TestProfilingCountersDoNotBreakTransfer() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "profiling")) {
    return;
  }
  pair.client->EnableProfiling();
  if (!Transfer(pair, 1024 * 1024, 32 * 1024, "profiling")) {
    pair.client->close(nullptr);
    pair.server->close(nullptr);
    return;
  }

  // Close both ends first: profile() is only coherent once the worker threads have joined (the
  // counters are written by four threads and a mid-flight snapshot is meaningless by design).
  pair.client->close(nullptr);
  pair.server->close(nullptr);

  const kcp::SessionProfile p = pair.client->profile();
  if (p.tx_n == 0) {
    Fail(__FILE__, __LINE__, "profiling: no sendto counted for a 1 MiB transfer");
  }
  // This test's peer only reads, so what comes back is ACK traffic, not echoes: the window cannot
  // move without it, hence rx_n > 0 (the echo-shaped invariant rx_n >= tx_n belongs to the
  // echo_client workload, where tools/bench/profile_split.py checks it).
  if (p.rx_n == 0) {
    Fail(__FILE__, __LINE__,
         "profiling: no recvfrom counted - ACKs must come back for the window to move");
  }
  // Drain pattern (ReadLoop): select(50ms) -> recvfrom -> select(0) per datagram, so a probe
  // follows every receive except the one a close() or an EWOULDBLOCK lands on. The structurally
  // guaranteed window is therefore probe_n in [rx_n - 2, rx_n].
  if (p.probe_n > p.rx_n || p.probe_n + 2 < p.rx_n) {
    Fail(__FILE__, __LINE__,
         "profiling: probe_n " + std::to_string(p.probe_n) + " vs rx_n " + std::to_string(p.rx_n) +
             " outside the drain pattern's [rx_n - 2, rx_n]");
  }
  if (p.write_calls == 0) {
    Fail(__FILE__, __LINE__, "profiling: write() calls not counted");
  }
  // The listener-owned server session reads on the monitor thread, which installs no counters:
  // read_thread_cpu_us stays 0 there by design (documented on SessionProfile).
  const kcp::SessionProfile server_profile = pair.server->profile();
  if (server_profile.read_thread_cpu_us != 0) {
    Fail(__FILE__, __LINE__, "profiling: listener session charged CPU to a thread it cannot see");
  }
}

// Regression guard for the R4 adversarial review: write_buffers() used to sum buffer lengths into
// an int, so a batch over INT_MAX bytes overflowed (signed overflow is UB) and the wrapped,
// negative total came back as a successful byte count. The batch is now validated before anything
// is queued; the check is length-only, which is what lets this test run without allocating two
// gigabytes - the oversized buffer is never dereferenced.
void TestWriteBuffersRejectsOversizedBatch() {
  Pair pair;
  if (!Establish(&pair, kcp::Crypt{}, 0, 0, "oversized")) {
    return;
  }
  const std::size_t too_big = static_cast<std::size_t>((std::numeric_limits<int>::max)()) + 1;
  std::error_code ec;
  const int n = pair.client->write_buffers({kcp::ConstBuffer{nullptr, too_big}}, &ec);
  if (n != -1 || ec != kcp::MakeErrorCode(ErrorCode::kInvalidArgument)) {
    Fail(__FILE__, __LINE__, "write_buffers: oversized batch not refused with kInvalidArgument");
  }
  // Second oversized shape: several buffers that are each individually legal but sum past
  // INT_MAX. The pre-check has to accumulate across buffers - a per-buffer-only check would
  // wave this batch through and hand KCP a >2 GiB copy source. Like the single-buffer case,
  // nothing is dereferenced, so this needs no allocation.
  const std::size_t half = static_cast<std::size_t>((std::numeric_limits<int>::max)()) / 2 + 1;
  const int m = pair.client->write_buffers(
      {kcp::ConstBuffer{nullptr, half}, kcp::ConstBuffer{nullptr, half}}, &ec);
  if (m != -1 || ec != kcp::MakeErrorCode(ErrorCode::kInvalidArgument)) {
    Fail(__FILE__, __LINE__,
         "write_buffers: multi-buffer oversized batch not refused with kInvalidArgument");
  }
  // An empty batch is legal and carries nothing: upstream kcp-go has no early return for it
  // either (it falls through the window wait), so on a fresh session it must report 0/kOk
  // rather than blocking or failing.
  const int z = pair.client->write_buffers({}, &ec);
  if (z != 0 || ec) {
    Fail(__FILE__, __LINE__,
         "write_buffers: empty batch misreported: n=" + std::to_string(z) + " ec=" + ec.message());
  }
  // A refused batch must have queued nothing: the session still has to carry a normal write.
  const std::string ping = "ping";
  if (pair.client->write(ping.data(), ping.size(), &ec) != static_cast<int>(ping.size())) {
    Fail(__FILE__, __LINE__,
         "write_buffers: session unusable after a refused batch: " + ec.message());
    pair.client->close(nullptr);
    pair.server->close(nullptr);
    return;
  }
  std::vector<char> echo(64);
  pair.server->SetReadDeadline(AfterMs(5000));
  const int got = pair.server->read(echo.data(), echo.size(), &ec);
  if (got != static_cast<int>(ping.size()) ||
      std::memcmp(echo.data(), ping.data(), ping.size()) != 0) {
    Fail(__FILE__, __LINE__, "write_buffers: follow-up write did not reach the peer");
  }
  pair.client->close(nullptr);
  pair.server->close(nullptr);
}

}  // namespace

int main() {
  kcp::platform::InitSockets();

  TestPlainRoundTrip();
  TestFecGcmRoundTrip();
  TestFecSalsaRoundTrip();
  TestConcurrentSessions();
  TestReadMessageBoundaries();
  TestCloseUnblocksRead();
  TestCloseFlushesTail();
  TestReadDeadline();
  TestListenerDeadlineAndClose();
  TestListenerCloseClosesSessions();
  TestListenerSurvivesPeerDisappearing();
  TestOobRequiresFec();
  TestOobRoundTrip();
  TestSocketOptionMatrix();
  TestSetMtu();
  TestCurrEstabAccounting();
  TestProfilingCountersDoNotBreakTransfer();
  TestWriteBuffersRejectsOversizedBatch();

  if (g_failures != 0) {
    std::fprintf(stderr, "session_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("session_test: OK\n");
  return 0;
}
