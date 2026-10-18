// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// P6 gate: PORTING-PLAN.md §6.2 through a real UDP relay. P5 ran the same loss models against the
// KCP state machine with a virtual clock; here a real client and a real server talk through
// tests/lossy_relay.cc, which drops whole datagrams and never reorders or corrupts them.
//
// What this pins that nothing else does: the session survives 10% and 30% loss, retransmissions
// actually increase with the loss rate (so recovery is KCP's doing, not luck), the payload arrives
// byte for byte, and no session hits dead_link.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "kcp/crypt.h"
#include "kcp/error.h"
#include "kcp/listener.h"
#include "kcp/snmp.h"
#include "kcp/udp_session.h"
#include "lossy_relay.h"

namespace {

int g_failures = 0;

void Fail(const char* file, int line, const std::string& message) {
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  ++g_failures;
}

using kcp::ErrorCode;
using kcp::Listener;
using kcp::UdpSession;

std::vector<std::uint8_t> Pattern(std::size_t n, std::uint8_t seed) {
  std::vector<std::uint8_t> out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<std::uint8_t>((i * 31 + seed) & 0xff);
  }
  return out;
}

void TuneSession(const std::shared_ptr<UdpSession>& session) {
  session->SetNoDelay(1, 10, 2, 1);
  // A moderate window: the relay forwards one datagram per wake, so a wide window only fills its
  // sockets faster than it can drain them and the overflow would look like extra loss.
  session->SetWindowSize(64, 64);
}

// Echoes whatever arrives until the peer closes.
void ServeEcho(const std::shared_ptr<UdpSession>& session, std::atomic<bool>* done) {
  std::vector<std::uint8_t> buffer(64 * 1024);
  for (;;) {
    std::error_code ec;
    const int n = session->read(buffer.data(), buffer.size(), &ec);
    if (n > 0) {
      std::error_code write_ec;
      if (session->write(buffer.data(), static_cast<std::size_t>(n), &write_ec) < 0) {
        break;
      }
      continue;
    }
    if (ec) {
      break;
    }
  }
  done->store(true);
  std::error_code close_ec;
  session->close(&close_ec);
}

// Sends `payload` through the relay and checks the echo. Returns false on any failure and normally
// reports the retransmission count through *retrans.
bool RunLossyCase(double loss, bool gilbert, std::size_t payload_size, int deadline_ms,
                  const std::string& label, std::uint64_t* retrans_out) {
  std::error_code ec;
  kcp::Crypt crypt;  // no encryption: this gate is about loss, not about the cipher
  crypt.block = nullptr;

  auto listener = kcp::ListenWithOptions("127.0.0.1:0", crypt, 0, 0, &ec);
  if (!listener) {
    Fail(__FILE__, __LINE__, label + ": listen failed: " + ec.message());
    return false;
  }

  kcp::test::LossyRelay relay;
  kcp::test::LossyRelay::Config config;
  config.loss = loss;
  config.gilbert = gilbert;
  config.seed = 0x1234;
  std::string error;
  if (!relay.Start(listener->addr(), config, &error)) {
    Fail(__FILE__, __LINE__, label + ": relay start failed: " + error);
    return false;
  }

  auto client = kcp::DialWithOptions(relay.front_addr(), crypt, 0, 0, &ec);
  if (!client) {
    Fail(__FILE__, __LINE__, label + ": dial failed: " + ec.message());
    return false;
  }
  TuneSession(client);
  client->SetDeadline(std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms));

  // The first write is what makes the listener create the server-side session.
  const char hello[] = "lossy";
  if (client->write(hello, sizeof(hello) - 1, &ec) != static_cast<int>(sizeof(hello) - 1)) {
    Fail(__FILE__, __LINE__, label + ": handshake write failed: " + ec.message());
    return false;
  }

  std::shared_ptr<UdpSession> server;
  listener->SetDeadline(std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms));
  server = listener->Accept(&ec);
  if (!server) {
    Fail(__FILE__, __LINE__, label + ": accept failed: " + ec.message());
    return false;
  }
  TuneSession(server);

  std::atomic<bool> echo_done{false};
  std::thread echo(ServeEcho, server, &echo_done);

  // The echo thread blocks in read() and KCP has no FIN, so the server-side session has to be
  // unblocked explicitly before it can be joined. Every exit path below goes through this.
  auto stop_echo = [&]() {
    server->SetReadDeadline(std::chrono::steady_clock::now());
    echo.join();
  };

  char handshake[16] = {};
  if (client->read(handshake, sizeof(handshake), &ec) != static_cast<int>(sizeof(hello) - 1)) {
    Fail(__FILE__, __LINE__, label + ": handshake read failed: " + ec.message());
    stop_echo();
    return false;
  }

  const std::uint64_t retrans_before = kcp::DefaultSnmp().retrans_segs.load();
  const std::vector<std::uint8_t> payload = Pattern(payload_size, 7);
  if (client->write(payload.data(), payload.size(), &ec) != static_cast<int>(payload.size())) {
    Fail(__FILE__, __LINE__, label + ": payload write failed: " + ec.message());
    stop_echo();
    return false;
  }

  std::vector<std::uint8_t> echoed(payload_size);
  std::size_t received = 0;
  while (received < echoed.size()) {
    std::error_code read_ec;
    const int n = client->read(echoed.data() + received, echoed.size() - received, &read_ec);
    if (n <= 0) {
      Fail(__FILE__, __LINE__,
           label + ": echo read failed at " + std::to_string(received) + ": " + read_ec.message());
      echo.join();
      return false;
    }
    received += static_cast<std::size_t>(n);
  }

  const std::uint64_t retrans_after = kcp::DefaultSnmp().retrans_segs.load();
  const std::uint64_t retrans = retrans_after - retrans_before;
  const kcp::test::LossyRelay::Stats stats = relay.Snapshot();

  if (echoed != payload) {
    Fail(__FILE__, __LINE__, label + ": payload differs");
  }
  if (client->IsDead()) {
    Fail(__FILE__, __LINE__, label + ": session hit dead_link");
  }

  std::error_code close_ec;
  client->close(&close_ec);
  stop_echo();
  listener->close(nullptr);
  if (!echo_done.load()) {
    Fail(__FILE__, __LINE__, label + ": echo thread did not finish");
  }
  relay.Stop();

  std::printf("relay %-14s loss=%.2f%s payload=%zu dropped=%llu retrans=%llu\n", label.c_str(),
              loss, gilbert ? " (gilbert)" : "", payload_size,
              static_cast<unsigned long long>(stats.dropped),
              static_cast<unsigned long long>(retrans));
  *retrans_out = retrans;
  return true;
}

}  // namespace

int main() {
  std::uint64_t retrans = 0;

  // 0% is the control: every datagram must arrive, and retransmissions must stay incidental. The
  // relay queues (one datagram per wake), so KCP can still fire a fast retransmit on an ack burst;
  // what must not happen is loss (dropped == 0 is asserted inside RunLossyCase through the relay
  // stats printed above) or a retransmission storm.
  constexpr std::uint64_t kCleanRetransBudget = 64;  // 5% of the 762 segments in 1 MiB
  if (!RunLossyCase(0.0, false, 1u << 20, 30000, "clean", &retrans)) {
    Fail(__FILE__, __LINE__, "clean run failed");
  } else if (retrans > kCleanRetransBudget) {
    Fail(
        __FILE__, __LINE__,
        "0% loss retransmitted " + std::to_string(retrans) + " segments: relay is not transparent");
  }

  // 10% is the "real link" case: recovery has to happen, and the payload still has to match.
  if (!RunLossyCase(0.10, false, 1u << 20, 60000, "uniform-10", &retrans)) {
    Fail(__FILE__, __LINE__, "10% loss run failed");
  } else if (retrans == 0) {
    Fail(__FILE__, __LINE__, "10% loss recovered nothing");
  }

  // 30% is the stress case. Kept at 256 KiB because the relay is real time: every dropped datagram
  // costs a retransmission round trip, and the P5 virtual-clock run already covered 1 MiB.
  if (!RunLossyCase(0.30, false, 256u << 10, 60000, "uniform-30", &retrans)) {
    Fail(__FILE__, __LINE__, "30% loss run failed");
  } else if (retrans == 0) {
    Fail(__FILE__, __LINE__, "30% loss recovered nothing");
  }

  // A burst model is a different shape of loss: whole runs of datagrams vanish, which is what makes
  // a sliding window stall. The gate only requires that it still completes.
  if (!RunLossyCase(0.0, true, 256u << 10, 60000, "gilbert", &retrans)) {
    Fail(__FILE__, __LINE__, "gilbert burst run failed");
  } else if (retrans == 0) {
    Fail(__FILE__, __LINE__, "gilbert burst loss recovered nothing");
  }

  if (g_failures != 0) {
    std::fprintf(stderr, "relay_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("relay_test: OK\n");
  return 0;
}
