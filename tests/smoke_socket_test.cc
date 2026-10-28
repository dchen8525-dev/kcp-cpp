// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Loopback smoke test for the platform layer: bind / sendto / recvfrom / close on 127.0.0.1.
// Both endpoints bind to port 0, so concurrent ctest runs cannot collide (PORTING-PLAN.md #31).

#include <cstdio>
#include <cstring>

#include "kcp/platform/socket.h"

namespace {

int g_failures = 0;

void ReportFailure(const char* file, int line, const char* expr) {
  const int err = kcp::platform::LastError();
  std::fprintf(stderr, "FAIL %s:%d: %s (last error %d: %s)\n", file, line, expr, err,
               kcp::platform::ErrorMessage(err).c_str());
  ++g_failures;
}

#define CHECK(expr)                             \
  do {                                          \
    if (!(expr)) {                              \
      ReportFailure(__FILE__, __LINE__, #expr); \
    }                                           \
  } while (0)

}  // namespace

int main() {
  using kcp::platform::kInvalidSocket;
  using kcp::platform::SocketAddress;
  using kcp::platform::SocketHandle;

  CHECK(kcp::platform::InitSockets());

  SocketAddress local;
  CHECK(SocketAddress::Parse("127.0.0.1", 0, &local));
  CHECK(local.valid());
  CHECK(local.ToString() == "127.0.0.1:0");

  SocketAddress bad;
  CHECK(!SocketAddress::Parse("not-an-ip", 1, &bad));

  SocketHandle server = kcp::platform::SysSocketUdp();
  CHECK(server != kInvalidSocket);
  if (server == kInvalidSocket) {
    return 1;
  }
  CHECK(kcp::platform::SysBind(server, local) == 0);
  CHECK(kcp::platform::SysSetRecvTimeout(server, 2000) == 0);

  SocketAddress server_addr;
  CHECK(kcp::platform::SysGetSockName(server, &server_addr) == 0);
  CHECK(server_addr.valid());
  // Port must have been assigned; string must start with the loopback address.
  CHECK(server_addr.ToString().rfind("127.0.0.1:", 0) == 0);
  CHECK(server_addr.ToString() != "127.0.0.1:0");

  SocketHandle client = kcp::platform::SysSocketUdp();
  CHECK(client != kInvalidSocket);
  SocketAddress client_bind;
  CHECK(SocketAddress::Parse("127.0.0.1", 0, &client_bind));
  CHECK(kcp::platform::SysBind(client, client_bind) == 0);
  SocketAddress client_addr;
  CHECK(kcp::platform::SysGetSockName(client, &client_addr) == 0);

  const char kPayload[] = "ping";
  const int payload_len = 4;
  CHECK(kcp::platform::SysSendTo(client, kPayload, payload_len, server_addr) == payload_len);

  char buffer[64] = {0};
  SocketAddress from;
  const int received = kcp::platform::SysRecvFrom(server, buffer, sizeof(buffer), &from);
  CHECK(received == payload_len);
  CHECK(std::memcmp(buffer, kPayload, payload_len) == 0);
  // The datagram must be attributed to the client's bound address; this is the Listener session
  // key rule (source address, not conv).
  CHECK(from == client_addr);
  CHECK(from.ToString() == client_addr.ToString());

  // Address equality must distinguish ports.
  SocketAddress other;
  CHECK(SocketAddress::Parse("127.0.0.1", 1, &other));
  CHECK(other != client_addr);

  // --- IPv4-mapped IPv6 identity (R47) -------------------------------------------------------
  // A peer named as ::ffff:127.0.0.1 is the same peer as 127.0.0.1: Go compares net.UDPAddr with
  // IP.Equal (readloop.go:29-35). The family a socket reports must not decide it, or a session
  // dialled with a mapped literal drops every datagram (udp_session.cc ReadLoop).
  SocketAddress mapped;
  CHECK(SocketAddress::Parse("::ffff:127.0.0.1", 9000, &mapped));
  SocketAddress plain;
  CHECK(SocketAddress::Parse("127.0.0.1", 9000, &plain));
  CHECK(mapped == plain);
  CHECK(plain == mapped);
  CHECK(mapped.ToString() == plain.ToString());
  CHECK(mapped.ToString() == "127.0.0.1:9000");
  // ... but the port still separates them.
  SocketAddress mapped_other_port;
  CHECK(SocketAddress::Parse("::ffff:127.0.0.1", 9001, &mapped_other_port));
  CHECK(mapped_other_port != plain);
  // ... and a different host does not become equal by normalisation.
  SocketAddress mapped_other_host;
  CHECK(SocketAddress::Parse("::ffff:127.0.0.2", 9000, &mapped_other_host));
  CHECK(mapped_other_host != plain);
  // A real IPv6 address is unchanged by the mapped-range handling.
  SocketAddress v6_a;
  CHECK(SocketAddress::Parse("::1", 9000, &v6_a));
  SocketAddress v6_b;
  CHECK(SocketAddress::Parse("::1", 9000, &v6_b));
  CHECK(v6_a == v6_b);
  CHECK(v6_a != plain);
  CHECK(v6_a.ToString() == "[::1]:9000");

  CHECK(kcp::platform::SysClose(client) == 0);
  CHECK(kcp::platform::SysClose(server) == 0);
  kcp::platform::ShutdownSockets();

  if (g_failures != 0) {
    std::fprintf(stderr, "smoke_socket_test: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("smoke_socket_test: OK\n");
  return 0;
}
