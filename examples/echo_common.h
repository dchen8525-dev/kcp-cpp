// The MIT License (MIT)
//
// Copyright (c) 2026 kcp-cpp contributors
//
// Helpers shared by examples/echo_server.cc and examples/echo_client.cc: command-line parsing,
// the cipher-name table the Go tools use, and a SHA-256 digest for the RESULT line.
//
// This is example/tooling code - nothing here is part of the library, which is why the digest is
// implemented locally instead of pulled in as a dependency.

#ifndef KCP_EXAMPLES_ECHO_COMMON_H_
#define KCP_EXAMPLES_ECHO_COMMON_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "kcp/crypt.h"
#include "kcp/udp_session.h"

namespace echo {

// FIPS 180-4 SHA-256. Used only to compare a payload across processes and languages: the Go side
// prints the same digest, so a mismatch in the matrix is visible without a byte dump.
class Sha256 {
 public:
  static constexpr std::size_t kDigestSize = 32;

  Sha256();

  void Update(const void* data, std::size_t len);
  std::array<std::uint8_t, kDigestSize> Final();

 private:
  void Compress(const std::uint8_t block[64]);

  std::uint32_t state_[8];
  std::uint8_t buffer_[64];
  std::size_t buffered_ = 0;
  std::uint64_t total_bits_ = 0;
  bool finished_ = false;
};

std::string ToHex(const std::array<std::uint8_t, Sha256::kDigestSize>& digest);

// One-shot convenience used by both binaries.
std::string Sha256Hex(const void* data, std::size_t len);

// Options shared by the echo pair. Defaults match PORTING-PLAN.md §6.3 so a baseline run needs no
// flags: conv=1, mtu=1400, no-delay(1,10,2,1), snd/rcv window 32/32.
struct Options {
  std::string addr = "127.0.0.1:9000";
  std::string crypt = "aes";
  std::string key = "kcp-cpp-interop-key";
  int data_shards = 10;
  int parity_shards = 3;
  int sndwnd = 32;
  int rcvwnd = 32;
  int mtu = 1400;
  // Socket buffers. The OS default (64 KB on Windows) overflows as soon as the window is larger
  // than a few dozen segments, and the resulting loss is indistinguishable from link loss.
  int sockbuf = 4 << 20;

  // Client only.
  int bytes = 1 << 20;
  int chunk = 32 * 1024;
  int iters = 1;
  int timeout_ms = 30000;
  // Server: read and drop instead of echoing. Client: send only. Used by §6.3 to separate the send
  // path from the echo path when attributing a throughput shortfall.
  bool discard = false;
  // Server: print a global SNMP line to stderr every N milliseconds (0 = off). Diagnostics only;
  // it has no effect on the packet path.
  int stats_ms = 0;
  // Both: capture the first datagram that crosses the socket into this file (§6.1). Empty = off.
  std::string dump_packet;
  // Client: enable the P8.0 per-session cost accounting and print the PROFILE line after RESULT.
  // Off by default because it adds clock reads to the code being measured.
  bool profile = false;
};

// Parses -name value / --name value / -name=value. Accepts both single and double dashes so the Go
// and C++ tools can be driven by one script. Returns false and fills *error on an unknown flag.
bool ParseOptions(int argc, char** argv, Options* out, std::string* error);

// Name table identical to tools/interop/kcpcrypt/crypt.go. Returns false and fills *error for an
// unknown name or a key the cipher rejects.
bool MakeCrypt(const std::string& name, const std::string& key, kcp::Crypt* out,
               std::string* error);

// Applies no-delay / window size / mtu exactly as the Go tools do, in the same order. Returns false
// when the mtu is outside the range SetMtu accepts (§3.7).
bool ApplyTuning(const std::shared_ptr<kcp::UdpSession>& session, const Options& options);

// Captures the first datagram that crosses the socket and writes it in the format
// tools/interop/dump_packet.py reads (PORTING-PLAN.md §6.1). Both implementations emit the same
// bytes for the same packet, so a C++ capture and a Go capture of the same datagram are identical
// files apart from the direction tag - which is exactly how the two taps are verified.
//
//   KCPDUMP 1 dir=out len=36
//   00000000 3c000000f1f10000...
class FirstPacketDump {
 public:
  // An empty path disables the dump; Record then does nothing.
  explicit FirstPacketDump(std::string path);

  void Record(bool outgoing, const std::uint8_t* data, std::size_t len);

 private:
  std::mutex mu_;
  std::string path_;
  bool done_ = false;
};

}  // namespace echo

#endif  // KCP_EXAMPLES_ECHO_COMMON_H_
